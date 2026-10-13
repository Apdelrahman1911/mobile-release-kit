"""Explicit, currently inspected image restoration through the existing writer.

A saved journal is DATA, not an original import receipt. This module binds a
new immutable capability to a complete read-only inspection, rechecks it for
Prepare and Apply, and then borrows the existing rollback/cleanup primitives.
It never retries an import, reconstructs RootedRevision, or writes arbitrary
paths supplied by the renderer. Native imports remain on the original owner
path; importing this facade does not qualify a platform.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from . import config_edit as _shared
from . import init_transaction as tx
from .api._json import bounded_json_text
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .errors import ValidationError
from .metadata_images import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_BATCH_BYTES,
                              MAX_IMAGES, MAX_IMAGE_BYTES, MAX_PREPARED_BYTES,
                              MAX_SIBLINGS, POLICY, MetadataImagesInputError,
                              PublicImageSelection, admit_baseline, content_digest,
                              image_summary, name_key, public_image_selection,
                              safe_name)
from .metadata_images_custody import _FolderEntry, _folder_entries, _relevant

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease


class _Conflict(ValueError):
    """A deterministic inspection refusal, not IO/cancellation uncertainty."""


def _need(condition: bool) -> None:
    if not condition:
        raise _Conflict("Incomplete or changed image recovery proof")


def _freeze(value: dict[str, Any] | None) -> tuple | None:
    return None if value is None else tuple(sorted(value.items()))


def _thaw(value: tuple | None) -> dict[str, Any] | None:
    return None if value is None else dict(value)


@dataclass(frozen=True, slots=True)
class _FileFact:
    binding: tuple | None
    raw: tuple | None


@dataclass(frozen=True, slots=True)
class _Inspection:
    state: str
    action: str
    selection: PublicImageSelection
    header: bytes
    plan: bytes
    private_identity: tuple
    private_facts: tuple
    controls: tuple[tuple[str, _FileFact], ...]
    data: tuple[tuple[str, bool, tuple, tuple], ...]
    dependencies: tuple[tuple[str, int, _FileFact], ...]
    public: tuple[tuple[str, _FileFact], ...]
    parents: tuple[tuple[str, tuple | None], ...]
    parent_facts: tuple[tuple[str, tuple | None], ...]
    directory_objects: tuple[tuple[str, tuple], ...]
    inventory: tuple[_FolderEntry, ...]


def _read(workspace: tx.InitWorkspace, fd: int | None, name: str, limit: int,
          budget: list[int] | None = None) -> tuple[_FileFact, bytes | None]:
    workspace._last_read_facts = None
    maximum = limit if budget is None else min(limit, tx.MAX_TOTAL_BYTES - budget[0])
    value = workspace._read(fd, name, maximum) if fd is not None else None
    if value is None:
        return _FileFact(None, None), None
    binding, raw = value
    facts = workspace._last_read_facts
    _need(type(facts) is tuple and type(raw) is bytes)
    if budget is not None:
        budget[0] += len(raw)
        _need(budget[0] <= tx.MAX_TOTAL_BYTES)
    return _FileFact(_freeze(binding), facts), raw


def _public(workspace: tx.InitWorkspace, path: str, limit: int,
            budget: list[int] | None = None, *, planning: bool = False
            ) -> tuple[_FileFact, bytes | None]:
    with workspace._parent(path, planning=planning) as parent:
        return _read(workspace, parent, path.rsplit("/", 1)[-1], limit, budget)


def _parse(raw: bytes) -> dict[str, Any]:
    try:
        value = tx._parse(raw)
    except ValidationError:
        raise _Conflict("Invalid image recovery control DATA") from None
    _need(tx._json(value) == raw)
    return value


def _inventory_data(value: object) -> tuple[_FolderEntry, ...]:
    _need(type(value) is list and len(value) <= MAX_SIBLINGS)
    rows = []
    for row in value:
        _need(type(row) is dict and set(row) == {
            "name", "kind", "device", "inode", "mode", "uid", "gid"})
        name = row["name"]
        _need(type(name) is str and bool(name) and name not in {".", ".."}
              and "/" not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name))
        try:
            _need(len(name.encode("utf-8")) <= 255)
        except UnicodeError:
            raise _Conflict("Invalid image inventory name") from None
        _need(all(type(row[key]) is int and 0 <= row[key] < 2**64 for key in row if key != "name")
              and row["inode"] > 0 and row["mode"] <= 0o7777
              and row["kind"] in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFIFO,
                                   stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK})
        rows.append(_FolderEntry(**row))
    _need([row.name for row in rows] == sorted(row.name for row in rows)
          and len({name_key(row.name) for row in rows}) == len(rows))
    return tuple(rows)


def _selection(config: bytes, ignore: bytes, context: dict[str, Any]) -> PublicImageSelection:
    from .config_payloads import sufficient_ignore_rules
    from .metadata import check_metadata_text

    _need(set(context) == {"policy", "platform", "locale", "assetType", "metadataRoot",
                           "config", "ignore", "inventory", "siblings"}
          and context["policy"] == POLICY
          and context["config"] == content_digest(config)
          and context["ignore"] == content_digest(ignore))
    try:
        text = config.decode("utf-8")
        _need(not any(code == "metadata.secret-pattern"
                      for code, _ in check_metadata_text("mobile-release.json", text).issues)
              and sufficient_ignore_rules(ignore, tx.IGNORE_LINES))
        selection = public_image_selection(text, context["platform"], context["locale"], context["assetType"])
    except (UnicodeError, MetadataImagesInputError):
        raise _Conflict("Saved image configuration cannot authorize this recovery") from None
    _need(selection.metadata_root == context["metadataRoot"])
    return selection


def _directory(workspace: tx.InitWorkspace, fd: int | None, name: str
               ) -> tuple[dict[str, Any] | None, tuple | None]:
    from .build_inputs import _directory as directory_facts

    binding = workspace._binding(fd, name, directory=True) if fd is not None else None
    if binding is None:
        return None, None
    with workspace._descriptor(name, workspace.flags, dir_fd=fd) as child:
        value = os.fstat(child)
        _need(tx._dir_identity(value) == binding)
        facts = tuple(sorted(directory_facts(value).items()))
    return binding, facts


def _inspect(workspace: tx.InitWorkspace, state: str, fd: int,
             config_pair: tuple[_FileFact, bytes], ignore_pair: tuple[_FileFact, bytes]) -> _Inspection:
    """Read and validate once; no authority is installed by this function."""
    names = set(workspace._list(fd))
    _need(len(names) <= 2 * MAX_IMAGES + tx.MAX_FILES + 4
          and {"header.json", "plan.json"} <= names
          and not names & {"header.tmp", "plan.tmp", *tx.PROBES})
    controls: dict[str, _FileFact] = {}
    bodies = {}
    for name in sorted(names & tx.CONTROLS):
        fact, raw = _read(workspace, fd, name, tx.MAX_CONTROL_BYTES)
        _need(fact.binding is not None and raw is not None)
        controls[name], bodies[name] = fact, raw
    header, plan = _parse(bodies["header.json"]), _parse(bodies["plan.json"])
    _need(set(header) == {"schemaVersion", "transactionId", "root", "domain", "image"}
          and type(header["schemaVersion"]) is int and header["schemaVersion"] == 1
          and type(header["transactionId"]) is str
          and _shared._TOKEN.fullmatch(header["transactionId"]) is not None
          and workspace._valid_identity(header["root"], directory=True)
          and header["root"] == workspace.root_identity
          and header["domain"] == "metadata_images" and type(header["image"]) is dict)
    try:
        workspace._validate_plan_data(header, plan)
    except (ValidationError, KeyError, TypeError):
        raise _Conflict("Invalid image recovery plan DATA") from None
    context = header["image"]
    config_fact, config = config_pair
    ignore_fact, ignore = ignore_pair
    selection = _selection(config, ignore, context)
    inventory = _inventory_data(context["inventory"])
    try:
        relevant = _relevant(selection, inventory)
    except tx.InitOperationFailure:
        raise _Conflict("Unsupported original image inventory") from None
    files, directories = plan["files"], plan["directories"]
    _need(1 <= len(files) <= MAX_IMAGES and any(row["after"] is not None for row in files))
    target_names = tuple(row["path"].rsplit("/", 1)[-1] for row in files)
    _need(all(safe_name(name) and row["path"] == selection.relative_path(name)
              for name, row in zip(target_names, files)))
    target_set = set(target_names)
    _need(len({name_key(name) for name in target_names}) == len(target_names)
          and not any(name != row.name and name_key(name) == name_key(row.name)
                      for name in target_names for row in inventory))
    if selection.asset_type.singleton:
        _need(len(files) == 1 and len(relevant) <= 1
              and target_names[0].rsplit(".", 1)[0].casefold() == selection.asset_type.identity.casefold()
              and (not relevant or relevant == target_names))
    _need(len(set(relevant) | target_set) <= selection.asset_type.max_count)
    original = {row.name: row for row in inventory}
    for name, row in zip(target_names, files):
        before, after = row["before"], row["after"]
        old = original.get(name)
        _need((old is None) == (before is None))
        if old is not None:
            _need(old.kind == stat.S_IFREG and all(getattr(old, key) == before[key]
                                                  for key in ("device", "inode", "mode")))
        if after is not None:
            _need(0 < after["size"] <= MAX_IMAGE_BYTES
                  and (after["mode"] == before["mode"] if before else not after["mode"] & ~0o644))
    expected_dirs = tuple("/".join(selection.folder.split("/")[:depth])
                          for depth in range(1, len(selection.folder.split("/")) + 1))
    _need(tuple(row["path"] for row in directories) == expected_dirs
          and sum(row["after"]["size"] for row in files if row["after"]) <= MAX_BATCH_BYTES
          and all(row["after"] is None or row["after"]["mode"] == 0o755 for row in directories))
    readonly = tuple(selection.relative_path(name) for name in relevant if name not in target_set)
    siblings = context["siblings"]
    _need(type(siblings) is list and len(siblings) == len(readonly))
    for row, path in zip(siblings, readonly):
        _need(type(row) is dict and set(row) == {"path", "binding"} and row["path"] == path
              and workspace._valid_identity(row["binding"], limit=MAX_IMAGE_BYTES)
              and row["binding"]["device"] == workspace.root_identity["device"])
    try:
        tx.validate_paths([*DEPENDENCY_PATHS, *readonly, *(row["path"] for row in files)])
    except ValidationError:
        raise _Conflict("Image recovery namespaces conflict") from None
    dependency_bytes = len(config) + len(ignore) + sum(row["binding"]["size"] for row in siblings)
    _need(dependency_bytes + sum(value["size"] for row in files
                                for value in (row["before"], row["after"]) if value) <= tx.MAX_TOTAL_BYTES)

    terminal = []
    for marker, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
        _need((marker in controls) != (pending in controls))
        name = marker if marker in controls else pending
        _need(bodies[name] == workspace._marker(plan, marker))
        if marker in controls:
            terminal.append(marker)
    _need(len(terminal) <= 1 and len(controls) == 4)
    if state == tx.IMAGE_PREPARING:
        _need(not terminal)
    action = ("committed_cleanup" if terminal == ["COMMITTED"] else
              "rolled_back_cleanup" if terminal == ["ROLLED_BACK"] else
              "rollback" if state == tx.IMAGE_READY else "preparing_cleanup")
    partial = state == tx.IMAGE_CLEANUP
    budget = [len(config) + len(ignore)]
    dependencies = [(DEPENDENCY_PATHS[0], DEPENDENCY_LIMITS[0], config_fact),
                    (DEPENDENCY_PATHS[1], DEPENDENCY_LIMITS[1], ignore_fact)]
    final_digests = []
    for row in siblings:
        fact, raw = _public(workspace, row["path"], MAX_IMAGE_BYTES, budget, planning=True)
        _need(fact.binding == _freeze(row["binding"]) and raw is not None)
        original_row = original[row["path"].rsplit("/", 1)[-1]]
        _need(all(dict(fact.raw)[key] == getattr(original_row, key) for key in ("uid", "gid")))
        if action == "committed_cleanup":
            _need(not image_summary(raw, original_row.name, selection.asset_type)[1])
        final_digests.append(dict(fact.binding)["sha256"])
        dependencies.append((row["path"], MAX_IMAGE_BYTES, fact))

    data: dict[str, tuple[bool, tuple, tuple]] = {}
    directory_objects = []
    for index, row in enumerate(directories):
        path, before, after = row["path"], row["before"], row["after"]
        with workspace._parent(path, planning=True) as parent:
            current, current_facts = _directory(workspace, parent, path.rsplit("/", 1)[-1])
        workspace.parents[path], workspace._parent_facts[path] = current, current_facts
        slot = f"directory-{index}"
        staged, staged_facts = _directory(workspace, fd, slot) if slot in names else (None, None)
        if before is not None:
            _need(current == before and staged is None)
            directory_objects.append((path, current_facts))
        else:
            _need(not inventory and (staged is None or staged == after))
            if action == "committed_cleanup":
                _need(current == after and staged is None)
            elif action == "rollback":
                _need((current == after and staged is None) or (current is None and staged == after))
            else:
                _need(current is None and (staged == after or partial and staged is None))
            if current_facts is not None or staged_facts is not None:
                directory_objects.append((path, current_facts or staged_facts))
            if staged is not None:
                with workspace._descriptor(slot, workspace.flags, dir_fd=fd) as child:
                    _need(not workspace._list(child))
                data[slot] = (True, _freeze(staged), staged_facts)

    public = []
    for index, (name, row) in enumerate(zip(target_names, files)):
        before, after = row["before"], row["after"]
        current, current_raw = _public(workspace, row["path"], MAX_IMAGE_BYTES, budget)
        public.append((row["path"], current))
        actual = _thaw(current.binding)
        staged = backup = None
        staged_raw = backup_raw = None
        for prefix in ("new", "old"):
            slot = f"{prefix}-{index}"
            if slot in names:
                fact, raw = _read(workspace, fd, slot, MAX_IMAGE_BYTES, budget)
                _need(fact.binding is not None and raw is not None)
                data[slot] = (False, fact.binding, fact.raw)
                if prefix == "new":
                    staged, staged_raw = _thaw(fact.binding), raw
                else:
                    backup, backup_raw = _thaw(fact.binding), raw
        if after is None:
            _need(actual == before and staged is None and backup is None)
        elif action == "committed_cleanup":
            _need(actual == after and staged is None
                  and (backup == before or partial and backup is None))
        elif action == "rollback":
            _need((actual == before and staged == after and backup is None)
                  or (before is not None and actual is None and staged == after and backup == before)
                  or (actual == after and staged is None and backup == before))
        else:
            _need(actual == before and backup is None and (staged == after or partial and staged is None))
        old_fact = current if actual == before and before is not None else (
            _FileFact(data[f"old-{index}"][1], data[f"old-{index}"][2]) if backup is not None else None)
        if old_fact is not None:
            _need(all(dict(old_fact.raw)[key] == getattr(original[name], key) for key in ("uid", "gid")))
        after_raw = (current_raw if after is not None and actual == after else staged_raw)
        if after_raw is not None:
            _need(not image_summary(after_raw, name, selection.asset_type)[1])
        if action == "committed_cleanup":
            _need(current_raw is not None and not image_summary(current_raw, name, selection.asset_type)[1])
        final_digests.append((after or before)["sha256"])
    _need(len(final_digests) == len(set(final_digests)))
    _need(names == set(controls) | set(data))
    actual_inventory = _folder_entries(workspace, selection, planning=False)
    _need(tuple(row for row in actual_inventory if row.name not in target_set)
          == tuple(row for row in inventory if row.name not in target_set))
    expected_paths = {row["path"] for row in (*directories, *files)}
    for row in directories:
        if row["after"] is not None and workspace.parents[row["path"]] is not None:
            with workspace._parent(row["path"] + "/.mrk-image-inventory") as parent:
                _need(parent is not None and all(row["path"] + "/" + name in expected_paths
                                                for name in workspace._list(parent)))
    _need(set(workspace._list(fd)) == names)
    return _Inspection(state, action, selection, bodies["header.json"], bodies["plan.json"],
                       _freeze(workspace.private_identity), workspace._private_facts,
                       tuple(sorted(controls.items())),
                       tuple((name, *value) for name, value in sorted(data.items())),
                       tuple(dependencies), tuple(public),
                       tuple((path, _freeze(value)) for path, value in sorted(workspace.parents.items())),
                       tuple(sorted(workspace._parent_facts.items())),
                       tuple(directory_objects), actual_inventory)


class ImageRecoveryRevision(_shared._PrivateAuthority):
    """A new restoration capability, never an original-import revision."""

    __slots__ = ("_identity", "_lease", "_inspection", "_token")

    def __repr__(self) -> str:
        return "<ImageRecoveryRevision>"

    @property
    def token(self) -> str:
        return self._token

    def _check_workspace(self, workspace: tx.InitWorkspace) -> None:
        from .init_workspace_custody import LockedInitScope

        if (type(self) is not ImageRecoveryRevision or self._identity is not self
                or type(workspace) is not tx.InitWorkspace
                or workspace._typed_profile is not tx.TypedEditProfile.METADATA_IMAGES
                or workspace._image_recovery is not self or self._lease._image_recovery is not self
                or not self._lease._image_recovery_mode or self._lease._revision is not None
                or type(workspace._scope) is not LockedInitScope
                or workspace._scope is not self._lease._active
                or workspace._scope.lease is not self._lease or workspace._scope.workspace is not workspace):
            raise tx.InitConflict("Image restoration does not belong to this original scope")

    @property
    def dependency_only_parents(self) -> dict[str, dict[str, Any] | None]:
        targets = {row["path"] for row in json.loads(self._inspection.plan)["directories"]}
        return {path: _thaw(value) for path, value in self._inspection.parents if path not in targets}

    def check_context(self, workspace: tx.InitWorkspace, *, changing: str | None = None) -> None:
        self._check_workspace(workspace)
        captured = self._inspection
        plan = json.loads(captured.plan)
        original_dirs = {row["path"]: row for row in plan["directories"]}
        skip_folder = changing is not None and (captured.selection.folder == changing
                                                or captured.selection.folder.startswith(changing + "/"))
        if changing is not None:
            original_inventory = json.loads(captured.header)["image"]["inventory"]
            row = original_dirs.get(changing)
            if (not skip_folder or not getattr(workspace, "_restoration_started", False)
                    or row is None or row["before"] is not None or row["after"] is None or original_inventory):
                raise tx.InitConflict("Image restoration cannot skip a pre-existing directory")
        for path, limit, expected in captured.dependencies:
            current, _ = _public(workspace, path, limit)
            if current != expected:
                raise tx.InitConflict("An inspected image dependency changed")
        directory_objects = dict(captured.directory_objects)
        for path, expected in captured.parent_facts:
            if changing is not None and (path == changing or path.startswith(changing + "/")):
                continue
            with workspace._parent(path) as parent:
                current, facts = _directory(workspace, parent, path.rsplit("/", 1)[-1])
            row = original_dirs.get(path)
            if row is not None and row["after"] is not None:
                valid = current is None or (current == row["after"] and facts == directory_objects.get(path))
            else:
                valid = facts == expected
            if not valid:
                raise tx.InitConflict("An inspected image ancestor changed")
        if not skip_folder:
            targets = {row["path"].rsplit("/", 1)[-1] for row in plan["files"]}
            current = _folder_entries(workspace, captured.selection, planning=False)
            if (tuple(row for row in current if row.name not in targets)
                    != tuple(row for row in captured.inventory if row.name not in targets)):
                raise tx.InitConflict("An unrelated image sibling changed")

    def check_header(self, raw: bytes, header: dict[str, Any]) -> None:
        if raw != self._inspection.header or tx._json(header) != raw:
            raise tx.InitConflict("Inspected image header changed")

    def check_plan(self, raw: bytes, plan: dict[str, Any]) -> None:
        if raw != self._inspection.plan or tx._json(plan) != raw:
            raise tx.InitConflict("Inspected image plan changed")

    def control(self, name: str, identity: Any) -> dict[str, Any]:
        expected = dict(self._inspection.controls).get(name)
        if name == "ROLLED_BACK" and self._inspection.action == "rollback":
            scope = self._lease._active
            workspace = scope.workspace if scope is not None else None
            if (workspace is None or not getattr(workspace, "_restoration_started", False)
                    or workspace._terminal_seen != "ROLLED_BACK"
                    and workspace._publishing_terminal != "ROLLED_BACK"):
                raise tx.InitConflict("No owned restoration marker transition occurred")
            expected = dict(self._inspection.controls).get("rollback.pending")
        if expected is None or identity != _thaw(expected.binding):
            raise tx.InitConflict("Inspected image control identity changed")
        return dict(identity)

    def check_preserved(self, workspace: tx.InitWorkspace, path: str) -> None:
        self._check_workspace(workspace)
        expected = dict(self._inspection.public).get(path)
        current, _ = _public(workspace, path, MAX_IMAGE_BYTES)
        if expected is None or current != expected:
            raise tx.InitConflict("An inspected preserved image changed")

    def cleanup_entries(self, workspace: tx.InitWorkspace) -> dict[str, tuple[bool, dict[str, Any]]]:
        self._check_workspace(workspace)
        self._check_final_public(workspace)
        captured = self._inspection
        result = {name: (False, _thaw(fact.binding)) for name, fact in captured.controls}
        if captured.action == "rollback":
            if workspace._terminal_seen != "ROLLED_BACK" or not workspace._terminal_durable:
                raise tx.InitConflict("Restoration terminal durability is unconfirmed")
            result["ROLLED_BACK"] = result.pop("rollback.pending")
            plan = json.loads(captured.plan)
            result.update({f"new-{index}": (False, row["after"])
                           for index, row in enumerate(plan["files"]) if row["after"] is not None})
            result.update({f"directory-{index}": (True, row["after"])
                           for index, row in enumerate(plan["directories"]) if row["after"] is not None})
        else:
            result.update({name: (directory, _thaw(binding)) for name, directory, binding, _ in captured.data})
        return result

    def _check_final_public(self, workspace: tx.InitWorkspace) -> None:
        """Never discard the last backup based on a terminal marker alone."""
        self._check_workspace(workspace)
        captured = self._inspection
        plan = json.loads(captured.plan)
        originals = dict(captured.public)
        data = {name: _FileFact(binding, raw) for name, directory, binding, raw in captured.data
                if not directory}
        for index, row in enumerate(plan["files"]):
            current, _ = _public(workspace, row["path"], MAX_IMAGE_BYTES)
            if captured.action != "rollback":
                valid = current == originals[row["path"]]
            else:
                before = row["before"]
                original = originals[row["path"]]
                moved = original.binding != _freeze(before)
                if moved and before is not None:
                    original = data.get(f"old-{index}")
                valid = current.binding == _freeze(before)
                if valid and before is not None:
                    valid = original is not None and original.raw is not None and current.raw is not None
                    if valid:
                        # An owned rename changes ctime, not payload, mtime,
                        # owner, mode or inode. Unmoved inputs retain all facts.
                        expected_facts, actual_facts = dict(original.raw), dict(current.raw)
                        if moved:
                            expected_facts.pop("ctime"); actual_facts.pop("ctime")
                        valid = actual_facts == expected_facts
            if not valid:
                raise tx.InitConflict("The actual final image changed before cleanup")
        for row in plan["directories"]:
            expected = row["before"]
            if captured.action == "committed_cleanup" and row["after"] is not None:
                expected = row["after"]
            if workspace._current(row["path"], directory=True) != expected:
                raise tx.InitConflict("The actual final image directory changed before cleanup")
        self.check_context(workspace)

    def check_preparing_cleanup(self, workspace: tx.InitWorkspace, fd: int, plan: dict[str, Any]) -> None:
        self._check_workspace(workspace)
        self.check_plan(tx._json(plan), plan)
        if self._inspection.action != "preparing_cleanup" or workspace._terminal(fd, plan) is not None:
            raise tx.InitConflict("The inspected cleanup is not a preparation")
        expected = self.cleanup_entries(workspace)
        if set(workspace._list(fd)) != set(expected):
            raise tx.InitConflict("Inspected preparation cleanup inventory changed")
        for row in plan["files"]:
            if workspace._current(row["path"]) != row["before"]:
                raise tx.InitConflict("Preparation cleanup would discard an unrestored image")
        for row in plan["directories"]:
            if workspace._current(row["path"], directory=True) != row["before"]:
                raise tx.InitConflict("Preparation cleanup directory state changed")
        self.check_context(workspace)

    def recheck(self, workspace: tx.InitWorkspace) -> None:
        self._check_workspace(workspace)
        captured = self._inspection
        workspace.private_identity = _thaw(captured.private_identity)
        workspace._private_facts = captured.private_facts
        pairs = [_public(workspace, path, limit, planning=True)
                 for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS)]
        try:
            _need(all(fact.binding is not None and raw is not None for fact, raw in pairs))
            with workspace.inspect_image_recovery_state() as (state, fd):
                _need(state == captured.state and fd is not None)
                current = _inspect(workspace, state, fd, *pairs)
            _need(current == captured)
        except _Conflict:
            raise tx.InitConflict("Image recovery changed since its original preview") from None

    def apply(self, workspace: tx.InitWorkspace) -> tx.InitApplyOutcome:
        self._check_workspace(workspace)
        if getattr(workspace, "_restoration_started", False):
            raise tx.InitConflict("Image restoration is one-use")
        try:
            workspace._checkpoint()
            workspace.rename = tx._rename_function()
            state, action = self._inspection.state, self._inspection.action
            with workspace._private(state) as fd:
                plan = workspace._load(fd)
                workspace._terminal(fd, plan)
                self.check_context(workspace)
                if action == "rollback":
                    workspace._locations(fd, plan)
                elif action == "preparing_cleanup":
                    workspace._preparing_inventory(fd)
                # Apply's entry scope already rechecked actual committed or
                # restored targets, including CLEANUP with missing old DATA.
                workspace._restoration_started = True
                if action == "rollback":
                    workspace._rollback(fd, plan)
            if state != tx.IMAGE_CLEANUP:
                workspace._state_move(state, tx.IMAGE_CLEANUP)
            workspace._cleanup()
            self._check_final_public(workspace)
        except BaseException as error:
            if getattr(workspace, "_restoration_primary", None) is None:
                workspace._restoration_primary = error
                workspace._restoration_reason = (error.outcome.reason if type(error) is tx.InitOperationFailure else
                                                 "cancelled" if isinstance(error, KeyboardInterrupt) else
                                                 "stale_revision" if isinstance(error, tx.InitConflict) else "filesystem_error")
            # No second cleanup loop, no import retry, and no late success that
            # erases the first failure. Original scope/lease still close slots.
            raise tx.InitOperationFailure(self.outcome(workspace), workspace._restoration_primary) from None
        return self.outcome(workspace)

    def outcome(self, workspace: tx.InitWorkspace, reason: str = "none") -> tx.InitApplyOutcome:
        """Pure final facts; safe after the borrowed scope has been closed."""
        first = getattr(workspace, "_restoration_reason", "none")
        if first == "none" and reason != "none":
            workspace._restoration_reason = first = reason
        action = self._inspection.action
        if action == "committed_cleanup":
            effect = "committed"  # Inspected pre-existing fact, not our import.
        elif action == "rolled_back_cleanup" or workspace._terminal_seen == "ROLLED_BACK":
            effect = "rolled_back"
        elif workspace._terminal_ambiguous or action == "rollback" and getattr(workspace, "_restoration_started", False):
            effect = "unknown"
        else:
            effect = "not_started"
        journal = "clean" if workspace._journal_clean else "recovery_required"
        resources = "unknown" if workspace._guard is not None and workspace._guard.lifetime_ledger.fatal else "settled"
        if first == "none" and (journal != "clean" or effect == "unknown" or resources == "unknown"):
            first = "custody_unknown" if resources == "unknown" else "pending_state"
        return tx.InitApplyOutcome(effect, journal, resources, first)


class MetadataImagesRecoveryCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_baseline_json",
                 "_view_json", "_state", "_prepared")

    def __repr__(self) -> str:
        return "<MetadataImagesRecoveryCheckout>"

    @property
    def intent(self) -> str:
        return "recover"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def baseline(self) -> dict[str, Any]:
        return json.loads(self._baseline_json)

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


class PreparedMetadataImagesRecovery(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_view_json", "_state")

    def __repr__(self) -> str:
        return "<PreparedMetadataImagesRecovery>"

    @property
    def intent(self) -> str:
        return "recover"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


def _authentic_checkout(value: object) -> bool:
    return type(value) is MetadataImagesRecoveryCheckout and getattr(value, "_identity", None) is value


def _authentic_prepared(value: object) -> bool:
    return (type(value) is PreparedMetadataImagesRecovery and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None))
            and value._checkout._prepared is value)


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    return (type(lease) is native.lease and getattr(lease, "profile", None) is tx.TypedEditProfile.METADATA_IMAGES
            and getattr(lease, "_image_recovery_mode", None) is True)


def _retain_inspected(lease: InitRootLease, failure: CoreEditOutcome) -> CoreEditOutcome:
    """A failed new scope cannot erase the original inspected pending journal.

    Initial lease checks may fail before a workspace is borrowed. Their generic
    not_created means this call created nothing, not that a previously observed
    image journal disappeared. Keep those known facts with the new failure.
    """
    if failure.journal != "not_created":
        return failure
    revision = getattr(lease, "_image_recovery", None)
    if type(revision) is not ImageRecoveryRevision or getattr(revision, "_identity", None) is not revision:
        return failure
    try:
        previous = _shared._native_outcome(_shared._native_contract(), lease.last_outcome)
        if previous.journal == "not_created":
            return CoreEditOutcome("unknown", "unknown", "unknown", failure.reason)
        return CoreEditOutcome(previous.effect, previous.journal,
                               "unknown" if "unknown" in (previous.resources, failure.resources) else "settled",
                               failure.reason)
    except BaseException:
        return CoreEditOutcome("unknown", "unknown", "unknown", failure.reason)


def _view(captured: _Inspection | None, *, conflict: bool = False) -> dict[str, Any]:
    result = {"kind": "recover", "state": "conflict" if conflict else "idle", "action": None,
              "transactionId": None, "platform": None, "locale": None, "assetType": None,
              "files": [], "privateCleanup": {"fileCount": 0, "directoryCount": 0,
                                                "scope": "original-image-journal-only"},
              "valid": False, "issues": [],
              "assurance": {"newRestorationAttempt": True, "sourceFilesUnchanged": True,
                            "storeContacted": False, "importRetried": False}}
    if conflict:
        result["issues"] = [{"code": "image.recovery-conflict", "severity": "error",
                             "message": "The complete image recovery state could not be verified. Nothing was changed; preserve the journal and review the conflict."}]
    if captured is None:
        return result
    plan = json.loads(captured.plan)
    result.update(state="recoverable", action=captured.action, transactionId=plan["transactionId"],
                  platform=captured.selection.platform, locale=captured.selection.locale,
                  assetType=captured.selection.asset_type.identity, valid=True)
    result["files"] = [{"path": row["path"],
                        "effect": ("preserve" if row["after"] is None else
                                   "keep_committed" if captured.action == "committed_cleanup" else "restore_original"),
                        "original": ({"byteLength": row["before"]["size"], "sha256": row["before"]["sha256"]}
                                     if row["before"] is not None else None),
                        "new": ({"byteLength": row["after"]["size"], "sha256": row["after"]["sha256"]}
                                if row["after"] is not None else None)} for row in plan["files"]]
    if captured.action == "rollback":
        file_count = len(captured.controls) + sum(row["after"] is not None for row in plan["files"])
        directory_count = sum(row["after"] is not None for row in plan["directories"])
    else:
        file_count = len(captured.controls) + sum(not row[1] for row in captured.data)
        directory_count = sum(row[1] for row in captured.data)
    result["privateCleanup"].update(fileCount=file_count, directoryCount=directory_count)
    return result


def _encoded(value: dict[str, Any]) -> bytes:
    return bounded_json_text(value, max_bytes=MAX_PREPARED_BYTES, max_nodes=16384, max_depth=24).encode("utf-8")


def capture_metadata_images_recovery(lease: InitRootLease) -> MetadataImagesRecoveryCheckout:
    try:
        native = _shared._native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None
    if not _lease_matches(native, lease):
        _shared._reject("invalid_params")
    captured, revision, conflict = None, None, False
    try:
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None:
            _shared._reject("custody_unknown")
        with lease.image_recovery_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            pairs = [_public(workspace, path, limit, planning=True)
                     for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS)]
            for index, (fact, raw) in enumerate(pairs):
                if fact.binding is None or raw is None:
                    from .init_workspace_custody import _failure
                    raise _failure("invalid_config" if index == 0 else "ignore_conflict")
            with workspace.inspect_image_recovery_state() as (state, fd):
                if state is not None:
                    try:
                        captured = _inspect(workspace, state, fd, *pairs)
                    except _Conflict:
                        conflict = True
            if captured is not None:
                revision = object.__new__(ImageRecoveryRevision)
                for name, value in (("_identity", revision), ("_lease", lease),
                                    ("_inspection", captured), ("_token", token)):
                    object.__setattr__(revision, name, value)
                lease._image_recovery = workspace._image_recovery = revision
    except BaseException as error:
        raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
    try:
        view = _view(captured, conflict=conflict)
        # These hashes are observed configuration bytes, not invented empty
        # values for missing/unreadable files. Invalid views have no authority.
        inventory = {"state": view["state"], "action": view["action"], "revision": token}
        if captured is not None:
            inventory.update(headerSha256=hashlib.sha256(captured.header).hexdigest(),
                             planSha256=hashlib.sha256(captured.plan).hexdigest(),
                             controls=[(name, row.binding, row.raw) for name, row in captured.controls],
                             data=captured.data, public=[(path, row.binding, row.raw) for path, row in captured.public],
                             dependencies=[(path, row.binding, row.raw) for path, _, row in captured.dependencies],
                             parents=captured.parents, parentFacts=captured.parent_facts,
                             private=captured.private_identity, privateFacts=captured.private_facts,
                             inventory=[row.data() for row in captured.inventory])
        baseline = {"config": content_digest(pairs[0][1]), "ignore": content_digest(pairs[1][1]),
                    "inventorySha256": hashlib.sha256(tx._json(inventory)).hexdigest()}
        checkout = object.__new__(MetadataImagesRecoveryCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_revision_token", token), ("_baseline_json", _encoded(baseline)),
                            ("_view_json", _encoded(view)), ("_state", _shared._CAPTURED), ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except BaseException as error:
        # Inspection may already have established a persisted commit. A later
        # bounded projection failure cannot turn that into "not_created".
        try:
            previous = _shared._native_outcome(native, lease.last_outcome)
            reason = (previous.reason if previous.reason not in {"none", "pending_state"} else
                      "cancelled" if isinstance(error, KeyboardInterrupt) else "custody_unknown")
            failed = CoreEditOutcome(previous.effect, previous.journal, previous.resources, reason)
        except BaseException:
            failed = _shared._uncertain()
        raise ConfigEditFailure(failed) from None


def prepare_metadata_images_recovery(lease: InitRootLease, checkout: MetadataImagesRecoveryCheckout,
                                     expected_revision: str, expected_baseline: object,
                                     choices: object) -> PreparedMetadataImagesRecovery:
    if not _authentic_checkout(checkout) or checkout._state != _shared._CAPTURED:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._PREPARING)
    try:
        if (lease is not checkout._lease or checkout._revision is None
                or type(choices) is not list or choices != []
                or type(expected_revision) is not str or _shared._TOKEN.fullmatch(expected_revision) is None):
            _shared._reject("invalid_params")
        try:
            expected = admit_baseline(expected_baseline)
        except MetadataImagesInputError:
            _shared._reject("invalid_params")
        if expected_revision != checkout.revision or expected != checkout.baseline:
            _shared._reject("stale_revision")
        native = _shared._native_contract()
        if not _lease_matches(native, lease) or lease._image_recovery is not checkout._revision:
            _shared._reject("invalid_params")
        try:
            with lease.image_recovery_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
        except BaseException as error:
            raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        prepared = object.__new__(PreparedMetadataImagesRecovery)
        for name, value in (("_identity", prepared), ("_checkout", checkout), ("_token", token),
                            ("_view_json", checkout._view_json), ("_state", _shared._PREPARED)):
            object.__setattr__(prepared, name, value)
        object.__setattr__(checkout, "_prepared", prepared)
        object.__setattr__(checkout, "_state", _shared._PREPARED)
        return prepared
    except ConfigEditFailure as error:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise ConfigEditFailure(_retain_inspected(checkout._lease, error.outcome)) from None
    except BaseException as error:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise ConfigEditFailure(_retain_inspected(checkout._lease, _shared._pure_failure(error))) from None


def apply_metadata_images_recovery(lease: InitRootLease, prepared: PreparedMetadataImagesRecovery) -> CoreEditOutcome:
    if (not _authentic_prepared(prepared) or prepared._state != _shared._PREPARED
            or prepared._checkout._state != _shared._PREPARED):
        return _shared._not_started("invalid_params")
    checkout = prepared._checkout
    object.__setattr__(prepared, "_state", _shared._RETIRED)
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if lease is not checkout._lease:
        return _shared._not_started("invalid_params")
    try:
        native = _shared._native_contract()
    except BaseException as error:
        return _shared._pure_failure(error)
    if not _lease_matches(native, lease) or lease._image_recovery is not checkout._revision:
        return _shared._not_started("invalid_params")
    result = None
    try:
        with lease.image_recovery_scope(checkout._revision) as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            result = workspace.apply_metadata_images_recovery(checkout._revision)
    except BaseException as error:
        try:
            previous = _shared._native_outcome(native, result)
        except _shared._ContractViolation:
            previous = None
        return _retain_inspected(lease, _shared._settled_failure(native, error, previous))
    try:
        outcome = _shared._native_outcome(native, result)
    except _shared._ContractViolation:
        return _shared._uncertain()
    if outcome.reason == "none":
        effect = {"rollback": "rolled_back", "committed_cleanup": "committed",
                  "rolled_back_cleanup": "rolled_back", "preparing_cleanup": "not_started"}[checkout.view["action"]]
        if (outcome.effect, outcome.journal) != (effect, "clean"):
            return _shared._uncertain(outcome)
    return outcome


def discard_metadata_images_recovery(authority: MetadataImagesRecoveryCheckout | PreparedMetadataImagesRecovery) -> None:
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_prepared(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)
