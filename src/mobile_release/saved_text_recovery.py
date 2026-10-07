"""Fresh, explicit recovery of the two saved-text transaction domains.

Persisted controls are DATA. A complete original read under the registered
root lock binds a new one-use restoration capability, not a RootedRevision or
CREATED claim. The existing transaction remains the sole rollback/fsync/cleanup
writer. Legacy or incomplete context is preserved, never upgraded by guessing.
"""
from __future__ import annotations

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
from .metadata_text import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_TEXT_BYTES,
                            MetadataTextInputError, PublicTextSelection,
                            content_digest, public_text_selection)
from .version_text import MAX_VERSION_BYTES, VersionSelection, VersionTextInputError, public_version_selection

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease

MAX_VIEW_BYTES = 16 * 1024
_PROFILES = (tx.TypedEditProfile.METADATA_TEXT, tx.TypedEditProfile.RELEASE_VERSION)
_REASONS = frozenset(("legacy_journal", "incomplete_journal", "invalid_journal",
                      "foreign_journal", "dependency_changed", "target_changed"))


class _Conflict(ValueError):
    def __init__(self, reason: str):
        if reason not in _REASONS:
            raise ValueError("Unknown saved-text recovery refusal")
        super().__init__("Saved-text recovery proof is incomplete or changed")
        self.reason = reason


def _need(condition: bool, reason: str = "invalid_journal") -> None:
    if not condition:
        raise _Conflict(reason)


def _domain(profile: tx.TypedEditProfile) -> str:
    if profile is tx.TypedEditProfile.METADATA_TEXT:
        return "metadata_text"
    if profile is tx.TypedEditProfile.RELEASE_VERSION:
        return "release_version"
    raise ValueError("Saved-text recovery has exactly two profiles")


def _limit(profile: tx.TypedEditProfile) -> int:
    _domain(profile)
    return MAX_TEXT_BYTES if profile is tx.TypedEditProfile.METADATA_TEXT else MAX_VERSION_BYTES


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
    domain: str
    selection: PublicTextSelection | VersionSelection
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
        raise _Conflict("invalid_journal") from None
    _need(tx._json(value) == raw)
    return value


def _selection_data(selection: PublicTextSelection | VersionSelection) -> dict[str, Any]:
    if type(selection) is PublicTextSelection:
        return {"platform": selection.platform, "locale": selection.locale, "metadataRoot": selection.metadata_root}
    if type(selection) is VersionSelection:
        return {"source": selection.source, "nameKey": selection.name_key,
                "buildKey": selection.build_key, "iosEnabled": selection.ios_enabled}
    raise ValueError("Unknown saved-text selection")


def _selection(profile: tx.TypedEditProfile, config: bytes, ignore: bytes,
               context: dict[str, Any]) -> PublicTextSelection | VersionSelection:
    from .config_payloads import sufficient_ignore_rules
    from .metadata import check_metadata_text

    _need(set(context) == {"policy", "config", "ignore", "selection"}
          and context["policy"] == "saved-text-recovery-v1" and type(context["selection"]) is dict)
    _need(all(type(context[name]) is dict and set(context[name]) == {"byteLength", "sha256"}
              and type(context[name]["byteLength"]) is int and context[name]["byteLength"] >= 0
              and type(context[name]["sha256"]) is str
              for name in ("config", "ignore")))
    _need(context["config"] == content_digest(config) and context["ignore"] == content_digest(ignore),
          "dependency_changed")
    requested = context["selection"]
    try:
        text = config.decode("utf-8")
        _need(not any(code == "metadata.secret-pattern"
                      for code, _ in check_metadata_text("mobile-release.json", text).issues)
              and (sufficient_ignore_rules(ignore, tx.METADATA_IGNORE_LINES)
                   if profile is tx.TypedEditProfile.METADATA_TEXT else sufficient_ignore_rules(ignore)),
              "dependency_changed")
        if profile is tx.TypedEditProfile.METADATA_TEXT:
            _need(set(requested) == {"platform", "locale", "metadataRoot"})
            selected = public_text_selection(text, requested["platform"], requested["locale"])
        else:
            _need(profile is tx.TypedEditProfile.RELEASE_VERSION
                  and set(requested) == {"source", "nameKey", "buildKey", "iosEnabled"}
                  and type(requested["iosEnabled"]) is bool)
            selected = public_version_selection(text)
    except (UnicodeError, MetadataTextInputError, VersionTextInputError):
        raise _Conflict("dependency_changed") from None
    _need(_selection_data(selected) == requested, "dependency_changed")
    return selected


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
    """Complete read-only custody and location graph, not a name-based grant."""
    profile = workspace._typed_profile
    domain, limit = _domain(profile), _limit(profile)
    names = set(workspace._list(fd))
    _need(len(names) <= 25 and {"header.json", "plan.json"} <= names
          and not names & {"header.tmp", "plan.tmp", *tx.PROBES}, "incomplete_journal")
    controls, bodies = {}, {}
    for name in sorted(names & tx.CONTROLS):
        fact, raw = _read(workspace, fd, name, tx.MAX_CONTROL_BYTES)
        _need(fact.binding is not None and raw is not None, "incomplete_journal")
        controls[name], bodies[name] = fact, raw
    header, plan = _parse(bodies["header.json"]), _parse(bodies["plan.json"])
    _need(header.get("domain") == domain, "foreign_journal")
    if type(header.get("schemaVersion")) is int and header["schemaVersion"] == 1:
        raise _Conflict("legacy_journal")
    _need(set(header) == {"schemaVersion", "domain", "transactionId", "root", "recovery"}
          and type(header["schemaVersion"]) is int and header["schemaVersion"] == 2
          and type(header["transactionId"]) is str
          and _shared._TOKEN.fullmatch(header["transactionId"]) is not None
          and workspace._valid_identity(header["root"], directory=True)
          and type(header["recovery"]) is dict)
    _need(header["root"] == workspace.root_identity, "foreign_journal")
    try:
        workspace._validate_plan_data(header, plan)
    except (ValidationError, KeyError, TypeError):
        raise _Conflict("invalid_journal") from None
    config_fact, config = config_pair
    ignore_fact, ignore = ignore_pair
    selection = _selection(profile, config, ignore, header["recovery"])
    files, directories = plan["files"], plan["directories"]
    _need(tuple(row["path"] for row in files) == selection.paths
          and tuple(row["path"] for row in directories) == selection.directories
          and any(row["after"] is not None for row in files)
          and all(value is None or value["size"] <= limit
                  for row in files for value in (row["before"], row["after"]))
          and all(row["after"] is None or (row["after"]["mode"] == row["before"]["mode"]
                  if row["before"] is not None else not row["after"]["mode"] & ~0o644)
                  for row in files)
          and all(row["after"] is None or row["after"]["mode"] == 0o755 for row in directories))
    _need(len(config) + len(ignore) + sum(value["size"] for row in files
          for value in (row["before"], row["after"]) if value) <= tx.MAX_TOTAL_BYTES)
    terminal = []
    for marker, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
        _need((marker in controls) != (pending in controls), "incomplete_journal")
        name = marker if marker in controls else pending
        _need(bodies[name] == workspace._marker(plan, marker))
        if marker in controls:
            terminal.append(marker)
    _need(len(terminal) <= 1 and len(controls) == 4)
    if state == workspace._state_names[0]:
        _need(not terminal)
    action = ("committed_cleanup" if terminal == ["COMMITTED"] else
              "rolled_back_cleanup" if terminal == ["ROLLED_BACK"] else
              "rollback" if state == workspace._state_names[1] else "preparing_cleanup")
    partial = state == workspace._state_names[2]
    budget = [len(config) + len(ignore)]
    dependencies = ((DEPENDENCY_PATHS[0], DEPENDENCY_LIMITS[0], config_fact),
                    (DEPENDENCY_PATHS[1], DEPENDENCY_LIMITS[1], ignore_fact))
    data = {}
    directory_objects = []
    for index, row in enumerate(directories):
        path, before, after = row["path"], row["before"], row["after"]
        with workspace._parent(path, planning=True) as parent:
            current, current_facts = _directory(workspace, parent, path.rsplit("/", 1)[-1])
        workspace.parents[path], workspace._parent_facts[path] = current, current_facts
        slot = f"directory-{index}"
        staged, staged_facts = _directory(workspace, fd, slot) if slot in names else (None, None)
        if before is not None:
            _need(current == before and staged is None, "target_changed")
            directory_objects.append((path, current_facts))
        else:
            _need(staged is None or staged == after, "target_changed")
            if action == "committed_cleanup":
                _need(current == after and staged is None, "target_changed")
            elif action == "rollback":
                _need((current == after and staged is None) or (current is None and staged == after), "target_changed")
            else:
                _need(current is None and (staged == after or partial and staged is None), "target_changed")
            if current_facts is not None or staged_facts is not None:
                directory_objects.append((path, current_facts or staged_facts))
            if staged is not None:
                with workspace._descriptor(slot, workspace.flags, dir_fd=fd) as child:
                    _need(not workspace._list(child), "target_changed")
                data[slot] = (True, _freeze(staged), staged_facts)
    public = []
    for index, row in enumerate(files):
        before, after = row["before"], row["after"]
        current, _ = _public(workspace, row["path"], limit, budget)
        public.append((row["path"], current))
        actual, staged, backup = _thaw(current.binding), None, None
        for prefix in ("new", "old"):
            slot = f"{prefix}-{index}"
            if slot in names:
                fact, raw = _read(workspace, fd, slot, limit, budget)
                _need(fact.binding is not None and raw is not None, "target_changed")
                data[slot] = (False, fact.binding, fact.raw)
                if prefix == "new":
                    staged = _thaw(fact.binding)
                else:
                    backup = _thaw(fact.binding)
        if after is None:
            _need(actual == before and staged is None and backup is None, "target_changed")
        elif action == "committed_cleanup":
            _need(actual == after and staged is None
                  and (backup == before or partial and backup is None), "target_changed")
        elif action == "rollback":
            _need((actual == before and staged == after and backup is None)
                  or (before is not None and actual is None and staged == after and backup == before)
                  or (actual == after and staged is None and backup == before), "target_changed")
        else:
            _need(actual == before and backup is None and (staged == after or partial and staged is None), "target_changed")
    _need(names == set(controls) | set(data))
    expected_paths = {row["path"] for row in (*directories, *files)}
    for row in directories:
        if row["after"] is not None and workspace.parents[row["path"]] is not None:
            with workspace._parent(row["path"] + "/.mrk-recovery-inventory") as parent:
                _need(parent is not None and all(row["path"] + "/" + name in expected_paths
                                                for name in workspace._list(parent)), "target_changed")
    _need(set(workspace._list(fd)) == names)
    return _Inspection(state, action, domain, selection, bodies["header.json"], bodies["plan.json"],
                       _freeze(workspace.private_identity), workspace._private_facts,
                       tuple(sorted(controls.items())),
                       tuple((name, *value) for name, value in sorted(data.items())),
                       dependencies, tuple(public),
                       tuple((path, _freeze(value)) for path, value in sorted(workspace.parents.items())),
                       tuple(sorted(workspace._parent_facts.items())), tuple(directory_objects))


def recovery_outcome(lease: InitRootLease, workspace: tx.InitWorkspace | None = None,
                     reason: str = "none") -> tx.InitApplyOutcome:
    """Retain inspected facts without latching a readonly pending-state error."""
    if lease._saved_text_recovery_reason == "none" and reason != "none":
        lease._saved_text_recovery_reason = reason
    if workspace is not None:
        if workspace._terminal_seen == "ROLLED_BACK" and lease._saved_text_recovery_effect != "committed":
            lease._saved_text_recovery_effect = "rolled_back"
        elif (workspace._terminal_ambiguous or getattr(workspace, "_restoration_started", False)
              and lease._saved_text_recovery is not None
              and lease._saved_text_recovery._inspection.action == "rollback"):
            if lease._saved_text_recovery_effect not in {"committed", "rolled_back"}:
                lease._saved_text_recovery_effect = "unknown"
        if workspace._journal_clean:
            lease._saved_text_recovery_journal = "clean"
    resources = "unknown" if lease.guard.lifetime_ledger.fatal else "settled"
    first = lease._saved_text_recovery_reason
    if first == "none" and (resources == "unknown" or lease._saved_text_recovery_journal == "unknown"
                            or lease._saved_text_recovery_effect == "unknown"):
        first = "custody_unknown" if resources == "unknown" else "pending_state"
    return tx.InitApplyOutcome(lease._saved_text_recovery_effect, lease._saved_text_recovery_journal, resources, first)


class SavedTextRecoveryRevision(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_inspection", "_token")

    def __repr__(self) -> str:
        return "<SavedTextRecoveryRevision>"

    @property
    def token(self) -> str:
        return self._token

    def _check_workspace(self, workspace: tx.InitWorkspace) -> None:
        from .init_workspace_custody import LockedInitScope
        if (type(self) is not SavedTextRecoveryRevision or self._identity is not self
                or type(workspace) is not tx.InitWorkspace or workspace._typed_profile not in _PROFILES
                or workspace._typed_profile is not self._lease.profile
                or workspace._saved_text_recovery is not self or self._lease._saved_text_recovery is not self
                or not self._lease._saved_text_recovery_mode or self._lease._revision is not None
                or type(workspace._scope) is not LockedInitScope or workspace._scope is not self._lease._active
                or workspace._scope.lease is not self._lease or workspace._scope.workspace is not workspace):
            raise tx.InitConflict("Saved-text restoration does not belong to this original scope")

    @property
    def dependency_only_parents(self) -> dict[str, dict[str, Any] | None]:
        targets = {row["path"] for row in json.loads(self._inspection.plan)["directories"]}
        return {path: _thaw(value) for path, value in self._inspection.parents if path not in targets}


    def check_context(self, workspace: tx.InitWorkspace, *, changing: str | None = None) -> None:
        self._check_workspace(workspace)
        captured = self._inspection
        original_dirs = {row["path"]: row for row in json.loads(captured.plan)["directories"]}
        if changing is not None:
            row = original_dirs.get(changing)
            if (not getattr(workspace, "_restoration_started", False)
                    or row is None or row["before"] is not None or row["after"] is None):
                raise tx.InitConflict("Saved-text restoration cannot skip a pre-existing directory")
        for path, limit, expected in captured.dependencies:
            current, _ = _public(workspace, path, limit)
            if current != expected:
                raise tx.InitConflict("An inspected saved-text dependency changed")
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
                raise tx.InitConflict("An inspected saved-text ancestor changed")

    def check_header(self, raw: bytes, header: dict[str, Any]) -> None:
        if raw != self._inspection.header or tx._json(header) != raw:
            raise tx.InitConflict("Inspected saved-text header changed")


    def check_plan(self, raw: bytes, plan: dict[str, Any]) -> None:
        if raw != self._inspection.plan or tx._json(plan) != raw:
            raise tx.InitConflict("Inspected saved-text plan changed")


    def _current_facts(self, workspace: tx.InitWorkspace) -> dict:
        """Captured named locations, changed only by returned original effects."""
        self._check_workspace(workspace)
        if workspace._saved_text_current is None:
            captured, absent = self._inspection, _FileFact(None, None)
            plan = json.loads(captured.plan)
            book = {("private", name): (False, absent) for name in
                    ("header.json", "plan.json", "commit.pending", "rollback.pending", "COMMITTED", "ROLLED_BACK")}
            for index, row in enumerate(plan["files"]):
                for prefix in ("old", "new"):
                    book["private", f"{prefix}-{index}"] = (False, absent)
            parents, parent_facts = dict(captured.parents), dict(captured.parent_facts)
            for index, row in enumerate(plan["directories"]):
                path = row["path"]
                book["private", f"directory-{index}"] = (True, absent)
                book["public", path] = (True, _FileFact(parents[path], parent_facts[path]))
            for path, fact in captured.public:
                book["public", path] = (False, fact)
            for name, fact in captured.controls:
                book["private", name] = (False, fact)
            for name, directory, binding, raw in captured.data:
                book["private", name] = (directory, _FileFact(binding, raw))
            book["journal", ""] = (True, _FileFact(captured.private_identity, captured.private_facts))
            workspace._saved_text_current = book
        return workspace._saved_text_current

    def _private_fd(self, workspace: tx.InitWorkspace, fd: int) -> bool:
        from .build_inputs import _directory as directory_facts
        return _freeze(directory_facts(os.fstat(fd))) == self._inspection.private_facts

    def _endpoint(self, workspace: tx.InitWorkspace, key: tuple[str, str], fd: int, name: str) -> None:
        from .build_inputs import _directory as directory_facts
        book = self._current_facts(workspace)
        if key not in book or key[0] not in {"private", "public"} or name != key[1].rsplit("/", 1)[-1]:
            raise tx.InitConflict("Saved-text effect has no exact original named location")
        if key[0] == "private":
            state = workspace.state()
            if state not in (self._inspection.state, workspace._state_names[2]):
                raise tx.InitConflict("Saved-text private location changed")
            workspace._private_check(fd, state)
            workspace._alias(fd, name)
            return
        path = key[1]
        with workspace._parent(path) as parent:
            if parent is None:
                raise tx.InitConflict("Saved-text effect's original parent is absent")
            actual = _freeze(directory_facts(os.fstat(parent)))
            if _freeze(directory_facts(os.fstat(fd))) != actual:
                raise tx.InitConflict("Saved-text effect was routed to another directory")
            if "/" in path:
                parent_path = path.rsplit("/", 1)[0]
                expected = (book["public", parent_path][1].raw if ("public", parent_path) in book
                            else dict(self._inspection.parent_facts).get(parent_path))
                if actual != expected:
                    raise tx.InitConflict("Saved-text effect's named parent facts changed")

    def _actual_fact(self, workspace: tx.InitWorkspace, key: tuple[str, str], fd: int,
                     name: str, directory: bool) -> _FileFact:
        self._endpoint(workspace, key, fd, name)
        if directory:
            binding, raw = _directory(workspace, fd, name)
        else:
            workspace._last_read_facts = None
            binding = workspace._binding(fd, name, limit=tx.MAX_CONTROL_BYTES if key[0] == "private"
                                         and name in tx.CONTROLS else _limit(self._lease.profile))
            raw = workspace._last_read_facts if binding is not None else None
        return _FileFact(_freeze(binding), raw)

    def _named_fact(self, workspace: tx.InitWorkspace, key: tuple[str, str], fd: int,
                    name: str, directory: bool, expected: _FileFact) -> None:
        from .build_inputs import _directory as directory_facts, _file as file_facts
        self._endpoint(workspace, key, fd, name)
        value = tx._stat(fd, name)
        if value is None:
            valid = expected == _FileFact(None, None)
        else:
            valid = (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
            valid = valid and _freeze((directory_facts if directory else file_facts)(value)) == expected.raw
        if not valid:
            raise tx.InitConflict("Saved-text original named facts changed before effect")

    def control_read(self, workspace: tx.InitWorkspace, fd: int, name: str, item: Any) -> None:
        # Capture this returned read's facts BEFORE any other bounded read.
        raw = workspace._last_read_facts if item is not None else None
        if name not in tx.CONTROLS or not self._private_fd(workspace, fd):
            return
        key = ("private", name)
        self._endpoint(workspace, key, fd, name)
        expected = self._current_facts(workspace)[key]
        if expected != (False, _FileFact(_freeze(item[0]) if item is not None else None, raw)):
            raise tx.InitConflict("Inspected saved-text control original facts changed")

    def before_move(self, workspace: tx.InitWorkspace, source_fd: int, source: str,
                    destination_fd: int, destination: str, expected: dict[str, Any],
                    directory: bool, directory_path: str | None) -> dict:
        book = self._current_facts(workspace)
        if self._inspection.action != "rollback" or not getattr(workspace, "_restoration_started", False):
            raise tx.InitConflict("Only the admitted original rollback may move saved-text objects")
        plan = json.loads(self._inspection.plan)
        private_source, private_destination = self._private_fd(workspace, source_fd), self._private_fd(workspace, destination_fd)
        route = None
        if private_source and private_destination and (source, destination) == ("rollback.pending", "ROLLED_BACK"):
            if not directory and directory_path is None and workspace._publishing_terminal == "ROLLED_BACK":
                self._check_final_public(workspace)
                route = (("private", source), ("private", destination))
        elif not directory and directory_path is None:
            for index, row in enumerate(plan["files"]):
                if row["after"] is None:
                    continue
                path, leaf = row["path"], row["path"].rsplit("/", 1)[-1]
                if not private_source and private_destination and (source, destination) == (leaf, f"new-{index}") and expected == row["after"]:
                    route = (("public", path), ("private", destination))
                elif private_source and not private_destination and (source, destination) == (f"old-{index}", leaf) and expected == row["before"]:
                    route = (("private", source), ("public", path))
        elif directory and not private_source and private_destination:
            for index, row in enumerate(plan["directories"]):
                if (row["before"] is None and row["after"] is not None and directory_path == row["path"]
                        and (source, destination) == (row["path"].rsplit("/", 1)[-1], f"directory-{index}")
                        and expected == row["after"]):
                    route = (("public", row["path"]), ("private", destination))
        if route is None:
            raise tx.InitConflict("Saved-text rollback cannot redirect its fixed original locations")
        source_key, destination_key = route
        current = book[source_key]
        if current[0] is not directory or current[1].binding != _freeze(expected) or book[destination_key] != (directory, _FileFact(None, None)):
            raise tx.InitConflict("Saved-text rollback location proof changed")
        if self._actual_fact(workspace, source_key, source_fd, source, directory) != current[1]:
            raise tx.InitConflict("Saved-text rollback source original facts changed")
        self._named_fact(workspace, destination_key, destination_fd, destination, directory, _FileFact(None, None))
        self.check_context(workspace)
        self._named_fact(workspace, source_key, source_fd, source, directory, current[1])
        return {"source": source_key, "destination": destination_key, "directory": directory,
                "before": current[1], "captured": None, "changing": directory_path}

    def captured_move(self, workspace: tx.InitWorkspace, receipt: dict, source_fd: int, source: str,
                      destination_fd: int, destination: str) -> None:
        current = self._actual_fact(workspace, receipt["destination"], destination_fd, destination, receipt["directory"])
        expected = receipt["before"]
        before, after = _thaw(expected.raw), _thaw(current.raw)
        valid = expected.binding == current.binding and before is not None and after is not None
        if valid and not receipt["directory"]:
            # One actually observed original rename may change ctime. This is
            # NOT a standing exception for any later read or public cleanup.
            before.pop("ctime"); after.pop("ctime")
        if not valid or before != after:
            raise tx.InitConflict("Saved-text move captured changed original facts")
        self._named_fact(workspace, receipt["source"], source_fd, source, receipt["directory"], _FileFact(None, None))
        receipt["captured"] = current  # Local proof only; a lost return grants no later effects.

    def moved(self, workspace: tx.InitWorkspace, receipt: dict, source_fd: int, source: str,
              destination_fd: int, destination: str) -> None:
        # Called ONLY after the existing rename, captured-object proof, namespace
        # checks and both fsyncs return. A failed original never reaches this.
        book, current = self._current_facts(workspace), receipt["captured"]
        directory = receipt["directory"]
        if (current is None or book[receipt["source"]] != (directory, receipt["before"])
                or book[receipt["destination"]] != (directory, _FileFact(None, None))):
            raise tx.InitConflict("Saved-text original move did not settle its captured locations")
        self._named_fact(workspace, receipt["source"], source_fd, source, directory, _FileFact(None, None))
        self._named_fact(workspace, receipt["destination"], destination_fd, destination, directory, current)
        book[receipt["source"]] = (directory, _FileFact(None, None))
        book[receipt["destination"]] = (directory, current)

    def cleanup_entry(self, workspace: tx.InitWorkspace, fd: int, name: str,
                      directory: bool, binding: dict[str, Any]) -> None:
        key = ("private", name)
        book = self._current_facts(workspace)
        if key not in book or book[key][0] is not directory or book[key][1].binding != _freeze(binding):
            raise tx.InitConflict("Saved-text cleanup has no original named entry")
        if self._actual_fact(workspace, key, fd, name, directory) != book[key][1]:
            raise tx.InitConflict("Saved-text cleanup original facts changed")

    def before_unlink(self, workspace: tx.InitWorkspace, fd: int, name: str, directory: bool) -> tuple:
        book = self._current_facts(workspace)
        if not getattr(workspace, "_restoration_started", False) or workspace.state() != workspace._state_names[2]:
            raise tx.InitConflict("Saved-text removal is outside its original cleanup")
        if fd == workspace.fd and name == workspace._state_names[2] and directory:
            key, expected = ("journal", ""), book["journal", ""][1]
            if expected.binding is None or any(fact.binding is not None for (where, _), (_, fact) in book.items() if where == "private"):
                raise tx.InitConflict("Saved-text cleanup still owns private originals")
            with workspace._private(name) as child:
                if workspace._list(child):
                    raise tx.InitConflict("Saved-text original cleanup directory is not empty")
            self._check_final_public(workspace)
            from .build_inputs import _directory as directory_facts
            value = tx._stat(fd, name)
            if value is None or not stat.S_ISDIR(value.st_mode) or _freeze(directory_facts(value)) != expected.raw:
                raise tx.InitConflict("Saved-text original cleanup directory changed before removal")
        else:
            key = ("private", name)
            expected = book.get(key)
            if expected is None or expected[0] is not directory or expected[1].binding is None:
                raise tx.InitConflict("Saved-text cleanup cannot remove an uncaptured location")
            expected = expected[1]
            self.cleanup_entry(workspace, fd, name, directory, _thaw(expected.binding))
            self._check_final_public(workspace)
            # Last private name/stat check, with NO content read after the
            # public/dependency check and before the existing original unlink.
            self._named_fact(workspace, key, fd, name, directory, expected)
        return key, directory, expected

    def unlinked(self, workspace: tx.InitWorkspace, receipt: tuple, fd: int, name: str) -> None:
        key, directory, expected = receipt
        book = self._current_facts(workspace)
        if book[key] != (directory, expected):
            raise tx.InitConflict("Saved-text original removal receipt changed")
        book[key] = (directory, _FileFact(None, None))  # Only an actual returned unlink/rmdir.
        if tx._stat(fd, name) is not None:
            raise tx.InitConflict("Another object appeared after the original saved-text removal")


    def control(self, name: str, identity: Any) -> dict[str, Any]:
        scope = self._lease._active
        workspace = scope.workspace if scope is not None else None
        self._check_workspace(workspace)
        expected = self._current_facts(workspace).get(("private", name))
        if expected is None or expected[0] or expected[1].binding is None or identity != _thaw(expected[1].binding):
            raise tx.InitConflict("Inspected saved-text control identity changed")
        return dict(identity)


    def check_preserved(self, workspace: tx.InitWorkspace, path: str) -> None:
        self._check_workspace(workspace)
        expected = dict(self._inspection.public).get(path)
        current, _ = _public(workspace, path, _limit(self._lease.profile))
        if expected is None or current != expected:
            raise tx.InitConflict("An inspected preserved saved-text changed")


    def cleanup_entries(self, workspace: tx.InitWorkspace) -> dict[str, tuple[bool, dict[str, Any]]]:
        self._check_workspace(workspace)
        self._check_final_public(workspace)
        if self._inspection.action == "rollback" and (workspace._terminal_seen != "ROLLED_BACK" or not workspace._terminal_durable):
            raise tx.InitConflict("Restoration terminal durability is unconfirmed")
        # This binding-only projection is not deletion authority. Full captured
        # or returned-move facts remain in the book and constrain each read,
        # inventory check and the last pre-unlink check inside the writer.
        return {name: (directory, _thaw(fact.binding))
                for (where, name), (directory, fact) in self._current_facts(workspace).items()
                if where == "private" and fact.binding is not None}


    def _check_final_public(self, workspace: tx.InitWorkspace) -> None:
        """Never discard a backup or publish rollback after original fact drift."""
        book = self._current_facts(workspace)
        captured, plan = self._inspection, json.loads(self._inspection.plan)
        for row in plan["files"]:
            current, _ = _public(workspace, row["path"], _limit(self._lease.profile))
            expected = row["after"] if captured.action == "committed_cleanup" and row["after"] is not None else row["before"]
            if current != book["public", row["path"]][1] or current.binding != _freeze(expected):
                raise tx.InitConflict("The actual final saved-text changed before cleanup")
        for row in plan["directories"]:
            with workspace._parent(row["path"]) as parent:
                binding, raw = _directory(workspace, parent, row["path"].rsplit("/", 1)[-1])
            expected = row["after"] if captured.action == "committed_cleanup" and row["after"] is not None else row["before"]
            if (binding != expected or _FileFact(_freeze(binding), raw) != book["public", row["path"]][1]):
                raise tx.InitConflict("The actual final saved-text directory changed before cleanup")
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
                raise tx.InitConflict("Preparation cleanup would discard an unrestored saved-text")
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
            with workspace.inspect_saved_text_recovery_state() as (state, fd):
                _need(state == captured.state and fd is not None)
                current = _inspect(workspace, state, fd, *pairs)
            _need(current == captured)
        except _Conflict:
            raise tx.InitConflict("Saved-text recovery changed since its original preview") from None


    def apply(self, workspace: tx.InitWorkspace) -> tx.InitApplyOutcome:
        self._check_workspace(workspace)
        if getattr(workspace, "_restoration_started", False):
            raise tx.InitConflict("Saved-text restoration is one-use")
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
            if state != workspace._state_names[2]:
                workspace._state_move(state, workspace._state_names[2])
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
            raise tx.InitOperationFailure(recovery_outcome(self._lease, workspace, workspace._restoration_reason), workspace._restoration_primary) from None
        return recovery_outcome(self._lease, workspace)


class SavedTextRecoveryCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_view_json", "_state", "_prepared")

    def __repr__(self) -> str:
        return "<SavedTextRecoveryCheckout>"

    @property
    def intent(self) -> str:
        return "recover"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


class PreparedSavedTextRecovery(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_view_json", "_state")

    def __repr__(self) -> str:
        return "<PreparedSavedTextRecovery>"

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
    return type(value) is SavedTextRecoveryCheckout and getattr(value, "_identity", None) is value


def _authentic_prepared(value: object) -> bool:
    return (type(value) is PreparedSavedTextRecovery and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None)) and value._checkout._prepared is value)


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    return (type(lease) is native.lease and getattr(lease, "profile", None) in _PROFILES
            and getattr(lease, "_saved_text_recovery_mode", None) is True)


def _retain_inspected(lease: InitRootLease, failure: CoreEditOutcome) -> CoreEditOutcome:
    previous = recovery_outcome(lease, reason=failure.reason)
    return CoreEditOutcome(previous.effect, previous.journal,
                           "unknown" if "unknown" in (previous.resources, failure.resources) else "settled",
                           previous.reason)


def _view(domain: str, captured: _Inspection | None, reason: str = "none") -> dict[str, Any]:
    result = {"schemaVersion": 1, "kind": "saved-text-recovery", "domain": domain,
              "state": "idle" if reason == "none" else "conflict", "reason": reason,
              "action": None, "transactionId": None, "selection": None, "files": [],
              "privateCleanup": {"fileCount": 0, "directoryCount": 0, "scope": "inspected-owned-journal-only"}}
    if captured is None:
        return result
    plan = json.loads(captured.plan)
    result.update(state="recoverable", action=captured.action, transactionId=plan["transactionId"],
                  selection=_selection_data(captured.selection))
    def summary(value):
        return None if value is None else {"byteLength": value["size"], "sha256": value["sha256"], "mode": value["mode"]}
    for row in plan["files"]:
        effect = "preserve"
        if row["after"] is not None:
            if captured.action == "committed_cleanup":
                effect = "keep_committed"
            elif captured.action == "rollback":
                effect = "remove_new" if row["before"] is None else "restore_original"
        result["files"].append({"path": row["path"], "effect": effect,
                                "before": summary(row["before"]), "after": summary(row["after"])})
    if captured.action == "rollback":
        file_count = len(captured.controls) + sum(row["after"] is not None for row in plan["files"])
        directory_count = sum(row["after"] is not None for row in plan["directories"])
    else:
        file_count = len(captured.controls) + sum(not row[1] for row in captured.data)
        directory_count = sum(row[1] for row in captured.data)
    result["privateCleanup"].update(fileCount=file_count, directoryCount=directory_count)
    return result


def _encoded(value: dict[str, Any]) -> bytes:
    return bounded_json_text(value, max_bytes=MAX_VIEW_BYTES, max_nodes=512, max_depth=16).encode("utf-8")


def capture_saved_text_recovery(lease: InitRootLease) -> SavedTextRecoveryCheckout:
    try:
        native = _shared._native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None
    if not _lease_matches(native, lease):
        _shared._reject("invalid_params")
    captured, revision, reason = None, None, "none"
    try:
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None:
            _shared._reject("custody_unknown")
        with lease.saved_text_recovery_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            with workspace.inspect_saved_text_recovery_state() as (state, fd):
                if state is not None:
                    try:
                        pairs = [_public(workspace, path, limit, planning=True)
                                 for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS)]
                        _need(all(fact.binding is not None and raw is not None for fact, raw in pairs), "dependency_changed")
                        captured = _inspect(workspace, state, fd, *pairs)
                    except _Conflict as conflict:
                        reason = conflict.reason
            if captured is not None:
                revision = object.__new__(SavedTextRecoveryRevision)
                for name, value in (("_identity", revision), ("_lease", lease),
                                    ("_inspection", captured), ("_token", token)):
                    object.__setattr__(revision, name, value)
                lease._saved_text_recovery = workspace._saved_text_recovery = revision
                lease._saved_text_recovery_effect = {"committed_cleanup": "committed",
                    "rolled_back_cleanup": "rolled_back"}.get(captured.action, "not_started")
    except BaseException as error:
        raise ConfigEditFailure(_retain_inspected(lease, _shared._settled_failure(native, error))) from None
    try:
        view = _view(_domain(lease.profile), captured, reason)
        checkout = object.__new__(SavedTextRecoveryCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_revision_token", token), ("_view_json", _encoded(view)),
                            ("_state", _shared._CAPTURED), ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except BaseException as error:
        failure = _shared._pure_failure(error)
        raise ConfigEditFailure(_retain_inspected(lease, failure)) from None


def prepare_saved_text_recovery(lease: InitRootLease, checkout: SavedTextRecoveryCheckout,
                                expected_revision: str) -> PreparedSavedTextRecovery:
    if not _authentic_checkout(checkout) or checkout._state != _shared._CAPTURED:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._PREPARING)
    try:
        if (lease is not checkout._lease or checkout._revision is None
                or type(expected_revision) is not str or _shared._TOKEN.fullmatch(expected_revision) is None):
            _shared._reject("invalid_params")
        if expected_revision != checkout.revision:
            _shared._reject("stale_revision")
        native = _shared._native_contract()
        if not _lease_matches(native, lease) or lease._saved_text_recovery is not checkout._revision:
            _shared._reject("invalid_params")
        try:
            with lease.saved_text_recovery_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
        except BaseException as error:
            raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        prepared = object.__new__(PreparedSavedTextRecovery)
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


def apply_saved_text_recovery(lease: InitRootLease, prepared: PreparedSavedTextRecovery) -> CoreEditOutcome:
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
    if not _lease_matches(native, lease) or lease._saved_text_recovery is not checkout._revision:
        return _shared._not_started("invalid_params")
    result = None
    try:
        with lease.saved_text_recovery_scope(checkout._revision) as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            result = workspace.apply_saved_text_recovery(checkout._revision)
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


def discard_saved_text_recovery(authority: SavedTextRecoveryCheckout | PreparedSavedTextRecovery) -> None:
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_prepared(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)


