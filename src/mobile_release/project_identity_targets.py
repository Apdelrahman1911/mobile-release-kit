"""Closed identity descriptor and original-lease inventory, never a raw writer."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from typing import Any

from . import config_edit as shared
from . import init_transaction as tx
from .config_payloads import sufficient_ignore_rules
from .discovery import IGNORED_PARTS
from .errors import ValidationError
from .project_identity import (CONFIG_PATH, IGNORE_PATH, MAX_DIRECTORIES, MAX_FILES,
                               MAX_FILE_BYTES, MAX_TOTAL_BYTES, IdentityAnalysis,
                               IdentityInputError, IdentityPreparation, IdentitySelection,
                               analyze_project_identity, need, prepare_project_identity,
                               public_path, selection_input, source_candidate)

DOMAIN = "project-identity"
MAX_VIEW_BYTES = 128 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SKIP = frozenset(name.casefold() for name in IGNORED_PARTS) | {
    "xcuserdata", "private", "secrets", "credentials", ".venv", "venv", "__pycache__"}


class DescriptorError(tx.InitConflict):
    def __init__(self, reason: str = "invalid_journal"):
        super().__init__("The identity descriptor is incomplete or changed; preserve its journal")
        self.reason = reason


def _need(value: bool, reason: str = "invalid_journal") -> None:
    if not value:
        raise DescriptorError(reason)


def _directory(value: os.stat_result) -> tuple[int, ...]:
    _need(stat.S_ISDIR(value.st_mode))
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


@dataclass(frozen=True, slots=True)
class Inventory:
    paths: tuple[str, ...]
    control_directories: tuple[str, ...]
    directories: tuple[tuple[str, tuple[int, ...]], ...]


def capture_inventory(workspace: tx.InitWorkspace) -> Inventory:
    """Read only through the original registered root descriptor, no rglob/follow.

    Renderer/source-map filenames never mint this inventory.  The finite scan
    is repeated before Prepare/Apply, including discovery of newly added build
    controls. Ignored private/generated/dependency trees are pruned before IO.
    """
    result = _scan_inventory(workspace)
    _need(CONFIG_PATH in result.paths and IGNORE_PATH in result.paths, "missing_configuration")
    return result


def recovery_inventory(workspace: tx.InitWorkspace) -> Inventory:
    """Inspection only; an original can temporarily be in its journal backup.

    The recovery caller must prove every missing public source through the
    original before/after location graph and rederive the entire transform.
    This is not an alternate capture grant or a missing-config fallback.
    """
    _need(type(workspace) is tx.InitWorkspace and workspace._identity_profile
          and workspace._workflow_recovery_mode and workspace._typed_profile is None)
    return _scan_inventory(workspace)


def _scan_inventory(workspace: tx.InitWorkspace) -> Inventory:
    _need(type(workspace) is tx.InitWorkspace and workspace._scope is not None
          and workspace._guard is not None)
    paths: list[str] = []
    controls: list[str] = []
    directories: list[tuple[str, tuple[int, ...]]] = []
    seen = 0

    def walk(fd: int, prefix: str, depth: int) -> None:
        nonlocal seen
        workspace._checkpoint()
        _need(depth <= 16 and len(directories) < MAX_DIRECTORIES, "inventory_changed")
        original = _directory(os.fstat(fd))
        directories.append((prefix, original))
        names = workspace._list(fd)
        seen += len(names)
        _need(seen <= 20_000, "inventory_changed")
        for name in sorted(names):
            workspace._checkpoint()
            lowered = name.casefold()
            if (lowered in _SKIP or tx.is_state_name(name)
                    or lowered.startswith((".private-", ".codex-private-", ".mobile-release-"))):
                continue
            relative = f"{prefix}/{name}" if prefix else name
            value = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not public_path(relative):
                _need(not (stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode))
                      and not source_candidate(relative), "inventory_changed")
                continue
            # An opaque public symlink could hide another consumer of an
            # edited xcconfig. Never advertise complete ownership by omitting
            # it; private/dependency trees were pruned before this point.
            _need(not stat.S_ISLNK(value.st_mode), "inventory_changed")
            if name in {"buildSrc", "build-logic", "Tuist"}:
                controls.append(relative)
            if stat.S_ISDIR(value.st_mode):
                with workspace._descriptor(name, workspace.flags, dir_fd=fd) as child:
                    _need(_directory(os.fstat(child)) == _directory(value), "inventory_changed")
                    walk(child, relative, depth + 1)
                _need(_directory(os.stat(name, dir_fd=fd, follow_symlinks=False)) == _directory(value),
                      "inventory_changed")
            elif source_candidate(relative):
                _need(stat.S_ISREG(value.st_mode), "inventory_changed")
                paths.append(relative)
                _need(len(paths) <= MAX_FILES, "inventory_changed")
        _need(_directory(os.fstat(fd)) == original, "inventory_changed")

    walk(workspace.fd, "", 0)
    tx.validate_paths(paths)
    return Inventory(tuple(sorted(paths)), tuple(sorted(controls)), tuple(sorted(directories)))


@dataclass(frozen=True, slots=True, repr=False)
class IdentityDescriptor:
    """Strict persisted DATA. Alone this can neither observe nor mutate files."""
    selection: IdentitySelection
    desired_identity: str
    intent: str
    sources: tuple[tuple[str, int, str], ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for path, _, _ in self.sources)

    @property
    def directories(self) -> tuple[str, ...]:
        return tuple(sorted({"/".join(path.split("/")[:index]) for path in self.paths
                             for index in range(1, len(path.split("/")))},
                            key=lambda path: (path.count("/"), path)))

    @property
    def limits(self) -> tuple[int, ...]:
        return tuple(MAX_FILE_BYTES for _ in self.paths)

    def context(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "policy": "project-identity-v1", "selection": self.selection.as_dict(),
                "desiredIdentity": self.desired_identity, "intent": self.intent,
                "sources": [{"path": path, "byteLength": size, "sha256": digest}
                            for path, size, digest in self.sources]}


def descriptor(prepared: IdentityPreparation) -> IdentityDescriptor:
    _need(type(prepared) is IdentityPreparation and prepared.changed)
    return from_context({"schemaVersion": 1, "policy": "project-identity-v1",
        "selection": prepared.analysis.selection.as_dict(), "desiredIdentity": prepared.desired_identity,
        "intent": prepared.intent, "sources": [{"path": path, "byteLength": len(raw),
                                                 "sha256": hashlib.sha256(raw).hexdigest()}
                                                for path, raw in prepared.analysis._sources]})


def from_context(context: object) -> IdentityDescriptor:
    try:
        _need(type(context) is dict and set(context) == {
            "schemaVersion", "policy", "selection", "desiredIdentity", "intent", "sources"})
        _need(type(context["schemaVersion"]) is int and context["schemaVersion"] == 1
              and context["policy"] == "project-identity-v1" and context["intent"] == "new-application")
        selected = context["selection"]
        _need(type(selected) is dict and set(selected) == {"platform", "target", "project", "continuity"})
        selection = selection_input(IdentitySelection(**selected))
        _need(selection.continuity == "unknown")
        from .config import ANDROID_ID_RE, IOS_ID_RE
        pattern = ANDROID_ID_RE if selection.platform == "android" else IOS_ID_RE
        desired = context["desiredIdentity"]
        _need(type(desired) is str and len(desired) <= 255 and pattern.fullmatch(desired) is not None)
        rows = context["sources"]
        _need(type(rows) is list and 2 <= len(rows) <= MAX_FILES)
        sources = []
        for row in rows:
            _need(type(row) is dict and set(row) == {"path", "byteLength", "sha256"})
            _need(public_path(row["path"]) and source_candidate(row["path"])
                  and type(row["byteLength"]) is int and 0 <= row["byteLength"] <= MAX_FILE_BYTES
                  and type(row["sha256"]) is str and _DIGEST.fullmatch(row["sha256"]) is not None)
            sources.append((row["path"], row["byteLength"], row["sha256"]))
        paths = tuple(path for path, _, _ in sources)
        _need(paths == tuple(sorted(set(paths))) and CONFIG_PATH in paths and IGNORE_PATH in paths
              and sum(size for _, size, _ in sources) <= MAX_TOTAL_BYTES)
        tx.validate_paths(list(paths))
        result = IdentityDescriptor(selection, desired, "new-application", tuple(sources))
        _need(len(tx._json(result.context())) <= tx.MAX_CONTROL_BYTES // 4)
        return result
    except DescriptorError:
        raise
    except (IdentityInputError, TypeError, KeyError, ValueError, ValidationError, UnicodeError):
        raise DescriptorError("invalid_journal") from None


def plan_shape(data: IdentityDescriptor, plan: dict[str, Any]) -> None:
    _need(type(data) is IdentityDescriptor and tuple(row["path"] for row in plan["files"]) == data.paths
          and tuple(row["path"] for row in plan["directories"]) == data.directories)
    _need(all(row["before"] is not None and row["after"] is None for row in plan["directories"]))
    changed = []
    for row, (_, size, digest) in zip(plan["files"], data.sources):
        before, after = row["before"], row["after"]
        _need(before is not None and before["size"] == size and before["sha256"] == digest)
        if after is not None:
            _need(row["path"] != IGNORE_PATH and 0 < after["size"] <= MAX_FILE_BYTES
                  and after["mode"] == before["mode"] and after["inode"] != before["inode"])
            changed.append(row["path"])
    _need(CONFIG_PATH in changed and 2 <= len(changed) <= 33)


class IdentityTargets(shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_capture_workspace", "_inventory", "_analysis", "_prepared", "_input")

    @property
    def paths(self) -> tuple[str, ...]:
        return self._inventory.paths

    @property
    def directories(self) -> tuple[str, ...]:
        return tuple(sorted({"/".join(path.split("/")[:index]) for path in self.paths
                             for index in range(1, len(path.split("/")))},
                            key=lambda path: (path.count("/"), path)))

    @property
    def observation_limits(self) -> tuple[int, ...]:
        return tuple(MAX_FILE_BYTES for _ in self.paths)

    def _check_workspace(self, workspace: tx.InitWorkspace) -> None:
        from .init_workspace_custody import LockedInitScope
        _need(type(self) is IdentityTargets and self._identity is self
              and type(workspace) is tx.InitWorkspace and workspace._typed_profile is tx.TypedEditProfile.PROJECT_IDENTITY
              and workspace._identity_targets is self and type(workspace._scope) is LockedInitScope
              and workspace._scope is self._lease._active and workspace._scope.lease is self._lease
              and workspace._scope.workspace is workspace and self._lease._identity_targets is self)

    def check_inventory(self, workspace: tx.InitWorkspace) -> None:
        self._check_workspace(workspace)
        _need(capture_inventory(workspace) == self._inventory, "inventory_changed")

    def check_public_inventory(self, workspace: tx.InitWorkspace, public: tuple[str, ...]) -> None:
        """Called after the original owner proves every public/backup location.

        No required-file fallback: absent public files are exactly the gaps
        established by that graph, never a renderer-selected replacement roster.
        """
        self._check_workspace(workspace)
        _need(type(public) is tuple and public == tuple(sorted(set(public)))
              and set(public) <= set(self.paths), "inventory_changed")
        current = _scan_inventory(workspace)
        _need(current.paths == public
              and current.control_directories == self._inventory.control_directories
              and current.directories == self._inventory.directories, "inventory_changed")

    def check_publication(self, workspace: tx.InitWorkspace, source_fd: int, destination_fd: int) -> None:
        """Recheck at the original native move boundary, not just at Prepare.

        The only journal handle used is already held by this move and matches
        the original private directory. Reload still requires the original
        control inodes/bytes; neither a caller FD nor persisted header grants
        new targets. Post-capture failure preserves a known terminal decision.
        """
        self._check_workspace(workspace)
        _need(workspace._workflow_complete and type(self._input) is IdentityDescriptor)
        private = {fd for fd in (source_fd, destination_fd)
                   if tx._dir_identity(os.fstat(fd)) == workspace.private_identity}
        _need(len(private) == 1, "namespace_changed")
        fd = private.pop()
        workspace._private_check(fd, workspace._state_names[1])
        plan = workspace._load(fd)
        final = {"COMMITTED": "new", "ROLLED_BACK": "old"}.get(workspace._publishing_terminal)
        workspace._locations(fd, plan, final=final)

    def bind_preparation(self, prepared: IdentityPreparation) -> None:
        _need(self._prepared is None and type(prepared) is IdentityPreparation
              and prepared.analysis is self._analysis)
        derived = prepare_project_identity(self._analysis, prepared.desired_identity,
            expected_revision=self._analysis.revision, intent=prepared.intent)
        _need(prepared._payloads == derived._payloads)
        object.__setattr__(self, "_prepared", prepared)
        object.__setattr__(self, "_input", descriptor(prepared) if prepared.changed else None)

    def journal_context(self) -> dict[str, Any]:
        _need(type(self._input) is IdentityDescriptor)
        return self._input.context()

    def check_changes(self, workspace: tx.InitWorkspace, changes: list[tuple[tx.ObservedFile, bytes | None]]) -> None:
        self._check_workspace(workspace)
        _need(type(self._prepared) is IdentityPreparation and len(changes) == len(self.paths))
        expected = dict(self._prepared._payloads)
        for (observed, payload), (path, raw) in zip(changes, self._analysis._sources):
            _need(type(observed) is tx.ObservedFile and observed.path == path
                  and workspace._captured.get(path) == observed and observed.data == raw
                  and observed.before is not None and payload == expected.get(path))
        _need(self._prepared.changed is bool(expected))


def bind_targets(lease: Any, workspace: tx.InitWorkspace, selection: IdentitySelection,
                 inventory: Inventory, originals: tuple[tx.ObservedFile, ...]) -> IdentityTargets:
    from .init_workspace_custody import InitRootLease
    _need(type(lease) is InitRootLease and lease.profile is tx.TypedEditProfile.PROJECT_IDENTITY
          and not lease._workflow_recovery_mode and lease._active is not None
          and lease._active.workspace is workspace and workspace._typed_profile is lease.profile
          and lease._identity_targets is None and workspace._identity_targets is None and lease._revision is None
          and type(inventory) is Inventory and tuple(item.path for item in originals) == inventory.paths
          and set(workspace._captured) == set(inventory.paths))
    lease.check()
    _need(all(type(item) is tx.ObservedFile and item.before is not None and type(item.data) is bytes
              and workspace._captured.get(item.path) is item for item in originals), "inventory_changed")
    sources = {item.path: item.data for item in originals}
    if not sufficient_ignore_rules(sources[IGNORE_PATH]):
        raise tx.InitOperationFailure(tx.InitApplyOutcome("not_started", "not_created", "settled", "ignore_conflict"))
    analysis = analyze_project_identity(sources, selection, directories=inventory.control_directories)
    targets = object.__new__(IdentityTargets)
    for name, value in (("_identity", targets), ("_lease", lease), ("_capture_workspace", workspace),
                        ("_inventory", inventory), ("_analysis", analysis), ("_prepared", None), ("_input", None)):
        object.__setattr__(targets, name, value)
    lease._identity_targets = workspace._identity_targets = targets
    return targets
