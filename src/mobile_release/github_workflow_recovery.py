"""One current-inspection recovery of two fixed, separately bound edit profiles.

The shared legacy journal is not an Apply grant. A fresh untyped workspace
borrows the registered root's original lock. This finite validator binds the
existing rollback/cleanup engine to the inspected controls and objects; it
does not render workflows, discover configuration, or choose another rollback.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from . import config_edit as _shared
from . import init_transaction as tx
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .errors import ValidationError

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease

_PROFILE = tx.TypedEditProfile.GITHUB_WORKFLOWS
_IDS = ("preflight", "candidate", "external-testing", "production-submit")
_CONTROLS = frozenset(("header.json", "plan.json", "commit.pending", "rollback.pending",
                       "COMMITTED", "ROLLED_BACK"))
_DELETE_CONTROLS = ("commit.pending", "rollback.pending", "plan.json",
                    "COMMITTED", "ROLLED_BACK", "header.json")
_LIMIT = 16 * 1024


class _Refused(tx.InitConflict):
    pass


def _need(value: bool, message: str = "Workflow recovery changed or is not completely qualified") -> None:
    if not value:
        raise _Refused(message)


def _full9(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _freeze(value: dict[str, Any] | None) -> tuple | None:
    return None if value is None else tuple(sorted(value.items()))


@dataclass(frozen=True, slots=True)
class _Fact:
    binding: tuple | None
    raw: tuple[int, ...] | None

    def value(self) -> dict[str, Any] | None:
        return None if self.binding is None else dict(self.binding)


_ABSENT = _Fact(None, None)


@dataclass(frozen=True, slots=True)
class _Entry:
    directory: bool
    fact: _Fact
    control: bytes | None = None


@dataclass(frozen=True, slots=True)
class _Inspection:
    profile: tx.TypedEditProfile
    state: str
    action: str
    root: tuple[int, ...]
    private: _Fact
    header: bytes
    plan: bytes
    entries: tuple[tuple[str, _Entry], ...]
    public: tuple[tuple[str, _Fact], ...]
    parents: tuple[tuple[str, _Fact], ...]


def _observed(workspace: tx.InitWorkspace, fd: int, name: str, *,
              directory: bool = False, limit: int = 1024 * 1024) -> tuple[_Fact, bytes | None]:
    workspace._checkpoint()
    if directory:
        value = tx._stat(fd, name)
        if value is None:
            return _ABSENT, None
        _need(stat.S_ISDIR(value.st_mode))
        with workspace._descriptor(name, workspace.flags, dir_fd=fd) as opened:
            current = os.fstat(opened)
            _need(_full9(current) == _full9(value))
            result = _Fact(_freeze(tx._dir_identity(current)), _full9(current))
        named = tx._stat(fd, name)
        _need(named is not None and _full9(named) == result.raw)
        return result, None
    workspace._last_read_facts = None
    # The existing owned read is used directly so the guard's own verification
    # does not recursively invoke its control-consumption hook.
    item = tx._read(fd, name, limit, owner=workspace)
    if item is None:
        _need(tx._stat(fd, name) is None)
        return _ABSENT, None
    from .build_inputs import _file
    value = tx._stat(fd, name)
    _need(value is not None and workspace._last_read_facts == tuple(sorted(_file(value).items())))
    return _Fact(_freeze(item[0]), _full9(value)), item[1]


def _current(workspace: tx.InitWorkspace, path: str, *, directory: bool = False) -> _Fact:
    with workspace._parent(path) as parent:
        if parent is None:
            return _ABSENT
        return _observed(workspace, parent, path.rsplit("/", 1)[-1], directory=directory)[0]


def _plan_shape(plan: dict[str, Any], profile: tx.TypedEditProfile) -> None:
    _need(tuple(row["path"] for row in plan["files"]) == profile.paths
          and tuple(row["path"] for row in plan["directories"]) == profile.directories)
    for row, before_limit, after_limit in zip(plan["files"], profile.observation_limits, profile.payload_limits):
        before, after = row["before"], row["after"]
        _need(before is None or before["size"] <= before_limit)
        _need(after is None or 0 < after["size"] <= after_limit)
        _need(before is None or after is None or
              before["mode"] == after["mode"] and before["inode"] != after["inode"])
        _need(before is not None or after is not None and not after["mode"] & ~0o644)


def _preparing_public(workspace: tx.InitWorkspace, plan: dict[str, Any]) -> None:
    # CLEANUP may already have deleted some staged NEW objects, but it cannot
    # contain backups or any installed destination. This validates the existing
    # preparation-cleanup phase; it is not another recovery algorithm.
    workspace.parents = {}
    for row in plan["directories"]:
        current = _current(workspace, row["path"], directory=True)
        _need(current.value() == row["before"])
        workspace.parents[row["path"]] = row["before"]
    for row in plan["files"]:
        _need(_current(workspace, row["path"]).value() == row["before"])


def _inspect(workspace: tx.InitWorkspace) -> _Inspection | None:
    """Read only. Shared-name incomplete legacy records are never classified."""
    profile = _workspace_profile(workspace)
    with workspace.inspect_workflow_recovery_state() as (state, fd):
        if state is None:
            return None
        _need(fd is not None and state in tx.STATE_NAMES)
        private = _Fact(_freeze(workspace.private_identity), _full9(os.fstat(fd)))
        names = set(workspace._list(fd))
        _need(len(names) <= 16 and {"header.json", "plan.json"} <= names,
              "The legacy journal lacks a complete fixed-profile plan; preserve it without guessing")
        header_fact, header_raw = _observed(workspace, fd, "header.json", limit=tx.MAX_CONTROL_BYTES)
        plan_fact, plan_raw = _observed(workspace, fd, "plan.json", limit=tx.MAX_CONTROL_BYTES)
        plan = workspace._load(fd)
        _plan_shape(plan, profile)
        _need(header_raw == tx._json({key: plan[key] for key in ("schemaVersion", "transactionId", "root")})
              and plan_raw == tx._json(plan))
        terminal_names = names & {"COMMITTED", "ROLLED_BACK"}
        _need(len(terminal_names) <= 1)
        terminal = next(iter(terminal_names), None)
        _need(terminal is None or state != tx.PREPARING)
        allowed_data: dict[str, tuple[bool, dict[str, Any]]] = {}
        for index, row in enumerate(plan["files"]):
            if row["after"] is not None:
                allowed_data[f"new-{index}"] = (False, row["after"])
                if row["before"] is not None:
                    allowed_data[f"old-{index}"] = (False, row["before"])
        for index, row in enumerate(plan["directories"]):
            if row["after"] is not None:
                allowed_data[f"directory-{index}"] = (True, row["after"])
        _need(names <= _CONTROLS | set(allowed_data))
        entries: dict[str, _Entry] = {}
        for name in sorted(names):
            if name in _CONTROLS:
                fact, raw = _observed(workspace, fd, name, limit=tx.MAX_CONTROL_BYTES)
                _need(fact.binding is not None and raw is not None
                      and fact.raw[3] == os.geteuid() and fact.value()["mode"] == 0o600)
                entries[name] = _Entry(False, fact, raw)
            else:
                directory, expected = allowed_data[name]
                fact, _ = _observed(workspace, fd, name, directory=directory)
                _need(fact.value() == expected)
                if directory:
                    with workspace._descriptor(name, workspace.flags, dir_fd=fd) as child:
                        _need(not workspace._list(child))
                entries[name] = _Entry(directory, fact)
        _need(entries["header.json"].fact == header_fact and entries["header.json"].control == header_raw
              and entries["plan.json"].fact == plan_fact and entries["plan.json"].control == plan_raw)
        data = names - _CONTROLS
        for marker, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
            decided, staged = entries.get(marker), entries.get(pending)
            _need(not (decided is not None and staged is not None))
            for item in (decided, staged):
                _need(item is None or item.control == workspace._marker(plan, marker))
            if state != tx.CLEANUP or data:
                _need((decided is None) != (staged is None))
        if terminal is not None:
            expected_data = {name for name in allowed_data if
                             (name.startswith("old-") if terminal == "COMMITTED" else not name.startswith("old-"))}
            _need(data == expected_data if state == tx.READY else data <= expected_data)
            action = "committed_cleanup" if terminal == "COMMITTED" else "rolled_back_cleanup"
            # A terminal journal authorizes private cleanup only. Public callers
            # may have subsequent user edits: do not read them, let alone undo them.
            public, parents = {}, {}
        else:
            if state == tx.READY:
                workspace._terminal(fd, plan)
                workspace._locations(fd, plan)
                action = "rollback"
            else:
                _need(not any(name.startswith("old-") for name in data))
                if state == tx.PREPARING:
                    workspace._terminal(fd, plan)
                    workspace._locations(fd, plan, final="old")
                else:
                    _preparing_public(workspace, plan)
                action = "preparing_cleanup"
            public = {path: _current(workspace, path) for path in profile.paths}
            parents = {path: _current(workspace, path, directory=True) for path in profile.directories}
        _need(set(workspace._list(fd)) == names)
        for name, entry in entries.items():
            fact, raw = _observed(workspace, fd, name, directory=entry.directory,
                                  limit=tx.MAX_CONTROL_BYTES if name in _CONTROLS else 1024 * 1024)
            _need(fact == entry.fact and (entry.control is None or raw == entry.control))
        if public:
            if state == tx.READY:
                workspace._locations(fd, plan)
            else:
                _preparing_public(workspace, plan)
            _need(all(_current(workspace, path) == fact for path, fact in public.items())
                  and all(_current(workspace, path, directory=True) == fact for path, fact in parents.items()))
        _need(_full9(os.fstat(fd)) == private.raw)
    return _Inspection(profile, state, action, _full9(os.fstat(workspace.fd)), private,
                       header_raw, plan_raw, tuple(sorted(entries.items())),
                       tuple(sorted(public.items())), tuple(sorted(parents.items())))


class _RestorationGuard:
    """Finite inspected locations, advanced only by successful owned receipts."""

    def __init__(self, revision: WorkflowRecoveryRevision, workspace: tx.InitWorkspace) -> None:
        self.revision, self.workspace = revision, workspace
        captured = revision._inspection
        self.state, self.action = captured.state, captured.action
        self.root, self.private = captured.root, captured.private
        self.entries = dict(captured.entries)
        self.public, self.parents = dict(captured.public), dict(captured.parents)
        self.changed_directories: set[str] = set()
        self.failed = self.rollback_active = self.cleaning = False
        self.pending: tuple | None = None
        self.first_error: BaseException | None = None
        self.check_workspace(workspace)

    def check_workspace(self, workspace: tx.InitWorkspace) -> None:
        _need(workspace is self.workspace and type(self.revision) is WorkflowRecoveryRevision
              and getattr(self.revision, "_identity", None) is self.revision
              and workspace._scope is not None and workspace._typed_profile is None
              and workspace._workflow_recovery_mode
              and workspace._scope.lease is self.revision._lease
              and workspace._scope.lease._workflow_recovery is self.revision
              and _workspace_profile(workspace) is self.revision._profile
              and self.revision._inspection.profile is self.revision._profile)

    def _live(self, workspace: tx.InitWorkspace) -> None:
        self.check_workspace(workspace)
        _need(not self.failed, "The failed recovery capability cannot authorize another effect")

    def record_failure(self, error: BaseException) -> None:
        if self.first_error is None:
            self.first_error = error

    def freeze(self) -> None:
        self.failed = True
        if self.pending is not None and self.pending[0] == "remove-journal":
            self.revision._lease._workflow_recovery_journal = "unknown"

    def _same(self, actual: _Fact, expected: _Fact, location: str) -> bool:
        if actual.binding != expected.binding:
            return False
        if location in self.changed_directories and actual.raw is not None and expected.raw is not None:
            # Own child moves/deletions change directory size/timestamps/nlink.
            # Retain its original identity, owner and mode, not a fresh roster.
            return actual.raw[:5] == expected.raw[:5]
        return actual.raw == expected.raw

    def _private_fd(self, fd: int) -> None:
        _need(self.private.raw is not None and _full9(os.fstat(fd))[:5] == self.private.raw[:5])

    def _private_entries(self, workspace: tx.InitWorkspace, fd: int) -> None:
        self._private_fd(fd)
        _need(set(workspace._list(fd)) == set(self.entries))
        for name, entry in self.entries.items():
            fact, raw = _observed(workspace, fd, name, directory=entry.directory,
                                  limit=tx.MAX_CONTROL_BYTES if name in _CONTROLS else 1024 * 1024)
            _need(self._same(fact, entry.fact, "private/" + name)
                  and (entry.control is None or raw == entry.control))
            if entry.directory:
                with workspace._descriptor(name, workspace.flags, dir_fd=fd) as child:
                    _need(not workspace._list(child))

    def check(self, workspace: tx.InitWorkspace) -> None:
        self._live(workspace)
        _need(workspace.state() == self.state)
        root = _full9(os.fstat(workspace.fd))
        _need(root[:5] == self.root[:5] if "root" in self.changed_directories else root == self.root)
        with workspace._private(self.state) as fd:
            current = _Fact(_freeze(tx._dir_identity(os.fstat(fd))), _full9(os.fstat(fd)))
            _need(self._same(current, self.private, "private"))
            self._private_entries(workspace, fd)
        if self.public:
            # Use only our fixed observed/owned parent locations for this check;
            # _load's generic before-or-after map is not restoration authority.
            original = workspace.parents
            workspace.parents = {path: fact.value() for path, fact in self.parents.items()}
            try:
                for path, expected in self.parents.items():
                    _need(self._same(_current(workspace, path, directory=True), expected, path))
                for path, expected in self.public.items():
                    _need(_current(workspace, path) == expected)
            finally:
                workspace.parents = original

    def control_read(self, workspace: tx.InitWorkspace, fd: int, name: str, item: Any) -> None:
        self._live(workspace)
        if name not in _CONTROLS:
            return
        self._private_fd(fd)
        expected = self.entries.get(name)
        if expected is None:
            _need(item is None and tx._stat(fd, name) is None)
            return
        _need(not expected.directory and item is not None and item[1] == expected.control
              and _freeze(item[0]) == expected.fact.binding)
        named = tx._stat(fd, name)
        _need(named is not None and _full9(named) == expected.fact.raw)

    def plan(self, plan: dict[str, Any]) -> None:
        _need(tx._json(plan) == self.revision._inspection.plan)

    def rollback(self, workspace: tx.InitWorkspace, fd: int, plan: dict[str, Any]) -> None:
        self.plan(plan)
        _need(self.action == "rollback" and self.state == tx.READY and not self.rollback_active)
        self.check(workspace)
        self._private_fd(fd)
        self.rollback_active = True

    def preparing(self, workspace: tx.InitWorkspace, fd: int) -> None:
        _need(self.action == "preparing_cleanup" and self.state in (tx.PREPARING, tx.CLEANUP))
        plan = workspace._load(fd)
        self.plan(plan)
        _preparing_public(workspace, plan)
        _need(not any(name.startswith("old-") for name in self.entries))
        self.check(workspace)

    def cleanup_start(self, workspace: tx.InitWorkspace, fd: int) -> None:
        _need(self.state == tx.CLEANUP)
        self.check(workspace)
        self._private_fd(fd)
        self.cleaning = True

    def cleanup_entry(self, workspace: tx.InitWorkspace, fd: int, name: str,
                      directory: bool, binding: dict[str, Any]) -> None:
        self._live(workspace)
        _need(self.cleaning)
        expected = self.entries.get(name)
        _need(expected is not None and (expected.directory, expected.fact.value()) == (directory, binding))
        # Called at capture AND verify_entry, before the shared deletion loop.
        self._private_entries(workspace, fd)

    def _fd_matches(self, fd: int, location: tuple[str, str]) -> bool:
        kind, path = location
        if kind == "private":
            expected = self.private.raw
        else:
            parent = path.rpartition("/")[0]
            expected = self.root if not parent else self.parents.get(parent, _ABSENT).raw
        return expected is not None and _full9(os.fstat(fd))[:5] == expected[:5]

    def _fact(self, location: tuple[str, str]) -> _Fact:
        kind, path = location
        return (self.entries.get(path, _Entry(False, _ABSENT)).fact if kind == "private"
                else self.parents[path] if path in self.parents else self.public[path])

    def _set(self, location: tuple[str, str], entry: _Entry | None) -> None:
        kind, path = location
        if kind == "private":
            if entry is None:
                self.entries.pop(path, None)
            else:
                self.entries[path] = entry
            self.changed_directories.add("private")
        else:
            target = self.parents if path in self.parents else self.public
            target[path] = _ABSENT if entry is None else entry.fact
            self.changed_directories.add(path.rpartition("/")[0] or "root")

    def before_move(self, workspace: tx.InitWorkspace, source_fd: int, source: str,
                    destination_fd: int, destination: str, expected: dict[str, Any],
                    directory: bool, directory_path: str | None) -> tuple:
        self.check(workspace)
        _need(self.pending is None and self.action == "rollback" and self.state == tx.READY
              and self.rollback_active)
        plan = json.loads(self.revision._inspection.plan)
        allowed = []
        for index, row in enumerate(plan["files"]):
            if row["after"] is not None:
                allowed.append((("public", row["path"]), ("private", f"new-{index}"), row["after"], False, None))
                if row["before"] is not None:
                    allowed.append((("private", f"old-{index}"), ("public", row["path"]), row["before"], False, None))
        for index, row in enumerate(plan["directories"]):
            if row["after"] is not None:
                allowed.append((("public", row["path"]), ("private", f"directory-{index}"), row["after"], True, row["path"]))
        allowed.append((("private", "rollback.pending"), ("private", "ROLLED_BACK"),
                        self.entries.get("rollback.pending", _Entry(False, _ABSENT)).fact.value(), False, None))
        matches = [(a, b) for a, b, binding, is_dir, changing in allowed
                   if a[1].rsplit("/", 1)[-1] == source and b[1].rsplit("/", 1)[-1] == destination
                   and (binding, is_dir, changing) == (expected, directory, directory_path)
                   and self._fd_matches(source_fd, a) and self._fd_matches(destination_fd, b)]
        _need(len(matches) == 1)
        origin, target = matches[0]
        before, raw = _observed(workspace, source_fd, source, directory=directory)
        location = "private/" + origin[1] if origin[0] == "private" else origin[1]
        _need(self._same(before, self._fact(origin), location)
              and self._fact(target) == _ABSENT and tx._stat(destination_fd, destination) is None)
        if destination == "ROLLED_BACK":
            _need(workspace._publishing_terminal == "ROLLED_BACK"
                  and all(_current(workspace, row["path"]).value() == row["before"] for row in plan["files"]))
        receipt = ("move", origin, target, _Entry(directory, before, raw if source in _CONTROLS else None))
        self.pending = receipt
        return receipt

    def effect_started(self, receipt: tuple) -> None:
        _need(receipt is self.pending)
        if receipt[1][0] == "public" or receipt[2][0] == "public":
            self.revision._lease._workflow_recovery_effect = "unknown"

    def captured_move(self, workspace: tx.InitWorkspace, receipt: tuple, source_fd: int,
                      source: str, destination_fd: int, destination: str) -> _Entry:
        self._live(workspace)
        _need(receipt is self.pending and receipt[0] == "move")
        original = receipt[3]
        fact, raw = _observed(workspace, destination_fd, destination, directory=original.directory)
        _need(tx._stat(source_fd, source) is None and fact.binding == original.fact.binding
              and fact.raw is not None and original.fact.raw is not None
              and fact.raw[:8] == original.fact.raw[:8]
              and (original.control is None or raw == original.control))
        return _Entry(original.directory, fact, original.control)

    def moved(self, workspace: tx.InitWorkspace, receipt: tuple, source_fd: int, source: str,
              destination_fd: int, destination: str) -> None:
        entry = self.captured_move(workspace, receipt, source_fd, source, destination_fd, destination)
        self._set(receipt[1], None)
        self._set(receipt[2], entry)
        self.pending = None
        if destination == "ROLLED_BACK":
            self.revision._lease._workflow_recovery_effect = "rolled_back"

    def before_state_move(self, workspace: tx.InitWorkspace, old: str, new: str) -> tuple:
        self.check(workspace)
        _need(self.pending is None and old == self.state and old in (tx.PREPARING, tx.READY)
              and new == tx.CLEANUP)
        if self.action == "rollback":
            _need("ROLLED_BACK" in self.entries and "rollback.pending" not in self.entries)
        current = tx._stat(workspace.fd, old)
        _need(current is not None and tx._stat(workspace.fd, new) is None)
        receipt = ("state", old, new, _full9(current))
        self.pending = receipt
        return receipt

    def state_capture_matches(self, receipt: tuple, captured: os.stat_result) -> bool:
        return receipt is self.pending and _full9(captured)[:8] == receipt[3][:8]

    def state_moved(self, workspace: tx.InitWorkspace, receipt: tuple) -> None:
        self._live(workspace)
        old, new = receipt[1:3]
        captured = tx._stat(workspace.fd, new)
        _need(captured is not None and tx._stat(workspace.fd, old) is None
              and self.state_capture_matches(receipt, captured))
        self.state = new
        self.private = _Fact(self.private.binding, _full9(captured))
        self.changed_directories.add("root")
        self.pending = None

    def before_unlink(self, workspace: tx.InitWorkspace, fd: int, name: str, directory: bool) -> tuple:
        self.check(workspace)
        _need(self.pending is None and self.cleaning and self.state == tx.CLEANUP)
        if fd == workspace.fd:
            _need(name == tx.CLEANUP and directory and not self.entries)
            receipt = ("remove-journal",)
        else:
            self._private_fd(fd)
            order = sorted(set(self.entries) - _CONTROLS) + [n for n in _DELETE_CONTROLS if n in self.entries]
            _need(bool(order) and name == order[0] and self.entries[name].directory == directory)
            receipt = ("unlink", name)
        self.pending = receipt
        return receipt

    def unlinked(self, workspace: tx.InitWorkspace, receipt: tuple, fd: int, name: str) -> None:
        self._live(workspace)
        _need(receipt is self.pending and tx._stat(fd, name) is None)
        if receipt[0] == "remove-journal":
            self.revision._lease._workflow_recovery_journal = "unknown"  # Await the existing root fsync.
        else:
            self.entries.pop(name)
            self.changed_directories.add("private")
        self.pending = None


def recovery_outcome(lease: InitRootLease, workspace: tx.InitWorkspace | None = None,
                     reason: str = "none") -> tx.InitApplyOutcome:
    """Pure retained facts, also when later lock acquisition never returned."""
    if lease._workflow_recovery_reason == "none" and reason != "none":
        lease._workflow_recovery_reason = reason
    effect = lease._workflow_recovery_effect
    if workspace is not None:
        if workspace._terminal_seen == "ROLLED_BACK" and effect != "committed":
            effect = lease._workflow_recovery_effect = "rolled_back"
        if workspace._journal_clean:
            lease._workflow_recovery_journal = "clean"
    journal = lease._workflow_recovery_journal
    resources = "unknown" if lease.guard.lifetime_ledger.fatal else "settled"
    first = lease._workflow_recovery_reason
    if first == "none":
        first = ("custody_unknown" if resources == "unknown" else
                 "pending_state" if journal == "recovery_required" else
                 "filesystem_error" if journal == "unknown" or effect == "unknown" else "none")
    return tx.InitApplyOutcome(effect, journal, resources, first)


class WorkflowRecoveryRevision(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_profile", "_inspection", "_applied")

    def recheck(self, workspace: tx.InitWorkspace) -> None:
        _need(type(workspace) is tx.InitWorkspace and workspace._workflow_recovery_mode
              and workspace._typed_profile is None and workspace._scope is not None
              and workspace._scope.lease is self._lease and self._lease._workflow_recovery is self
              and _workspace_profile(workspace) is self._profile and self._inspection.profile is self._profile)
        _need(_inspect(workspace) == self._inspection)

    def apply(self, workspace: tx.InitWorkspace) -> tx.InitApplyOutcome:
        _need(not self._applied and workspace._scope.lease._rechecks == 2)
        object.__setattr__(self, "_applied", True)
        guard = _RestorationGuard(self, workspace)
        workspace._workflow_recovery_guard = guard
        try:
            guard.check(workspace)
            workspace.rename = tx._rename_function()
            workspace.recover()  # The existing ordering/rollback engine, once.
        except BaseException as error:
            guard.freeze()
            primary = guard.first_error if guard.first_error is not None else error
            if workspace._primary is None:
                workspace._primary = primary
            reason = (primary.outcome.reason if type(primary) is tx.InitOperationFailure else
                      "cancelled" if isinstance(primary, KeyboardInterrupt) else
                      "stale_revision" if isinstance(primary, tx.InitConflict) else "filesystem_error")
            raise tx.InitOperationFailure(recovery_outcome(self._lease, workspace, reason),
                                          workspace._primary) from None
        return recovery_outcome(self._lease, workspace)


class WorkflowRecoveryCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_profile", "_revision", "_revision_token", "_view_json", "_state", "_prepared")

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


class PreparedWorkflowRecovery(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_state")

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> dict[str, Any]:
        return self._checkout.view


def _lease_matches(lease: object, profile: tx.TypedEditProfile = _PROFILE) -> bool:
    from .init_workspace_custody import InitRootLease
    return (profile in (_PROFILE, tx.TypedEditProfile.CONFIGURATION)
            and type(lease) is InitRootLease and lease.profile is profile
            and lease._workflow_recovery_mode and not lease._image_recovery_mode
            and not lease._saved_text_recovery_mode
            and lease._configuration_recovery_mode is (profile is tx.TypedEditProfile.CONFIGURATION))


def _workspace_profile(workspace: tx.InitWorkspace) -> tx.TypedEditProfile:
    _need(type(workspace) is tx.InitWorkspace and workspace._scope is not None
          and workspace._workflow_recovery_mode and workspace._typed_profile is None)
    lease = workspace._scope.lease
    _need(_lease_matches(lease, lease.profile))
    return lease.profile


def _configuration_read_limit(workspace: tx.InitWorkspace, name: str) -> int:
    # Complete fixed names only; this narrows bytes, never grants a path or
    # adopts an object. The inspection/guard still binds its original location.
    _need(_workspace_profile(workspace) is tx.TypedEditProfile.CONFIGURATION)
    if name in _CONTROLS:
        return tx.MAX_CONTROL_BYTES
    for index, (path, limit) in enumerate(zip(tx.TypedEditProfile.CONFIGURATION.paths,
                                            tx.TypedEditProfile.CONFIGURATION.observation_limits)):
        if name in (path.rsplit("/", 1)[-1], f"new-{index}", f"old-{index}"):
            return limit
    raise _Refused("Unrecognized configuration recovery input")


def _checkout(value: object) -> bool:
    return type(value) is WorkflowRecoveryCheckout and getattr(value, "_identity", None) is value


def _prepared(value: object) -> bool:
    return (type(value) is PreparedWorkflowRecovery and getattr(value, "_identity", None) is value
            and _checkout(getattr(value, "_checkout", None)) and value._checkout._prepared is value)


def _failure(lease: InitRootLease, error: BaseException) -> CoreEditOutcome:
    native = _shared._native_contract()
    failed = _shared._settled_failure(native, error)
    retained = recovery_outcome(lease, reason=failed.reason)
    return CoreEditOutcome(retained.effect, retained.journal,
                           "unknown" if "unknown" in (retained.resources, failed.resources) else "settled",
                           retained.reason)


def _invalid(lease: object, reason: str = "invalid_params", *, profile: tx.TypedEditProfile = _PROFILE) -> CoreEditOutcome:
    if not _lease_matches(lease, profile):
        return _shared._not_started(reason)
    value = recovery_outcome(lease, reason=reason)
    return CoreEditOutcome(value.effect, value.journal, value.resources, value.reason)


def _view(captured: _Inspection | None, conflict: bool, profile: tx.TypedEditProfile) -> dict[str, Any]:
    view: dict[str, Any] = {"schemaVersion": 1, "kind": "recovery",
        "state": "conflict" if conflict else "idle", "action": None, "transactionId": None,
        "files": [], "privateCleanup": {"fileCount": 0, "directoryCount": 0,
                                       "scope": ("inspected-configuration-journal-only" if profile is tx.TypedEditProfile.CONFIGURATION
                                                 else "inspected-workflow-journal-only")}}
    if captured is None:
        return view
    plan = json.loads(captured.plan)
    view.update(state="recoverable", action=captured.action, transactionId=plan["transactionId"])
    view["files"] = [{"id": identity, "path": row["path"],
                      "action": ("preserve" if captured.action != "rollback" or row["after"] is None else
                                 "remove" if row["before"] is None else "restore"),
                      "before": None if row["before"] is None else
                                {key: row["before"][key] for key in ("size", "mode", "sha256")},
                      "after": None if row["after"] is None else
                               {key: row["after"][key] for key in ("size", "mode", "sha256")}}
                     for identity, row in zip(("configuration", "root-ignore") if profile is tx.TypedEditProfile.CONFIGURATION else _IDS, plan["files"])]
    view["privateCleanup"].update(fileCount=sum(not entry.directory for _, entry in captured.entries),
                                  directoryCount=sum(entry.directory for _, entry in captured.entries))
    return view


def _capture_recovery(lease: InitRootLease, profile: tx.TypedEditProfile) -> WorkflowRecoveryCheckout:
    if not _lease_matches(lease, profile):
        _shared._reject("invalid_params")
    captured, revision, conflict = None, None, False
    try:
        token = _shared.uuid.uuid4().hex
        _need(type(token) is str and _shared._TOKEN.fullmatch(token) is not None)
        with lease.workflow_recovery_scope() as workspace:
            try:
                captured = _inspect(workspace)
            except (ValidationError, OSError):
                if lease.guard.lifetime_ledger.fatal:
                    raise
                conflict = True
            if captured is not None:
                # Rechecks remain observational until exact equality succeeds.
                # A replacement terminal can never rewrite this inspected fact.
                if captured.action == "committed_cleanup":
                    lease._workflow_recovery_effect = "committed"
                elif captured.action == "rolled_back_cleanup":
                    lease._workflow_recovery_effect = "rolled_back"
                revision = object.__new__(WorkflowRecoveryRevision)
                for name, value in (("_identity", revision), ("_lease", lease), ("_profile", profile), ("_inspection", captured), ("_applied", False)):
                    object.__setattr__(revision, name, value)
                lease._workflow_recovery = revision
        view = tx._json(_view(captured, conflict, profile))
        _need(len(view) <= 4096)
        checkout = object.__new__(WorkflowRecoveryCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_profile", profile), ("_revision", revision),
                            ("_revision_token", token), ("_view_json", view), ("_state", _shared._CAPTURED),
                            ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except BaseException as error:
        raise ConfigEditFailure(_failure(lease, error)) from None


def _prepare_recovery(lease: InitRootLease, checkout: WorkflowRecoveryCheckout,
                      expected_revision: str, profile: tx.TypedEditProfile) -> PreparedWorkflowRecovery:
    if not _checkout(checkout) or checkout._state != _shared._CAPTURED:
        raise ConfigEditFailure(_invalid(lease, profile=profile))
    object.__setattr__(checkout, "_state", _shared._PREPARING)
    try:
        if (not _lease_matches(lease, profile) or lease is not checkout._lease or checkout._profile is not profile or checkout._revision is None
                or type(expected_revision) is not str or _shared._TOKEN.fullmatch(expected_revision) is None):
            raise ConfigEditFailure(_invalid(lease, profile=profile))
        if expected_revision != checkout.revision:
            raise ConfigEditFailure(_invalid(lease, "stale_revision", profile=profile))
        with lease.workflow_recovery_scope(checkout._revision):
            pass  # Second read-only qualification; no mutation before confirmation.
        token = _shared.uuid.uuid4().hex
        _need(type(token) is str and _shared._TOKEN.fullmatch(token) is not None and token != checkout.revision)
        plan = object.__new__(PreparedWorkflowRecovery)
        for name, value in (("_identity", plan), ("_checkout", checkout), ("_token", token), ("_state", _shared._PREPARED)):
            object.__setattr__(plan, name, value)
        object.__setattr__(checkout, "_prepared", plan)
        object.__setattr__(checkout, "_state", _shared._PREPARED)
        return plan
    except BaseException as error:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        if type(error) is ConfigEditFailure:
            raise
        raise ConfigEditFailure(_failure(lease, error)) from None


def _apply_recovery(lease: InitRootLease, plan: PreparedWorkflowRecovery, profile: tx.TypedEditProfile) -> CoreEditOutcome:
    if (not _prepared(plan) or plan._state != _shared._PREPARED
            or plan._checkout._state != _shared._PREPARED):
        return _invalid(lease, profile=profile)
    # Consume before lock acquisition. An old Apply token, failed recheck, or
    # lost return cannot become another recovery grant.
    object.__setattr__(plan, "_state", _shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if not _lease_matches(lease, profile) or lease is not checkout._lease or checkout._profile is not profile:
        return _invalid(lease, profile=profile)
    try:
        with lease.workflow_recovery_scope(checkout._revision) as workspace:
            result = workspace.apply_workflow_recovery(checkout._revision)
    except BaseException as error:
        return _failure(lease, error)
    return _shared._native_outcome(_shared._native_contract(), result)


def _discard_recovery(authority: WorkflowRecoveryCheckout | PreparedWorkflowRecovery, profile: tx.TypedEditProfile) -> None:
    if _checkout(authority):
        checkout = authority
    elif _prepared(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    if checkout._profile is not profile or not _lease_matches(checkout._lease, profile):
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)


def capture_github_workflow_recovery(lease: InitRootLease) -> WorkflowRecoveryCheckout:
    return _capture_recovery(lease, _PROFILE)


def prepare_github_workflow_recovery(lease: InitRootLease, checkout: WorkflowRecoveryCheckout,
                                     expected_revision: str) -> PreparedWorkflowRecovery:
    return _prepare_recovery(lease, checkout, expected_revision, _PROFILE)


def apply_github_workflow_recovery(lease: InitRootLease, plan: PreparedWorkflowRecovery) -> CoreEditOutcome:
    return _apply_recovery(lease, plan, _PROFILE)


def discard_github_workflow_recovery(authority: WorkflowRecoveryCheckout | PreparedWorkflowRecovery) -> None:
    _discard_recovery(authority, _PROFILE)
