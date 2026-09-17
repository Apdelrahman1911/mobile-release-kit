"""Native-only rooted lease for one closed finite edit, not a controller.

Never imported from the passive API. A retained no-follow root has no flock
over review; each short scope opens a fresh description of '.' and lends it
to InitWorkspace. All handles are original accepted _FD slots.
"""
from __future__ import annotations

import os
import stat
import sys
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .build_inputs import (BuildInputError, _Directory, _FD, _attempt_all,
                           _build_pending_names_locked, _directory,
                           _init_pending_names_locked)
from .cancellation import CleanupScope, DefaultCancellation
from .init_transaction import (InitApplyOutcome, InitOperationFailure,
                               InitWorkspace, ObservedFile, TypedEditProfile)


def _failure(reason: str, primary: BaseException | None = None, *,
             outcome: InitApplyOutcome | None = None, unknown: bool = False) -> InitOperationFailure:
    current = outcome or InitApplyOutcome("not_started", "not_created", "settled", reason)
    return InitOperationFailure(InitApplyOutcome(
        current.effect, current.journal, "unknown" if unknown else current.resources,
        (current.reason if current.reason != "none" else reason)), primary)


class RootedRevision:
    """Exact private immutable capture; a token string cannot reconstruct it."""
    __slots__ = ("_lease", "_profile", "_token", "_parents", "_parent_facts", "_files", "_raw", "_absent")

    def __new__(cls, *args: Any, **kwargs: Any):
        raise TypeError("rooted revisions are bound only by the original lease")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("rooted revision is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("rooted revision is immutable")

    def __copy__(self):
        raise TypeError("rooted revision cannot be copied")

    def __deepcopy__(self, memo: Any):
        raise TypeError("rooted revision cannot be copied")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("rooted revision cannot be serialized")

    @property
    def token(self) -> str:
        return self._token

    @property
    def profile(self) -> TypedEditProfile:
        return self._profile

    @property
    def release_directory_absent(self) -> bool:
        if self._profile is not TypedEditProfile.CONFIGURATION:
            raise _failure("invalid_params")
        return self._absent

    @property
    def missing_workflow_directories(self) -> tuple[str, ...]:
        if self._profile is not TypedEditProfile.GITHUB_WORKFLOWS:
            raise _failure("invalid_params")
        parents = dict(self._parents)
        return tuple(path for path in self._profile.directories if parents[path] is None)


class LockedInitScope:
    def __init__(self, lease: InitRootLease) -> None:
        self.lease = lease
        self.lock = _FD(lease.guard)
        self.meta = _FD(lease.guard)
        self.identity: dict[str, int] | None = None
        self.meta_identity: dict[str, int] | None = None
        self.workspace: InitWorkspace | None = None
        self.locked = False
        self.claimed = False
        self.closed = False

    @property
    def fd(self) -> int:
        if self.lock.number is None or not self.locked or self.claimed:
            raise _failure("custody_unknown", unknown=True)
        return self.lock.number

    def acquire(self) -> None:
        import fcntl
        guard = self.lease.guard
        guard.check()
        self.lease.check()
        number = self.lock.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.lease.directory.fd)
        self.identity = _directory(os.fstat(number))
        if self.identity != _directory(os.fstat(self.lease.directory.fd)):
            raise _failure("stale_revision")
        try:
            with guard.deferred(check_on_exit=False):
                fcntl.flock(number, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.locked = True
        except BlockingIOError as error:
            raise _failure("busy", error) from None
        guard.check()
        self.check()
        try:
            names = _init_pending_names_locked(number)
            if ".mobile-release" in names:
                meta = self.meta.open(".mobile-release", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=number)
                self.meta_identity = _directory(os.fstat(meta))
                if (self.meta_identity["uid"] != os.geteuid()
                        or self.meta_identity["mode"] != 0o700
                        or self.meta_identity["device"] != self.identity["device"]):
                    raise _failure("pending_state")
                self.check()
                _build_pending_names_locked(meta)
        except BuildInputError as error:
            raise _failure("pending_state", error) from None
        guard.check()

    def check(self) -> None:
        self.lease.check()
        number = self.fd
        if _directory(os.fstat(number)) != self.identity:
            raise _failure("stale_revision")
        if self.meta.number is not None:
            if (_directory(os.fstat(self.meta.number)) != self.meta_identity
                    or _directory(os.stat(".mobile-release", dir_fd=number,
                                          follow_symlinks=False)) != self.meta_identity):
                raise _failure("pending_state")

    def claim_workspace(self, workspace: InitWorkspace) -> None:
        self.check()
        if type(workspace) is not InitWorkspace or self.workspace is not None:
            raise _failure("invalid_params")
        self.workspace = workspace

    def outcome(self, reason: str) -> InitApplyOutcome:
        if self.workspace is None:
            return InitApplyOutcome("not_started", "not_created", "settled", reason)
        return self.workspace.current_outcome(reason)

    def close(self) -> None:
        self.lease.guard._check_owner()
        if self.claimed:
            if not self.closed:
                raise _failure("custody_unknown", outcome=self.outcome("custody_unknown"), unknown=True)
            return
        self.claimed = True
        actions = ([self.workspace.settle_slots] if self.workspace is not None else [])
        actions += [self.meta.close, self.lock.close]
        _attempt_all(self.lease.guard, actions)
        self.closed = True


class InitRootLease:
    def __init__(self, root: Path, *, cancellation: DefaultCancellation,
                 profile: TypedEditProfile = TypedEditProfile.CONFIGURATION,
                 registered_identity: dict[str, int] | None = None) -> None:
        if type(cancellation) is not DefaultCancellation or type(profile) is not TypedEditProfile:
            raise _failure("invalid_params")
        cancellation._check_owner()
        if threading.current_thread() is not threading.main_thread():
            raise _failure("invalid_params")
        if profile is TypedEditProfile.GITHUB_WORKFLOWS:
            if (type(registered_identity) is not dict
                    or set(registered_identity) != {"device", "inode", "mode", "uid", "gid"}
                    or any(type(value) is not int for value in registered_identity.values())
                    or not 0 <= registered_identity["device"] < 2**64
                    or not 0 < registered_identity["inode"] < 2**64
                    or any(not 0 <= registered_identity[key] < 2**32 for key in ("mode", "uid", "gid"))
                    or not stat.S_ISDIR(registered_identity["mode"])):
                raise _failure("invalid_params")
            self._registered_identity = tuple(sorted(registered_identity.items()))
        else:
            if registered_identity is not None:
                raise _failure("invalid_params")
            self._registered_identity = None
        self._profile = profile
        self.root, self.guard = root, cancellation
        self.directory = _Directory(root, cancellation, edit_checkpoints=True)
        self._scopes: list[LockedInitScope] = []
        self._active: LockedInitScope | None = None
        self._revision: RootedRevision | None = None
        self._acquire_claimed = False
        self._acquired = False
        self._capture_claimed = False
        self._rechecks = 0
        self._failed = False
        self._close_claimed = False
        self.closed = False

    @property
    def profile(self) -> TypedEditProfile:
        return self._profile

    def acquire(self) -> None:
        self.guard._check_owner()
        if self._acquire_claimed or self._close_claimed:
            raise _failure("invalid_params")
        self._acquire_claimed = True
        if not self.guard._activated:
            raise _failure("invalid_params")
        try:
            self.guard._borrowable()
        except BaseException as error:
            raise _failure("custody_unknown", error, unknown=True) from None
        if not (sys.platform == "darwin" or sys.platform.startswith("linux")):
            raise _failure("unsupported_platform")
        if self._profile is TypedEditProfile.GITHUB_WORKFLOWS and not sys.platform.startswith("linux"):
            raise _failure("unsupported_platform")
        try:
            value = str(self.root)
            parts = self.root.parts
            valid = (type(self.root) is Path or isinstance(self.root, Path)) and self.root.is_absolute()
            valid = (valid and not value.startswith("//") and len(value.encode("utf-8")) <= 4096
                     and len(parts) <= 128 and all(
                         part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                         and not part.endswith((" ", "."))
                         and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                         for part in parts[1:]))
        except (AttributeError, UnicodeError):
            valid = False
        if not valid:
            raise _failure("invalid_params")
        self.guard.check()
        try:
            self.directory.acquire()
            self._acquired = True
            self.check()
            self.guard.check()
        except InitOperationFailure:
            raise
        except BaseException as error:
            self._failed = True
            raise _failure("cancelled" if isinstance(error, KeyboardInterrupt) else "filesystem_error",
                           error, unknown=self.guard.lifetime_ledger.fatal) from None

    def check(self) -> None:
        self.guard._check_owner()
        if not self._acquired or self._close_claimed or self._failed:
            raise _failure("custody_unknown", unknown=True)
        try:
            self.directory.check()
            if self._profile is TypedEditProfile.GITHUB_WORKFLOWS:
                # Rust registration carries full st_mode, not S_IMODE. Read the
                # original retained root descriptor before any target capture;
                # a new pathname observation is not registration authority.
                value = os.fstat(self.directory.fd)
                facts = dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
                             uid=value.st_uid, gid=value.st_gid)
                if not stat.S_ISDIR(value.st_mode) or tuple(sorted(facts.items())) != self._registered_identity:
                    raise _failure("stale_revision")
        except KeyboardInterrupt:
            raise
        except InitOperationFailure:
            raise
        except BaseException as error:
            fatal = self.guard.lifetime_ledger.fatal
            raise _failure("custody_unknown" if fatal else "stale_revision", error, unknown=fatal) from None

    @property
    def last_outcome(self) -> InitApplyOutcome:
        if not self._scopes:
            return InitApplyOutcome("not_started", "not_created", "settled", "none")
        return self._scopes[-1].outcome("none")

    def bind_revision(self, workspace: InitWorkspace,
                      observed: tuple[ObservedFile, ...]) -> RootedRevision:
        self.check()
        scope = self._active
        if (scope is None or scope.workspace is not workspace or self._revision is not None
                or workspace._typed_profile is not self._profile
                or type(observed) is not tuple or len(observed) != len(self._profile.paths)
                or any(type(item) is not ObservedFile or item.path != path
                       or workspace._captured.get(path) is not item
                       for path, item in zip(self._profile.paths, observed))
                or set(workspace._captured) != set(self._profile.paths)
                or set(workspace.parents) != set(self._profile.directories)):
            raise _failure("invalid_params")
        revision = object.__new__(RootedRevision)
        parents = tuple((path, tuple(sorted(value.items())) if value is not None else None)
                        for path, value in sorted(workspace.parents.items()))
        files = tuple((item.path, tuple(sorted(item.before.items())) if item.before is not None else None,
                       item.data) for item in observed)
        for name, value in (
            ("_lease", self), ("_profile", self._profile), ("_token", uuid.uuid4().hex), ("_parents", parents),
            ("_parent_facts", tuple(sorted(workspace._parent_facts.items()))),
            ("_files", files), ("_raw", tuple(sorted(workspace._raw_observations.items()))),
            ("_absent", self._profile is TypedEditProfile.CONFIGURATION and workspace.parents["release"] is None),
        ):
            object.__setattr__(revision, name, value)
        self._revision = revision
        return revision

    def _recheck(self, workspace: InitWorkspace, revision: RootedRevision) -> None:
        if revision._profile is not self._profile or workspace._typed_profile is not self._profile:
            raise _failure("invalid_params")
        workspace.parents = {path: dict(value) if value is not None else None
                             for path, value in revision._parents}
        try:
            current = tuple(workspace.observe(path, limit=limit)
                            for path, limit in zip(self._profile.paths, self._profile.observation_limits))
        except (KeyboardInterrupt, InitOperationFailure):
            raise
        except BaseException as error:
            raise _failure("stale_revision", error, unknown=self.guard.lifetime_ledger.fatal) from None
        files = tuple((item.path, tuple(sorted(item.before.items())) if item.before is not None else None,
                       item.data) for item in current)
        if (files != revision._files or tuple(sorted(workspace._raw_observations.items())) != revision._raw
                or tuple(sorted(workspace._parent_facts.items())) != revision._parent_facts):
            raise _failure("stale_revision")

    @contextmanager
    def workspace_scope(self, revision: RootedRevision | None = None) -> Iterator[InitWorkspace]:
        self.check()
        if self._active is not None:
            raise _failure("invalid_params")
        if revision is None:
            if self._capture_claimed:
                raise _failure("invalid_params")
            self._capture_claimed = True
        else:
            if (type(revision) is not RootedRevision or revision is not self._revision
                    or revision._lease is not self or revision._profile is not self._profile or self._rechecks >= 2):
                raise _failure("invalid_params")
            self._rechecks += 1
        owner = LockedInitScope(self)
        self._scopes.append(owner)
        self._active = owner
        cleanup = CleanupScope(self.guard, owner.close, owns_cancellation=False, first_primary=True)
        try:
            try:
                with cleanup:
                    owner.acquire()
                    workspace = InitWorkspace.borrowed(owner)
                    if revision is not None:
                        self._recheck(workspace, revision)
                    yield workspace
                    owner.check()
                    self.guard.check()
            finally:
                cleanup.__exit__(*sys.exc_info())
        except BaseException as error:
            self._failed = True
            if type(error) is InitOperationFailure:
                outcome = error.outcome
            else:
                reason = "cancelled" if isinstance(error, KeyboardInterrupt) else "filesystem_error"
                outcome = owner.outcome(reason)
            unknown = self.guard.lifetime_ledger.fatal or not owner.closed
            if unknown:
                outcome = InitApplyOutcome(outcome.effect, outcome.journal, "unknown",
                                           outcome.reason if outcome.reason != "none" else "custody_unknown")
            raise InitOperationFailure(outcome, error) from None
        finally:
            self._active = None

    def close(self) -> None:
        self.guard._check_owner()
        if self._close_claimed:
            if not self.closed:
                raise _failure("custody_unknown", outcome=self.last_outcome, unknown=True)
            return
        self._close_claimed = True
        try:
            _attempt_all(self.guard, [scope.close for scope in reversed(self._scopes)] + [self.directory.close])
        except BaseException as error:
            raise _failure("custody_unknown", error, outcome=self.last_outcome, unknown=True) from None
        self.closed = True
