"""One cooperating macOS account signing lifetime, with fail-closed recovery.

The private journal is local ownership bookkeeping, not authenticated release
evidence. A hostile same-UID process or an asynchronous OS service is not locked
by flock. Never remove the persistent lease inode or adopt another PID's files.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import threading
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from sys import exc_info
from typing import Any

from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner, _mark_fork_unsafe
from ._profile_callers import fatal_cancellation_error
from .errors import CredentialError
from . import _native_process as native_process
from .owned_process import (
    ProcessCleanupError, ProcessError, ProcessInterrupted, fatal_lifetime_error,
    preserve_lifetime_error, run_owned,
)

LEASE_DIRECTORY = ".mobile-release-signing"
SESSION_RE = re.compile(r"session-([0-9a-f]{32})\Z")
TOKEN_RE = re.compile(r"[0-9a-f]{32}\Z")
UUID_RE = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
DB_NAME = "signing.keychain-db"
# Apple's local AtomicFile lock naming, NOT a SHA1 authenticity mechanism.
LOCK_NAME = ".fl" + hashlib.sha1(DB_NAME.encode(), usedforsecurity=False).hexdigest()[:8].upper()
CONTROL_LIMIT = 512 * 1024
PROFILE_LIMIT = 4 * 1024 * 1024
CONFIRMATION = "account-signing-is-idle-and-restore-owned-state"
CONTROLS = {"intent.json", "intent.pending", "state.json", "state.pending", "completed.json", "completed.pending"}
FENCE_CONTROLS = {"command-final.pending", "command-final.json"}
FENCE_LIMIT = 4096
_RECOVERY_KEY = object()
_SNAPSHOT_KEY = object()
MUTABLE_KINDS = {"create", "settings", "unlock", "import", "partition", "build"}
KINDS = MUTABLE_KINDS | {"observe", "search", "default", "delete", "extract"}
PROFILE_PHASES = {"not-started", "inspected", "reused", "stage-intent", "stage-created",
                  "link-intent", "linked", "stage-removed", "resolved"}


class SigningBusy(CredentialError):
    pass


class SigningPending(CredentialError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CredentialError("local signing: " + message)


def _pending() -> SigningPending:
    return SigningPending("local signing cleanup is pending; run mobile-release local-signing status and follow the recovery guide")


def _identity(details: os.stat_result) -> dict[str, int]:
    return {"device": details.st_dev, "inode": details.st_ino}


def _same_file_state(before: os.stat_result | None, after: os.stat_result | None) -> bool:
    # Compare one observation interval, never metadata saved before our own
    # link/unlink. Reading can change atime; none of these fields may change.
    return before is not None and after is not None and all(
        getattr(before, key) == getattr(after, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                    "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _identity_valid(value: object) -> bool:
    return (type(value) is dict and set(value) == {"device", "inode"}
            and all(type(number) is int and 0 < number < 2**64 for number in value.values()))


def _stat(fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError as error:
        raise preserve_lifetime_error(ProcessCleanupError(
            "local signing descriptor cleanup is unconfirmed; end this process before retrying",
        ), previous=error) from None


def _names(fd: int, maximum: int = 16) -> set[str]:
    names = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            names.add(entry.name)
            _require(len(names) <= maximum, "private namespace has too many entries; preserve it")
    return names


def _directory(details: os.stat_result, *, private: bool = True) -> dict[str, int]:
    _require(stat.S_ISDIR(details.st_mode) and details.st_uid == os.getuid(), "directory ownership is unsafe")
    mode = stat.S_IMODE(details.st_mode)
    _require(mode == 0o700 if private else not mode & 0o7022, "directory permissions are unsafe")
    return _identity(details)


def _open_dir(name: str | Path, *, parent: int | None = None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)


def account_home(home: Path | None = None) -> Path:
    # An explicit home is an internal credential-free filesystem test seam. It
    # is never exposed as CLI input, configuration or an environment override.
    if home is not None:
        path = home.expanduser().resolve(strict=True)
    else:
        _require(sys.platform == "darwin", "signed iOS builds and local recovery require macOS")
        import pwd

        _require(os.getuid() != 0 and os.getuid() == os.geteuid(), "use a non-root, unmapped macOS login account")
        path = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        supplied = os.environ.get("HOME")
        _require(supplied is None or (Path(supplied).is_absolute() and Path(supplied).resolve(strict=True) == path),
                 "HOME differs from the real signing account home")
    _directory(path.stat(), private=False)
    return path


class _Statfs64(ctypes.Structure):
    _fields_ = [("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32),
                *[(name, ctypes.c_uint64) for name in ("blocks", "bfree", "bavail", "files", "ffree")],
                ("fsid", ctypes.c_int32 * 2), ("owner", ctypes.c_uint32), ("type", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("subtype", ctypes.c_uint32), ("fstypename", ctypes.c_char * 16),
                ("mntonname", ctypes.c_char * 1024), ("mntfromname", ctypes.c_char * 1024),
                ("flags_ext", ctypes.c_uint32), ("reserved", ctypes.c_uint32 * 7)]


def require_local_volume(fd: int) -> None:
    _require(sys.platform == "darwin" and ctypes.sizeof(ctypes.c_void_p) == 8
             and ctypes.sizeof(_Statfs64) == 2168 and _Statfs64.flags.offset == 64
             and _Statfs64.fstypename.offset == 72, "unsupported native filesystem ABI")
    try:
        function = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).fstatfs64
        function.argtypes, function.restype = (ctypes.c_int, ctypes.POINTER(_Statfs64)), ctypes.c_int
        info = _Statfs64()
        _require(function(fd, ctypes.byref(info)) == 0, "filesystem identity could not be inspected")
    except (AttributeError, OSError):
        raise CredentialError("local signing: filesystem inspection is unavailable") from None
    _require(bool(info.flags & 0x1000) and not info.flags & 1 and bytes(info.fstypename) in {b"apfs", b"hfs"},
             "signing requires a writable local APFS or HFS+ volume")


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def _fence_json(value: object) -> bytes:
    return _json(value)[:-1]


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate recovery field")
        result[key] = value
    return result


def _parse(content: bytes) -> dict:
    try:
        value = json.loads(content, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _require(type(value) is dict, "recovery control is not an object")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise CredentialError("local signing: committed recovery control is malformed; preserve it") from None


def _read_regular(
    fd: int, name: str, maximum: int, *, private: bool, cancellation: DefaultCancellation | None = None,
) -> tuple[bytes, os.stat_result] | None:
    descriptor = None
    cancellation, owns = cancellation_owner(cancellation, ProcessCleanupError, "local signing read cancellation cleanup failed")

    def cleanup() -> None:
        nonlocal descriptor
        if descriptor is not None:
            closing, descriptor = descriptor, None
            _close(closing)

    scope = CleanupScope(cancellation, cleanup, owns_cancellation=owns, fork_cleanup=cleanup,
                         first_primary=True)
    try:
        try:
            with scope:
                if owns:
                    cancellation.install()
                    cancellation.activate()
                try:
                    with cancellation.deferred():
                        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    before = os.fstat(descriptor)
                    _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                             "local signing file type or size is unsafe")
                    if private:
                        _require(before.st_nlink == 1 and before.st_uid == os.getuid()
                                 and stat.S_IMODE(before.st_mode) == 0o600, "recovery control is unsafe")
                    result = bytearray()
                    while len(result) <= maximum:
                        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(result)))
                        if not chunk:
                            break
                        result.extend(chunk)
                    after = os.fstat(descriptor)
                    _require(len(result) == before.st_size and _same_file_state(before, after)
                             and _same_file_state(before, os.stat(name, dir_fd=fd, follow_symlinks=False)),
                             "local signing file changed while reading")
                    return bytes(result), before
                except FileNotFoundError:
                    # Optional file absence is not an error inherited from the
                    # caller's body. Close/handler restoration occur OUTSIDE this
                    # catch and can never be mistaken for an absent file.
                    return None
        finally:
            scope.__exit__(*exc_info())
    except BaseException as error:
        fatal = fatal_cancellation_error(
            error, cancellation, "local signing read cleanup is unconfirmed; end this process before retrying",
        )
        if fatal is not None:
            raise fatal from None
        raise


def _control(fd: int, name: str, *, cancellation: DefaultCancellation | None = None) -> bytes | None:
    result = _read_regular(fd, name, CONTROL_LIMIT, private=True, cancellation=cancellation)
    return None if result is None else result[0]


def _literal_path(value: object) -> bool:
    return (type(value) is str and value.startswith("/") and 0 < len(value) <= 4096
            and not any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} or char == '"' for char in value)
            and len(value.encode("utf-8")) <= 4096)


def parse_keychain_paths(output: str, *, default: bool = False) -> list[str]:
    _require(type(output) is str and len(output.encode("utf-8")) <= CONTROL_LIMIT, "native keychain output exceeds its bound")
    values = []
    lines = output.split("\n")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        match = re.fullmatch(r'[ \t]*"([^"\r\n]+)"', line)
        _require(match is not None and _literal_path(match[1]), "native keychain output is ambiguous")
        values.append(match[1])
    _require(len(values) <= 128 and len(set(values)) == len(values)
             and (not default or len(values) == 1), "native keychain list/default is incomplete or duplicated")
    return values


def _preferences_valid(value: object) -> bool:
    return (type(value) is dict and set(value) == {"default", "search"} and _literal_path(value["default"])
            and type(value["search"]) is list and len(value["search"]) <= 128
            and all(_literal_path(path) for path in value["search"])
            and len(set(value["search"])) == len(value["search"]))


def _profile_snapshot(fd: int, name: str, *, cancellation: DefaultCancellation | None = None) -> dict | None:
    result = _read_regular(fd, name, PROFILE_LIMIT, private=False, cancellation=cancellation)
    return None if result is None else {"identity": _identity(result[1]), "sha256": hashlib.sha256(result[0]).hexdigest()}


def _snapshot_valid(value: object) -> bool:
    return (value is None or (type(value) is dict and set(value) == {"identity", "sha256"}
            and _identity_valid(value["identity"]) and type(value["sha256"]) is str and bool(HASH_RE.fullmatch(value["sha256"]))))


@dataclass(frozen=True, slots=True)
class SigningSnapshot:
    _session: SigningSession
    phase: str
    _controls: tuple[tuple[str, bytes | None], ...]
    _intent: bytes | None
    _state: bytes | None
    _completed: bytes | None
    _key: object


class _RecoveryAttempt:
    """One fresh recovery invocation; reload and manual retry cannot renew it."""

    def __init__(self, session: SigningSession, *, _key: object) -> None:
        _require(_key is _RECOVERY_KEY and session.lease._recovery_mode is True,
                 "recovery authorization issuer differs")
        self.session, self.lease = session, session.lease
        self.pid, self.owner_thread = os.getpid(), threading.current_thread()
        self.revoked = False
        self.active_query = None

    def revoke(self) -> None:
        self.revoked = True

    def check(self, session: SigningSession, *, clear_query: bool = False) -> None:
        _require(self.pid == os.getpid() and self.owner_thread is threading.current_thread()
                 and session is self.session and session.lease is self.lease
                 and self.lease.active is session and self.lease._recovery_mode is True
                 and not self.revoked and not session.journal_failed and not session.unresolved
                 and (not clear_query or self.active_query is None),
                 "recovery authorization is unavailable; preserve pending state")
        self.lease.assert_owner()
        _require(not self.lease.cancellation.lifetime_ledger.fatal,
                 "recovery lifetime is unresolved")
        # Expected values advance only after this invocation's genuine durable
        # commit/removal. A caller reload never makes intervening edits owned.
        if session._committed_controls is not None:
            for name in ("intent.json", "state.json", "completed.json"):
                _require(_control(session.fd, name, cancellation=session.cancellation) == session._committed_controls.get(name),
                         "recovery control generation changed")

    def begin_query(self, session: SigningSession, scope) -> None:
        self.check(session, clear_query=True)
        self.active_query = scope

    def finish_query(self, session: SigningSession, scope) -> None:
        self.check(session)
        _require(self.active_query is scope, "recovery query ownership differs")
        self.active_query = None


class _AccountFDSlot:
    """Account-owned raw descriptor; exported borrowers never take its close."""

    def __init__(self, lease: SigningLease) -> None:
        self._lease = lease
        self.pid, self.owner_thread = os.getpid(), threading.current_thread()
        self.state = "NEW"
        self._fd: int | None = None
        self._original_fd: int | None = None
        self._exports_retired = False
        self._borrowers: set[object] = set()

    def _owner(self) -> None:
        if self.pid != os.getpid():
            self.relinquish_inherited()
            raise ProcessCleanupError("inherited account descriptor cannot authorize work")
        _require(threading.current_thread() is self.owner_thread, "account descriptor owner differs")

    def _begin_open(self) -> None:
        self._owner()
        _require(self.state == "NEW", "account descriptor open was repeated")
        self.state = "ACQUIRING"

    def _publish(self, fd: int) -> None:
        _require(self.state == "ACQUIRING" and type(fd) is int and 0 <= fd < 2**31,
                 "account descriptor publication differs")
        self._fd = self._original_fd = fd
        self.state = "OPEN"
        self._owner()  # Publish a late child copy before rejecting its use.

    def _open_failed(self) -> None:
        if self.state == "ACQUIRING":
            self.state = "UNKNOWN"

    def fileno(self) -> int:
        self._owner()
        _require(self.state == "OPEN" and self._fd is not None and not self._exports_retired,
                 "account descriptor ownership ended")
        return self._fd

    def _borrow(self, acquisition: object) -> int:
        descriptor = self.fileno()
        _require(acquisition not in self._borrowers, "account source borrow was repeated")
        self._borrowers.add(acquisition)
        return descriptor

    def _release(self, acquisition: object) -> None:
        self._owner()
        _require(acquisition in self._borrowers, "account source borrower differs")
        self._borrowers.remove(acquisition)

    def retire_exports(self) -> None:
        self._exports_retired = True

    def close_once(self) -> None:
        self.retire_exports()
        if self.pid != os.getpid():
            self.relinquish_inherited()
            return
        self._owner()
        if self.state in ("NEW", "CLOSED"):
            return
        if self.state != "OPEN" or self._fd is None or self._borrowers:
            raise ProcessCleanupError("account descriptor cleanup lacks settled original custody")
        descriptor, self._fd, self.state = self._fd, None, "CLOSE_IN_FLIGHT"
        try:
            _close(descriptor)
        except BaseException:
            self.state = "UNKNOWN"
            raise
        self.state = "CLOSED"

    def relinquish_inherited(self) -> None:
        if self.pid == os.getpid():
            return
        self.retire_exports()
        if self.state in ("NEW", "CLOSED", "INHERITED_CLOSED"):
            return
        if self.state != "OPEN" or self._fd is None:
            _mark_fork_unsafe()
            return  # Unknown original publication/close cannot authorize retry.
        descriptor, self._fd, self.state = self._fd, None, "INHERITED_CLOSE_IN_FLIGHT"
        try:
            os.close(descriptor)
        except BaseException:
            self.state = "INHERITED_UNKNOWN"
            _mark_fork_unsafe()
        else:
            self.state = "INHERITED_CLOSED"


class SigningLease:
    def __init__(self, cancellation: DefaultCancellation, *, home: Path | None = None):
        self.cancellation, self.supplied_home = cancellation, home
        self.pid, self.owner_thread = os.getpid(), threading.current_thread()
        self.thread = threading.get_ident()  # Diagnostic compatibility only.
        self.home_fd = None
        self._hold_slot = _AccountFDSlot(self)
        self._locked_source: native_process.LockedAccountSource | None = None
        self._recovery_mode: bool | None = None
        self._normal_execution_revoked = False
        self.home = self.path = None
        self.home_identity = self.identity = None
        self.locked = False
        self.active: SigningSession | None = None

    @property
    def fd(self) -> int | None:
        return self._hold_slot._fd

    def assert_owner(self) -> None:
        if self.pid != os.getpid():
            self._close_inherited()
            raise ProcessCleanupError("inherited account lease cannot authorize work")
        _require(self.pid == os.getpid() and self.owner_thread is threading.current_thread() and self.locked,
                 "lease cannot be used across processes/threads or after release")
        _require(_directory(os.fstat(self.home_fd), private=False) == self.home_identity
                 and _identity(self.home.stat()) == self.home_identity
                 and _directory(os.fstat(self.fd)) == self.identity
                 and _identity(os.stat(LEASE_DIRECTORY, dir_fd=self.home_fd, follow_symlinks=False)) == self.identity,
                 "account lease namespace changed")

    def acquire(self, *, recovery: bool = False) -> None:
        _require(type(recovery) is bool and self._recovery_mode is None, "account lease mode was reused")
        self._recovery_mode = recovery
        with self.cancellation.deferred():
            self.cancellation.check()
            self.home = account_home(self.supplied_home)
            import fcntl

            self.home_fd = _open_dir(self.home)
            self.cancellation.check()
            self.home_identity = _directory(os.fstat(self.home_fd), private=False)
            if self.supplied_home is None or sys.platform == "darwin":
                require_local_volume(self.home_fd)
            try:
                os.mkdir(LEASE_DIRECTORY, mode=0o700, dir_fd=self.home_fd)
                os.fsync(self.home_fd)
            except FileExistsError:
                pass
            self._hold_slot._begin_open()
            try:
                self._hold_slot._publish(_open_dir(LEASE_DIRECTORY, parent=self.home_fd))
            except BaseException:
                self._hold_slot._open_failed()
                raise
            self.cancellation.check()
            self.identity = _directory(os.fstat(self.fd))
            self.path = self.home / LEASE_DIRECTORY
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SigningBusy("another signing task owns this macOS account; wait for it to finish, then retry") from None
            self.locked = True
            self.assert_owner()
            if not recovery and _names(self.fd):
                raise _pending()
            self._locked_source = native_process._issue_locked_account_source(self)

    def _observe_session_execution(self, session, *, closing: bool = False) -> None:
        # Original callers have already checked PID/thread ownership. This is
        # nonthrowing policy observation, not a new cleanup/finality receipt.
        if (self._recovery_mode is False and session is not None
                and (session.unresolved or session.journal_failed
                     or (closing and session._open_attempted and not session._disposal_complete))):
            self._normal_execution_revoked = True

    def _admit_execution(self, authorization=None) -> None:
        self.assert_owner()
        _require(self._locked_source is not None, "account execution source was not admitted")
        self._observe_session_execution(self.active)
        if self.cancellation.lifetime_ledger.fatal:
            raise ProcessCleanupError("account lifetime is unresolved; end this process before retrying")
        if self._recovery_mode:
            _require(type(authorization) is _RecoveryAttempt, "recovery execution needs its original authorization")
            authorization.check(self.active)
        else:
            _require(authorization is None, "normal account work cannot adopt recovery authorization")
            if self._normal_execution_revoked:
                raise _pending()
        if self.active is None or not self.active.cleaning:
            self.cancellation.check()

    def execution_source(self, *, authorization=None):
        from ._command_process import _issue_account_execution_source

        self._admit_execution(authorization)
        return _issue_account_execution_source(self, self._locked_source, authorization=authorization)

    def close(self) -> None:
        if self.pid != os.getpid():
            self._close_inherited()
            return
        _require(self.owner_thread is threading.current_thread(), "account close owner differs")
        if self._locked_source is not None:
            self._locked_source.retire()
        self._hold_slot.retire_exports()
        observed = preserve_lifetime_error(ProcessError(
            "local signing lease cleanup is unconfirmed; end this process before retrying",
        ), previous=exc_info()[1])
        failed = False
        first_failure: BaseException | None = None
        if self.active is not None:
            try:
                self.active.close()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
                preserve_lifetime_error(observed, previous=error)
                failed = True
        self.locked = False
        # Closing child copies is safe; LOCK_UN would unlock the parent's shared
        # file description and is deliberately never used.
        try:
            self._hold_slot.close_once()
        except BaseException as error:
            if first_failure is None:
                first_failure = error
            preserve_lifetime_error(observed, previous=error)
            failed = True
        for attr in ("home_fd",):
            descriptor = getattr(self, attr)
            if descriptor is not None:
                setattr(self, attr, None)
                try:
                    _close(descriptor)
                except BaseException as error:
                    if first_failure is None:
                        first_failure = error
                    preserve_lifetime_error(observed, previous=error)
                    failed = True
        if failed:
            self.cancellation.lifetime_ledger._abort(first_failure)
            if isinstance(first_failure, (KeyboardInterrupt, SystemExit)):
                raise first_failure
            raise preserve_lifetime_error(ProcessCleanupError(str(observed)), previous=observed) from None

    def _close_inherited(self) -> None:
        # No parent ledger, callback, lock or namespace operation is admissible
        # in a raw-fork child. Only newly published copies may be closed once.
        if self.pid == os.getpid():
            return
        self.locked = False
        if self._locked_source is not None:
            self._locked_source.retire()
        if self.active is not None:
            self.active._close_inherited()
        self._hold_slot.relinquish_inherited()
        if self.home_fd is not None:
            descriptor, self.home_fd = self.home_fd, None
            try:
                os.close(descriptor)
            except BaseException:
                _mark_fork_unsafe()

    @contextmanager
    def profile_directory(self) -> Iterator[int | None]:
        self.assert_owner()
        descriptor = None

        def cleanup() -> None:
            nonlocal descriptor
            if descriptor is not None:
                closing, descriptor = descriptor, None
                _close(closing)

        scope = CleanupScope(self.cancellation, cleanup, owns_cancellation=False, fork_cleanup=cleanup,
                             first_primary=True)
        try:
            try:
                with scope:
                    with self.cancellation.deferred():
                        descriptor = os.dup(self.home_fd)
                    for name in ("Library", "MobileDevice", "Provisioning Profiles"):
                        with self.cancellation.deferred():
                            self.assert_owner()
                            try:
                                child = _open_dir(name, parent=descriptor)
                            except FileNotFoundError:
                                cleanup()
                                break
                            previous, descriptor = descriptor, child
                            _close(previous)
                            _directory(os.fstat(descriptor), private=False)
                    self.assert_owner()
                    yield descriptor
            finally:
                scope.__exit__(*exc_info())
        except BaseException as error:
            fatal = fatal_cancellation_error(
                error, self.cancellation,
                "local signing profile directory cleanup is unconfirmed; end this process before retrying",
            )
            if fatal is not None:
                raise fatal from None
            raise

    def session(self, *, token: str | None = None) -> SigningSession:
        self.assert_owner()
        if self._recovery_mode is False:
            self._admit_execution()
        _require(self.active is None, "this lease already has an active signing context")
        self.active = SigningSession(self, token=token)
        return self.active


@contextmanager
def local_signing_lease(
    *, home: Path | None = None, recovery: bool = False, cancellation: DefaultCancellation | None = None,
):
    cancellation, owns = cancellation_owner(cancellation, ProcessCleanupError, "local signing cancellation handlers could not be restored")
    lease = SigningLease(cancellation, home=home)
    scope = CleanupScope(cancellation, lease.close, owns_cancellation=owns, fork_cleanup=lease.close,
                         first_primary=True)
    try:
        try:
            with scope:
                if owns:
                    cancellation.install()
                    cancellation.activate()
                lease.acquire(recovery=recovery)
                yield lease
        finally:
            scope.__exit__(*exc_info())
    except BaseException as error:
        fatal = fatal_cancellation_error(
            error, cancellation, "local signing lease cleanup is unconfirmed; end this process before retrying",
        )
        if fatal is not None:
            raise fatal from None
        if isinstance(error, OSError):
            raise CredentialError("local signing account lease could not be acquired or retained safely") from None
        raise


class SigningSession:
    def __init__(self, lease: SigningLease, *, token: str | None = None):
        self.lease, self.cancellation = lease, lease.cancellation
        self.pid = os.getpid()
        self.token = secrets.token_hex(16) if token is None else token
        _require(type(self.token) is str and TOKEN_RE.fullmatch(self.token) is not None, "invalid session token")
        self.name = "session-" + self.token
        self.path = lease.path / self.name
        self.keychain = self.path / "keychain" / DB_NAME
        self.fd = self.native_fd = None
        self.identity = self.native_identity = None
        self.intent: dict | None = None
        self.state: dict | None = None
        self.completed: dict | None = None
        self.runner: Callable | None = None
        self.environment: dict[str, str] = {}
        self.unresolved = False
        self.journal_failed = False
        self.cleaning = False
        self.closed = False
        self._open_attempted = False
        self._disposal_complete = False
        self._create_origin: object | None = None
        self._loaded_snapshot: SigningSnapshot | None = None
        self._committed_controls: dict[str, bytes | None] | None = None
        self._recovery_attempt: _RecoveryAttempt | None = None
        self._command_scope = None
        self._command_binding = None
        self._command_finished = False

    def assert_owner(self) -> None:
        self.lease.assert_owner()
        _require(self.pid == os.getpid() and not self.closed, "session ownership ended")
        if self.fd is not None:
            _require(_directory(os.fstat(self.fd)) == self.identity
                     and _identity(os.stat(self.name, dir_fd=self.lease.fd, follow_symlinks=False)) == self.identity,
                     "session directory was replaced")
        if self.native_fd is not None:
            _require(_directory(os.fstat(self.native_fd)) == self.native_identity
                     and _identity(os.stat("keychain", dir_fd=self.fd, follow_symlinks=False)) == self.native_identity,
                     "native directory was replaced")

    def _write(self, name: str, value: dict, *, immutable: bool = False) -> None:
        self.assert_owner()
        _require(not self.journal_failed, "failed journal cannot be retried in this invocation")
        if self._recovery_attempt is not None:
            self._recovery_attempt.check(self, clear_query=True)
        stage = name.removesuffix(".json") + ".pending"
        data = _json(value)
        _require(len(data) <= CONTROL_LIMIT and name in CONTROLS, "recovery control exceeds its bound")
        descriptor = None
        committed = False

        def cleanup() -> None:
            nonlocal descriptor
            if descriptor is not None:
                closing, descriptor = descriptor, None
                _close(closing)

        scope = CleanupScope(self.cancellation, cleanup, owns_cancellation=False, fork_cleanup=cleanup,
                             first_primary=True)
        try:
            with scope, self.cancellation.deferred():
                try:
                    previous = _control(self.fd, name, cancellation=self.cancellation)
                    _require(not immutable or previous is None, "immutable recovery control already exists")
                    before = _stat(self.fd, name)
                    descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
                    identity = _identity(os.fstat(descriptor))
                    remaining = memoryview(data)
                    while remaining:
                        self.assert_owner()
                        count = os.write(descriptor, remaining[:64 * 1024])
                        _require(0 < count <= len(remaining), "recovery control write was incomplete")
                        remaining = remaining[count:]
                    os.fsync(descriptor)
                    closing, descriptor = descriptor, None
                    _close(closing)
                    self.assert_owner()
                    _require(_identity(os.stat(stage, dir_fd=self.fd, follow_symlinks=False)) == identity
                             and _stat(self.fd, name) == before, "recovery control changed during commit")
                    os.replace(stage, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
                    os.fsync(self.fd)
                    committed = True
                    if self._committed_controls is None:
                        self._committed_controls = {}
                    self._committed_controls[name] = data
                finally:
                    if descriptor is not None:
                        closing, descriptor = descriptor, None
                        _close(closing)
        except BaseException:
            # Current memory can contain a post-effect observation whose disk
            # checkpoint failed. Only explicit recovery reloads disk authority.
            self.journal_failed = self.journal_failed or not committed
            if self._recovery_attempt is not None:
                self._recovery_attempt.revoke()
            raise
        finally:
            scope.__exit__(*exc_info())

    def checkpoint(self) -> None:
        _require(self.state is not None, "missing active checkpoint")
        _require(type(self.state["revision"]) is int and self.state["revision"] < 2**63 - 1,
                 "journal revision exhausted")
        self.state["revision"] += 1
        self._write("state.json", self.state)

    def _remove_control(self, name: str) -> None:
        self.assert_owner()
        _require(name in CONTROLS, "not an owner control slot")
        self._recovery_clear()
        if _control(self.fd, name, cancellation=self.cancellation) is not None:
            # A fork during the reader's return/close can invalidate this FD.
            # Never let dir_fd=None become a cwd-relative unlink in the child.
            self.assert_owner()
            try:
                os.unlink(name, dir_fd=self.fd)
                os.fsync(self.fd)
                if self._committed_controls is not None:
                    self._committed_controls[name] = None
            except BaseException:
                self.journal_failed = True
                if self._recovery_attempt is not None:
                    self._recovery_attempt.revoke()
                raise

    def open(self, *, create: bool) -> None:
        self.lease.assert_owner()
        _require(not self.closed and not self._open_attempted, "session opening cannot be repeated")
        with self.cancellation.deferred():
            # Even a lost mkdir/open return may have acquired pending state.
            self._open_attempted = True
            if create:
                _require(not _names(self.lease.fd), "a pending session already exists")
                os.mkdir(self.name, mode=0o700, dir_fd=self.lease.fd)
                self._create_origin = object()
                os.fsync(self.lease.fd)
            self.fd = _open_dir(self.name, parent=self.lease.fd)
            self.lease.assert_owner()  # Includes a raw-FD handoff after fork.
            self.identity = _directory(os.fstat(self.fd))
            if create:
                self.assert_owner()
                os.mkdir("keychain", mode=0o700, dir_fd=self.fd)
                os.fsync(self.fd)
            if _stat(self.fd, "keychain") is not None:
                self.native_fd = _open_dir("keychain", parent=self.fd)
                self.lease.assert_owner()
                self.native_identity = _directory(os.fstat(self.native_fd))
            self.assert_owner()

    def bind_runner(self, runner: Callable | None = None, *, environment: dict[str, str] | None = None) -> None:
        self.environment = dict(environment or {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"})
        self.environment["HOME"] = str(self.lease.home)
        self.runner = run_owned if runner is None else runner

    def _call(self, argv: list[str], *, timeout: int = 30, on_start: Callable[[int], None] | None = None,
              cwd: Path | None = None, capture: bool = True, environ: dict[str, str] | None = None,
              execution_scope, journal_binding=None):
        if argv[0] == "security":
            argv = ["/usr/bin/security", *argv[1:]]
        environment = dict(self.environment if environ is None else environ)
        environment["HOME"] = str(self.lease.home)
        return self.runner(argv, environ=environment, timeout=timeout, cancellation=self.cancellation,
                           on_start=on_start, cwd=cwd, capture=capture, cleanup=self.cleaning,
                           execution_scope=execution_scope, journal_binding=journal_binding)

    def _new_scope(self):
        self._recovery_clear()
        return self.lease.execution_source(authorization=self._recovery_attempt).new_scope()

    def _recovery_clear(self) -> None:
        if self._recovery_attempt is not None:
            self._recovery_attempt.check(self, clear_query=True)

    def _original_outcome(self, scope, binding=None):
        from ._command_process import OriginalCommandFinality, OriginalCommandOutcome

        try:
            outcome = scope.outcome.read()
        except BaseException as error:
            self.unresolved = True
            self.cancellation.lifetime_ledger._abort(error)
            raise
        settled = (type(outcome) is OriginalCommandOutcome and outcome.matches(scope, binding)
                   and type(outcome.original_finality) is OriginalCommandFinality
                   and outcome.original_finality._engine is outcome._engine
                   and outcome.create_w.retired and outcome.run_tool.retired)
        if not settled:
            self.unresolved = True
            self.cancellation.lifetime_ledger._abort()
            raise ProcessCleanupError("original command finality is incomplete; preserve pending state",
                                      dispatched=True, contained=False)
        if outcome.result_integrity != "complete":
            self.unresolved = True
            self.cancellation.lifetime_ledger._abort()
            raise ProcessCleanupError("original command result is incomplete; preserve pending state")
        _require(not self.cancellation.lifetime_ledger.fatal,
                 "account lifetime is unresolved")
        return outcome

    def _observe_one(self, name: str, *, journal: bool) -> list[str]:
        attempt = self._recovery_attempt
        try:
            scope = self._new_scope()
            if attempt is not None:
                attempt.begin_query(self, scope)
            argv = ["security", name, "-d", "user"]
            result = (self._run_command(scope, argv, kind="observe")
                      if journal and attempt is None and self.state is not None else
                      self._call(argv, execution_scope=scope, journal_binding=None))
            outcome = self._original_outcome(scope, scope._binding)
            _require(outcome.termination == "normal-exit" and outcome.returncode == 0
                     and result.returncode == 0 and result.stderr == "",
                     "complete native keychain state could not be observed")
            parsed = parse_keychain_paths(result.stdout, default=name == "default-keychain")
            if attempt is not None:
                attempt.finish_query(self, scope)
            return parsed
        except BaseException:
            if attempt is not None:
                attempt.revoke()
            raise

    def observe(self, *, journal: bool = True) -> dict:
        self.assert_owner()
        results = []
        for name in ("default-keychain", "list-keychains"):
            results.append(self._observe_one(name, journal=journal))
        return {"default": results[0][0], "search": results[1]}

    def inventory(self) -> dict:
        self.assert_owner()
        if self.native_fd is None:
            return {}
        names = _names(self.native_fd)
        _require(names <= {DB_NAME, LOCK_NAME}, "unknown native staging remains; preserve it for recovery")
        result = {}
        for name in names:
            details = os.stat(name, dir_fd=self.native_fd, follow_symlinks=False)
            _require(stat.S_ISREG(details.st_mode) and details.st_uid == os.getuid() and details.st_nlink == 1
                     and stat.S_IMODE(details.st_mode) == 0o600 and details.st_size <= 64 * 1024 * 1024,
                     "native resource ownership is unsafe")
            result[name] = _identity(details)
        return result

    def prepare(self, content: bytes, profile_uuid: str) -> None:
        self.assert_owner()
        _require(type(content) is bytes and 0 < len(content) <= PROFILE_LIMIT and type(profile_uuid) is str
                 and UUID_RE.fullmatch(profile_uuid) is not None, "authenticated profile identity is invalid")
        baseline = self.observe(journal=False)
        with self.lease.profile_directory() as fd:
            before = None if fd is None else _profile_snapshot(fd, profile_uuid + ".mobileprovision", cancellation=self.cancellation)
        self.intent = {"version": 2, "token": self.token, "uid": os.getuid(), "home": str(self.lease.home),
                       "homeIdentity": self.lease.home_identity,
                       "lease": self.lease.identity, "session": self.identity, "nativeDirectory": self.native_identity,
                       "baseline": baseline, "profile": {"uuid": profile_uuid, "sha256": hashlib.sha256(content).hexdigest(),
                       "before": before, "stage": ".mobile-release-profile-" + self.token}}
        self._write("intent.json", self.intent, immutable=True)
        self.state = self._initial_state()
        self.checkpoint()

    def _initial_state(self) -> dict:
        return {"version": 2, "token": self.token, "revision": 0, "commandSequence": 0,
                      "native": {}, "inflight": None,
                      "preferences": copy.deepcopy(self.intent["baseline"]),
                      "searchAttempted": False, "defaultAttempted": False, "conflict": False,
                      "cleanupStarted": False,
                      "profile": {"phase": "not-started", "stageIdentity": None, "ownedIdentity": None,
                                  "reused": False, "borrowed": None}}

    def profile_event(self, phase: str, *, identity: tuple[int, int] | None = None, owned: bool = False) -> None:
        self.assert_owner()
        _require(phase in PROFILE_PHASES and self.state is not None, "invalid profile transition")
        data = self.state["profile"]
        if phase == "resolved" and data["phase"] == "link-intent":
            # A successful link may have preceded cancellation/its completion
            # checkpoint. Retain that potential original link identity forever
            # through terminal cleanup, even when the installer already removed it.
            data["ownedIdentity"] = copy.deepcopy(data["stageIdentity"])
        data["phase"] = phase
        if phase == "stage-created":
            _require(identity is not None, "profile stage has no identity")
            data["stageIdentity"] = {"device": identity[0], "inode": identity[1]}
        if phase == "linked":
            data["ownedIdentity"] = copy.deepcopy(data["stageIdentity"]) if owned else None
        if phase == "reused":
            _require(identity is not None, "borrowed profile has no observed identity")
            data["reused"] = True
            data["borrowed"] = {"identity": {"device": identity[0], "inode": identity[1]},
                                "sha256": self.intent["profile"]["sha256"]}
        self.checkpoint()

    def run(self, argv: list[str], *, kind: str, timeout: int = 30, cwd: Path | None = None, capture: bool = True,
            environ: dict[str, str] | None = None):
        return self._run_command(self._new_scope(), argv, kind=kind, timeout=timeout,
                                 cwd=cwd, capture=capture, environ=environ)

    def _fence_observation_policy(self):
        from ._command_process import FenceObservationPolicy

        return FenceObservationPolicy.OFF

    def _fence_binding(self, operation: dict) -> dict:
        _require(self.intent is not None and self._committed_controls is not None,
                 "command fence lacks immutable intent")
        content = self._committed_controls.get("intent.json")
        _require(type(content) is bytes, "command fence lacks original intent bytes")
        return {"version": 2, "role": "command-custodian", "uid": os.getuid(),
                "homeIdentity": self.lease.home_identity, "leaseIdentity": self.lease.identity,
                "sessionIdentity": self.identity, "sessionToken": self.token,
                "intentSha256": hashlib.sha256(content).hexdigest(),
                "sequence": operation["sequence"], "nonce": operation["nonce"], "kind": operation["kind"]}

    def _arm_original_command(self, reservation) -> None:
        self.assert_owner()
        self._recovery_clear()
        _require(self._command_binding is not None and self.state is not None
                 and self.state["inflight"] is not None and not self.journal_failed and not self.unresolved,
                 "command arming has no original operation")
        self._command_binding.validate_reservation(reservation)
        operation = self.state["inflight"]
        _require(operation["phase"] == "PREPARED" and operation["nonce"] == self._command_scope.nonce.hex(),
                 "command arming generation differs")
        operation["phase"] = "ARMED"
        self.checkpoint()  # No CreatePermit is issued if this does not return durably.

    def _run_command(self, scope, argv: list[str], *, kind: str, timeout: int = 30,
                     cwd: Path | None = None, capture: bool = True, environ: dict[str, str] | None = None):
        from ._command_process import _issue_journal_binding

        self.assert_owner()
        self._recovery_clear()
        _require(kind in KINDS and self.state is not None and self.state["inflight"] is None and self.completed is None,
                 "native operation lacks an idle original checkpoint")
        _require(not self.journal_failed and not self.unresolved, "recovery is required before another native operation")
        _require(not (_names(self.fd) & FENCE_CONTROLS), "previous command fence remains")
        _require(self.inventory() == self.state["native"], "native resource was replaced outside an owned operation")
        _require(type(self.state["commandSequence"]) is int and self.state["commandSequence"] < 2**63 - 1,
                 "command sequence exhausted")
        self.state["commandSequence"] += 1
        operation = {"sequence": self.state["commandSequence"], "nonce": scope.nonce.hex(),
                     "kind": kind, "phase": "PREPARED", "settlement": None}
        self._command_scope, self._command_binding, self._command_finished = scope, None, False
        with self.cancellation.deferred():
            self.state["inflight"] = operation
            self.checkpoint()
            self._command_binding = _issue_journal_binding(
                scope, session=self, arm=self._arm_original_command,
                fence_binding=_fence_json(self._fence_binding(operation)),
                observation_policy=self._fence_observation_policy(),
            )
        try:
            with self.cancellation.deferred():
                result = self._call(argv, timeout=timeout, cwd=cwd, capture=capture, environ=environ,
                                    execution_scope=scope, journal_binding=self._command_binding)
                self.finish_original_command_if_settled(result=result)
                return result
        except BaseException:
            if not self._command_finished:
                # This can discharge only the retained original no-target
                # outcome. A public exception flag or absent callback cannot.
                try:
                    with self.cancellation.deferred(check_on_exit=False):
                        self.finish_original_command_if_settled()
                except BaseException as finishing_error:
                    self.unresolved = True
                    if fatal_lifetime_error(finishing_error, "command cleanup is unresolved") is not None:
                        self.cancellation.lifetime_ledger._abort(finishing_error)
            raise

    def _fence_file(self, name: str, *, links: int) -> tuple[bytes, os.stat_result] | None:
        self.assert_owner()
        _require(name in FENCE_CONTROLS, "invalid command fence name")
        item = _read_regular(self.fd, name, FENCE_LIMIT, private=False, cancellation=self.cancellation)
        if item is not None:
            content, details = item
            _require(details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) == 0o600
                     and details.st_nlink == links and 0 < len(content) <= FENCE_LIMIT,
                     "command fence metadata differs")
        return item

    def _read_fence_pair(self, operation: dict) -> dict:
        pending = self._fence_file("command-final.pending", links=2)
        final = self._fence_file("command-final.json", links=2)
        _require(pending is not None and final is not None and pending[0] == final[0]
                 and _same_file_state(pending[1], final[1]), "complete original custodian fence is missing")
        record = _parse(final[0])
        expected = self._fence_binding(operation)
        outcome = record.get("outcome")
        _require(outcome in ("never-dispatched", "producer-settled")
                 and record == {**expected, "outcome": outcome}
                 and final[0] == _fence_json(record), "command fence generation differs")
        if operation["phase"] == "PREPARED":
            _require(outcome == "never-dispatched", "PREPARED fence contradicts its no-grant gate")
        return {"basis": "custodian-fence", "outcome": outcome,
                "fence": {"identity": _identity(final[1]), "sha256": hashlib.sha256(final[0]).hexdigest()}}

    def _retire_fence(self, operation: dict) -> None:
        self.assert_owner()
        self._recovery_clear()
        _require(operation["phase"] == "SETTLED", "fence cannot retire before durable settlement")
        receipt = operation["settlement"]["fence"]
        names = _names(self.fd) & FENCE_CONTROLS
        if receipt is None:
            _require(not names, "no-fence settlement has unexpected fence content")
            return
        _require(names in (FENCE_CONTROLS, {"command-final.json"}, set()),
                 "command fence retirement has an invalid cut")
        expected = _fence_json({**self._fence_binding(operation), "outcome": operation["settlement"]["outcome"]})

        def verify(name: str, links: int) -> None:
            item = self._fence_file(name, links=links)
            _require(item is not None and _identity(item[1]) == receipt["identity"]
                     and item[0] == expected and hashlib.sha256(item[0]).hexdigest() == receipt["sha256"],
                     "settled fence identity changed")

        try:
            if names == FENCE_CONTROLS:
                verify("command-final.pending", 2)
                verify("command-final.json", 2)
                self.assert_owner()
                os.unlink("command-final.pending", dir_fd=self.fd)
                os.fsync(self.fd)
                names = {"command-final.json"}
            if names:
                verify("command-final.json", 1)
                _require(_stat(self.fd, "command-final.pending") is None, "fence stage reappeared")
                self.assert_owner()
                os.unlink("command-final.json", dir_fd=self.fd)
                os.fsync(self.fd)
            _require(not (_names(self.fd) & FENCE_CONTROLS), "fence retirement is incomplete")
        except BaseException:
            self.journal_failed = True
            if self._recovery_attempt is not None:
                self._recovery_attempt.revoke()
            raise

    def _settle_operation(self, settlement: dict) -> None:
        self._recovery_clear()
        operation = self.state["inflight"]
        _require(operation is not None, "no operation to settle")
        operation["phase"], operation["settlement"] = "SETTLED", settlement
        self.checkpoint()
        self._retire_fence(operation)
        self.state["inflight"] = None
        self.checkpoint()

    def finish_original_command_if_settled(self, *, result=None) -> bool:
        from ._command_process import NoTargetProof
        from .owned_process import ProcessOutcomeUnknown

        self.assert_owner()
        if self._command_finished:
            return True
        _require(self._command_scope is not None and self._command_binding is not None
                 and self.state is not None and self.state["inflight"] is not None
                 and not self.journal_failed and not self.unresolved,
                 "original command is not available for settlement")
        outcome = self._original_outcome(self._command_scope, self._command_binding)
        if outcome.execution_unknown:
            self.unresolved = True
            raise ProcessOutcomeUnknown("signing command execution is ambiguous; explicit recovery is required",
                                        dispatched=True, contained=True, cleanup_complete=True)
        no_target = outcome.no_target
        if no_target is not None:
            _require(type(no_target) is NoTargetProof and no_target._engine is outcome._engine,
                     "original no-target proof differs")
        else:
            _require(outcome.termination == "normal-exit"
                     and type(outcome.returncode) is int and 0 <= outcome.returncode <= 255
                     and (result is None or result.returncode == outcome.returncode),
                     "signing command has no admissible original result")
        operation = self.state["inflight"]
        names = _names(self.fd) & FENCE_CONTROLS
        if (not names and no_target is not None and no_target.kind == "NO_W_CREATION"
                and not outcome.create_w.attempted and not outcome.run_tool.attempted):
            settlement = {"basis": "original-no-dispatch", "outcome": "never-dispatched", "fence": None}
        else:
            settlement = self._read_fence_pair(operation)
            expected = ("never-dispatched" if no_target is not None
                        and no_target.kind in ("NO_W_CREATION", "CLOSED_BEFORE_RUN") else "producer-settled")
            _require(settlement["outcome"] == expected, "original outcome disagrees with custodian fence")
        after = self.inventory()
        kind = operation["kind"]
        if no_target is not None:
            _require(after == self.state["native"], "unstarted command changed native resources")
        elif kind in MUTABLE_KINDS:
            _require(DB_NAME in after or (kind == "create" and outcome.returncode != 0 and not after),
                     "native operation did not retain its owned keychain")
            self.state["native"] = after
        elif kind == "delete":
            _require((DB_NAME not in after or outcome.returncode != 0)
                     and all(self.state["native"].get(name) == value for name, value in after.items()),
                     "native deletion left an unknown resource")
            self.state["native"] = after
        else:
            _require(after == self.state["native"], "read-only/preference operation changed native resource identity")
        self._settle_operation(settlement)
        self._command_finished = True
        return True

    def remember_preferences(self, expected: dict) -> None:
        observed = self.observe()
        _require(observed == expected, "native preferences changed unexpectedly")
        self.state["preferences"] = observed
        self.checkpoint()

    def activate(self) -> None:
        original = self.intent["baseline"]
        after_create = self.observe()
        search = after_create["search"]
        _require(after_create["default"] == original["default"]
                 and [value for value in search if value != str(self.keychain)] == original["search"],
                 "native creation changed unrelated keychain preferences")
        self.state["preferences"] = after_create
        self.checkpoint()
        for field, kind, command in (("search", "search", "list-keychains"), ("default", "default", "default-keychain")):
            _require(self.observe() == self.state["preferences"], "preferences changed before activation")
            with self.cancellation.deferred():
                self.state[field + "Attempted"] = True
                self.checkpoint()
                result = self.run(["security", command, "-d", "user", "-s", str(self.keychain)], kind=kind)
                _require(result.returncode == 0, "native activation failed")
                expected = copy.deepcopy(self.state["preferences"])
                expected[field] = [str(self.keychain)] if field == "search" else str(self.keychain)
                self.remember_preferences(expected)
        self.remember_preferences({"default": str(self.keychain), "search": [str(self.keychain)]})

    def _detached(self, value: dict) -> bool:
        prefix = str(self.path) + "/"
        return not any(os.path.normpath(path) == str(self.path) or os.path.normpath(path).startswith(prefix)
                       for path in [value["default"], *value["search"]])

    def cleanup_native(self) -> None:
        self.assert_owner()
        self._recovery_clear()
        if self.state is None:
            return
        if self.unresolved or self.journal_failed or self.state["inflight"] is not None:
            raise _pending()
        current_inventory = self.inventory()
        _require(all(self.state["native"].get(name) == value for name, value in current_inventory.items()),
                 "native resource changed; manual recovery is required")
        if current_inventory != self.state["native"] and not self.state["cleanupStarted"]:
            self.state["conflict"] = True
        self.state["native"] = current_inventory
        self.state["cleanupStarted"] = True
        self.checkpoint()
        original, owned = self.intent["baseline"], str(self.keychain)
        current = self.observe()
        expected_active = self.state["preferences"]
        if current != expected_active:
            self.state["conflict"] = True
        for field, command in (("default", "default-keychain"), ("search", "list-keychains")):
            now = self.observe()
            _require(now == current, "preferences changed during cleanup; preserve them and retry recovery")
            target = copy.deepcopy(now)
            if field == "default" and now[field] == owned:
                target[field] = original[field]
            elif field == "search":
                target[field] = (original[field] if self.state["searchAttempted"] and now[field] == [owned]
                                 else [path for path in now[field] if path != owned])
            if target != now:
                args = target[field] if field == "search" else [target[field]]
                result = self.run(["security", command, "-d", "user", "-s", *args], kind=field)
                _require(result.returncode == 0, "native preference cleanup failed")
                actual = self.observe()
                _require(actual == target, "native preference cleanup readback differs")
                current = actual
            self.state["preferences"] = current
            self.checkpoint()
        _require(self._detached(current), "owned native references remain")
        if DB_NAME in self.state["native"]:
            result = self.run(["security", "delete-keychain", owned], kind="delete")
            _require(result.returncode == 0, "native keychain deletion failed")
            _require(self.observe() == current, "native deletion changed unrelated preferences")
        # Apple's deletion normally removes this source-derived lock too.
        if LOCK_NAME in self.state["native"]:
            _require(self.inventory() == self.state["native"], "native lock identity changed")
            os.unlink(LOCK_NAME, dir_fd=self.native_fd)
            os.fsync(self.native_fd)
            self.state["native"] = {}
            self.checkpoint()
        _require(not self.inventory() and self.observe() == current, "native cleanup could not be fully verified")

    def cleanup_profile(self, *, terminal: bool = False) -> None:
        self.assert_owner()
        self._recovery_clear()
        _require(not self.unresolved and self.state["inflight"] is None, "signing users may still need the profile")
        info, record = self.intent["profile"], self.state["profile"]
        with self.lease.profile_directory() as fd:
            if fd is None:
                if info["before"] is not None or record["borrowed"] is not None:
                    self.state["conflict"] = True
            else:
                name = info["uuid"] + ".mobileprovision"
                expected_borrowed = record["borrowed"] or info["before"]
                owned_identity = record["ownedIdentity"]
                if owned_identity is None and record["phase"] == "link-intent":
                    owned_identity = record["stageIdentity"]
                    record["ownedIdentity"] = copy.deepcopy(owned_identity)
                for path, identity in ((info["stage"], record["stageIdentity"]), (name, owned_identity)):
                    details = _stat(fd, path)
                    borrowed = expected_borrowed if path == name else None
                    if borrowed is not None and (details is None or _identity(details) != borrowed["identity"]):
                        self.state["conflict"] = True
                    if identity is None:
                        if details is not None:
                            _require(path != info["stage"],
                                     "unproven profile stage remains; manual recovery is required")
                            _require(record["reused"] or record["phase"] not in {"link-intent", "linked", "stage-removed"},
                                     "unproven installed profile remains; manual recovery is required")
                        # No later owned-loop stat may ignore a contradiction
                        # after this last borrowed check, including terminal use.
                        # Never open a known foreign/special file to prove it differs.
                        if borrowed is not None and details is not None and _identity(details) == borrowed["identity"]:
                            if not stat.S_ISREG(details.st_mode):
                                self.state["conflict"] = True
                                continue
                            try:
                                snapshot = _read_regular(fd, path, PROFILE_LIMIT, private=False, cancellation=self.cancellation)
                                self.state["conflict"] |= (
                                    snapshot is None or not _same_file_state(details, snapshot[1])
                                    or _identity(snapshot[1]) != borrowed["identity"]
                                    or hashlib.sha256(snapshot[0]).hexdigest() != borrowed["sha256"]
                                    or not _same_file_state(snapshot[1], _stat(fd, path))
                                )
                            except (CredentialError, OSError) as error:
                                fatal = fatal_lifetime_error(error, "local signing profile read cleanup is unconfirmed; end this process before retrying")
                                if fatal is not None:
                                    raise fatal from None
                                self.state["conflict"] = True
                        continue
                    if details is None:
                        continue
                    if _identity(details) != identity:
                        self.state["conflict"] = True
                        _require(path == name, "private profile stage was replaced; preserve it")
                        continue
                    _require(not terminal, "a previously cleaned profile resource reappeared")
                    snapshot = _read_regular(fd, path, PROFILE_LIMIT, private=False, cancellation=self.cancellation)
                    if snapshot is None:
                        self.state["conflict"] |= borrowed is not None
                        continue  # An original-owned absent file needs no deletion.
                    content, observed = snapshot
                    if _identity(observed) != identity:
                        self.state["conflict"] = True
                        _require(path == name, "private profile stage was replaced; preserve it")
                        continue
                    _require(_same_file_state(details, observed), "owned profile changed during inspection; preserve it for recovery")
                    digest = hashlib.sha256(content).hexdigest()
                    if borrowed is not None and digest != borrowed["sha256"]:
                        self.state["conflict"] = True
                    _require(digest == info["sha256"], "owned profile bytes changed; preserve them for recovery")
                    current = _stat(fd, path)  # The reader has CLOSED; bind its result to the current name.
                    if current is None:
                        self.state["conflict"] |= borrowed is not None
                        continue
                    if _identity(current) != identity:
                        self.state["conflict"] = True
                        _require(path == name, "private profile stage was replaced; preserve it")
                        continue
                    _require(_same_file_state(observed, current), "owned profile changed after inspection; preserve it for recovery")
                    os.unlink(path, dir_fd=fd)
                    os.fsync(fd)
        record["phase"] = "resolved"
        if not terminal:
            self.checkpoint()

    def finish(self) -> bool:
        self.assert_owner()
        self._recovery_clear()
        _require(self.intent is not None and self.state is not None and self.state["inflight"] is None
                 and not self.unresolved and not self.journal_failed, "active session cannot be finalized")
        if self.completed is None:
            last_observed = self.observe()
            _require(not self.inventory() and self._detached(last_observed), "owned native resources/references remain")
            if last_observed != self.state["preferences"]:
                self.state["conflict"] = True
            self.state["preferences"] = last_observed
            self.cleanup_profile()
            _require(not (_names(self.fd) & FENCE_CONTROLS), "terminal command fence remains")
            completed = {"version": 2, "intent": copy.deepcopy(self.intent), "state": copy.deepcopy(self.state)}
            self._write("completed.json", completed, immutable=True)
            self.completed = completed
        return self.finish_terminal()

    def finish_terminal(self) -> bool:
        self.assert_owner()
        self._recovery_clear()
        _require(self.completed is not None and self.state["inflight"] is None
                 and not self.unresolved and not self.journal_failed
                 and not (_names(self.fd) & FENCE_CONTROLS), "missing or unresolved terminal ownership")
        _require(not self.inventory() and self._detached(self.observe(journal=False)), "terminal session has new native resources/references")
        self.cleanup_profile(terminal=True)
        for name in ("state.pending", "state.json", "intent.pending", "completed.pending"):
            self._remove_control(name)
        if self.native_fd is not None:
            _require(not _names(self.native_fd), "native directory is not empty")
            os.rmdir("keychain", dir_fd=self.fd)
            closing, self.native_fd = self.native_fd, None
            _close(closing)
            os.fsync(self.fd)
        self._remove_control("intent.json")
        _require(_names(self.fd) == {"completed.json"} and self._detached(self.observe(journal=False)), "terminal namespace changed")
        self._remove_control("completed.json")
        conflict = self.state["conflict"]
        self._remove_empty_session()
        return conflict

    def _remove_empty_session(self) -> None:
        self.assert_owner()
        _require(not _names(self.fd), "session is not empty")
        os.rmdir(self.name, dir_fd=self.lease.fd)
        os.fsync(self.lease.fd)
        # Only this original removal/sync can permit normal lease reuse. A
        # snapshot reload or later path absence is not completion of this call.
        self._disposal_complete = True
        self.close()

    def close(self) -> None:
        if self.pid != os.getpid():
            self._close_inherited()
            return
        _require(self.lease.owner_thread is threading.current_thread(), "session close owner differs")
        self.lease._observe_session_execution(self, closing=True)
        observed = preserve_lifetime_error(ProcessError(
            "local signing session descriptor cleanup is unconfirmed; end this process before retrying",
        ), previous=exc_info()[1])
        failed = False
        first_failure: BaseException | None = None
        for attr in ("native_fd", "fd"):
            descriptor = getattr(self, attr)
            if descriptor is not None:
                setattr(self, attr, None)
                try:
                    _close(descriptor)
                except BaseException as error:
                    if self.lease._recovery_mode is False:
                        self.lease._normal_execution_revoked = True
                    if first_failure is None:
                        first_failure = error
                    preserve_lifetime_error(observed, previous=error)
                    failed = True
        self.lease._observe_session_execution(self, closing=True)
        self.closed = True
        if self.pid == os.getpid() and self.lease.active is self:
            self.lease.active = None
        # A fork can occur inside open(), before a returned FD reaches this
        # object. Keep the inherited holder's reference until its later unwind
        # so child-safe cleanup can close such late handoffs too. It is never
        # valid for a new child operation (PID/lease checks still reject it).
        if failed:
            self.cancellation.lifetime_ledger._abort(first_failure)
            if isinstance(first_failure, (KeyboardInterrupt, SystemExit)):
                raise first_failure
            raise preserve_lifetime_error(ProcessCleanupError(str(observed)), previous=observed) from None

    def _close_inherited(self) -> None:
        if self.pid == os.getpid():
            return
        self.closed = True
        for name in ("native_fd", "fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                try:
                    os.close(descriptor)
                except BaseException:
                    _mark_fork_unsafe()

    def _validate_intent(self, value: object) -> dict:
        fields = {"version", "token", "uid", "home", "homeIdentity", "lease", "session", "nativeDirectory", "baseline", "profile"}
        _require(type(value) is dict and set(value) == fields, "invalid committed intent fields")
        _require(type(value["version"]) is int and value["version"] == 2 and value["token"] == self.token
                 and type(value["uid"]) is int and value["uid"] == os.getuid() and value["home"] == str(self.lease.home)
                 and _identity_valid(value["homeIdentity"]) and value["homeIdentity"] == self.lease.home_identity
                 and _identity_valid(value["lease"]) and value["lease"] == self.lease.identity
                 and _identity_valid(value["session"]) and value["session"] == self.identity
                 and _identity_valid(value["nativeDirectory"])
                 and (self.native_fd is None or value["nativeDirectory"] == self.native_identity)
                 and _preferences_valid(value["baseline"]), "committed intent has incompatible account/session bindings")
        _require(self._detached(value["baseline"]), "original baseline already references this session")
        profile = value["profile"]
        _require(type(profile) is dict and set(profile) == {"uuid", "sha256", "before", "stage"}
                 and type(profile["uuid"]) is str and UUID_RE.fullmatch(profile["uuid"]) is not None
                 and type(profile["sha256"]) is str and HASH_RE.fullmatch(profile["sha256"]) is not None
                 and _snapshot_valid(profile["before"])
                 and profile["stage"] == ".mobile-release-profile-" + self.token, "invalid committed profile authority")
        return value

    def _validate_state(self, value: object, *, intent: dict | None = None) -> dict:
        fields = {"version", "token", "revision", "commandSequence", "native", "inflight", "preferences", "searchAttempted",
                  "defaultAttempted", "cleanupStarted", "conflict", "profile"}
        _require(type(value) is dict and set(value) == fields, "invalid committed state fields")
        _require(type(value["version"]) is int and value["version"] == 2 and value["token"] == self.token
                 and type(value["revision"]) is int and 0 <= value["revision"] < 2**63
                 and type(value["commandSequence"]) is int and 0 <= value["commandSequence"] < 2**63
                 and all(type(value[key]) is bool for key in ("searchAttempted", "defaultAttempted", "cleanupStarted", "conflict"))
                 and (not value["defaultAttempted"] or value["searchAttempted"])
                 and _preferences_valid(value["preferences"]), "invalid committed state bindings/preferences")
        native = value["native"]
        _require(type(native) is dict and set(native) <= {DB_NAME, LOCK_NAME}
                 and all(_identity_valid(identity) for identity in native.values()), "invalid native identity checkpoint")
        operation = value["inflight"]
        if operation is not None:
            _require(type(operation) is dict
                     and set(operation) == {"sequence", "nonce", "kind", "phase", "settlement"}
                     and type(operation["sequence"]) is int
                     and 0 < operation["sequence"] == value["commandSequence"] < 2**63
                     and type(operation["nonce"]) is str and TOKEN_RE.fullmatch(operation["nonce"]) is not None
                     and type(operation["kind"]) is str and operation["kind"] in KINDS
                     and operation["phase"] in ("PREPARED", "ARMED", "SETTLED"),
                     "invalid in-flight operation checkpoint")
            settlement = operation["settlement"]
            if operation["phase"] != "SETTLED":
                _require(settlement is None, "unsettled command contains a receipt")
            else:
                _require(type(settlement) is dict and set(settlement) == {"basis", "outcome", "fence"},
                         "invalid command settlement fields")
                if settlement["basis"] in ("original-no-dispatch", "durable-no-grant"):
                    _require(settlement["outcome"] == "never-dispatched" and settlement["fence"] is None,
                             "invalid no-fence settlement")
                else:
                    _require(settlement["basis"] == "custodian-fence"
                             and settlement["outcome"] in ("never-dispatched", "producer-settled")
                             and _snapshot_valid(settlement["fence"]) and settlement["fence"] is not None,
                             "invalid custodian settlement")
        profile = value["profile"]
        _require(type(profile) is dict and set(profile) == {"phase", "stageIdentity", "ownedIdentity", "reused", "borrowed"}
                 and type(profile["phase"]) is str and profile["phase"] in PROFILE_PHASES
                 and type(profile["reused"]) is bool
                 and _snapshot_valid(profile["borrowed"])
                 and profile["reused"] == (profile["borrowed"] is not None)
                 and all(profile[key] is None or _identity_valid(profile[key]) for key in ("stageIdentity", "ownedIdentity"))
                 and (profile["ownedIdentity"] is None or profile["ownedIdentity"] == profile["stageIdentity"]),
                 "invalid profile checkpoint")
        _require(profile["phase"] not in {"stage-created", "link-intent", "linked", "stage-removed"}
                 or profile["stageIdentity"] is not None, "profile transition has no original inode")
        _require(not profile["reused"] or profile["ownedIdentity"] is None, "reused profile cannot be owned")
        authority = self.intent if intent is None else intent
        _require(authority is not None, "state is missing its immutable intent")
        _require(profile["borrowed"] is None or profile["borrowed"]["sha256"] == authority["profile"]["sha256"],
                 "borrowed profile does not bind the authenticated bytes")
        return value

    def load_snapshot(self) -> SigningSnapshot:
        """Read-bound immutable classification; never reset invocation failures."""
        self.assert_owner()
        _require(_names(self.fd) <= CONTROLS | FENCE_CONTROLS | {"keychain"}, "unknown private session content; preserve it")
        controls = {name: _control(self.fd, name, cancellation=self.cancellation) for name in CONTROLS}
        completed = controls["completed.json"]
        intent_bytes, state_bytes = controls["intent.json"], controls["state.json"]
        intent = state = marker = None
        phase = "active"
        for content in (completed, intent_bytes, state_bytes):
            if content is not None and _parse(content).get("version") == 1:
                phase = "legacy-pending"
                break
        if phase == "legacy-pending":
            pass  # Read-only status; no native/manual migration authority.
        elif completed is not None:
            marker = _parse(completed)
            _require(set(marker) == {"version", "intent", "state"} and type(marker["version"]) is int
                     and marker["version"] == 2, "invalid terminal authority")
            intent = self._validate_intent(marker["intent"])
            state = self._validate_state(marker["state"], intent=intent)
            _require(not state["native"] and state["inflight"] is None
                     and state["profile"]["phase"] == "resolved"
                     and self._detached(state["preferences"])
                     and not (_names(self.fd) & FENCE_CONTROLS), "terminal marker contains unfinished ownership")
            _require(intent_bytes is None or self._validate_intent(_parse(intent_bytes)) == intent,
                     "terminal marker disagrees with original intent")
            _require(state_bytes is None or self._validate_state(_parse(state_bytes), intent=intent) == state,
                     "terminal marker disagrees with final checkpoint")
            phase = "completed"
        elif intent_bytes is None:
            _require(state_bytes is None and controls["state.pending"] is None
                     and controls["completed.pending"] is None and not (_names(self.fd) & FENCE_CONTROLS),
                     "session is missing its immutable authority; preserve it")
            phase = "preparing"
        else:
            intent = self._validate_intent(_parse(intent_bytes))
            _require(self.native_fd is not None, "active session lost its native directory authority")
            if state_bytes is None:
                _require(controls["completed.pending"] is None and not (_names(self.fd) & FENCE_CONTROLS),
                         "missing original active checkpoint; preserve it")
                phase = "initializing"
            else:
                state = self._validate_state(_parse(state_bytes), intent=intent)
                _require(state["inflight"] is not None or not (_names(self.fd) & FENCE_CONTROLS),
                         "idle state has command fence debt")
        snapshot = SigningSnapshot(self, phase, tuple(sorted(controls.items())),
                                   None if intent is None else _json(intent),
                                   None if state is None else _json(state),
                                   None if marker is None else _json(marker), _SNAPSHOT_KEY)
        self._loaded_snapshot = snapshot
        return snapshot

    def load(self) -> SigningSnapshot:
        """Compatibility spelling, without the old mutable phase-string authority."""
        return self.load_snapshot()

    def _adopt_snapshot(self, snapshot: SigningSnapshot) -> None:
        _require(type(snapshot) is SigningSnapshot and snapshot._key is _SNAPSHOT_KEY
                 and snapshot._session is self and snapshot is self._loaded_snapshot
                 and snapshot.phase != "legacy-pending" and not self.journal_failed and not self.unresolved,
                 "loaded recovery snapshot cannot authorize this invocation")
        self.assert_owner()
        for name, content in snapshot._controls:
            _require(_control(self.fd, name, cancellation=self.cancellation) == content, "loaded recovery controls changed")
        self.intent = None if snapshot._intent is None else _parse(snapshot._intent)
        self.state = None if snapshot._state is None else _parse(snapshot._state)
        self.completed = None if snapshot._completed is None else _parse(snapshot._completed)
        self._committed_controls = dict(snapshot._controls)

    def _recover_command_gate(self) -> dict | None:
        """Original exclusion + durable no-grant/C proof, never a PID probe."""
        _require(type(self._recovery_attempt) is _RecoveryAttempt,
                 "recovery gate needs a fresh original authorization")
        self._recovery_clear()
        if self.state is None or self.state["inflight"] is None:
            _require(not (_names(self.fd) & FENCE_CONTROLS), "unexpected command fence debt")
            return None
        operation = self.state["inflight"]
        if operation["phase"] == "SETTLED":
            self._validate_retirement_cut(operation)
            return operation["settlement"]
        names = _names(self.fd) & FENCE_CONTROLS
        if operation["phase"] == "PREPARED" and not names:
            return {"basis": "durable-no-grant", "outcome": "never-dispatched", "fence": None}
        if operation["phase"] == "PREPARED" and names == {"command-final.pending"}:
            self._dispose_prepared_prefix(operation)
            return {"basis": "durable-no-grant", "outcome": "never-dispatched", "fence": None}
        return self._read_fence_pair(operation)

    def _validate_retirement_cut(self, operation: dict) -> None:
        names = _names(self.fd) & FENCE_CONTROLS
        receipt = operation["settlement"]["fence"]
        if receipt is None:
            _require(not names, "unexpected no-fence retirement content")
            return
        _require(names in (FENCE_CONTROLS, {"command-final.json"}, set()),
                 "invalid durable fence retirement cut")
        expected = _fence_json({**self._fence_binding(operation), "outcome": operation["settlement"]["outcome"]})
        for name in names:
            item = self._fence_file(name, links=len(names))
            _require(item is not None and item[0] == expected and _identity(item[1]) == receipt["identity"]
                     and hashlib.sha256(item[0]).hexdigest() == receipt["sha256"],
                     "durable fence retirement receipt differs")

    def _dispose_prepared_prefix(self, operation: dict) -> None:
        _require(type(self._recovery_attempt) is _RecoveryAttempt,
                 "prefix disposal needs a fresh original authorization")
        self._recovery_clear()
        _require(operation["phase"] == "PREPARED" and _stat(self.fd, "command-final.json") is None,
                 "prefix disposal lacks durable no-grant state")
        expected = _fence_json({**self._fence_binding(operation), "outcome": "never-dispatched"})
        item = _read_regular(self.fd, "command-final.pending", FENCE_LIMIT, private=True, cancellation=self.cancellation)
        _require(item is not None and expected.startswith(item[0]), "unpublished fence prefix differs")
        again = _read_regular(self.fd, "command-final.pending", FENCE_LIMIT, private=True, cancellation=self.cancellation)
        _require(again is not None and item[0] == again[0] and _same_file_state(item[1], again[1])
                 and _same_file_state(again[1], _stat(self.fd, "command-final.pending"))
                 and _stat(self.fd, "command-final.json") is None,
                 "unpublished fence prefix changed")
        self._recovery_clear()
        try:
            self.assert_owner()
            os.unlink("command-final.pending", dir_fd=self.fd)
            os.fsync(self.fd)
        except BaseException:
            self.journal_failed = True
            self._recovery_attempt.revoke()
            raise

    def _clear_stages(self) -> None:
        # Only private reserved control slots; never native/profile content.
        for name in ("intent.pending", "state.pending", "completed.pending"):
            self._remove_control(name)

    def cleanup_preparation(self) -> None:
        self.assert_owner()
        self._recovery_clear()
        names = _names(self.fd)
        _require(names <= {"intent.pending", "keychain"} and not self.inventory(),
                 "preparation has unexpected resources; preserve it")
        _require(self._detached(self.observe(journal=False)), "preparation still has native references")
        self._remove_control("intent.pending")
        if self.native_fd is not None:
            os.rmdir("keychain", dir_fd=self.fd)
            closing, self.native_fd = self.native_fd, None
            _close(closing)
            os.fsync(self.fd)
        self._remove_empty_session()

    def cleanup_unstarted_initialization(self) -> bool:
        """Only this invocation's exclusive create may clean unstarted setup."""
        self.assert_owner()
        _require(self._create_origin is not None and self.lease._recovery_mode is False
                 and self._recovery_attempt is None and self._command_scope is None
                 and not self.unresolved and not self.journal_failed
                 and not self.cancellation.lifetime_ledger.fatal,
                 "initialization cleanup lacks its original unstarted owner")
        snapshot = self.load_snapshot()
        _require(snapshot.phase in ("preparing", "initializing"), "initialization already entered active work")
        self._adopt_snapshot(snapshot)
        if snapshot.phase == "preparing":
            self.cleanup_preparation()
            return False
        _require(not self.inventory() and self._detached(self.observe(journal=False)),
                 "initialization has native resources or references")
        with self.lease.profile_directory() as fd:
            _require(fd is None or _stat(fd, self.intent["profile"]["stage"]) is None,
                     "initialization has a profile stage")
        self._clear_stages()
        self.state = self._initial_state()
        self.checkpoint()
        self.cleanup_profile()
        return self.finish()

    def recover(self, snapshot: SigningSnapshot, *, authorization: _RecoveryAttempt) -> bool:
        """Fresh admitted recovery, with exact existing account/service-idle consent."""
        self.assert_owner()
        _require(type(authorization) is _RecoveryAttempt and authorization is self._recovery_attempt,
                 "recovery requires its original fresh authorization")
        authorization.check(self, clear_query=True)
        self._adopt_snapshot(snapshot)
        phase = snapshot.phase
        self.cleaning = True
        if phase == "preparing":
            self.cleanup_preparation()
            return False
        if phase == "completed":
            return self.finish_terminal()
        if phase == "initializing":
            _require(not self.inventory() and self._detached(self.observe(journal=False)),
                     "initial checkpoint is absent but native resources remain; manual recovery is required")
            with self.lease.profile_directory() as fd:
                _require(fd is None or _stat(fd, self.intent["profile"]["stage"]) is None,
                         "initial checkpoint is absent but a profile stage remains; manual recovery is required")
            self._clear_stages()
            self.state = self._initial_state()
            self.checkpoint()
        else:
            _require(phase == "active", "unsupported recovery classification")
            settlement = self._recover_command_gate()  # Before native inventory/query.
            inventory = self.inventory()
            _require(all(self.state["native"].get(name) == value for name, value in inventory.items()),
                     "native transaction identity is unknown; locked manual recovery is required")
            # Missing original-owned resources require no adoption/deletion. New
            # or changed files never gain authority through this reconciliation.
            if inventory != self.state["native"] and not self.state["cleanupStarted"]:
                self.state["conflict"] = True
            if DB_NAME not in inventory:
                _require(self._detached(self.observe(journal=False)),
                         "missing native database still has preferences; locked manual recovery is required")
            authorization.check(self, clear_query=True)
            _require(self._recover_command_gate() == settlement, "recovery fence generation changed")
            self._clear_stages()
            self.state["native"] = inventory
            if self.state["inflight"] is not None:
                self._settle_operation(settlement)
            else:
                self.checkpoint()
        self.cleanup_native()
        self.cleanup_profile()
        return self.finish()


def _session_name(lease: SigningLease, expected: str | None = None) -> str | None:
    lease.assert_owner()
    names = _names(lease.fd)
    _require(len(names) <= 1 and all(SESSION_RE.fullmatch(name) is not None for name in names),
             "unknown account-signing directory content; preserve it")
    if not names:
        return None
    name = next(iter(names))
    _require(expected is None or name == "session-" + expected, "session token does not match pending recovery")
    return name[8:]


def signing_status(*, home: Path | None = None) -> dict:
    """Sanitized local-only status: no profile, original paths, or native queries."""
    try:
        with local_signing_lease(home=home, recovery=True) as lease:
            token = _session_name(lease)
            if token is None:
                return {"status": "idle", "sessions": 0}
            session = lease.session(token=token)
            session.open(create=False)
            snapshot = session.load_snapshot()
            return {"status": "pending", "sessions": 1, "session": token, "phase": snapshot.phase,
                    "recovery": ("unsupported-legacy-controls" if snapshot.phase == "legacy-pending" else
                                 "owner-confirmed-quiescence-required")}
    except SigningBusy:
        return {"status": "busy", "recovery": "wait-for-account-owner"}


def recover_signing(
    token: str, confirmation: str, *, manual: bool = False, home: Path | None = None,
    runner: Callable | None = None, input_stream=None, output_stream=None,
) -> dict:
    """No arbitrary path, command, force-reset, credential, Store or PID takeover."""
    _require(type(token) is str and TOKEN_RE.fullmatch(token) is not None, "expected a 32-character lowercase hexadecimal session token")
    _require(confirmation == CONFIRMATION, "recovery requires the exact account-idle confirmation")
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    _require(not manual or (input_stream.isatty() and output_stream.isatty()), "manual recovery requires an interactive TTY")
    with local_signing_lease(home=home, recovery=True) as lease:
        if _session_name(lease, token) is None:
            return {"status": "absent", "session": token}
        session = lease.session(token=token)
        session.open(create=False)
        session.bind_runner(runner)
        snapshot = session.load_snapshot()  # Corrupt/legacy authority cannot enter manual recovery.
        _require(snapshot.phase != "legacy-pending", "legacy controls are read-only; preserve them")
        authorization = _RecoveryAttempt(session, _key=_RECOVERY_KEY)
        session._recovery_attempt = authorization
        try:
            conflict = session.recover(snapshot, authorization=authorization)
        except CredentialError as error:
            fatal = fatal_lifetime_error(error, "local signing recovery cleanup is unconfirmed; end this process before retrying")
            if fatal is not None:
                raise fatal from None
            if not manual or session.closed:
                raise
            session.assert_owner()
            authorization.check(session, clear_query=True)
            session._recover_command_gate()
            print("Recovery remains locked. Inspect only this session's resources locally; preserve unfamiliar files.", file=output_stream)
            print(f"Session directory: {session.path}", file=output_stream)
            if session.intent is not None:
                profile_directory = lease.home / "Library/MobileDevice/Provisioning Profiles"
                print(f"Reserved stage: {profile_directory / session.intent['profile']['stage']}", file=output_stream)
                print(f"Profile destination: {profile_directory / (session.intent['profile']['uuid'] + '.mobileprovision')}", file=output_stream)
            print("Do not edit/delete recovery controls or stop shared services. Move only independently identified abandoned resources; detach this session in Keychain Access.", file=output_stream)
            print(f"After owner work is idle, enter: recheck {token}", file=output_stream, flush=True)
            _require(input_stream.readline(128) == f"recheck {token}\n", "manual recheck cancelled or incorrect; state is preserved")
            authorization.check(session, clear_query=True)
            snapshot = session.load_snapshot()
            conflict = session.recover(snapshot, authorization=authorization)
        return {"status": "recovered-with-conflict" if conflict else "recovered", "session": token}
