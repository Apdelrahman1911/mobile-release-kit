"""Finite local build-input custody; not a command runner or signing lease.

Private preparation draft; caller integration/native verification is pending.
Only the original successful fixed online writer can bind a readback output.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
import threading
import unicodedata
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import BuiltinFunctionType
from typing import TYPE_CHECKING, Any, Iterator, Literal, Mapping

from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner, _FORK_RESOURCES
from .checked_files import (
    _MAX_COMPONENTS, _MAX_PATH_BYTES, _alias_parts, _file_identity as _external_file_identity,
    _protect_directory,
)
from ._profile_callers import fatal_cancellation_error
from .errors import CredentialError, ValidationError
from .init_transaction import STATE_NAMES as INIT_STATES, _rename_function
from .owned_process import ProcessCleanupError, ProcessError, preserve_lifetime_error

if TYPE_CHECKING:
    from .local_signing import SigningLease

_SMALL = 4 * 1024**2
_LARGE = 32 * 1024**2
_CONTROL = 256 * 1024
_MAX_CHECKPOINTS = 128
_PRIVATE = ".mobile-release"
_PENDING = "build-inputs"
_TERMINAL = "build-inputs-complete.json"
_TERMINAL_STAGE = "build-inputs-complete.stage"
_CONFIRM = "project-build-inputs-are-idle-and-restore-owned-state"
_BUNDLETOOL_BYTES = 32_520_401
_BUNDLETOOL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ENV_LOCK = threading.Lock()
_ENV_OWNER: InvocationCustody | None = None
_ENV_TAINTED = False
_ENV_PID = os.getpid()
# Identity anchors for recognizing only the direct builtin's bounded refusal.
# Operations still fetch os.open/mkdir at dispatch; wrappers are not bypassed.
_OS_OPEN, _OS_MKDIR, _OS_LINK = os.open, os.mkdir, os.link
_OPEN_REFUSALS = {errno.ENOENT, errno.EEXIST, errno.ENOTDIR, errno.ELOOP,
                  errno.EACCES, errno.EPERM, errno.EMFILE, errno.ENFILE,
                  errno.EROFS, errno.ENAMETOOLONG}
_MKDIR_REFUSALS = {errno.ENOENT, errno.EEXIST, errno.ENOTDIR, errno.ELOOP,
                   errno.EACCES, errno.EPERM, errno.EROFS, errno.ENAMETOOLONG}
_LINK_REFUSALS = {errno.ENOENT, errno.EEXIST, errno.ENOTDIR, errno.ELOOP,
                  errno.EACCES, errno.EPERM, errno.EROFS, errno.EXDEV,
                  errno.ENAMETOOLONG}


class BuildInputError(CredentialError, ValidationError):
    """Bounded local admission/conflict diagnostic, without private values."""


class _PrivatePublicationError(ProcessError):
    """Generated recovery locations, never arbitrary private exception text."""

    def __init__(self, temporary: str, retired: str) -> None:
        if (re.fullmatch(r"\.mrk-[0-9a-f]{32}", temporary) is None
                or re.fullmatch(r"\.mrk-retired-[0-9a-f]{32}", retired) is None):
            raise ValueError("invalid private publication diagnostic")
        super().__init__(
            "private report publication did not settle; preserve the report directory and inspect "
            f"retained slots {retired} and {temporary} before retrying"
        )


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise BuildInputError("build inputs: " + message)


def _supported() -> None:
    _need(sys.platform == "darwin" or sys.platform.startswith("linux"),
          "local Linux/macOS filesystem semantics are required")


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        _need(key not in result, "duplicate control field")
        result[key] = value
    return result


def _parse(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as error:
        raise BuildInputError("build inputs: invalid private control") from error
    _need(type(value) is dict and _json(value) == data, "noncanonical private control")
    return value


def _directory(value: os.stat_result) -> dict[str, int]:
    _need(stat.S_ISDIR(value.st_mode), "directory identity is not ordinary")
    return dict(device=value.st_dev, inode=value.st_ino, uid=value.st_uid,
                gid=value.st_gid, mode=stat.S_IMODE(value.st_mode))


def _file(value: os.stat_result) -> dict[str, int]:
    _need(stat.S_ISREG(value.st_mode), "file identity is not ordinary")
    return dict(device=value.st_dev, inode=value.st_ino, uid=value.st_uid,
                gid=value.st_gid, mode=stat.S_IMODE(value.st_mode), links=value.st_nlink,
                size=value.st_size, mtime=value.st_mtime_ns, ctime=value.st_ctime_ns)


def _stat(fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _names(fd: int, limit: int = 4096) -> set[str]:
    values = os.listdir(fd)
    _need(len(values) <= limit, "directory inventory exceeds its bound")
    keys = [_name_key(value) for value in values]
    _need(len(set(keys)) == len(keys), "ambiguous directory aliases")
    return set(values)


def _name_absent(fd: int, name: str, *, limit: int = 4096) -> None:
    key = _name_key(name)
    _need(all(_name_key(value) != key for value in _names(fd, limit)),
          "reserved name is occupied or aliased")


def _name_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _exact_reserved_names(fd: int, reserved: set[str]) -> set[str]:
    """Never adopt a different physical spelling of a fixed protocol name."""
    names = _names(fd)
    canonical = {_name_key(name): name for name in reserved}
    _need(all(_name_key(name) not in canonical or canonical[_name_key(name)] == name for name in names),
          "reserved namespace has a foreign alias")
    return names


def _private_is_ignored(content: bytes) -> bool:
    # Git's leading spaces are meaningful. Do not strip them or split a single
    # pattern at arbitrary Unicode line separators. Positive later patterns do
    # not undo an exclusion; a later negation invalidates this sufficient proof.
    try:
        lines = content.decode("utf-8").split("\n")
    except UnicodeError:
        return False
    excluded = False
    for raw in lines:
        line = raw[:-1] if raw.endswith("\r") else raw
        if line in (".mobile-release/", "/.mobile-release/"):
            excluded = True
        elif line.startswith("!"):
            excluded = False
    return excluded


def _same_object(current: Mapping[str, Any], expected: Mapping[str, Any],
                 *, renamed: bool = False) -> bool:
    ignored = {"ctime"} if renamed else set()
    return (set(current) == set(expected)
            and all(current[key] == value for key, value in expected.items() if key not in ignored))


def _consumer_idle(guard: DefaultCancellation, *, lane_binding=None, owner=None) -> bool:
    try:
        # An unrelated cleanup fatality is not a claim that a consumer lives.
        # Active/unpublished original records project unknown containment here.
        if not guard.lifetime_ledger.verdict().contained:
            return False
        if lane_binding is None:
            return True
        from ._store_lane_evidence import StoreLaneCallEvidence, StoreLaneResourceBinding

        return (type(lane_binding) is StoreLaneResourceBinding
                and type(lane_binding._record) is StoreLaneCallEvidence
                and lane_binding._record.dependents_settled_for(
                    lane_binding, owner=owner, cancellation=guard))
    except BaseException:
        return False


def _cleanup_failure(guard: DefaultCancellation, cause: BaseException) -> ProcessCleanupError:
    try:
        facts = guard.lifetime_ledger.verdict()
        dispatched = facts.profile_dispatched is not False or facts.command_dispatched is not False
        contained = facts.contained
    except BaseException:
        dispatched, contained = True, False
    error = preserve_lifetime_error(ProcessCleanupError(
        "build-input resource cleanup is unconfirmed", dispatched=dispatched, contained=contained),
        previous=cause, dispatched=dispatched, contained=contained)
    guard._abort(error)
    return error


def _direct_refusal(error: BaseException, attempted: Any, builtin: Any,
                    caller_code: Any, allowed: set[int]) -> bool:
    """Only the exact builtin's immediate documented no-effect error receipt.

    A wrapper, custom signal callback, allocation failure or additional traceback
    frame is not that receipt, even if it supplies a familiar errno.
    """
    trace = error.__traceback__
    return (attempted is builtin and type(attempted) is BuiltinFunctionType
            and isinstance(error, OSError) and type(error.errno) is int and error.errno in allowed
            and trace is not None and trace.tb_frame.f_code is caller_code and trace.tb_next is None)


def _mkdir_private(name: str, parent: int, guard: DefaultCancellation, record: dict[str, str]) -> None:
    _need(record["state"] == "NEW", "directory creation cannot be repeated")
    operation = os.mkdir
    with guard.deferred(check_on_exit=False):
        try:
            record["state"] = "ATTEMPTED"
            operation(name, 0o700, dir_fd=parent)
            record["state"] = "CREATED"
        except BaseException as error:
            record["state"] = ("NO_EFFECT" if _direct_refusal(
                error, operation, _OS_MKDIR, _mkdir_private.__code__, _MKDIR_REFUSALS) else "UNKNOWN")
            if guard.pid == os.getpid():
                guard.lifetime_ledger._remember(error)
                if record["state"] == "UNKNOWN":
                    _cleanup_failure(guard, error)
            raise


def _check_creation(record: dict[str, str], identity: dict[str, int] | None) -> None:
    _need(record["state"] not in ("ATTEMPTED", "UNKNOWN")
          and (record["state"] != "CREATED" or identity is not None),
          "private directory acquisition is unconfirmed; preserve its namespace")


class _FD:
    """One prearmed numeric slot; retire before its only close attempt."""
    def __init__(self, guard: DefaultCancellation) -> None:
        self.guard, self.pid, self.number = guard, os.getpid(), None
        self.thread = threading.current_thread()
        self.open_state, self.close_state = "NEW", "NOT_ATTEMPTED"
        _FORK_RESOURCES.add(self)

    def open(self, name: str | Path, flags: int, mode: int = 0o600,
             *, dir_fd: int | None = None) -> int:
        _need(self.number is None and self.open_state == "NEW" and self.close_state == "NOT_ATTEMPTED"
              and self.pid == os.getpid(), "invalid descriptor acquisition")
        operation = os.open
        with self.guard.deferred(check_on_exit=False):
            try:
                self.open_state = "ATTEMPTED"
                self.number = operation(name, flags | os.O_CLOEXEC, mode, dir_fd=dir_fd)
                _need(type(self.number) is int and self.number >= 0, "descriptor result was not established")
                if self.pid != os.getpid() and self.close_state == "CLOSED":
                    self.close_state = "NOT_ATTEMPTED"  # A newly returned late child-copy slot only.
                self.open_state = "OPEN"
            except BaseException as error:
                if type(self.number) is int and self.number >= 0:
                    self.open_state = "OPEN"  # Its positive result still grants one close.
                else:
                    self.number = None
                    self.open_state = ("NO_EFFECT" if _direct_refusal(
                        error, operation, _OS_OPEN, _FD.open.__code__, _OPEN_REFUSALS) else "UNKNOWN")
                if self.pid == os.getpid():
                    self.guard.lifetime_ledger._remember(error)
                    if self.open_state == "UNKNOWN":
                        _cleanup_failure(self.guard, error)
                raise
            if self.pid != os.getpid():
                self.close()  # A positively returned late child-copy handoff only.
                raise BuildInputError("build inputs: inherited descriptor acquisition")
        return self.number

    def close(self) -> None:
        parent = self.pid == os.getpid()
        if parent:
            _need(self.thread is threading.current_thread(), "descriptor belongs to another thread")
        if self.close_state == "CLOSED":
            return
        if self.close_state != "NOT_ATTEMPTED" or (
                self.number is None and self.open_state in ("ATTEMPTED", "UNKNOWN", "OPEN")):
            error = BuildInputError("build inputs: original descriptor settlement is unknown")
            if parent:
                raise _cleanup_failure(self.guard, error)
            raise error
        if self.number is None:
            self.close_state = "CLOSED"  # NEW or a positive direct no-effect receipt only.
            return
        try:
            # Default cancellation cannot cut between numeric retirement and the
            # single close/error-publication attempt. Custom callback ambiguity
            # remains UNKNOWN; the retired integer is never retried.
            with (self.guard.deferred(check_on_exit=False) if parent else nullcontext()):
                self.close_state = "ATTEMPTED"
                number, self.number = self.number, None
                os.close(number)
                self.close_state = "CLOSED"
        except BaseException as error:
            self.close_state = "UNKNOWN"
            if parent:
                self.guard.lifetime_ledger._remember(error)
                fatal = _cleanup_failure(self.guard, error)
                current, seen, interruption = error, set(), None
                while current is not None and id(current) not in seen:
                    seen.add(id(current))
                    if isinstance(current, (KeyboardInterrupt, SystemExit)):
                        interruption = current
                    current = current.__context__
                if interruption is not None:
                    raise interruption
                raise fatal from None
            raise

    def after_fork_child(self) -> None:
        if self.pid != os.getpid():
            self.close()


@contextmanager
def _fd_cleanup(slot: _FD) -> Iterator[None]:
    """Prearm a local descriptor's existing fixed cleanup scope before opening."""
    guard = slot.guard
    scope = CleanupScope(guard, slot.close, owns_cancellation=False,
                         fork_cleanup=slot.after_fork_child, first_primary=True)
    try:
        try:
            with scope:
                yield
        finally:
            scope.__exit__(*sys.exc_info())
        _need(guard.pid == os.getpid(), "inherited descriptor scope cannot publish parent completion")
        if not guard.depth:
            guard.check()  # During enclosing cleanup, safe independent reads remain allowed.
    except BaseException as error:
        if guard.pid == os.getpid():
            fatal = fatal_cancellation_error(error, guard, "build-input descriptor lifetime did not settle")
            if fatal is not None:
                raise fatal from None
        raise


def _attempt_all(guard: DefaultCancellation, actions: list[Any]) -> None:
    first: BaseException | None = None
    with guard.deferred(check_on_exit=False):
        for action in actions:
            try:
                action()
            except BaseException as error:
                guard._abort(error)
                if first is None or (not isinstance(first, (KeyboardInterrupt, SystemExit))
                                     and isinstance(error, (KeyboardInterrupt, SystemExit))):
                    first = error
    if first is not None:
        if isinstance(first, (KeyboardInterrupt, SystemExit)):
            raise first
        raise _cleanup_failure(guard, first) from None


class _Directory:
    """Pinned no-follow absolute ancestry; no directory deletion authority."""
    def __init__(self, path: Path, guard: DefaultCancellation,
                 *, system_root_aliases: bool = False) -> None:
        self.path, self.lexical_path, self.guard = path, path, guard
        self.system_root_aliases = system_root_aliases
        self.slots: list[_FD] = []
        self.bindings: list[tuple[int | None, str, dict[str, int]]] = []
        self.physical_bindings: list[tuple[_FD, int, str, dict[str, int]]] = []
        self.alias: tuple[str, tuple[int, ...], str] | None = None

    @property
    def fd(self) -> int:
        _need(bool(self.slots) and self.slots[-1].number is not None, "directory is not open")
        return self.slots[-1].number  # type: ignore[return-value]

    def _open(self, name: str, parent: int | None) -> tuple[_FD, os.stat_result]:
        slot = _FD(self.guard)
        self.slots.append(slot)
        number = slot.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        observed = os.fstat(number)
        binding = _directory(observed)
        _need(_directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == binding,
              "directory changed during acquisition")
        self.bindings.append((parent, name, binding))
        return slot, observed

    def _physical_role(self, parent: int, role: Path | None, observed: os.stat_result) -> Path | None:
        if sys.platform != "darwin":
            return None
        names = (("private",) if role == Path("/") else
                 ("var", "tmp") if role == Path("/private") else ())
        for name in names:
            physical = os.stat(name, dir_fd=parent, follow_symlinks=False)
            binding = _directory(physical)
            if (physical.st_dev, physical.st_ino) == (observed.st_dev, observed.st_ino):
                _need(binding == _directory(observed), "system directory changed during acquisition")
                assert role is not None
                return role / name
        return None

    def _protect(self, role: Path | None, observed: os.stat_result) -> None:
        try:
            _protect_directory(role, observed)
        except ValidationError:
            raise BuildInputError("build inputs: default scratch system ancestry is not protected") from None

    def acquire(self) -> None:
        _supported()
        _need(self.lexical_path.is_absolute() and ".." not in self.lexical_path.parts and not self.slots,
              "directory requires an absolute lexical path")
        root, observed = self._open("/", None)
        assert root.number is not None
        parts = self.lexical_path.parts[1:]
        physical: Path | None = Path("/")
        if self.system_root_aliases:
            self._protect(physical, observed)
            if parts:
                first = os.stat(parts[0], dir_fd=root.number, follow_symlinks=False)
                if stat.S_ISLNK(first.st_mode):
                    target = os.readlink(parts[0], dir_fd=root.number)
                    try:
                        replacement = _alias_parts(parts[0], first, target)
                    except ValidationError:
                        raise BuildInputError("build inputs: unsupported default scratch system alias") from None
                    self.alias = parts[0], _external_file_identity(first), target
                    parts = (*replacement, *parts[1:])
        parent, canonical = root.number, Path("/")
        for name in parts:
            slot, observed = self._open(name, parent)
            if self.system_root_aliases:
                physical = self._physical_role(parent, physical, observed)
                self._protect(physical, observed)
                if physical is not None and name != physical.name:
                    # Case-insensitive spellings do not select their own policy:
                    # keep the exact entry which identified the physical role.
                    self.physical_bindings.append((slot, parent, physical.name, _directory(observed)))
            canonical = (physical if self.system_root_aliases and physical is not None else canonical / name)
            assert slot.number is not None
            parent = slot.number
        self.check()
        # Only live checked custody may publish the expanded diagnostic path.
        if self.system_root_aliases:
            self.path = canonical

    def check(self) -> None:
        _need(len(self.bindings) == len(self.slots), "directory acquisition is incomplete")
        for slot, (parent, name, binding) in zip(self.slots, self.bindings):
            _need(slot.number is not None and _directory(os.fstat(slot.number)) == binding
                  and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == binding,
                  "directory ancestry changed")
        for slot, parent, name, binding in self.physical_bindings:
            _need(slot.number is not None and _directory(os.fstat(slot.number)) == binding
                  and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == binding,
                  "physical system directory ancestry changed")
        if self.alias is not None:
            root = self.slots[0].number
            _need(root is not None, "original system alias root is not open")
            name, identity, target = self.alias
            _need(_external_file_identity(os.stat(name, dir_fd=root, follow_symlinks=False)) == identity
                  and os.readlink(name, dir_fd=root) == target,
                  "default scratch system alias changed")

    def close(self) -> None:
        _attempt_all(self.guard, [slot.close for slot in reversed(self.slots)])

    def fork_close(self) -> None:
        for slot in reversed(self.slots):
            slot.close()


def _read_file(fd: int, name: str, guard: DefaultCancellation, limit: int,
               *, private: bool = False, binding_only: bool = False) -> tuple[dict[str, Any], bytes] | None:
    """Observe coherently; binding-only callers receive no retained content buffer."""
    before_named = _stat(fd, name)
    if before_named is None:
        return None
    slot = _FD(guard)
    result = None
    with _fd_cleanup(slot):
        number = slot.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = _file(os.fstat(number))
        _need(before == _file(before_named) and before["size"] <= limit
              and not before["mode"] & 0o7000, "unsafe or changed bounded file")
        if private:
            _need(before["uid"] == os.geteuid() and before["mode"] == 0o600 and before["links"] == 1,
                  "private file permissions changed")
        blocks, size, digest = [], 0, hashlib.sha256()
        while True:
            block = os.read(number, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            _need(size <= limit, "file exceeded its read bound")
            digest.update(block)
            if not binding_only:
                blocks.append(block)
        _need(size == before["size"] and _file(os.fstat(number)) == before
              and _file(os.stat(name, dir_fd=fd, follow_symlinks=False)) == before,
              "file changed during observation")
        content = b"".join(blocks)
        result = ({**before, "sha256": digest.hexdigest()}, content)
    _need(_file(os.stat(name, dir_fd=fd, follow_symlinks=False)) == before,
          "file changed at descriptor retirement")
    return result


@dataclass(frozen=True)
class _ScratchSpec:
    name: str
    limit: int
    direction: Literal["input", "output", "exclusive-output"] = "input"


_MATERIALS = {
    "android-keystore": _ScratchSpec("android-keystore", _LARGE),
    "distribution-p12": _ScratchSpec("distribution.p12", _LARGE),
    "apple-profile": _ScratchSpec("profile.mobileprovision", _SMALL),
    "asc-p8": _ScratchSpec("AuthKey.p8", _SMALL),
    "android-services": _ScratchSpec("google-services.json", _SMALL),
    "ios-services": _ScratchSpec("GoogleService-Info.plist", _SMALL),
}
_EXTRACTIONS = {name: _ScratchSpec(name + ".pem", _SMALL) for name in (
    "signing-certificate", "signing-chain", "signing-private-key", "distribution-certificate",
    "private-key", "certificate-public", "key-public")}
_LAYOUTS = {
    "build": {**_MATERIALS, **_EXTRACTIONS},
    "signing-validation": {**_MATERIALS, **_EXTRACTIONS},
    "store-selection": {"asc-p8": _MATERIALS["asc-p8"],
                        "google-adc": _ScratchSpec("google-adc.json", _LARGE)},
    "bundletool": {"bundletool": _ScratchSpec("bundletool.jar", _BUNDLETOOL_BYTES)},
    # Public metadata plus bounded ZIP directory overhead; not a generic output role.
    "store-metadata": {"metadata": _ScratchSpec("store-metadata.zip", 512 * 1024**2)},
    "ios-snapshot": {},  # Fixed bounded tree implementation lives in ios_artifacts.
    "online-runner": {},
    "online-readback": {platform: _ScratchSpec(platform + ".json", _SMALL, "exclusive-output")
                        for platform in ("android", "ios")},
}


@dataclass(frozen=True, repr=False)
class InputSnapshot:
    size: int
    sha256: str
    _owner: object = field(repr=False)
    _role: str = field(repr=False)
    _token: object = field(repr=False)


def _default_scratch_parent() -> Path:
    # Freeze one selection; do not resolve links, consult tempfile's cache or
    # try another location if a configured parent cannot be admitted.
    selected = os.environ.get("TMPDIR") or ("/private/tmp" if sys.platform == "darwin" else "/tmp")
    message = "default scratch parent requires a bounded absolute lexical path"
    try:
        path = Path(selected)
        _need(path.anchor == "/" and ".." not in path.parts and "\x00" not in str(path)
              and len(path.parts) <= _MAX_COMPONENTS and len(os.fsencode(path)) <= _MAX_PATH_BYTES,
              message)
    except (TypeError, ValueError, UnicodeError):
        raise BuildInputError("build inputs: " + message) from None
    return path


class FiniteScratch:
    def __init__(self, layout: str, guard: DefaultCancellation, parent: Path | None,
                 *, _name: str | None = None, _journal: BuildInputs | None = None,
                 lane_evidence=None) -> None:
        _need(type(layout) is str and layout in _LAYOUTS, "unknown scratch layout")
        self.layout, self.cancellation = layout, guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.parent = _Directory(_default_scratch_parent() if parent is None else parent, guard,
                                 system_root_aliases=parent is None)
        self.name = _name or ("mobile-release-inputs-" + uuid.uuid4().hex)
        self.slot = _FD(guard)
        self.identity: dict[str, int] | None = None
        self.records: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, object] = {}
        self.snapshots: dict[str, InputSnapshot] = {}
        self.writer_slots: list[_FD] = []
        self.active = self.claimed = False
        self.created = False
        self.creation = {"state": "NEW"}
        self.journal = _journal
        self._lane_binding = None
        self._cleanup_complete = False
        if lane_evidence is not None:
            from ._store_lane_evidence import StoreLaneCallEvidence

            _need(type(lane_evidence) is StoreLaneCallEvidence and _journal is None
                  and layout in ("store-selection", "store-metadata", "ios-snapshot"),
                  "only an original Store input may bind the Store composite")
            lane_evidence._origin(guard)
            self._lane_binding = lane_evidence.bind_resource(
                {"store-metadata": "metadata", "store-selection": "store-selection",
                 "ios-snapshot": "ios-snapshot"}[layout], self,
                cancellation=guard,
            )

    @property
    def _path(self) -> Path:
        return self.parent.path / self.name

    def _owner(self, *, cleanup: bool = False) -> None:
        _need(self.pid == os.getpid() and self.thread is threading.current_thread(),
              "scratch belongs to another process/thread")
        if not cleanup:
            _need(self.active and not self.claimed, "scratch is not active")
            self.cancellation.check()

    def _check(self) -> None:
        self.parent.check()
        _need(self.slot.number is not None and self.identity is not None
              and _directory(os.fstat(self.slot.number)) == self.identity
              and _directory(os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)) == self.identity,
              "scratch directory changed")

    def acquire(self) -> None:
        self.parent.acquire()
        _name_absent(self.parent.fd, self.name)
        with self.cancellation.deferred(check_on_exit=False):
            _mkdir_private(self.name, self.parent.fd, self.cancellation, self.creation)
            self.created = True
            number = self.slot.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=self.parent.fd)
            self.identity = _directory(os.fstat(number))
        _need(self.identity["uid"] == os.geteuid() and self.identity["mode"] == 0o700,
              "scratch is not private")
        self._check()
        self.active = True

    def _spec(self, role: str) -> _ScratchSpec:
        _need(type(role) is str and role in _LAYOUTS[self.layout], "unknown scratch role")
        return _LAYOUTS[self.layout][role]

    def _publish(self, role: str, blocks: Iterator[bytes], *, expected: str | None = None) -> InputSnapshot:
        self._owner()
        if self._lane_binding is not None:
            record = self._lane_binding._record
            record._origin(self.cancellation)
            record._resource(self._lane_binding, self)
            _need(not record._sealed and not record._attempted and not record._finished and not record._failed,
                  "Store input publication is closed before dispatch")
        self._check()
        spec = self._spec(role)
        _need(spec.direction == "input" and role not in self.records, "input role is not available")
        fd = self.slot.number
        assert fd is not None
        _name_absent(fd, spec.name)
        writer = _FD(self.cancellation)
        self.writer_slots.append(writer)
        # Reserve before creation.  An unobserved created inode stays unknown.
        self.records[role] = {"binding": None}
        digest, size = hashlib.sha256(), 0
        with _fd_cleanup(writer):
            number = writer.open(spec.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 dir_fd=fd)
            initial = _file(os.fstat(number))
            self.records[role]["created"] = initial
            _need(initial["mode"] == 0o600 and initial["uid"] == os.geteuid() and initial["links"] == 1,
                  "input is not private")
            for block in blocks:
                _need(type(block) is bytes, "input chunk is not bytes")
                size += len(block)
                _need(size <= spec.limit, "input exceeds its fixed role bound")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(number, view)
                    _need(written > 0, "input write made no progress")
                    view = view[written:]
            _need(size > 0 and (expected is None or digest.hexdigest() == expected),
                  "input is empty or has the wrong digest")
            os.fsync(number)
            final = _file(os.fstat(number))
            _need(all(final[key] == initial[key] for key in ("device", "inode", "uid", "gid", "mode", "links"))
                  and final["size"] == size,
                  "input identity changed while writing")
            self.records[role]["binding"] = {**final, "sha256": digest.hexdigest()}
        observed = _read_file(fd, spec.name, self.cancellation, spec.limit, private=True, binding_only=True)
        _need(observed is not None and observed[0] == self.records[role]["binding"],
              "input changed at publication")
        self._check()
        os.fsync(fd)
        if self.journal is not None:
            self.journal._checkpoint()
        token = object()
        self.tokens[role] = token
        snapshot = InputSnapshot(size, digest.hexdigest(), self, role, token)
        self.snapshots[role] = snapshot
        self.cancellation.check()
        return snapshot

    def put(self, role: str, content: bytes) -> InputSnapshot:
        _need(type(content) is bytes, "selected input must be immutable bytes")
        return self._publish(role, iter((content,)))

    def metadata_archive(self, root: Path, *, platform: str) -> InputSnapshot:
        """Build the existing deterministic public ZIP into original private custody.

        ZIP assembly uses bounded memory, not a second pathname writer whose
        identity could be adopted later. The original _publish owns every
        native descriptor and final private-file check. No Store code runs.
        """
        import io
        import zipfile
        from .metadata import MAX_ARCHIVE_SIZE, MAX_FILE_COUNT, MAX_FILE_SIZE, _safe_platform_files

        self._owner()
        _need(self.layout == "store-metadata" and platform in ("android", "ios"),
              "metadata requires its fixed original role")
        _need(root.is_dir(), "metadata directory is missing")
        files = _safe_platform_files(root, (platform,))
        _need(len(files) <= MAX_FILE_COUNT, "metadata file count exceeds its bound")
        total = sum(path.stat().st_size for path in files)
        _need(total <= MAX_ARCHIVE_SIZE, "metadata archive exceeds its input bound")
        with io.BytesIO() as buffer:
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
                written = 0
                for path in files:
                    self.cancellation.check()
                    # Existing selected public source, but with the original
                    # checked bounded reader/close path rather than read_bytes.
                    observed = _read_file(self.parent.fd, str(path), self.cancellation,
                                          MAX_FILE_SIZE)
                    _need(observed is not None, "selected metadata file disappeared")
                    data = observed[1]
                    written += len(data)
                    _need(written <= MAX_ARCHIVE_SIZE, "metadata grew beyond its input bound")
                    info = zipfile.ZipInfo(path.relative_to(root).as_posix(),
                                           date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type, info.external_attr = zipfile.ZIP_STORED, 0o100644 << 16
                    archive.writestr(info, data)
                    _need(buffer.tell() <= self._spec("metadata").limit,
                          "metadata ZIP exceeds its output bound")
            view = buffer.getbuffer()
            try:
                _need(len(view) <= self._spec("metadata").limit,
                      "metadata ZIP exceeds its output bound")
                return self._publish("metadata", (
                    bytes(view[offset:offset + 1024**2]) for offset in range(0, len(view), 1024**2)
                ))
            finally:
                view.release()

    def copy_from_fd(self, role: str, source_fd: int, *, maximum_bytes: int,
                     expected_sha256: str) -> InputSnapshot:
        _need(self.layout == "bundletool" and role == "bundletool"
              and type(source_fd) is int and source_fd >= 0
              and type(maximum_bytes) is int and maximum_bytes == _BUNDLETOOL_BYTES
              and expected_sha256 == _BUNDLETOOL_SHA256,
              "bundletool copy requires its exact pinned artifact")

        def chunks() -> Iterator[bytes]:
            size = 0
            while True:
                block = os.read(source_fd, min(1024 * 1024, maximum_bytes + 1 - size))
                if not block:
                    break
                size += len(block)
                _need(size <= maximum_bytes, "tool copy exceeded its fixed artifact bound")
                yield block
            _need(size == maximum_bytes, "tool copy has the wrong artifact length")

        return self._publish(role, chunks(), expected=expected_sha256)

    def require(self, snapshot: InputSnapshot) -> Path:
        self._owner()
        _need(type(snapshot) is InputSnapshot and snapshot._owner is self
              and self.snapshots.get(snapshot._role) is snapshot
              and self.tokens.get(snapshot._role) is snapshot._token,
              "snapshot was not selected by this owner")
        if self.journal is not None:
            _need(self.journal.prepared, "target batch must be prepared before native input use")
        self._check()
        spec = self._spec(snapshot._role)
        observed = _read_file(self.slot.number, spec.name, self.cancellation, spec.limit,
                              private=True, binding_only=True)  # type: ignore[arg-type]
        _need(observed is not None and observed[0] == self.records[snapshot._role]["binding"]
              and observed[0]["size"] == snapshot.size and observed[0]["sha256"] == snapshot.sha256,
              "selected snapshot changed")
        return self._path / spec.name

    def require_input(self, role: str) -> InputSnapshot:
        """Return the original minted object, never reconstruct it from a token."""
        self._owner()
        _need(self._spec(role).direction == "input" and role in self.snapshots,
              "input role was not selected by this owner")
        snapshot = self.snapshots[role]
        self.require(snapshot)
        return snapshot

    def output_path(self, role: str, *, evidence=None) -> Path:
        self._owner()
        self._check()
        spec = self._spec(role)
        from ._command_process import CommandCallEvidence

        _need(self.layout == "online-readback" and spec.direction == "exclusive-output"
              and role not in self.records and type(evidence) is CommandCallEvidence,
              "native output requires its original fixed-writer binding")
        assert self.slot.number is not None
        _name_absent(self.slot.number, spec.name)
        # Reservation is finite and precedes any native call. No output is
        # precreated: Fastfile's unchanged writer requires an absent EXCL name.
        self.records[role] = {"binding": None, "binding_attempted": False, "writer": evidence}
        path = self._path / spec.name
        evidence._reserve_readback(self, role, path, self.cancellation)
        return path

    def _observe_output(self, role: str, *, binding_only: bool = False) -> bytes:
        spec = self._spec(role)
        _need(self.layout == "online-readback" and spec.direction == "exclusive-output"
              and role in self.records, "output role has no original reservation")
        record = self.records[role]
        first = record["binding"] is None
        if first:
            _need(not record["binding_attempted"], "original output binding is unconfirmed")
            record["binding_attempted"] = True
            # A settled nonzero EXCL writer may have found somebody else's
            # file. Only the original fully retired normal-zero writer allows
            # a first binding; its sidecar grants no process/cleanup authority.
            _need(record["writer"].successful_readback(owner=self, role=role,
                  path=self._path / spec.name, cancellation=self.cancellation),
                  "original output writer did not complete successfully")
        self._check()
        assert self.slot.number is not None
        observed = _read_file(self.slot.number, spec.name, self.cancellation, spec.limit,
                              private=True, binding_only=binding_only)
        _need(observed is not None and observed[0]["size"] > 0,
              "original writer produced no nonempty private output")
        self._check()
        if first:
            record["binding"] = observed[0]
        else:
            _need(observed[0] == record["binding"], "original output changed")
        return observed[1]

    def read_output(self, role: str) -> bytes:
        self._owner()
        content = self._observe_output(role)
        self.cancellation.check()
        return content

    def _dispose(self, *, recovery_idle: bool = False) -> None:
        self._owner(cleanup=True)
        _check_creation(self.creation, self.identity)
        if not self.created:
            return
        _need(self.identity is not None, "scratch acquisition ownership is unknown")
        self._check()
        _need((recovery_idle and self._lane_binding is None)
              or _consumer_idle(self.cancellation, lane_binding=self._lane_binding, owner=self),
              "original scratch consumers are unconfirmed")
        fd = self.slot.number
        assert fd is not None
        expected = {self._spec(role).name for role in self.records}
        _need(_names(fd) <= expected, "unexpected scratch entry must be preserved")
        actions = []
        for role, record in reversed(tuple(self.records.items())):
            def remove(role=role, record=record):
                spec = self._spec(role)
                if spec.direction == "exclusive-output" and record.get("binding") is None:
                    # Consumer finality above permits observing absence. A
                    # present unbound output needs its one original successful
                    # writer and reader-finality gate even during error cleanup.
                    if _stat(fd, spec.name) is None:
                        return
                    self._observe_output(role, binding_only=True)
                found = _read_file(fd, spec.name, self.cancellation, spec.limit, private=True, binding_only=True)
                if found is None:
                    return
                _need(record.get("binding") is not None and found[0] == record["binding"],
                      "scratch file ownership changed or is unknown")
                os.unlink(spec.name, dir_fd=fd)
            actions.append(remove)
        _attempt_all(self.cancellation, actions)
        _need(not _names(fd), "scratch is not empty")
        self._check()
        os.rmdir(self.name, dir_fd=self.parent.fd)
        os.fsync(self.parent.fd)
        self.creation["state"] = "RETIRED"
        self.created = False

    def cleanup(self) -> None:
        self._owner(cleanup=True)
        if self.claimed:
            return
        self.claimed, self.active = True, False
        _attempt_all(self.cancellation, [self._dispose,
            *[slot.close for slot in reversed(self.writer_slots)], self.slot.close, self.parent.close])
        self._cleanup_complete = True

    def _lane_closed_for(self, record, binding, guard: DefaultCancellation) -> bool:
        """Original closure observation only; neither deletion nor adoption authority."""
        self._owner(cleanup=True)
        if binding is not self._lane_binding or binding is None or guard is not self.cancellation:
            return False
        record._origin(guard)
        record._resource(binding, self)
        slots = (*self.writer_slots, self.slot, *self.parent.slots)
        return (self.claimed and not self.active and self._cleanup_complete and not self.created
                and self.creation["state"] in ("NEW", "NO_EFFECT", "RETIRED")
                and all(slot.number is None and slot.close_state == "CLOSED" for slot in slots))

    def fork_close(self) -> None:
        self.active = False
        for slot in reversed(self.writer_slots):
            slot.close()
        self.slot.close()
        self.parent.fork_close()


@contextmanager
def _scope(owner: Any, guard: DefaultCancellation, owns: bool) -> Iterator[Any]:
    def cleanup() -> None:
        # Failed context entry has no outer ExitStack callback yet. Retire the
        # original Store admission BEFORE that input's own cleanup, preserving
        # the incoming primary rather than manufacturing live consumers on a
        # genuine no-command path. Closing any original input is one-way.
        record = None
        if isinstance(owner, FiniteScratch) and owner._lane_binding is not None:
            record = owner._lane_binding._record
        elif type(owner) is InvocationCustody:
            record = owner.lane_evidence
        if record is None:
            owner.cleanup()
            return
        # Even a failure to observe the composite cannot skip original FD
        # retirement. Each owner still refuses deletion of unsettled inputs.
        _attempt_all(guard, [lambda: record.finish(cancellation=guard, primary=scope._first_error),
                             owner.cleanup])

    scope = CleanupScope(guard, cleanup, owns_cancellation=owns,
                         fork_cleanup=owner.fork_close, first_primary=True)
    try:
        try:
            with scope:
                if owns:
                    guard.install()
                    guard.activate()
                owner.acquire()
                guard.check()
                try:
                    yield owner
                except BaseException as error:
                    if guard.pid == os.getpid():
                        guard.lifetime_ledger._remember(error)
                    raise
        finally:
            scope.__exit__(*sys.exc_info())
        if guard.pid != os.getpid():
            raise BuildInputError("build inputs: inherited scope cannot publish parent completion")
        guard.check()  # Includes explicitly borrowed zero-handler owners.
    except BaseException as error:
        if guard.pid != os.getpid():
            raise
        fatal = fatal_cancellation_error(error, guard, "build-input lifetime did not settle")
        if fatal is not None:
            if type(error) is _PrivatePublicationError:
                # This exact local type contains only generated slot basenames.
                # Keep its actionable location without losing later close facts.
                raise preserve_lifetime_error(error, previous=fatal) from None
            raise fatal from None
        raise


@contextmanager
def finite_scratch(*, layout: str, cancellation: DefaultCancellation | None = None,
                   parent: Path | None = None, lane_evidence=None) -> Iterator[FiniteScratch]:
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "build-input cancellation ownership did not settle")
    owner = FiniteScratch(layout, guard, parent, lane_evidence=lane_evidence)
    with _scope(owner, guard, owns):
        yield owner


def _fork_environment() -> None:
    global _ENV_LOCK, _ENV_OWNER, _ENV_TAINTED, _ENV_PID
    _ENV_TAINTED = _ENV_TAINTED or _ENV_OWNER is not None
    _ENV_OWNER, _ENV_LOCK, _ENV_PID = None, threading.Lock(), os.getpid()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_fork_environment)


class _EnvironmentFrame:
    def __init__(self, owner: InvocationCustody, updates: Mapping[str, str | None]) -> None:
        self.owner = owner
        self.updates = dict(updates)
        _need(all(type(key) is str and key and "=" not in key and "\0" not in key
                  and (value is None or type(value) is str and "\0" not in value)
                  for key, value in self.updates.items()), "invalid environment delta")
        self.previous: dict[str, str | None] = {}
        self.installed: list[str] = []
        self.claimed = False

    def acquire(self) -> None:
        self.owner._owner()
        self.owner.frames.append(self)
        # Freeze every before-value before the first process-global mutation.
        self.previous = {key: os.environ.get(key) for key in self.updates}
        for key, value in self.updates.items():
            with self.owner.cancellation.deferred(check_on_exit=False):
                self.installed.append(key)
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def cleanup(self) -> None:
        global _ENV_TAINTED
        owner = self.owner
        if owner.pid != os.getpid():
            return
        owner._owner(cleanup=True)
        if self.claimed:
            return
        self.claimed = True
        try:
            _need(owner.frames and owner.frames[-1] is self, "environment frames exited out of order")
            try:
                actions = []
                for key in reversed(self.installed):
                    def restore(key=key):
                        _need(os.environ.get(key) == self.updates[key], "environment ownership changed")
                        old = self.previous[key]
                        if old is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = old
                    actions.append(restore)
                _attempt_all(owner.cancellation, actions)
            finally:
                # Retire this actually-top consumed frame even on failure, so
                # an outer frame can independently restore its unchanged keys.
                # Never pop a frame inserted out of order by another owner.
                _need(owner.frames and owner.frames[-1] is self, "environment cleanup order changed")
                owner.frames.pop()
        except BaseException:
            _ENV_TAINTED = True
            raise

    def fork_close(self) -> None:
        self.claimed = True


class _StoreNamespace:
    """Original app-private ancestry; admission grants no deletion authority.

    Store callers retain the two fixed components. Root-only/fixed-role callers
    and the internal explicit-destination adapter reuse exactly the same slots,
    creation receipts and checked no-follow walk, never a chmod/adoption path.
    """

    def __init__(self, root: Path, guard: DefaultCancellation, *, include_store: bool = True,
                 _descendants: tuple[str, ...] = (), _exclusive_index: int | None = None,
                 _create: bool = True) -> None:
        _need(type(include_store) is bool and type(_create) is bool
              and type(_descendants) is tuple and (not include_store or not _descendants),
              "invalid private namespace selection")
        self.components = (_PRIVATE, "store") if include_store else (_PRIVATE, *_descendants)
        _need(root.anchor == "/" and ".." not in root.parts and "\0" not in str(root)
              and len(root.parts) + len(self.components) <= _MAX_COMPONENTS
              and len(os.fsencode(root.joinpath(*self.components))) <= _MAX_PATH_BYTES
              and all(type(name) is str and name not in ("", ".", "..")
                      and not any(char in name for char in ("/", "\\", "\0"))
                      for name in self.components), "private namespace requires a bounded lexical path")
        if len(self.components) > 1:
            first = self.components[1]
            _need(all(_name_key(first) != reserved or first == reserved
                      for reserved in ("store", "build", "reports", "handoff")),
                  "private role has an aliased spelling")
        _need(_exclusive_index is None or type(_exclusive_index) is int
              and 0 <= _exclusive_index < len(self.components), "invalid exclusive private role")
        self.exclusive_index, self.create = _exclusive_index, _create
        self.root, self.cancellation = root, guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.parent = _Directory(root, guard)
        self.parent_acquired = False
        self.slots = [_FD(guard) for _ in self.components]
        self.identities: list[dict[str, int] | None] = [None for _ in self.components]
        self.creations = [{"state": "NEW"} for _ in self.components]
        self.claimed = self._cleanup_complete = False
        # All fixed callbacks exist before any acquisition, not after cleanup
        # has claimed the owner or a diagnostic allocation has failed.
        self._cleanup_actions = [self.check, *[slot.close for slot in reversed(self.slots)],
                                 self.parent.close]

    @property
    def path(self) -> Path:
        return self.root.joinpath(*self.components)

    @property
    def fd(self) -> int:
        self._owner()
        _need(not self.claimed and all(identity is not None for identity in self.identities),
              "private namespace is not live")
        self.cancellation.check()
        self.check()
        number = self.slots[-1].number
        _need(number is not None, "private namespace descriptor is not open")
        return number

    def require_empty(self) -> None:
        _need(not _names(self.fd), "application workflow output must be empty")
        self.check()

    def _owner(self) -> None:
        _need(self.pid == os.getpid() and self.thread is threading.current_thread(),
              "Store namespace belongs to another process/thread")

    def acquire(self) -> None:
        self._owner()
        _need(not self.claimed and not self.parent_acquired, "Store namespace acquisition cannot be repeated")
        self.parent.acquire()
        self.parent_acquired = True
        parent = self.parent.fd
        for index, name in enumerate(self.components):
            self.cancellation.check()
            exists = name in _exact_reserved_names(parent, {name})
            _need(not exists or index != self.exclusive_index,
                  "exclusive private output already exists; preserve it")
            if not exists:
                _need(self.create, "required private source directory is missing")
                _mkdir_private(name, parent, self.cancellation, self.creations[index])
            slot = self.slots[index]
            try:
                number = slot.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=parent)
            except OSError as error:
                # Only the original builtin's proven no-effect refusal is an
                # ordinary path diagnostic. Unknown acquisitions stay fatal.
                if error.errno in (errno.ENOTDIR, errno.ELOOP) and slot.open_state == "NO_EFFECT":
                    raise BuildInputError(
                        "build inputs: application-private parents must be real directories "
                        "without symbolic links"
                    ) from None
                raise
            identity = _directory(os.fstat(number))
            self.identities[index] = identity
            _need(identity["uid"] == os.geteuid() and identity["mode"] == 0o700
                  and identity["device"] == os.fstat(parent).st_dev,
                  "application-private directories require original-user0700 custody "
                  "on the application filesystem; preserve an incompatible legacy layout and use "
                  "a new clean checkout with authenticated original evidence, never automatic chmod or adoption")
            _need(_directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                  "Store namespace changed during acquisition")
            os.fsync(parent)
            parent = number
        self.check()

    def check(self) -> None:
        self._owner()
        # An untouched/no-effect failed acquisition needs no path adoption.
        for creation, identity in zip(self.creations, self.identities):
            _check_creation(creation, identity)
        if not self.parent_acquired:
            return
        self.parent.check()
        parent = self.parent.fd
        for index, name in enumerate(self.components):
            identity, slot = self.identities[index], self.slots[index]
            if identity is None:
                break
            _exact_reserved_names(parent, {name})
            _need(slot.number is not None and _directory(os.fstat(slot.number)) == identity
                  and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                  "original Store application-private namespace changed")
            parent = slot.number

    def cleanup(self) -> None:
        self._owner()
        if self.claimed:
            return
        self.claimed = True
        _attempt_all(self.cancellation, self._cleanup_actions)
        self._cleanup_complete = True
        self._cleanup_actions.clear()  # No healthy owner/callback cycle remains.

    def closed(self) -> bool:
        self._owner()
        return (self.claimed and self._cleanup_complete
                and all(creation["state"] in ("NEW", "NO_EFFECT", "CREATED") for creation in self.creations)
                and all(slot.number is None and slot.close_state == "CLOSED"
                        for slot in (*self.parent.slots, *self.slots)))

    def fork_close(self) -> None:
        first = None
        for slot in reversed(self.slots):
            try:
                slot.close()
            except BaseException as error:
                if first is None:
                    first = error
        for slot in reversed(self.parent.slots):
            try:
                slot.close()
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first


@contextmanager
def store_private_namespace(root: Path, *, cancellation: DefaultCancellation | None = None):
    """Admit fixed persistent namespace before online-dependent output writes."""
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "Store namespace cancellation ownership did not settle")
    owner = _StoreNamespace(root, guard)
    with _scope(owner, guard, owns):
        yield owner


@contextmanager
def app_private_namespace(root: Path, *, cancellation: DefaultCancellation | None = None):
    """Live root-only admission; does not create Store/build/report contents."""
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "application namespace cancellation ownership did not settle")
    owner = _StoreNamespace(root, guard, include_store=False)
    with _scope(owner, guard, owns):
        yield owner


@contextmanager
def app_private_role(root: Path, *, role: str, cancellation: DefaultCancellation | None = None):
    """Only finite workflow roles, retained across their actual publication."""
    roles = {"empty-root": (), "reports": ("reports",),
             "android-handoff": ("handoff", "android"), "ios-handoff": ("handoff", "ios")}
    _need(type(role) is str and role in roles, "unknown fixed application-private role")
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "application role cancellation ownership did not settle")
    owner = _StoreNamespace(root, guard, include_store=False, _descendants=roles[role],
                            _exclusive_index=1 if role.endswith("-handoff") else None)
    with _scope(owner, guard, owns):
        if role == "empty-root":
            owner.require_empty()
        yield owner


@contextmanager
def _app_private_directory(directory: Path, *, app_root: Path | None = None,
                           cancellation: DefaultCancellation | None = None,
                           exclusive: bool = False, create: bool = True):
    """Internal explicit-destination adapter, not root inference or a public walker.

    None selects the unchanged generic/public destination contract. For an
    explicitly caller-bound private destination the original owner encloses use
    and final checks. A returned Path after exit is not custody for later use.
    """
    if app_root is None:
        yield None
        return
    root, path = Path(app_root).expanduser(), Path(directory).expanduser()
    _need(root.anchor == "/" and ".." not in root.parts and ".." not in path.parts
          and "\0" not in str(root) and "\0" not in str(path),
          "explicit application output requires a lexical path without parent traversal")
    if not path.is_absolute():
        path = root / path
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        # A case/NFC alias of this exact caller's root must not fall through to
        # generic mkdir on a filesystem which maps it back into the namespace.
        prefix = path.parts[:len(root.parts)]
        same_root_key = tuple(map(_name_key, prefix)) == tuple(map(_name_key, root.parts))
        _need(not same_root_key, "application output root has an aliased spelling")
        yield None
        return
    if not parts or _name_key(parts[0]) != _name_key(_PRIVATE):
        yield None
        return
    _need(parts[0] == _PRIVATE, "application-private root has an aliased spelling")
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "application output cancellation ownership did not settle")
    owner = _StoreNamespace(root, guard, include_store=False, _descendants=parts[1:],
                            _exclusive_index=len(parts) - 1 if exclusive else None, _create=create)
    with _scope(owner, guard, owns):
        yield owner


def _link_private_output(parent: int, temporary: str, name: str, guard: DefaultCancellation,
                         record: dict[str, str]) -> None:
    """One exclusive link; a wrapper's lost return is not an EEXIST receipt."""
    _need(record["state"] == "NEW", "private publication cannot be repeated")
    operation = os.link
    with guard.deferred(check_on_exit=False):
        try:
            record["state"] = "ATTEMPTED"
            operation(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                      follow_symlinks=False)
            record["state"] = "LINKED"
        except BaseException as error:
            record["state"] = ("NO_EFFECT" if _direct_refusal(
                error, operation, _OS_LINK, _link_private_output.__code__, _LINK_REFUSALS) else "UNKNOWN")
            if guard.pid == os.getpid():
                guard.lifetime_ledger._remember(error)
                if record["state"] == "UNKNOWN":
                    _cleanup_failure(guard, error)
            raise


@contextmanager
def _private_file_writer(owner: _StoreNamespace, name: str, *, replace: bool = False):
    """Borrow one original write fd; the helper alone closes and publishes it.

    Callers may stream ordinary bytes (including a nonseekable ZipFile sink),
    but must not fdopen/close/transfer the borrowed descriptor. All actions are
    relative to the retained directory, not a reopened diagnostic pathname.

    Report replacement retires the original before exclusive publication: the
    diagnostic name can briefly be absent, but never exposes partial new bytes.
    It is not an atomic old-to-new swap. Callers consume the report only after
    this scope returns; conflicts preserve displaced entries rather than
    overwriting a newly arrived leaf or guessing an interrupted move succeeded.
    """
    _need(type(owner) is _StoreNamespace and type(name) is str and name not in ("", ".", "..")
          and not any(char in name for char in ("/", "\\", "\0")) and type(replace) is bool,
          "private file publication requires one checked component")
    guard, parent = owner.cancellation, owner.fd
    _exact_reserved_names(parent, {name})
    before = _stat(parent, name)
    if before is not None:
        _need(stat.S_ISREG(before.st_mode), "private output is not a regular non-symlink file")
        if not replace:
            raise FileExistsError(errno.EEXIST, "immutable private output already exists")
    temporary = ".mrk-" + uuid.uuid4().hex
    _name_absent(parent, temporary)
    retired = ".mrk-retired-" + uuid.uuid4().hex if before is not None else None
    rename = _rename_function() if retired is not None else None
    if retired is not None:
        _name_absent(parent, retired)
    writer, original = _FD(guard), _FD(guard)
    identity = None
    retirement, retirement_cleanup = "NEW", "NEW"
    publication = {"state": "NEW"}
    committed = False

    def settle_original_report() -> None:
        nonlocal retirement_cleanup
        _need(retirement_cleanup == "NEW", "report retirement cleanup cannot be repeated")
        retirement_cleanup = "ATTEMPTED"
        if retirement == "NEW":
            retirement_cleanup = "NOT_NEEDED"
            return
        _need(retirement == "MOVED", "report retirement is unknown; preserve both report slots")
        assert retired is not None and rename is not None and before is not None
        owner.check()
        if committed:
            # Only the positive original move AND positive new publication may
            # dispose of this known old file. The original FD remains open.
            current = _file(os.stat(retired, dir_fd=parent, follow_symlinks=False))
            _need(original.number is not None and _same_object(current, _file(before), renamed=True)
                  and _file(os.fstat(original.number)) == current,
                  "retired original report changed; preserve both report slots")
            retirement_cleanup = "UNLINK_ATTEMPTED"
            try:
                os.unlink(retired, dir_fd=parent)
                retirement_cleanup = "REMOVED"
            except BaseException:
                retirement_cleanup = "UNKNOWN"
                raise
        else:
            # MOVED is established before type checks: a substituted symlink or
            # directory is restored without being adopted as an original file.
            # A late occupant at name is never removed/replaced for restoration.
            if _stat(parent, name) is not None:
                retirement_cleanup = "RETAINED"
                raise BuildInputError("report name is occupied; preserve its retired entry")
            retirement_cleanup = "RESTORE_ATTEMPTED"
            try:
                rename(parent, retired, parent, name)
                retirement_cleanup = "RESTORED"
            except BaseException:
                retirement_cleanup = "UNKNOWN"
                raise
        os.fsync(parent)

    def close_inherited_files() -> None:
        first = None
        for slot in (writer, original):
            try:
                slot.after_fork_child()
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first

    def remove_original_temporary() -> None:
        if identity is None:
            return  # A failed/unknown open does not authorize later adoption.
        owner.check()
        current = _stat(parent, temporary)
        if current is None:
            return
        found = _file(current)
        _need(all(found[key] == identity[key] for key in ("device", "inode", "uid", "gid", "mode"))
              and found["links"] in (1, 2), "private temporary ownership changed; preserve it")
        os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)

    actions = [writer.close, settle_original_report, original.close, remove_original_temporary]
    scope = CleanupScope(guard, lambda: _attempt_all(guard, actions), owns_cancellation=False,
                         fork_cleanup=close_inherited_files, first_primary=True)
    try:
        try:
            with scope:
                if before is not None:
                    old_number = original.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                               dir_fd=parent)
                    old = _file(os.fstat(old_number))
                    _need(old == _file(before) and old["uid"] == os.geteuid()
                          and old["mode"] == 0o600 and old["links"] == 1
                          and old["device"] == os.fstat(parent).st_dev,
                          "original report is not original-user0600 single-link custody")
                    owner.check()
                number = writer.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     dir_fd=parent)
                identity = _file(os.fstat(number))
                _need(identity["uid"] == os.geteuid() and identity["mode"] == 0o600
                      and identity["links"] == 1, "new private output is not original-user0600")
                guard.check()
                yield number
                guard.check()
                owner.check()
                os.fsync(number)
                final = _file(os.fstat(number))
                _need(all(final[key] == identity[key] for key in
                          ("device", "inode", "uid", "gid", "mode", "links"))
                      and _file(os.stat(temporary, dir_fd=parent, follow_symlinks=False)) == final,
                      "private output changed during writing")
                writer.close()  # No publication after an unknown close result.
                owner.check()
                _exact_reserved_names(parent, {name, temporary})
                _need(_file(os.stat(temporary, dir_fd=parent, follow_symlinks=False)) == final,
                      "private temporary changed at retirement")
                if retired is not None:
                    assert rename is not None and before is not None
                    _need(original.number is not None and _file(os.fstat(original.number)) == _file(before)
                          and _file(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _file(before),
                          "report output changed before replacement")
                    _name_absent(parent, retired)
                    with guard.deferred(check_on_exit=False):
                        retirement = "ATTEMPTED"
                        try:
                            rename(parent, name, parent, retired)
                            retirement = "MOVED"
                        except BaseException as error:
                            retirement = "UNKNOWN"
                            guard.lifetime_ledger._remember(error)
                            _cleanup_failure(guard, error)
                            raise
                    moved = _stat(parent, retired)
                    _need(moved is not None and stat.S_ISREG(moved.st_mode)
                          and _same_object(_file(moved), _file(before), renamed=True)
                          and _file(os.fstat(original.number)) == _file(moved),
                          "report changed at retirement; restore its displaced entry without adoption")
                    owner.check()
                    os.fsync(parent)
                    guard.check()
                # The same exclusive publication covers immutable/absent-report
                # destinations and an established original report retirement.
                _link_private_output(parent, temporary, name, guard, publication)
                if publication["state"] != "LINKED":
                    raise _cleanup_failure(guard, BuildInputError("private publication return is unconfirmed"))
                owner.check()
                published = _file(os.stat(name, dir_fd=parent, follow_symlinks=False))
                _need(all(published[key] == final[key] for key in final if key not in ("ctime", "links"))
                      and published["links"] == 2,
                      "private publication identity changed")
                os.fsync(parent)
                guard.check()
                committed = True
        finally:
            scope.__exit__(*sys.exc_info())
        _need(guard.pid == os.getpid(), "inherited private writer cannot publish parent completion")
        if (not committed or publication["state"] != "LINKED"
                or writer.number is not None or writer.close_state != "CLOSED"
                or original.number is not None or original.close_state != "CLOSED"
                or retirement_cleanup != ("REMOVED" if retired is not None else "NOT_NEEDED")):
            raise _cleanup_failure(guard, BuildInputError("private publication original cleanup is unconfirmed"))
        owner.check()
        _exact_reserved_names(parent, {name})
        settled = _file(os.stat(name, dir_fd=parent, follow_symlinks=False))
        _need(all(settled[key] == final[key] for key in final if key not in ("ctime", "links"))
              and settled["links"] == 1, "private output changed at publication cleanup")
        guard.check()
    except BaseException as error:
        if guard.pid == os.getpid():
            fatal = fatal_cancellation_error(error, guard, "private publication lifetime did not settle")
            if retired is not None and retirement != "NEW":
                diagnostic = preserve_lifetime_error(_PrivatePublicationError(temporary, retired),
                                                       previous=error)
                if fatal is not None:
                    preserve_lifetime_error(diagnostic, previous=fatal)
                raise diagnostic from None
            if fatal is not None:
                raise fatal from None
        raise


def _publish_private_file(owner: _StoreNamespace, name: str, blocks: Iterator[bytes], *,
                          replace: bool = False) -> None:
    with _private_file_writer(owner, name, replace=replace) as number:
        for block in blocks:
            _need(type(block) is bytes, "private output chunk is not immutable bytes")
            owner.cancellation.check()
            view = memoryview(block)
            while view:
                written = os.write(number, view)
                _need(written > 0, "private output write made no progress")
                view = view[written:]


class InvocationCustody:
    def __init__(self, root: Path, mode: str, guard: DefaultCancellation, *, lane_evidence=None) -> None:
        _need(mode in ("build", "online", "store"), "unknown invocation mode")
        _need((mode == "store") == (lane_evidence is not None),
              "Store invocation requires exactly its original composite record")
        if lane_evidence is not None:
            from ._store_lane_evidence import StoreLaneCallEvidence

            _need(type(lane_evidence) is StoreLaneCallEvidence, "Store composite record is not original")
            lane_evidence._origin(guard)
            _need(not lane_evidence._attempted and not lane_evidence._finished and not lane_evidence._failed,
                  "Store invocation is already consumed")
        self.root, self.mode, self.cancellation = root, mode, guard
        self.lane_evidence = lane_evidence
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.reserved = self.active = self.claimed = False
        self.environment_lock = _ENV_LOCK
        self.lock_result: bool | None = None
        self.reservation_state = "NEW"
        self.project_started = False
        self.frames: list[_EnvironmentFrame] = []
        self.project_owner: _Project | None = None
        self.child: BuildInputs | None = None
        self.signing_lease: SigningLease | None = None
        self._cleanup_complete = False
        self.store_namespace = _StoreNamespace(root, guard) if mode == "store" else None
        if lane_evidence is not None:
            # One exact caller-layer binding. It grants no process, deletion or
            # receipt authority; the final Store gate checks its actual closure.
            _need(getattr(lane_evidence, "_caller_invocation", None) is None,
                  "Store invocation already has its original environment owner")
            lane_evidence._caller_invocation = self

    def _owner(self, *, cleanup: bool = False) -> None:
        _need(self.pid == os.getpid() and self.thread is threading.current_thread(),
              "invocation belongs to another process/thread")
        if not cleanup:
            _need(self.active and _ENV_OWNER is self and not _ENV_TAINTED,
                  "invocation environment is not admitted")
            self.cancellation.check()

    def acquire(self) -> None:
        global _ENV_OWNER, _ENV_TAINTED
        _need(_ENV_PID == os.getpid() and not _ENV_TAINTED,
              "environment ownership is unresolved; end this process")
        _need(self.reservation_state == "NEW", "environment reservation cannot be repeated")
        with self.cancellation.deferred(check_on_exit=False):
            try:
                self.reservation_state = "ATTEMPTED"
                self.lock_result = self.environment_lock.acquire(blocking=False)
                _need(type(self.lock_result) is bool, "environment reservation result is unknown")
                self.reservation_state = "ACQUIRED" if self.lock_result else "REFUSED"
                if self.lock_result:
                    self.reserved = True
                    _need(_ENV_OWNER is None, "environment reservation is inconsistent")
                    _ENV_OWNER, self.active = self, True
            except BaseException as error:
                self.cancellation.lifetime_ledger._remember(error)
                if type(self.lock_result) is not bool:
                    self.lock_result, self.reservation_state = None, "UNKNOWN"
                    _ENV_TAINTED = True
                    _cleanup_failure(self.cancellation, error)
                elif self.lock_result and _ENV_OWNER is not None and _ENV_OWNER is not self:
                    _ENV_TAINTED = True
                    _cleanup_failure(self.cancellation, error)
                raise
        _need(self.lock_result is True, "another invocation reserves the environment")
        if self.store_namespace is not None:
            # Persistent parents precede ordinary output mkdir under0022.
            self.store_namespace.acquire()

    def require(self, *, root: Path, cancellation: DefaultCancellation,
                signing_lease: SigningLease | None = None) -> None:
        self._owner()
        _need(root == self.root and cancellation is self.cancellation
              and signing_lease is self.signing_lease, "borrowed invocation binding differs")
        if self.signing_lease is not None:
            self.signing_lease.assert_owner()
        if self.project_owner is not None:
            self.project_owner.check()
        if self.store_namespace is not None:
            self.store_namespace.check()

    @contextmanager
    def environment(self, updates: Mapping[str, str | None]) -> Iterator[None]:
        frame = _EnvironmentFrame(self, updates)
        with _scope(frame, self.cancellation, False):
            yield

    @contextmanager
    def project(self, *, signing_lease: SigningLease | None) -> Iterator[None]:
        self._owner()
        _need(self.mode == "build" and not self.project_started and self.project_owner is None,
              "project admission is not available")
        if signing_lease is not None:
            from .local_signing import SigningLease
            _need(type(signing_lease) is SigningLease and signing_lease.cancellation is self.cancellation,
                  "account cancellation owner differs")
            signing_lease.assert_owner()
        self.project_started = True
        project = _Project(self.root, self.cancellation, recovery=False)
        self.project_owner, self.signing_lease = project, signing_lease
        try:
            with _scope(project, self.cancellation, False):
                yield
        finally:
            self.project_owner = None

    @contextmanager
    def materialization(self, *, signing_lease: SigningLease | None) -> Iterator[BuildInputs]:
        self.require(root=self.root, cancellation=self.cancellation, signing_lease=signing_lease)
        _need(self.mode == "build" and self.project_owner is not None and self.child is None,
              "one materializer requires continuous project admission")
        child = BuildInputs(self, self.project_owner)
        self.child = child
        try:
            with _scope(child, self.cancellation, False):
                yield child
        finally:
            self.child = None

    def cleanup(self) -> None:
        global _ENV_OWNER, _ENV_TAINTED
        self._owner(cleanup=True)
        if self.claimed:
            return
        self.claimed, self.active = True, False
        actions = ([self.child.cleanup] if self.child is not None else [])
        actions += [frame.cleanup for frame in reversed(tuple(self.frames))]
        if self.project_owner is not None:
            actions.append(self.project_owner.cleanup)
        if self.store_namespace is not None:
            actions.append(self.store_namespace.cleanup)
        try:
            _attempt_all(self.cancellation, actions)
        finally:
            primary = sys.exc_info()[1]
            if self.lock_result is True:
                if self.frames or _ENV_OWNER is not None and _ENV_OWNER is not self:
                    _ENV_TAINTED = True
                try:
                    with self.cancellation.deferred(check_on_exit=False):
                        # A positive original acquire result, not lock.locked(),
                        # is the authority for this one release attempt.
                        self.reservation_state = "RELEASE_ATTEMPTED"
                        self.lock_result, self.reserved = None, False
                        if _ENV_OWNER is self:
                            _ENV_OWNER = None
                        self.environment_lock.release()
                        self.reservation_state = "RELEASED"
                except BaseException as error:
                    self.reservation_state = "UNKNOWN"
                    _ENV_TAINTED = True
                    self.cancellation.lifetime_ledger._remember(error)
                    _cleanup_failure(self.cancellation, error)
                    if primary is not None:
                        raise primary from None
                    raise
            elif self.lock_result is not False and self.reservation_state in (
                    "ATTEMPTED", "UNKNOWN", "RELEASE_ATTEMPTED"):
                _ENV_TAINTED = True
                failure = _cleanup_failure(self.cancellation, BuildInputError(
                    "build inputs: environment reservation settlement is unknown"))
                if primary is not None:
                    raise primary from None
                raise failure
        self._cleanup_complete = True

    def _lane_closed_for(self, record, guard: DefaultCancellation) -> bool:
        self._owner(cleanup=True)
        record._origin(guard)
        return (self.mode == "store" and self.lane_evidence is record
                and getattr(record, "_caller_invocation", None) is self
                and guard is self.cancellation and self.claimed and not self.active
                and self._cleanup_complete and not self.reserved and not self.frames
                and self.child is None and self.project_owner is None and self.signing_lease is None
                and self.reservation_state in ("NEW", "REFUSED", "RELEASED")
                and (self.lock_result is None or self.lock_result is False)
                and self.store_namespace is not None and self.store_namespace.closed()
                and _ENV_OWNER is not self and not _ENV_TAINTED)

    def fork_close(self) -> None:
        self.active = False
        if self.child is not None:
            self.child.fork_close()
        if self.project_owner is not None:
            self.project_owner.fork_close()
        if self.store_namespace is not None:
            self.store_namespace.fork_close()


@contextmanager
def invocation_custody(root: Path, *, mode: Literal["build", "online", "store"],
                      cancellation: DefaultCancellation | None = None,
                      lane_evidence=None) -> Iterator[InvocationCustody]:
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "build-input cancellation ownership did not settle")
    owner = InvocationCustody(root, mode, guard, lane_evidence=lane_evidence)
    with _scope(owner, guard, owns):
        yield owner


class _Project:
    def __init__(self, root: Path, guard: DefaultCancellation, *, recovery: bool) -> None:
        self.root, self.guard, self.recovery = root, guard, recovery
        self.directory = _Directory(root, guard)
        self.meta = _FD(guard)
        self.meta_identity: dict[str, int] | None = None
        self.meta_creation = {"state": "NEW"}
        self.claimed = False
        self.rename: Any = None

    @property
    def fd(self) -> int:
        return self.directory.fd

    @property
    def identity(self) -> dict[str, int]:
        return _directory(os.fstat(self.fd))

    def check(self) -> None:
        self.directory.check()
        if self.meta.number is not None:
            _need(_PRIVATE in _exact_reserved_names(self.fd, {_PRIVATE}), "private project directory is absent")
            _need(_directory(os.fstat(self.meta.number)) == self.meta_identity
                  and _directory(os.stat(_PRIVATE, dir_fd=self.fd, follow_symlinks=False)) == self.meta_identity,
                  "private project ancestry changed")

    def acquire(self) -> None:
        import fcntl
        self.directory.acquire()
        self.rename = _rename_function()
        try:
            with self.guard.deferred(check_on_exit=False):
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BuildInputError("build inputs: another owner holds this project") from None
        self.check()
        names = _exact_reserved_names(self.fd, {_PRIVATE, *INIT_STATES})
        _need(not ({_name_key(name) for name in names} & {_name_key(name) for name in INIT_STATES}),
              "pending init transaction must be resolved separately")
        if _PRIVATE in names:
            self._open_meta()
        if self.meta.number is not None:
            names = _exact_reserved_names(self.meta.number, {_PENDING, _TERMINAL, _TERMINAL_STAGE})
            if not self.recovery:
                _need(not (names & {_PENDING, _TERMINAL, _TERMINAL_STAGE}),
                  "pending build-input state requires explicit recovery")

    def _open_meta(self) -> None:
        _need(_PRIVATE in _exact_reserved_names(self.fd, {_PRIVATE}), "private project directory is absent")
        if self.meta.number is None:
            number = self.meta.open(_PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
            self.meta_identity = _directory(os.fstat(number))
            _need(self.meta_identity["uid"] == os.geteuid()
                  and self.meta_identity["mode"] == 0o700
                  and self.meta_identity["device"] == self.identity["device"],
                  "project metadata is not private and on the same filesystem")
        self.check()

    def ensure_meta(self) -> int:
        self.check()
        ignore = _read_file(self.fd, ".gitignore", self.guard, _SMALL)
        _need(ignore is not None, "project must explicitly ignore its private metadata")
        _need(_private_is_ignored(ignore[1]),
              "private metadata needs an unambiguous directory ignore rule")
        if self.meta.number is None:
            _name_absent(self.fd, _PRIVATE)
            with self.guard.deferred(check_on_exit=False):
                _mkdir_private(_PRIVATE, self.fd, self.guard, self.meta_creation)
                self._open_meta()
            os.fsync(self.fd)
        assert self.meta.number is not None
        return self.meta.number

    def cleanup(self) -> None:
        self.guard._check_owner()
        if self.claimed:
            return
        self.claimed = True
        # Closing only our original description releases our lock; never LOCK_UN
        # an inherited/shared description or delete the persistent project root.
        _attempt_all(self.guard, [lambda: _check_creation(self.meta_creation, self.meta_identity),
                                 self.meta.close, self.directory.close])

    def fork_close(self) -> None:
        self.meta.close()
        self.directory.fork_close()


@dataclass(frozen=True)
class TargetReplacement:
    role: Literal["android-services", "ios-services"]
    relative: PurePosixPath
    content: bytes


def _target_path(role: str, relative: str) -> PurePosixPath:
    _need(role in ("android-services", "ios-services") and type(relative) is str,
          "unknown target role")
    path = PurePosixPath(relative)
    _need(not path.is_absolute() and str(path) == relative and len(path.parts) <= 64
          and all(_name_key(part) not in {_name_key(name) for name in ("", ".", "..", ".git", _PRIVATE, *INIT_STATES)}
                  and "\0" not in part and "\\" not in part for part in path.parts),
          "target escapes its ordinary project namespace")
    _need(path.name == ("google-services.json" if role == "android-services" else "GoogleService-Info.plist"),
          "target basename does not match its fixed role")
    return path


def _valid_binding(value: Any, *, directory: bool = False) -> bool:
    keys = {"device", "inode", "uid", "gid", "mode"}
    if not directory:
        keys |= {"links", "size", "mtime", "ctime", "sha256"}
    return (type(value) is dict and set(value) == keys
            and all(type(item) is int and item >= 0 for key, item in value.items() if key != "sha256")
            and value.get("inode", 0) > 0 and value.get("mode", 0) <= 0o7777
            and (directory or type(value.get("sha256")) is str and bool(_DIGEST.fullmatch(value["sha256"]))))


class BuildInputs:
    """One finite target batch plus its original materialization scratch."""
    def __init__(self, invocation: InvocationCustody | None, project: _Project) -> None:
        self.invocation, self.project = invocation, project
        self.cancellation = project.guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.slot = _FD(self.cancellation)
        self.token = uuid.uuid4().hex
        self.identity: dict[str, int] | None = None
        self.header: dict[str, Any] = {}
        self.header_digest = ""
        self.intent_digest: str | None = None
        self.records: list[dict[str, Any]] = []
        self.parents: dict[str, _Directory] = {}
        self.control_slots: list[_FD] = []
        self.controls: dict[str, dict[str, Any]] = {}
        self.seq, self.previous = -1, None
        self.quiescence = "none"
        self.prepared = self.claimed = self.failed = False
        self.created = False
        self.creation = {"state": "NEW"}
        self.scratch = FiniteScratch("build", self.cancellation,
            project.root / _PRIVATE / _PENDING, _name="scratch", _journal=self)

    @property
    def fd(self) -> int:
        _need(self.slot.number is not None, "transaction directory is not open")
        return self.slot.number  # type: ignore[return-value]

    def _owner(self) -> None:
        _need(self.pid == os.getpid() and self.thread is threading.current_thread(),
              "transaction belongs to another process/thread")

    def _check(self) -> None:
        self._owner()
        self.project.check()
        meta = self.project.meta.number
        _need(meta is not None and _PENDING in _exact_reserved_names(meta, {_PENDING}),
              "transaction namespace is absent or aliased")
        _need(meta is not None and self.identity is not None
              and _directory(os.fstat(self.fd)) == self.identity
              and _directory(os.stat(_PENDING, dir_fd=meta, follow_symlinks=False)) == self.identity,
              "transaction namespace changed")

    def _write(self, fd: int, name: str, content: bytes, *, limit: int = _CONTROL) -> dict[str, Any]:
        _need(len(content) <= limit, "private staged file exceeds its bound")
        _name_absent(fd, name)
        slot = _FD(self.cancellation)
        self.control_slots.append(slot)
        with _fd_cleanup(slot):
            number = slot.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, dir_fd=fd)
            before = _file(os.fstat(number))
            _need(before["uid"] == os.geteuid() and before["mode"] == 0o600 and before["links"] == 1,
                  "control is not private")
            view = memoryview(content)
            while view:
                amount = os.write(number, view)
                _need(amount > 0, "control write made no progress")
                view = view[amount:]
            os.fsync(number)
            after = _file(os.fstat(number))
            _need(all(after[key] == before[key] for key in ("device", "inode", "uid", "gid", "mode", "links"))
                  and after["size"] == len(content), "staged file changed while writing")
        found = _read_file(fd, name, self.cancellation, limit, private=True)
        _need(found is not None and found[1] == content
              and {key: value for key, value in found[0].items() if key != "sha256"} == after,
              "staged publication changed")
        return found[0]

    def _publish_control(self, name: str, value: dict[str, Any]) -> str:
        self._check()
        stage = name + ".stage"
        content = _json(value)
        self.controls[stage] = self._write(self.fd, stage, content)
        self.project.rename(self.fd, stage, self.fd, name)
        found = _read_file(self.fd, name, self.cancellation, _CONTROL, private=True)
        _need(found is not None and found[1] == content
              and _same_object(found[0], self.controls[stage], renamed=True), "control rename changed ownership")
        self.controls.pop(stage)
        self.controls[name] = found[0]
        os.fsync(self.fd)
        return found[0]["sha256"]

    def _checkpoint(self) -> None:
        _need(self.header_digest and not self.failed and self.seq + 1 < _MAX_CHECKPOINTS,
              "transaction checkpoint authority is unavailable")
        sequence = self.seq + 1
        payload = dict(schemaVersion=1, session=self.token, header=self.header_digest,
            intent=self.intent_digest, sequence=sequence, previous=self.previous,
            prepared=self.prepared, quiescence=self.quiescence, targets=self.records,
            scratch=self.scratch.records)
        try:
            digest = self._publish_control(f"checkpoint-{sequence:03}.json", payload)
        except BaseException:
            self.failed = True
            raise
        self.seq, self.previous = sequence, digest

    def acquire(self) -> None:
        self._owner()
        meta = self.project.ensure_meta()
        _name_absent(meta, _PENDING)
        _need(_stat(meta, _TERMINAL) is None and _stat(meta, _TERMINAL_STAGE) is None,
              "terminal metadata must be retired first")
        with self.cancellation.deferred(check_on_exit=False):
            _mkdir_private(_PENDING, meta, self.cancellation, self.creation)
            self.created = True
            number = self.slot.open(_PENDING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=meta)
            self.identity = _directory(os.fstat(number))
        _need(self.identity["uid"] == os.geteuid() and self.identity["mode"] == 0o700
              and self.identity["device"] == self.project.identity["device"], "transaction is not private")
        self.scratch.acquire()
        self.header = dict(schemaVersion=1, session=self.token, root=self.project.identity,
            private=self.project.meta_identity, pending=self.identity, scratch=self.scratch.identity)
        self.header_digest = self._publish_control("header.json", self.header)
        self._checkpoint()
        os.fsync(meta)

    def _probe_exclusive_move(self) -> None:
        # Exercise the selected filesystem before any application-target move.
        # An interrupted/unobserved probe remains unknown private metadata.
        bindings = {name: self._write(self.fd, name, b"") for name in ("probe-a", "probe-b")}
        try:
            self.project.rename(self.fd, "probe-a", self.fd, "probe-b")
        except FileExistsError:
            pass
        else:
            raise BuildInputError("build inputs: filesystem did not enforce no-replace")
        for name, binding in bindings.items():
            observed = _read_file(self.fd, name, self.cancellation, _CONTROL, private=True)
            _need(observed is not None and observed[0] == binding, "exclusive-rename probe changed")
        self.project.rename(self.fd, "probe-a", self.fd, "probe-c")
        moved = _read_file(self.fd, "probe-c", self.cancellation, _CONTROL, private=True)
        _need(moved is not None and _same_object(moved[0], bindings["probe-a"], renamed=True),
              "exclusive-rename probe has unknown ownership")
        os.unlink("probe-c", dir_fd=self.fd)
        os.unlink("probe-b", dir_fd=self.fd)
        os.fsync(self.fd)

    def _parent(self, row: dict[str, Any], *, planning: bool = False) -> _Directory:
        role, path = row["role"], _target_path(row["role"], row["relative"])
        if role not in self.parents:
            directory = _Directory(self.project.root / path.parent, self.cancellation)
            self.parents[role] = directory
            directory.acquire()
        parent = self.parents[role]
        parent.check()
        bindings = [{"name": name, "identity": identity} for _, name, identity in parent.bindings]
        if planning:
            row["parents"] = bindings
        _need(row["parents"] == bindings and _directory(os.fstat(parent.fd))["device"] == self.identity["device"],
              "target parent changed or is on another filesystem")
        return parent

    def _endpoint(self, row: dict[str, Any], endpoint: str) -> tuple[int, str]:
        if endpoint == "target":
            return self._parent(row).fd, PurePosixPath(row["relative"]).name
        _need(endpoint in ("stage", "backup", "retired"), "unknown target slot")
        return self.fd, row[endpoint]

    def _observe(self, row: dict[str, Any], endpoint: str) -> dict[str, Any] | None:
        fd, name = self._endpoint(row, endpoint)
        found = _read_file(fd, name, self.cancellation, _SMALL)
        return None if found is None else found[0]

    def replace_all(self, replacements: tuple[TargetReplacement, ...]) -> None:
        self._check()
        self.cancellation.check()
        _need(not self.prepared and not self.records and type(replacements) is tuple
              and len(replacements) <= 2, "target batch must be selected once")
        paths, roles = [], set()
        for item in replacements:
            _need(type(item) is TargetReplacement and item.role not in roles
                  and type(item.content) is bytes and 0 < len(item.content) <= _SMALL,
                  "invalid selected target")
            path = _target_path(item.role, str(item.relative))
            normalized = unicodedata.normalize("NFC", str(path)).casefold()
            _need(all(normalized != other and not normalized.startswith(other + "/")
                      and not other.startswith(normalized + "/") for other in paths), "target paths overlap")
            roles.add(item.role)
            paths.append(normalized)
            index = len(self.records)
            row = dict(role=item.role, relative=str(path), parents=[], original=None, original_current=None,
                       new=None, new_current=None, stage=f"stage-{index}", backup=f"backup-{index}",
                       retired=f"retired-{index}", move=None, restored=False, conflict=False)
            self.records.append(row)
            parent = self._parent(row, planning=True)
            _names(parent.fd)
            original = _read_file(parent.fd, path.name, self.cancellation, _SMALL)
            if original is None:
                _name_absent(parent.fd, path.name)
            row["original"] = row["original_current"] = None if original is None else original[0]
            if original is not None:
                _need(original[0]["device"] == self.identity["device"], "target is on another filesystem")
        # Every original and parent has been observed before creating stages or moving any target.
        self._probe_exclusive_move()
        for row, item in zip(self.records, replacements):
            row["new"] = row["new_current"] = self._write(self.fd, row["stage"], item.content, limit=_SMALL)
        intent = dict(schemaVersion=1, session=self.token, header=self.header_digest,
                      targets=[{key: row[key] for key in ("role", "relative", "parents", "original", "new",
                                                        "stage", "backup", "retired")} for row in self.records])
        self.intent_digest = self._publish_control("intent.json", intent)
        self.prepared = True
        self._checkpoint()
        for row in self.records:
            _need(self._observe(row, "target") == row["original"], "target changed after planning")
        for row in self.records:
            if row["original"] is not None:
                self._move(row, "target", "backup", "original_current")
            self._move(row, "stage", "target", "new_current")
        self.cancellation.check()

    def _settle_move(self, row: dict[str, Any]) -> None:
        pending = row["move"]
        if pending is None:
            return
        source, destination = self._observe(row, pending["source"]), self._observe(row, pending["destination"])
        expected = pending["binding"]
        if source == expected and destination is None:
            row["move"] = None  # Positively no filesystem effect, not a replay grant.
        elif source is None and destination is not None and _same_object(destination, expected, renamed=True):
            row[pending["field"]] = destination
            row["move"] = None
        else:
            row["conflict"] = True
            raise BuildInputError("build inputs: exclusive move ownership is ambiguous")

    def _move(self, row: dict[str, Any], source: str, destination: str, field: str) -> None:
        self._check()
        self._settle_move(row)
        binding = row[field]
        _need(binding is not None and self._observe(row, source) == binding
              and self._observe(row, destination) is None, "move would clobber changed ownership")
        row["move"] = dict(source=source, destination=destination, field=field, binding=binding)
        self._checkpoint()  # Write-before-move, including a possible after-effect exception.
        error: BaseException | None = None
        try:
            source_fd, source_name = self._endpoint(row, source)
            destination_fd, destination_name = self._endpoint(row, destination)
            _name_absent(destination_fd, destination_name)
            self.project.rename(source_fd, source_name, destination_fd, destination_name)
            os.fsync(source_fd)
            if source_fd != destination_fd:
                os.fsync(destination_fd)
        except BaseException as caught:
            self.cancellation.lifetime_ledger._remember(caught)
            error = caught
        try:
            self._settle_move(row)
            self._checkpoint()
        except BaseException as reconciliation_error:
            self.cancellation._abort(reconciliation_error)
            if error is not None:
                # An original interruption/primary cannot be replaced by a
                # later observation, persistence or cleanup failure.
                raise error from None
            raise
        if error is not None:
            raise error

    def _restore(self, row: dict[str, Any]) -> None:
        _need(not row["conflict"], "earlier target conflict requires a fresh recovery invocation")
        self._settle_move(row)
        original, current = row["original_current"], self._observe(row, "target")
        if current != original:
            if current is not None:
                _need(current == row["new_current"], "intervening target must be preserved")
                self._move(row, "target", "retired", "new_current")
            if original is not None:
                _need(self._observe(row, "backup") == original, "original backup is missing or changed")
                self._move(row, "backup", "target", "original_current")
            _need(self._observe(row, "target") == row["original_current"], "target restoration is unconfirmed")
        else:
            _need(self._observe(row, "backup") is None, "original has contradictory locations")
        for endpoint in ("stage", "retired"):
            value = self._observe(row, endpoint)
            if value is not None:
                _need(value == row["new_current"], "retired publication changed")
                fd, name = self._endpoint(row, endpoint)
                os.unlink(name, dir_fd=fd)
                os.fsync(fd)
        row["restored"] = True
        self._checkpoint()

    def _finish(self) -> None:
        _check_creation(self.creation, self.identity)
        if not self.created:
            return
        self._check()
        _need(self.header_digest and not self.failed, "incomplete transaction controls must be preserved")
        if self.invocation is not None:
            _need(_consumer_idle(self.cancellation), "original material consumers are unconfirmed")
            self.quiescence = "original"
            self._checkpoint()
        _need(self.quiescence in ("original", "operator"), "recovery needs original or explicit operator quiescence")
        actions = []
        for row in reversed(self.records):
            def restore(row=row):
                try:
                    self._restore(row)
                except BaseException:
                    row["conflict"] = True
                    raise
            actions.append(restore)
        actions.append(lambda: self.scratch._dispose(recovery_idle=self.invocation is None))
        try:
            _attempt_all(self.cancellation, actions)
        except BaseException as original_error:
            if not self.failed:
                try:
                    # Explicit recovery reaches this error path outside an
                    # enclosing cleanup deferral. Persist settlement metadata
                    # under the same fatal guard, without replacing its primary.
                    with self.cancellation.deferred(check_on_exit=False):
                        self._checkpoint()
                except BaseException as checkpoint_error:
                    self.cancellation._abort(checkpoint_error)
            raise original_error
        _need(all(row["restored"] for row in self.records), "target settlement is incomplete")
        self._check()
        expected = set(self.controls)
        _need(_names(self.fd) == expected, "unknown transaction entry prevents terminal retirement")
        inventory = []
        for name in sorted(expected):
            found = _read_file(self.fd, name, self.cancellation, _CONTROL, private=True)
            _need(found is not None and found[0] == self.controls[name], "transaction metadata changed")
            inventory.append({"name": name, "binding": found[0]})
        terminal = dict(schemaVersion=1, session=self.token, root=self.project.identity,
            private=self.project.meta_identity, pending=self.identity, header=self.header_digest,
            intent=self.intent_digest, quiescence=self.quiescence, metadata=inventory)
        meta = self.project.meta.number
        assert meta is not None
        stage_binding = self._write(meta, _TERMINAL_STAGE, _json(terminal))
        self.project.rename(meta, _TERMINAL_STAGE, meta, _TERMINAL)
        found = _read_file(meta, _TERMINAL, self.cancellation, _CONTROL, private=True)
        _need(found is not None and _same_object(found[0], stage_binding, renamed=True),
              "terminal publication changed")
        os.fsync(meta)
        _retire_terminal(self.project, terminal, found[0])
        self.creation["state"] = "RETIRED"
        self.created = False

    def cleanup(self) -> None:
        self._owner()
        if self.claimed:
            return
        self.claimed = True
        _attempt_all(self.cancellation, [self._finish,
            *[slot.close for slot in reversed(self.scratch.writer_slots)],
            self.scratch.slot.close, self.scratch.parent.close,
            *[parent.close for parent in reversed(tuple(self.parents.values()))],
            *[slot.close for slot in reversed(self.control_slots)], self.slot.close])

    def fork_close(self) -> None:
        self.scratch.fork_close()
        for parent in reversed(tuple(self.parents.values())):
            parent.fork_close()
        for slot in reversed(self.control_slots):
            slot.close()
        self.slot.close()


def _terminal_control(project: _Project) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if project.meta.number is None:
        return None
    _need(_stat(project.meta.number, _TERMINAL_STAGE) is None, "terminal staging ownership is incomplete")
    found = _read_file(project.meta.number, _TERMINAL, project.guard, _CONTROL, private=True)
    if found is None:
        return None
    terminal = _parse(found[1])
    _need(set(terminal) == {"schemaVersion", "session", "root", "private", "pending", "header",
                            "intent", "quiescence", "metadata"}
          and terminal["schemaVersion"] == 1 and type(terminal["schemaVersion"]) is int
          and type(terminal["session"]) is str and _TOKEN.fullmatch(terminal["session"])
          and terminal["root"] == project.identity and terminal["private"] == project.meta_identity
          and _valid_binding(terminal["pending"], directory=True)
          and type(terminal["header"]) is str and _DIGEST.fullmatch(terminal["header"])
          and (terminal["intent"] is None or type(terminal["intent"]) is str and _DIGEST.fullmatch(terminal["intent"]))
          and terminal["quiescence"] in ("original", "operator")
          and type(terminal["metadata"]) is list and len(terminal["metadata"]) <= _MAX_CHECKPOINTS + 2,
          "invalid terminal authority")
    seen = set()
    for entry in terminal["metadata"]:
        _need(type(entry) is dict and set(entry) == {"name", "binding"}
              and type(entry["name"]) is str
              and (entry["name"] in ("header.json", "intent.json")
                   or re.fullmatch(r"checkpoint-\d{3}\.json", entry["name"]))
              and entry["name"] not in seen and _valid_binding(entry["binding"])
              and entry["binding"]["uid"] == os.geteuid() and entry["binding"]["mode"] == 0o600
              and entry["binding"]["device"] == terminal["pending"]["device"]
              and entry["binding"]["size"] <= _CONTROL, "invalid terminal inventory")
        seen.add(entry["name"])
    _need("header.json" in seen and "checkpoint-000.json" in seen, "terminal inventory is incomplete")
    controls = {entry["name"]: entry["binding"] for entry in terminal["metadata"]}
    checkpoint_names = sorted(name for name in seen if name.startswith("checkpoint-"))
    _need(checkpoint_names == [f"checkpoint-{i:03}.json" for i in range(len(checkpoint_names))]
          and controls["header.json"]["sha256"] == terminal["header"]
          and ((terminal["intent"] is None and "intent.json" not in controls)
               or "intent.json" in controls and controls["intent.json"]["sha256"] == terminal["intent"]),
          "terminal provenance inventory is inconsistent")
    return terminal, found[0]


def _retire_terminal(project: _Project, terminal: dict[str, Any], binding: dict[str, Any]) -> None:
    """Metadata only. Never inspect a historical application target here."""
    project.check()
    meta = project.meta.number
    assert meta is not None
    slot = _FD(project.guard)
    with _fd_cleanup(slot):
        pending = _stat(meta, _PENDING)
        if pending is not None:
            _need(_directory(pending) == terminal["pending"], "terminal pending directory changed")
            number = slot.open(_PENDING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=meta)
            _need(_directory(os.fstat(number)) == terminal["pending"], "terminal directory changed while opening")
            inventory = {item["name"]: item["binding"] for item in terminal["metadata"]}
            _need(_names(number) <= set(inventory), "unknown residual terminal metadata")
            actions = []
            for name, expected in inventory.items():
                def remove(name=name, expected=expected):
                    found = _read_file(number, name, project.guard, _CONTROL, private=True)
                    if found is not None:
                        _need(found[0] == expected, "terminal metadata changed")
                        os.unlink(name, dir_fd=number)
                actions.append(remove)
            _attempt_all(project.guard, actions)
            _need(not _names(number) and _directory(os.stat(_PENDING, dir_fd=meta, follow_symlinks=False))
                  == terminal["pending"], "terminal directory did not settle")
            os.rmdir(_PENDING, dir_fd=meta)
            os.fsync(meta)
    found = _read_file(meta, _TERMINAL, project.guard, _CONTROL, private=True)
    _need(found is not None and found[0] == binding, "terminal control changed before retirement")
    os.unlink(_TERMINAL, dir_fd=meta)
    os.fsync(meta)


def _load_pending(owner: BuildInputs) -> None:
    """Load only inside the caller's prearmed inspection lifetime."""
    project = owner.project
    meta = project.meta.number
    _need(meta is not None, "pending metadata is absent")
    number = owner.slot.open(_PENDING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=meta)
    owner.identity = _directory(os.fstat(number))
    owner.created = True
    _need(owner.identity["uid"] == os.geteuid() and owner.identity["mode"] == 0o700,
          "pending directory is not private")
    header = _read_file(number, "header.json", project.guard, _CONTROL, private=True)
    _need(header is not None, "original header is missing")
    owner.header = _parse(header[1])
    _need(set(owner.header) == {"schemaVersion", "session", "root", "private", "pending", "scratch"}
          and type(owner.header["schemaVersion"]) is int and owner.header["schemaVersion"] == 1
          and type(owner.header["session"]) is str and _TOKEN.fullmatch(owner.header["session"])
          and owner.header["root"] == project.identity and owner.header["private"] == project.meta_identity
          and owner.header["pending"] == owner.identity
          and _valid_binding(owner.header["scratch"], directory=True)
          and owner.header["scratch"]["uid"] == os.geteuid()
          and owner.header["scratch"]["mode"] == 0o700
          and owner.header["scratch"]["device"] == owner.identity["device"], "invalid original header")
    owner.token, owner.header_digest = owner.header["session"], header[0]["sha256"]
    owner.controls["header.json"] = header[0]
    owner._check()
    names = _names(number)
    checkpoints = sorted(name for name in names if re.fullmatch(r"checkpoint-\d{3}\.json", name))
    _need(checkpoints and len(checkpoints) <= _MAX_CHECKPOINTS
          and checkpoints == [f"checkpoint-{i:03}.json" for i in range(len(checkpoints))],
          "checkpoint sequence is missing or ambiguous")
    intent = _read_file(number, "intent.json", project.guard, _CONTROL, private=True)
    immutable = None
    if intent is not None:
        immutable = _parse(intent[1])
        _need(set(immutable) == {"schemaVersion", "session", "header", "targets"}
              and type(immutable["schemaVersion"]) is int and immutable["schemaVersion"] == 1
              and immutable["session"] == owner.token and immutable["header"] == owner.header_digest
              and type(immutable["targets"]) is list and len(immutable["targets"]) <= 2,
              "invalid immutable target intent")
        owner.intent_digest = intent[0]["sha256"]
        owner.controls["intent.json"] = intent[0]
    previous = None
    last = None
    for sequence, name in enumerate(checkpoints):
        found = _read_file(number, name, project.guard, _CONTROL, private=True)
        assert found is not None
        payload = _parse(found[1])
        _need(set(payload) == {"schemaVersion", "session", "header", "intent", "sequence", "previous",
                               "prepared", "quiescence", "targets", "scratch"}
              and type(payload["schemaVersion"]) is int and payload["schemaVersion"] == 1
              and payload["session"] == owner.token and payload["header"] == owner.header_digest
              and type(payload["sequence"]) is int and payload["sequence"] == sequence
              and payload["previous"] == previous and type(payload["prepared"]) is bool
              and payload["intent"] in (None, owner.intent_digest)
              and payload["quiescence"] in ("none", "original", "operator")
              and type(payload["targets"]) is list and len(payload["targets"]) <= 2
              and type(payload["scratch"]) is dict,
              "invalid original checkpoint")
        previous, last = found[0]["sha256"], payload
        owner.controls[name] = found[0]
    assert last is not None
    owner.seq, owner.previous = len(checkpoints) - 1, previous
    owner.prepared, owner.quiescence = last["prepared"], last["quiescence"]
    owner.records, owner.scratch.records = last["targets"], last["scratch"]
    _need((not owner.prepared and not owner.records and immutable is None)
          or owner.prepared and immutable is not None and last["intent"] == owner.intent_digest
          and len(immutable["targets"]) == len(owner.records), "target preparation is incomplete")
    roles, targets = set(), set()
    for index, row in enumerate(owner.records):
        _need(type(row) is dict and set(row) == {"role", "relative", "parents", "original", "original_current",
            "new", "new_current", "stage", "backup", "retired", "move", "restored", "conflict"},
            "invalid target record")
        _target_path(row["role"], row["relative"])
        _need(row["role"] not in roles and row["relative"] not in targets
              and type(row["restored"]) is bool and type(row["conflict"]) is bool
              and row["stage"] == f"stage-{index}" and row["backup"] == f"backup-{index}"
              and row["retired"] == f"retired-{index}", "duplicate or invalid target slots")
        roles.add(row["role"])
        targets.add(row["relative"])
        original_fields = {key: row[key] for key in ("role", "relative", "parents", "original", "new",
                                                    "stage", "backup", "retired")}
        _need(original_fields == immutable["targets"][index], "target differs from immutable intent")
        _need(_valid_binding(row["new"]) and _valid_binding(row["new_current"])
              and row["new"]["uid"] == os.geteuid() and row["new"]["mode"] == 0o600
              and row["new"]["links"] == 1 and 0 < row["new"]["size"] <= _SMALL
              and row["new"]["device"] == owner.identity["device"]
              and _same_object(row["new"], row["new_current"], renamed=True)
              and ((row["original"] is None and row["original_current"] is None)
                   or _valid_binding(row["original"]) and _valid_binding(row["original_current"])
                   and row["original"]["size"] <= _SMALL and not row["original"]["mode"] & 0o7000
                   and row["original"]["device"] == owner.identity["device"]
                   and _same_object(row["original"], row["original_current"], renamed=True)),
              "target object authority changed")
        pending = row["move"]
        if pending is not None:
            _need(type(pending) is dict and set(pending) == {"source", "destination", "field", "binding"}
                  and (pending["source"], pending["destination"], pending["field"]) in {
                      ("target", "backup", "original_current"), ("stage", "target", "new_current"),
                      ("target", "retired", "new_current"), ("backup", "target", "original_current")}
                  and pending["binding"] == row[pending["field"]], "invalid pending move")
        owner._parent(row)
    scratch_names = set()
    for role, record in owner.scratch.records.items():
        spec = owner.scratch._spec(role)
        _need(type(record) is dict and set(record) == {"binding", "created"}
              and _valid_binding(record["binding"]) and record["binding"]["size"] <= spec.limit
              and record["binding"]["uid"] == os.geteuid() and record["binding"]["mode"] == 0o600
              and record["binding"]["links"] == 1
              and type(record["created"]) is dict
              and set(record["created"]) == set(record["binding"]) - {"sha256"}
              and all(record["created"][key] == record["binding"][key]
                      for key in ("device", "inode", "uid", "gid", "mode", "links"))
              and record["created"]["size"] == 0
              and spec.direction == "input", "unknown scratch creation ownership")
        scratch_names.add(spec.name)
    expected = set(owner.controls) | {"scratch"}
    expected |= {row[key] for row in owner.records for key in ("stage", "backup", "retired")}
    _need(names <= expected, "unknown transaction entry must be preserved")
    scratch_entry = _stat(number, "scratch")
    if scratch_entry is not None:
        owner.scratch.parent.acquire()
        owner.scratch.slot.open("scratch", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=owner.scratch.parent.fd)
        owner.scratch.identity = owner.header["scratch"]
        owner.scratch.created, owner.scratch.active = True, True
        owner.scratch._check()
        _need(_names(owner.scratch.slot.number) <= scratch_names, "unexpected pending scratch entry")  # type: ignore[arg-type]
    else:
        # A completed scratch removal can precede the next checkpoint.
        _need(owner.quiescence != "none", "scratch absence has no original finality")


@contextmanager
def _pending_inspection(project: _Project) -> Iterator[BuildInputs]:
    # Construction is acquisition-free. No FD-bearing return crosses from an
    # unowned loader into the public caller: this scope owns the full lifetime.
    owner, guard = BuildInputs(None, project), project.guard

    def close() -> None:
        # Enumerate at exit, including control FDs created by explicit recovery.
        # Never call _finish/cleanup: inspection failure is no retry authority.
        _attempt_all(guard, [*[slot.close for slot in reversed(owner.scratch.writer_slots)],
            owner.scratch.slot.close, owner.scratch.parent.close,
            *[parent.close for parent in reversed(tuple(owner.parents.values()))],
            *[slot.close for slot in reversed(owner.control_slots)], owner.slot.close])

    scope = CleanupScope(guard, close, owns_cancellation=False,
                         fork_cleanup=owner.fork_close, first_primary=True)
    try:
        try:
            with scope:
                _load_pending(owner)
                guard.check()
                yield owner
        finally:
            scope.__exit__(*sys.exc_info())
        _need(guard.pid == os.getpid(), "inherited inspection cannot publish parent completion")
        guard.check()
    except BaseException as error:
        if guard.pid == os.getpid():
            fatal = fatal_cancellation_error(error, guard, "build-input inspection lifetime did not settle")
            if fatal is not None:
                raise fatal from None
        raise


@contextmanager
def _inspection(root: Path, cancellation: DefaultCancellation | None) -> Iterator[_Project]:
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "build-input recovery ownership did not settle")
    project = _Project(root, guard, recovery=True)
    with _scope(project, guard, owns):
        yield project


def build_inputs_status(root: Path, *, cancellation: DefaultCancellation | None = None) -> dict[str, Any]:
    try:
        with _inspection(root, cancellation) as project:
            terminal = _terminal_control(project)
            if terminal is not None:
                return {"status": "cleanup-only", "session": terminal[0]["session"]}
            if project.meta.number is None or _stat(project.meta.number, _PENDING) is None:
                return {"status": "idle"}
            with _pending_inspection(project) as owner:
                return {"status": "pending", "session": owner.token,
                        "roles": sorted(row["role"] for row in owner.records)}
    except ProcessError:
        raise
    except BuildInputError as error:
        if str(error) == "build inputs: another owner holds this project":
            return {"status": "busy"}
        return {"status": "conflict"}


def recover_build_inputs(root: Path, *, session: str, confirm: str, manual: bool = False,
                         cancellation: DefaultCancellation | None = None,
                         input_stream: Any = None, output_stream: Any = None) -> dict[str, Any]:
    _need(type(session) is str and bool(_TOKEN.fullmatch(session)) and confirm == _CONFIRM
          and type(manual) is bool, "recovery requires the exact session and confirmation")
    with _inspection(root, cancellation) as project:
        terminal = _terminal_control(project)
        if terminal is not None:
            _need(terminal[0]["session"] == session, "another terminal session is present")
            _retire_terminal(project, *terminal)
            return {"status": "recovered", "session": session}
        if project.meta.number is None or _stat(project.meta.number, _PENDING) is None:
            return {"status": "absent", "session": session}
        with _pending_inspection(project) as owner:
            _need(owner.token == session, "another pending session is present")
            if owner.quiescence == "none":
                _need(manual, "original consumer finality is missing; explicit manual quiescence is required")
                incoming, outgoing = input_stream or sys.stdin, output_stream or sys.stdout
                _need(incoming.isatty() and outgoing.isatty(), "manual recovery requires an interactive terminal")
                outgoing.write("Establish that this session's exact original workers are idle.\n")
                for row in owner.records:
                    outgoing.write(f"{row['role']}: {row['relative']}\n")
                outgoing.write(f"Type recheck {session} original-workers-are-idle: ")
                outgoing.flush()
                _need(incoming.readline(256).rstrip("\n") == f"recheck {session} original-workers-are-idle",
                      "manual recheck did not confirm exact-worker quiescence")
                project.guard.check()
                owner.quiescence = "operator"  # New explicit fact, never repaired historical containment.
                owner._checkpoint()
            for row in owner.records:
                row["conflict"] = False  # Fresh explicit observation attempt, not an implicit in-context retry.
            owner._finish()
            return {"status": "recovered", "session": session}
