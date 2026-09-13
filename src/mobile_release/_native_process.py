"""Private, explicit native-child acquisition; not a command runner.

The owner must exclusively wait its exact children from BEFORE creation through
accounting, and keep SIGCHLD waitable throughout.  The read-only policy snapshot
does not detect a hostile outside reaper.  A creator is an already-owned thread:
this module neither starts a task nor installs a handler, reaper or finalizer.

Acquisition/FD slots must remain rooted by the owner through actual creator joins.
``settled`` says only that this leaf has no call in flight; it is NOT a task join,
a no-producer proof, or permission to discard UNKNOWN custody.  Group authority,
deadlines, cancellation, protocol admission and scratch finality belong to the
profile owner.  Importing this module loads no CDLL and acquires no descriptor.
"""
from __future__ import annotations

import os
import signal
import stat
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal


_MAX_ELEMENT = 8 * 1024
_MAX_VECTOR = 64
_MAX_COLLECTION = 64 * 1024
_MAX_CONFIGURATION = 128 * 1024
_MAX_LEASES = 64
_MAX_PID = (1 << 31) - 1
_CHILD_KEY = object()


class NativeProcessError(RuntimeError):
    """A fixed, non-secret native ownership/capability failure."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeProcessError(message)


def _string(value: str) -> bytes:
    _require(type(value) is str and "\0" not in value,
             "native process argument type differs")
    try:
        raw = os.fsencode(value)
    except (UnicodeError, ValueError):
        raise NativeProcessError("native process argument encoding differs") from None
    _require(len(raw) <= _MAX_ELEMENT, "native process argument exceeds its bound")
    return raw


@dataclass(frozen=True, slots=True)
class SpawnSpec:
    executable: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    fd_sources: tuple[FDLease, ...]

    def __post_init__(self) -> None:
        path = _string(self.executable)
        _require(path.startswith(b"/"), "native executable must be absolute")
        _require(type(self.argv) is tuple and 0 < len(self.argv) <= _MAX_VECTOR
                 and self.argv[0] == self.executable,
                 "native process argv contract differs")
        arguments = tuple(_string(value) for value in self.argv)
        _require(type(self.env) is tuple and len(self.env) <= _MAX_VECTOR,
                 "native process environment contract differs")
        keys, environment = set(), []
        for item in self.env:
            _require(type(item) is tuple and len(item) == 2,
                     "native process environment entry differs")
            key, value = item
            encoded_key, encoded_value = _string(key), _string(value)
            _require(bool(encoded_key) and b"=" not in encoded_key and key not in keys,
                     "native process environment key differs")
            keys.add(key)
            combined = encoded_key + b"=" + encoded_value
            _require(len(combined) <= _MAX_ELEMENT,
                     "native process environment entry exceeds its bound")
            environment.append(combined)
        argv_size = sum(len(value) + 1 for value in arguments)
        env_size = sum(len(value) + 1 for value in environment)
        _require(argv_size <= _MAX_COLLECTION and env_size <= _MAX_COLLECTION
                 and argv_size + env_size <= _MAX_CONFIGURATION,
                 "native process vectors exceed their bound")
        _require(type(self.fd_sources) is tuple and len(self.fd_sources) in (3, 8)
                 and all(type(source) is FDLease for source in self.fd_sources),
                 "native child descriptor map differs")


@dataclass(frozen=True, slots=True)
class WaitReceipt:
    pid: int
    status_kind: Literal["exit", "signal"]
    status_code: int
    raw_status: int


@dataclass(slots=True)
class _Call:
    name: str
    roots: tuple[Any, ...] = ()
    state: str = "PREPARED"
    value: Any = None
    errno: int | None = None


@dataclass(slots=True)
class _Container:
    name: str
    storage: Any
    state: str = "NEW"


@dataclass(slots=True)
class _ABI:
    c: Any
    family: str
    architecture: str
    sigaction: Any
    file_actions: Any
    attributes: Any
    constants: dict[str, Any]
    functions: dict[str, Any]


def _abi_types() -> _ABI:
    # ctypes and the loaded-library handle are deliberately not import effects.
    import ctypes as c

    _require(sys.implementation.name == "cpython" and sys.version_info >= (3, 11),
             "native process requires supported CPython")
    _require(sys.platform in ("linux", "darwin") and sys.byteorder == "little",
             "native process platform ABI is unavailable")
    machine = os.uname().machine
    _require(machine in ("x86_64", "arm64", "aarch64"),
             "native process architecture ABI is unavailable")
    family = "linux-glibc" if sys.platform == "linux" else "darwin"
    architecture = "arm64" if machine in ("arm64", "aarch64") else "x86_64"

    if family == "linux-glibc":
        class Sigaction(c.Structure):
            _fields_ = [("handler", c.c_void_p), ("mask", c.c_ulong * 16),
                        ("flags", c.c_int), ("restorer", c.c_void_p)]

        class FileActions(c.Structure):
            _fields_ = [("allocated", c.c_int), ("used", c.c_int),
                        ("actions", c.c_void_p), ("pad", c.c_int * 16)]

        attributes = None
    else:
        class Sigaction(c.Structure):
            _fields_ = [("handler", c.c_void_p), ("mask", c.c_uint), ("flags", c.c_int)]

        FileActions = c.c_void_p
        attributes = c.c_void_p

    constants = {
        "SIG_IGN": 1, "SA_NOCLDWAIT": 2 if family == "linux-glibc" else 32,
        "SIGCHLD": int(signal.SIGCHLD), "NSIG": int(signal.NSIG),
        "F_DUPFD_CLOEXEC": 1030 if family == "linux-glibc" else 67,
        "F_GETFD": 1, "F_GETFL": 3, "FD_CLOEXEC": 1,
        "O_RDONLY": os.O_RDONLY, "O_WRONLY": os.O_WRONLY,
        "O_RDWR": os.O_RDWR, "O_ACCMODE": os.O_ACCMODE,
        "POSIX_SPAWN_CLOEXEC_DEFAULT": None if family == "linux-glibc" else 0x4000,
    }

    def signature(*args: str, variadic: bool = False) -> dict:
        return {"return": "int", "args": list(args), "variadic": variadic}

    functions = {
        "fcntl": signature("int", "int", variadic=True),
        "close": signature("int"),
        "sigaction": signature("int", "pointer", "pointer"),
        "posix_spawn": signature(*(["pointer"] * 6)),
        "posix_spawn_file_actions_init": signature("pointer"),
        "posix_spawn_file_actions_destroy": signature("pointer"),
        "posix_spawn_file_actions_adddup2": signature("pointer", "int", "int"),
        "posix_spawn_file_actions_addclosefrom_np": (
            signature("pointer", "int") if family == "linux-glibc" else None),
        "posix_spawnattr_init": signature("pointer") if family == "darwin" else None,
        "posix_spawnattr_destroy": signature("pointer") if family == "darwin" else None,
        "posix_spawnattr_setflags": signature("pointer", "short") if family == "darwin" else None,
        "posix_spawnattr_getflags": signature("pointer", "pointer") if family == "darwin" else None,
    }
    return _ABI(c, family, architecture, Sigaction, FileActions, attributes, constants, functions)


def _abi_record(abi: _ABI) -> dict:
    c = abi.c

    def scalar(ctype: Any) -> dict:
        return {"size": c.sizeof(ctype), "align": c.alignment(ctype)}

    def fields(ctype: Any) -> dict:
        return {name: {"offset": getattr(ctype, name).offset, "size": c.sizeof(kind)}
                for name, kind in ctype._fields_}

    sigaction_fields = fields(abi.sigaction)
    sigaction_fields.setdefault("restorer", None)
    return {
        "schema": "mrk-native-process-abi-v1", "family": abi.family,
        "architecture": abi.architecture, "byteorder": sys.byteorder,
        "scalars": {"pointer": scalar(c.c_void_p), "int": scalar(c.c_int),
                    "short": scalar(c.c_short), "long": scalar(c.c_long),
                    "pid_t": {**scalar(c.c_int), "signed": c.c_int(-1).value == -1}},
        "sigaction": {**scalar(abi.sigaction), "fields": sigaction_fields},
        "file_actions": {"kind": "struct" if abi.family == "linux-glibc" else "pointer_slot",
                         **scalar(abi.file_actions),
                         "fields": fields(abi.file_actions) if abi.family == "linux-glibc" else {}},
        "spawn_attributes": (None if abi.attributes is None else
                             {"kind": "pointer_slot", **scalar(abi.attributes), "fields": {}}),
        "constants": dict(abi.constants),
        "functions": {name: (None if spec is None else
                             {"return": spec["return"], "args": list(spec["args"]),
                              "variadic": spec["variadic"]})
                      for name, spec in abi.functions.items()},
    }


def declared_abi() -> dict:
    """Describe actual ctypes declarations without the acquisition's C bindings.

    The lazy stdlib ctypes import initializes its own default Python-API handle;
    this is not a literal zero-FFI operation or a native-platform proof.
    """
    return _abi_record(_abi_types())


def _admit_abi(abi: _ABI) -> None:
    record = _abi_record(abi)
    for name, size in (("pointer", 8), ("int", 4), ("short", 2), ("long", 8), ("pid_t", 4)):
        scalar = record["scalars"][name]
        _require(scalar["size"] == scalar["align"] == size,
                 "native process scalar ABI differs")
    _require(record["scalars"]["pid_t"]["signed"], "native process pid ABI differs")
    expected_sigaction = {
        "handler": {"offset": 0, "size": 8},
        "mask": {"offset": 8, "size": 128 if abi.family == "linux-glibc" else 4},
        "flags": {"offset": 136 if abi.family == "linux-glibc" else 12, "size": 4},
        "restorer": {"offset": 144, "size": 8} if abi.family == "linux-glibc" else None,
    }
    _require(record["sigaction"] == {"size": 152 if abi.family == "linux-glibc" else 16,
                                     "align": 8, "fields": expected_sigaction},
             "native process signal ABI differs")
    if abi.family == "linux-glibc":
        _require(record["file_actions"] == {
            "kind": "struct", "size": 80, "align": 8,
            "fields": {"allocated": {"offset": 0, "size": 4},
                       "used": {"offset": 4, "size": 4},
                       "actions": {"offset": 8, "size": 8},
                       "pad": {"offset": 16, "size": 64}}},
            "native process file-action ABI differs")
    else:
        slot = {"kind": "pointer_slot", "size": 8, "align": 8, "fields": {}}
        _require(record["file_actions"] == record["spawn_attributes"] == slot,
                 "native process public pointer-slot ABI differs")
    _require(abi.constants["SIGCHLD"] == (17 if abi.family == "linux-glibc" else 20)
             and abi.constants["NSIG"] == (65 if abi.family == "linux-glibc" else 32)
             and tuple(abi.constants[key] for key in ("O_RDONLY", "O_WRONLY", "O_RDWR", "O_ACCMODE"))
             == (0, 1, 2, 3), "native process public constants differ")


class _Native:
    """One rooted handle/function set per acquisition; no shared mutable FFI CIF."""

    def __init__(self) -> None:
        self.abi = _abi_types()
        _admit_abi(self.abi)
        c = self.abi.c
        # Resolve only already-loaded public runtime symbols, never find_library,
        # a PATH command, a private interpreter API, or a downloaded library.
        self.library = c.CDLL(None, use_errno=True)
        self.functions: dict[str, Any] = {}
        self.last_errno = 0
        types = {"pointer": c.c_void_p, "int": c.c_int, "short": c.c_short}
        for name, spec in self.abi.functions.items():
            if spec is None:
                continue
            try:
                function = self.library[name]
            except (AttributeError, OSError):
                raise NativeProcessError("native process public function is unavailable") from None
            function.argtypes = [types[item] for item in spec["args"]]
            function.restype = types[spec["return"]]
            self.functions[name] = function
        if self.abi.family == "linux-glibc":
            try:
                version = self.library["gnu_get_libc_version"]
                version.argtypes, version.restype = [], c.c_char_p
                self.libc_version_function = version
                raw = version()
                _require(type(raw) is bytes and 0 < len(raw) <= 32,
                         "native process libc identity differs")
                numbers = raw.split(b".")
                _require(len(numbers) >= 2 and all(value.isdigit() for value in numbers[:2])
                         and tuple(int(value) for value in numbers[:2]) >= (2, 34),
                         "native process requires the public glibc closefrom API")
            except (AttributeError, OSError, ValueError):
                raise NativeProcessError("native process libc identity is unavailable") from None

    def call(self, name: str, *arguments: Any) -> int:
        if name == "fcntl":
            # Two FIXED arguments, then a typed variadic int.  In particular do
            # not declare three fixed arguments on Darwin arm64.
            fd, command, value = arguments
            result = self.functions[name](fd, command, self.abi.c.c_int(value))
        else:
            result = self.functions[name](*arguments)
        self.last_errno = self.abi.c.get_errno()
        return result


class Acquisition:
    """Prepublished custody for one creator, or a role-local original-IO owner."""

    def __init__(self, *, failure_recorder: Callable[[BaseException], None] | None = None) -> None:
        _require(failure_recorder is None or callable(failure_recorder),
                 "native acquisition failure recorder differs")
        self._failure_recorder = failure_recorder
        self._first_error: BaseException | None = None
        self._recorder_error: BaseException | None = None
        self._creator: threading.Thread | None = None
        self._check_callback: Callable[[], None] | None = None
        self._grant_used = False
        self._launch_retired = False
        self._state = "CONFIGURING"
        self._attempted = False
        self._create_started = False
        self._create_running = False
        self._active_calls = 0
        self._native: _Native | None = None
        self._native_ready = False
        self._calls: list[_Call] = []
        self._leases: list[FDLease] = []
        self._borrowed: list[FDLease] = []
        self._prepared: _Prepared | None = None
        self._child: Child | None = None
        self._creation_unknown = False
        self._resource_unknown = False
        self._cleanup_errors: list[str] = []
        self._interruption: BaseException | None = None

    def grant(self, creator: threading.Thread, check: Callable[[], None]) -> None:
        _require(not self._grant_used and not self._launch_retired
                 and isinstance(creator, threading.Thread) and callable(check),
                 "native acquisition grant differs")
        self._creator, self._check_callback = creator, check
        self._grant_used = True

    def close_launch(self) -> None:
        self._launch_retired = True

    @property
    def launch_retired(self) -> bool:
        return self._launch_retired

    @property
    def child(self) -> Child | None:
        return self._child

    @property
    def attempted(self) -> bool:
        return self._attempted

    @property
    def state(self) -> str:
        return self._state

    @property
    def settled(self) -> bool:
        return not self._create_running and self._active_calls == 0

    @property
    def cleanup_unknown(self) -> bool:
        return self._creation_unknown or self._resource_unknown or any(lease.unknown for lease in self._leases)

    @property
    def cleanup_errors(self) -> tuple[str, ...]:
        return tuple(self._cleanup_errors)

    @property
    def interruption(self) -> BaseException | None:
        return self._interruption

    @property
    def leases(self) -> tuple[FDLease, ...]:
        return tuple(self._leases)

    def _record_error(self, error: BaseException) -> None:
        """Reach the owning common latch at the actual catch, before cleanup.

        This is ownership wiring, not a debug hook.  The owner synchronizes and
        deduplicates the same original object; neither side backdates errors or
        promotes a later interruption by class.  Keep the bound owner through
        late creator return and every later owned close/wait.
        """
        recording_failure: BaseException | None = None
        try:
            if self._failure_recorder is not None:
                self._failure_recorder(error)
        except BaseException as recording_error:
            recording_failure = recording_error
        finally:
            # The COMMON recording above precedes even these private latches.
            # Retain the original first interruption before the recorder's
            # possible later interruption, regardless of exception class.
            if self._first_error is None:
                self._first_error = error
            if self._interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                self._interruption = error
            self.close_launch()
            if recording_failure is not None:
                if self._recorder_error is None:
                    self._recorder_error = recording_failure
                # Never throw the recorder's failure in place of the original
                # or bypass the creator's required transient cleanup.
                self._remember("failure_record", recording_failure)

    def _remember(self, code: str, error: BaseException | None = None) -> None:
        self._resource_unknown = True
        self.close_launch()
        if self._interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
            self._interruption = error
        try:
            self._cleanup_errors.append(code)  # Only fixed internal codes reach here.
        except BaseException as recording_error:
            # Even failure to allocate an error-list entry must not replace
            # the first actual error or erase the already retained uncertainty.
            if self._interruption is None and isinstance(recording_error, (KeyboardInterrupt, SystemExit)):
                self._interruption = recording_error

    def _check(self) -> None:
        _require(self._grant_used and not self._launch_retired
                 and threading.current_thread() is self._creator,
                 "native acquisition launch is closed")
        assert self._check_callback is not None
        try:
            self._check_callback()
        except BaseException as error:
            self._record_error(error)
            self.close_launch()
            if self._interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                self._interruption = error
            raise
        _require(not self._launch_retired, "native acquisition launch is closed")

    def _runtime(self) -> _Native:
        self._check()
        if self._native is None:
            # Publish the containing object before CDLL/function setup too.
            native = _Native.__new__(_Native)
            self._native = native
            try:
                native.__init__()
                self._native_ready = True
            except BaseException as error:
                self._record_error(error)
                self.close_launch()
                if self._interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                    self._interruption = error
                raise
        _require(self._native_ready, "native process runtime admission is unavailable")
        return self._native

    def _invoke(self, name: str, function: Callable[..., Any], *arguments: Any,
                roots: tuple[Any, ...] = (), mutating: bool = True) -> Any:
        call = _Call(name, roots)
        self._calls.append(call)
        self._active_calls += 1
        call.state = "IN_FLIGHT"
        try:
            result = function(*arguments)
            call.value = result
            target = getattr(function, "__self__", None)
            if isinstance(target, _Native):
                call.errno = target.last_errno
            call.state = "RETURNED"
            return result
        except BaseException as error:
            self._record_error(error)
            call.state = "UNKNOWN"
            if mutating:
                self._remember(name, error)
            elif self._interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                self._interruption = error
            raise
        finally:
            self._active_calls -= 1

    def _new_lease(self) -> FDLease:
        _require(len(self._leases) < _MAX_LEASES, "native descriptor inventory exceeds its bound")
        lease = FDLease(self)
        self._leases.append(lease)
        return lease

    def pipe(self) -> tuple[FDLease, FDLease]:
        native = self._runtime()
        reader, writer = self._new_lease(), self._new_lease()
        try:
            self._check()
            reader._state = writer._state = "ACQUIRING"
            descriptors = self._invoke("pipe", os.pipe, roots=(reader, writer))
            _require(type(descriptors) is tuple and len(descriptors) == 2
                     and all(type(fd) is int and 0 <= fd <= _MAX_PID for fd in descriptors)
                     and descriptors[0] != descriptors[1], "native pipe publication differs")
            reader._publish(descriptors[0], native, os.O_RDONLY, "pipe")
            writer._publish(descriptors[1], native, os.O_WRONLY, "pipe")
            reader._validate()
            writer._validate()
            return reader, writer
        except BaseException as error:
            self._record_error(error)
            self.close_launch()
            for lease in (reader, writer):
                if lease._state == "ACQUIRING":
                    lease._state = "UNKNOWN"
                    self._remember("pipe_publication", error)
            raise

    def open_null(self, *, writable: bool) -> FDLease:
        _require(type(writable) is bool, "native null descriptor mode differs")
        native = self._runtime()
        lease = self._new_lease()
        access = os.O_WRONLY if writable else os.O_RDONLY
        try:
            self._check()
            lease._state = "ACQUIRING"
            descriptor = self._invoke("null_open", os.open, "/dev/null",
                                      access | os.O_CLOEXEC | os.O_NOFOLLOW, roots=(lease,))
            _require(type(descriptor) is int and 0 <= descriptor <= _MAX_PID,
                     "native null descriptor publication differs")
            lease._publish(descriptor, native, access, "null")
            lease._validate()
            return lease
        except BaseException as error:
            self._record_error(error)
            self.close_launch()
            if lease._state == "ACQUIRING":
                lease._state = "UNKNOWN"
                self._remember("null_publication", error)
            raise

    def adopt_fd(self, fd: int, *, access: int, kind: Literal["pipe", "null"]) -> FDLease:
        """Adopt ONLY the helper's positively owned fixed application endpoint.

        Caller first establishes the original bootstrap map; a supplied number
        alone is not ownership.  Native null stdio0--2 remain process-lifetime
        descriptors and cannot be adopted for raw close through this method.
        """
        _require(type(fd) is int and 3 <= fd <= 7
                 and type(access) is int and access in (os.O_RDONLY, os.O_WRONLY)
                 and kind in ("pipe", "null"), "native inherited descriptor role differs")
        native = self._runtime()
        _require(all(lease._original_fd != fd for lease in self._leases),
                 "native inherited descriptor was already adopted")
        lease = self._new_lease()
        changing = False
        try:
            lease._publish(fd, native, access, kind)
            lease._validate(require_cloexec=False)
            self._check()
            changing = True
            self._invoke("inherited_cloexec", os.set_inheritable, fd, False, roots=(lease,))
            lease._validate()
        except BaseException as error:
            self._record_error(error)
            self.close_launch()
            if changing:
                self._remember("inherited_cloexec", error)
            raise
        return lease


class FDLease:
    """An explicitly published raw FD.  No __del__, implicit close or retry."""

    def __init__(self, owner: Acquisition) -> None:
        self._owner = owner
        self._native: _Native | None = None
        self._fd: int | None = None
        self._original_fd: int | None = None
        self._access: int | None = None
        self._kind: str | None = None
        self._identity: tuple[int, int] | None = None
        self._validated = False
        self._state = "NEW"
        self._borrowers: set[Acquisition] = set()

    @property
    def state(self) -> str:
        return self._state

    @property
    def unknown(self) -> bool:
        return self._state in ("ACQUIRING", "CLOSE_IN_FLIGHT", "UNKNOWN")

    def _publish(self, fd: int, native: _Native, access: int, kind: str) -> None:
        _require(self._state in ("NEW", "ACQUIRING"), "native descriptor publication was repeated")
        self._fd = self._original_fd = fd
        self._native, self._access, self._kind = native, access, kind
        self._state = "OPEN"

    def _validate(self, *, require_cloexec: bool = True) -> None:
        _require(self._state == "OPEN" and self._fd is not None and self._native is not None,
                 "native descriptor is not owned")
        fd, native = self._fd, self._native
        info = self._owner._invoke("descriptor_stat", os.fstat, fd, roots=(self,), mutating=False)
        mode = self._owner._invoke("descriptor_mode", native.call, "fcntl", fd,
                                   native.abi.constants["F_GETFL"], 0, roots=(self,), mutating=False)
        flags = self._owner._invoke("descriptor_flags", native.call, "fcntl", fd,
                                    native.abi.constants["F_GETFD"], 0, roots=(self,), mutating=False)
        _require(type(mode) is int and mode >= 0 and mode & os.O_ACCMODE == self._access
                 and type(flags) is int and flags >= 0
                 and (not require_cloexec or flags & native.abi.constants["FD_CLOEXEC"]),
                 "native descriptor access or inheritance differs")
        if self._kind == "pipe":
            _require(stat.S_ISFIFO(info.st_mode), "native pipe type differs")
        else:
            null = self._owner._invoke("null_stat", os.stat, "/dev/null", mutating=False)
            _require(stat.S_ISCHR(info.st_mode) and stat.S_ISCHR(null.st_mode)
                     and info.st_rdev == null.st_rdev, "native null device differs")
        self._identity = info.st_dev, info.st_ino
        self._validated = require_cloexec

    def fileno(self) -> int:
        _require(self._state == "OPEN" and self._validated and self._fd is not None,
                 "native descriptor lease is unavailable")
        return self._fd

    def _borrow(self, owner: Acquisition) -> None:
        self.fileno()
        self._borrowers.add(owner)

    def _release(self, owner: Acquisition) -> None:
        self._borrowers.discard(owner)

    def close(self) -> None:
        if self._state in ("NEW", "CLOSED"):
            return
        _require(self._state == "OPEN" and self._fd is not None and self._native is not None
                 and not self._borrowers, "native descriptor close lacks settled custody")
        descriptor, native = self._fd, self._native
        # Retire BEFORE close; EINTR/EBADF/lost publication never authorizes reuse.
        self._state, self._fd, self._validated = "CLOSE_IN_FLIGHT", None, False
        try:
            result = self._owner._invoke("fd_close", native.call, "close", descriptor, roots=(self,))
            _require(type(result) is int and result == 0, "native descriptor close could not be confirmed")
            self._state = "CLOSED"
        except BaseException as error:
            self._owner._record_error(error)
            self._state = "UNKNOWN"
            self._owner._remember("fd_close", error)
            raise


class Child:
    """Original-child receipt state; a numeric pid is not a replacement lease."""

    def __init__(self, acquisition: Acquisition, *, _key: object) -> None:
        _require(_key is _CHILD_KEY, "native child cannot be synthesized")
        self._acquisition = acquisition
        self._pid: int | None = None
        self._numeric_retired = False
        self._wait_state = "UNPUBLISHED"
        self._wait_owner: threading.Thread | None = None
        self._receipt: WaitReceipt | None = None

    @property
    def pid(self) -> int:
        _require(self._pid is not None and self._wait_state != "UNPUBLISHED",
                 "native child publication is unavailable")
        return self._pid

    @property
    def numeric_retired(self) -> bool:
        return self._numeric_retired

    @property
    def wait_state(self) -> str:
        return self._wait_state

    @property
    def receipt(self) -> WaitReceipt | None:
        return self._receipt

    def retire_numeric(self) -> None:
        self._numeric_retired = True

    def poll_wait(self) -> WaitReceipt | None:
        if self._wait_state == "REAPED":
            assert self._receipt is not None
            return self._receipt
        _require(self._wait_state in ("OWNED", "POLLABLE") and self._pid is not None,
                 "native child wait custody is unavailable")
        owner = threading.current_thread()
        if self._wait_owner is not None and self._wait_owner is not owner:
            self.retire_numeric()
            self._wait_state = "UNKNOWN"
            self._acquisition._creation_unknown = True
            raise NativeProcessError("native child wait owner differs")
        self._wait_owner = owner
        self.retire_numeric()
        self._wait_state = "WAIT_IN_FLIGHT"
        try:
            result = os.waitpid(self._pid, os.WNOHANG)
            _require(self._wait_state == "WAIT_IN_FLIGHT" and type(result) is tuple and len(result) == 2
                     and type(result[0]) is int and type(result[1]) is int,
                     "native child wait publication differs")
            pid, raw_status = result
            if pid == 0:
                _require(raw_status == 0, "native child idle wait publication differs")
                self._wait_state = "POLLABLE"
                return None  # Only the genuine published pid0 reaches this branch.
            self._wait_state = "CONSUMED"
            _require(pid == self._pid and 0 < pid <= _MAX_PID,
                     "native child wait identity differs")
            exitcode = os.waitstatus_to_exitcode(raw_status)
            if os.WIFEXITED(raw_status):
                _require(type(exitcode) is int and 0 <= exitcode <= 255,
                         "native child exit status differs")
                kind, code = "exit", exitcode
            else:
                _require(os.WIFSIGNALED(raw_status) and type(exitcode) is int
                         and -signal.NSIG < exitcode < 0, "native child signal status differs")
                kind, code = "signal", -exitcode
            receipt = WaitReceipt(pid, kind, code, raw_status)
            self._receipt = receipt
            self._wait_state = "REAPED"
            return receipt
        except BaseException as error:
            self._acquisition._record_error(error)
            if self._wait_state != "REAPED":
                self._wait_state = "UNKNOWN"
                self._acquisition._creation_unknown = True
            if (self._acquisition._interruption is None
                    and isinstance(error, (KeyboardInterrupt, SystemExit))):
                self._acquisition._interruption = error
            raise


@dataclass(slots=True)
class _Prepared:
    native: _Native
    path: Any = None
    argv: Any = None
    env: Any = None
    strings: list[Any] = field(default_factory=list)
    pid: Any = None
    flags: Any = None
    actions: _Container | None = None
    attributes: _Container | None = None
    duplicates: list[FDLease] = field(default_factory=list)
    child: Child | None = None

    def buffers(self, spec: SpawnSpec, acquisition: Acquisition) -> None:
        c, abi = self.native.abi.c, self.native.abi

        def string(raw: bytes) -> Any:
            value = c.create_string_buffer(raw, len(raw) + 1)
            self.strings.append(value)
            return value

        self.path = string(_string(spec.executable))
        self.argv = (c.c_void_p * (len(spec.argv) + 1))()
        for index, value in enumerate(spec.argv):
            self.argv[index] = c.addressof(string(_string(value)))
        self.env = (c.c_void_p * (len(spec.env) + 1))()
        for index, (key, value) in enumerate(spec.env):
            self.env[index] = c.addressof(string(_string(key) + b"=" + _string(value)))
        self.pid, self.flags = c.c_int(0), c.c_short(0)
        self.actions = _Container("file_actions", abi.file_actions())
        self.attributes = None if abi.attributes is None else _Container("attributes", abi.attributes())
        self.child = Child(acquisition, _key=_CHILD_KEY)


def _waitability(acquisition: Acquisition, native: _Native) -> None:
    c = native.abi.c
    old_action = native.abi.sigaction()
    result = acquisition._invoke("sigchld_inspection", native.call, "sigaction",
                                  native.abi.constants["SIGCHLD"], None, c.byref(old_action),
                                  roots=(old_action,), mutating=False)
    _require(type(result) is int and result == 0, "native child waitability inspection failed")
    _require(old_action.handler != native.abi.constants["SIG_IGN"]
             and not old_action.flags & native.abi.constants["SA_NOCLDWAIT"],
             "native child waitability policy is unavailable")


def assert_child_waitability() -> None:
    """Read-only native policy admission; never alter caller SIGCHLD or reap."""
    acquisition = Acquisition()
    acquisition.grant(threading.current_thread(), lambda: None)
    try:
        _waitability(acquisition, acquisition._runtime())
    finally:
        acquisition.close_launch()


def _initialize(acquisition: Acquisition, prepared: _Prepared, container: _Container) -> None:
    native, c = prepared.native, prepared.native.abi.c
    name = "posix_spawn_file_actions_init" if container.name == "file_actions" else "posix_spawnattr_init"
    acquisition._check()
    container.state = "INIT_IN_FLIGHT"
    try:
        result = acquisition._invoke(container.name + "_init", native.call, name,
                                      c.byref(container.storage), roots=(prepared, container))
        _require(type(result) is int and result == 0, "native spawn object initialization failed")
        container.state = "INITIALIZED"
    except BaseException as error:
        acquisition._record_error(error)
        container.state = "UNKNOWN"
        acquisition._remember(container.name + "_init", error)
        raise


def _update(acquisition: Acquisition, prepared: _Prepared, container: _Container,
            name: str, *arguments: Any) -> None:
    acquisition._check()
    returned = False
    try:
        result = acquisition._invoke(container.name + "_update", prepared.native.call, name,
                                      prepared.native.abi.c.byref(container.storage), *arguments,
                                      roots=(prepared, container))
        returned = True
        _require(type(result) is int and result == 0, "native spawn object configuration failed")
    except BaseException as error:
        acquisition._record_error(error)
        if not returned or type(result) is not int:
            container.state = "UNKNOWN"
            acquisition._remember(container.name + "_update", error)
        raise


def _prepare(acquisition: Acquisition, spec: SpawnSpec) -> _Prepared:
    acquisition._check()
    _require(type(spec) is SpawnSpec, "native spawn specification differs")
    native = acquisition._runtime()
    _waitability(acquisition, native)
    prepared = _Prepared(native)
    acquisition._prepared = prepared  # All buffers/containers are rooted before init/dup.
    prepared.buffers(spec, acquisition)
    modes = (os.O_RDONLY, os.O_WRONLY, os.O_WRONLY, os.O_RDONLY,
             os.O_WRONLY, os.O_RDONLY, os.O_WRONLY, os.O_WRONLY)
    for index, source in enumerate(spec.fd_sources):
        if source not in acquisition._borrowed:
            acquisition._borrowed.append(source)
            source._borrow(acquisition)
        _require(source._access == modes[index], "native child descriptor direction differs")
        if len(spec.fd_sources) == 8:
            _require((index >= 3 or source._kind == "null")
                     and (index not in (3, 4) or source._kind == "pipe"),
                     "native helper descriptor role differs")
        _require(source._kind != "pipe" or all(
            earlier._kind != "pipe" or earlier._identity != source._identity
            for earlier in spec.fd_sources[:index]),
                 "native child pipe endpoint was aliased")
    originals = {source.fileno() for source in spec.fd_sources}
    for source in spec.fd_sources:
        duplicate = acquisition._new_lease()
        prepared.duplicates.append(duplicate)
        try:
            acquisition._check()
            duplicate._state = "ACQUIRING"
            descriptor = acquisition._invoke("fd_duplicate", native.call, "fcntl", source.fileno(),
                                              native.abi.constants["F_DUPFD_CLOEXEC"], 8,
                                              roots=(prepared, source, duplicate))
            if type(descriptor) is int and descriptor == -1:
                duplicate._state = "NEW"  # Genuine failure: no positive FD was published.
                raise NativeProcessError("native atomic descriptor duplication failed")
            _require(type(descriptor) is int and 8 <= descriptor <= _MAX_PID
                     and descriptor not in originals
                     and all(other._original_fd != descriptor for other in prepared.duplicates[:-1]),
                     "native duplicate descriptor publication differs")
            duplicate._publish(descriptor, native, source._access, source._kind)
            duplicate._validate()
        except BaseException as error:
            acquisition._record_error(error)
            if duplicate._state == "ACQUIRING":
                duplicate._state = "UNKNOWN"
                acquisition._remember("fd_duplicate_publication", error)
            raise
    assert prepared.actions is not None
    _initialize(acquisition, prepared, prepared.actions)
    if prepared.attributes is not None:
        _initialize(acquisition, prepared, prepared.attributes)
        _update(acquisition, prepared, prepared.attributes, "posix_spawnattr_setflags",
                native.abi.constants["POSIX_SPAWN_CLOEXEC_DEFAULT"])
        _update(acquisition, prepared, prepared.attributes, "posix_spawnattr_getflags",
                native.abi.c.byref(prepared.flags))
        _require(prepared.flags.value == native.abi.constants["POSIX_SPAWN_CLOEXEC_DEFAULT"],
                 "native spawn inheritance flags differ")
    for destination, duplicate in enumerate(prepared.duplicates):
        _update(acquisition, prepared, prepared.actions, "posix_spawn_file_actions_adddup2",
                duplicate.fileno(), destination)
    if native.abi.family == "linux-glibc":
        _update(acquisition, prepared, prepared.actions, "posix_spawn_file_actions_addclosefrom_np",
                len(spec.fd_sources))
    acquisition._state = "INITIALIZED"
    return prepared


def _close_transients(acquisition: Acquisition) -> BaseException | None:
    """Called only by the returned native creator; never from a cutoff observer."""
    first: BaseException | None = None
    prepared = acquisition._prepared
    if prepared is not None:
        for container in (prepared.attributes, prepared.actions):
            if container is None or container.state in ("NEW", "RETIRED", "UNKNOWN"):
                continue
            if container.state != "INITIALIZED":
                error = NativeProcessError("native spawn object custody is unsettled")
                acquisition._record_error(error)
                container.state = "UNKNOWN"
                acquisition._remember(container.name + "_unsettled", error)
                if first is None:
                    first = error
                continue
            container.state = "DESTROY_IN_FLIGHT"  # Irreversible BEFORE public destroy.
            try:
                name = ("posix_spawn_file_actions_destroy" if container.name == "file_actions"
                        else "posix_spawnattr_destroy")
                result = acquisition._invoke(container.name + "_destroy", prepared.native.call, name,
                                              prepared.native.abi.c.byref(container.storage),
                                              roots=(prepared, container))
                _require(type(result) is int and result == 0, "native spawn object destruction failed")
                container.state = "RETIRED"
            except BaseException as error:
                acquisition._record_error(error)
                container.state = "UNKNOWN"
                acquisition._remember(container.name + "_destroy", error)
                first = first if first is not None else error
        for duplicate in prepared.duplicates:
            try:
                duplicate.close()
            except BaseException as error:
                acquisition._record_error(error)
                first = first if first is not None else error
    for source in acquisition._borrowed:
        try:
            source._release(acquisition)
        except BaseException as error:
            acquisition._record_error(error)
            acquisition._remember("source_release", error)
            first = first if first is not None else error
    return first


def create(acquisition: Acquisition, spec: SpawnSpec) -> Child:
    """Attempt once in the granted creator; a return is not protocol admission.

    A genuine Child is published on acquisition before transient cleanup/return.
    Even a native error return is UNKNOWN child acquisition, not a made-up
    no-attempt or libc-internal wait receipt.  The owner must inspect its slot on
    EVERY exception and must actually join the creator before releasing roots.
    """
    _require(type(acquisition) is Acquisition and not acquisition._create_started,
             "native child creation was repeated")
    acquisition._check()
    acquisition._create_started = acquisition._create_running = True
    primary: BaseException | None = None
    cleanup_error: BaseException | None = None
    child: Child | None = None
    try:
        prepared = _prepare(acquisition, spec)
        native, c = prepared.native, prepared.native.abi.c
        assert prepared.actions is not None and prepared.child is not None
        acquisition._check()
        _waitability(acquisition, native)
        acquisition._check()
        acquisition._attempted = True
        acquisition._state = "ATTEMPTING"
        result = acquisition._invoke("native_return", native.call, "posix_spawn", c.byref(prepared.pid),
                                      prepared.path, c.byref(prepared.actions.storage),
                                      None if prepared.attributes is None else c.byref(prepared.attributes.storage),
                                      prepared.argv, prepared.env, roots=(prepared,))
        _require(type(result) is int and result == 0
                 and type(prepared.pid.value) is int and 0 < prepared.pid.value <= _MAX_PID,
                 "native child creation receipt is unavailable")
        child = prepared.child
        child._pid = prepared.pid.value
        child._wait_state = "OWNED"
        acquisition._child = child
        acquisition._state = "PID_PUBLISHED"
    except BaseException as error:
        acquisition._record_error(error)
        primary = error
        if acquisition._attempted and acquisition._child is None:
            acquisition._state = "UNKNOWN"
            acquisition._creation_unknown = True
            if acquisition._prepared is not None and acquisition._prepared.child is not None:
                acquisition._prepared.child.retire_numeric()
                acquisition._prepared.child._wait_state = "UNKNOWN"
        elif acquisition._child is not None:
            acquisition._state = "PID_PUBLISHED"
        if isinstance(error, (KeyboardInterrupt, SystemExit)) and acquisition._interruption is None:
            acquisition._interruption = error
    finally:
        acquisition.close_launch()
        try:
            try:
                cleanup_error = _close_transients(acquisition)
            except BaseException as error:
                # Rescue the entire cleanup tail too.  Unexpected publication
                # loss cannot replace an already observed body primary, prove
                # no resources, or permit a second native destruction attempt.
                cleanup_error = error
                acquisition._record_error(error)
                acquisition._remember("cleanup_tail", error)
        finally:
            acquisition._create_running = False
    if primary is not None:
        raise primary
    if cleanup_error is not None:
        raise cleanup_error
    _require(child is not None and acquisition._child is child,
             "native child publication is unavailable")
    return child
