"""Closed, private credential endpoint in the ORIGINAL command descriptor map.

This module does not acquire a socket, discover credentials, run Git or expose a
command/FD endpoint.  The initial entry issuer is deliberately absent until the
fixed GitRemote native/input owner is integrated.  An inherited descriptor
number, an equal-looking binding or a selected account DTO cannot supply it.

Only the original C/A/W map owner may forward its single admitted socket.  Its
ordinary leases, creator joins and one-attempt closes remain authoritative.
The native operation must additionally join the private peer IO and observe EOF
from ALL inherited copies; CommandCallEvidence alone is not that evidence.
"""
from __future__ import annotations

import os
import stat
import threading
from typing import Any

from . import _native_process as native


MAP_VERSION = 2
DESCRIPTOR = 8
_KEY = object()


def _require(value: bool) -> None:
    native._require(value, "original Git credential channel is unavailable")


def _identity(value: object) -> bool:
    return (type(value) is tuple and len(value) == 3
            and all(type(part) is int and 0 <= part < 2**64 for part in value)
            and value[0] < 2**32)


class SocketBinding:
    """Private original identity, not a serializable credential capability."""

    __slots__ = ("_origin", "_pid", "_nonce", "_identity", "_adopted")

    def __init__(self, origin: object, nonce: bytes, identity: tuple[int, int, int],
                 *, _key: object) -> None:
        _require(_key is _KEY and type(nonce) is bytes and len(nonce) == 16
                 and _identity(identity))
        self._origin, self._pid = origin, os.getpid()
        self._nonce, self._identity, self._adopted = nonce, identity, False

    def __repr__(self) -> str:
        return "<private Git credential socket binding>"

    def _check(self, nonce: bytes) -> None:
        _require(self._pid == os.getpid() and type(nonce) is bytes
                 and self._nonce == nonce and _identity(self._identity))

    def _check_descriptor(self, info: Any, access: int) -> None:
        self._check(self._nonce)
        _require(access == os.O_RDWR and stat.S_ISSOCK(info.st_mode)
                 and (info.st_uid, info.st_dev, info.st_ino) == self._identity)

    def _wire(self) -> str:
        self._check(self._nonce)
        return ",".join(str(value) for value in self._identity)


def bootstrap_binding(bootstrap: native.CommandBootstrapMap,
                      identity: tuple[int, int, int]) -> SocketBinding:
    """Only called inside the original fixed loader's map-v2 constructor.

    These numbers compare the actual inherited socket.  The original parent
    permit, controlled spawn, same nonce/map HELLO and native peer custody are
    still required.  This function never opens/connects a replacement socket.
    """
    _require(type(bootstrap) is native.CommandBootstrapMap
             and bootstrap._pid == os.getpid()
             and bootstrap.fd_map_version == MAP_VERSION
             and bootstrap.role in ("C", "A", "W")
             and bootstrap.account_binding is None)
    return SocketBinding(bootstrap, bootstrap.command_nonce, identity, _key=_KEY)


def parsed_binding(value: str) -> tuple[int, int, int]:
    _require(type(value) is str and len(value) <= 62)
    fields = value.split(",")
    _require(len(fields) == 3 and all(field and field.isascii()
                                    and field.isdecimal() for field in fields))
    result = tuple(int(field) for field in fields)
    _require(_identity(result) and value == ",".join(str(part) for part in result))
    return result


def binding_of(lease: native.FDLease, nonce: bytes) -> SocketBinding:
    _require(type(lease) is native.FDLease and lease._kind == "git_remote_socket"
             and lease._access == os.O_RDWR)
    result = lease._git_remote_binding
    _require(type(result) is SocketBinding)
    result._check(nonce)
    return result


def adopt(bootstrap: native.CommandBootstrapMap,
          acquisition: native.Acquisition) -> native.FDLease:
    """Claim fixed FD8 once into the SAME existing original lease inventory."""
    _require(type(acquisition) is native.Acquisition
             and type(bootstrap) is native.CommandBootstrapMap
             and bootstrap._pid == os.getpid()
             and bootstrap.fd_map_version == MAP_VERSION)
    binding = bootstrap.git_remote_binding
    _require(type(binding) is SocketBinding and binding._origin is bootstrap
             and not binding._adopted)
    binding._check(bootstrap.command_nonce)
    acquisition._check_origin()
    _require(all(lease._original_fd != DESCRIPTOR for lease in acquisition._leases))
    runtime = acquisition._runtime()
    lease = acquisition._new_lease()
    binding._adopted = True  # Before any possibly consuming native effect.
    lease._git_remote_binding = binding
    changing = False
    try:
        lease._publish(DESCRIPTOR, runtime, os.O_RDWR, "git_remote_socket")
        lease._validate(require_cloexec=False)
        acquisition._check()
        changing = True
        acquisition._invoke("git_remote_inherited_cloexec", os.set_inheritable,
                            DESCRIPTOR, False, roots=(lease, bootstrap, binding))
        lease._validate()
        return lease
    except BaseException as error:
        acquisition._record_error(error)
        acquisition.close_launch()
        if changing:
            acquisition._remember("git_remote_inherited_cloexec", error)
        raise


class OriginalChannel:
    """One original input's endpoint, consumed by one fixed command only.

    No production constructor/entry issuer is installed by this supporting
    slice.  The later fixed GitRemoteInput must own the actual native-mapped
    socket and retain this object through original peer IO/EOF/close joins.
    """

    __slots__ = ("source", "lease", "guard", "_pid", "_thread", "_entered",
                 "_admitted", "_exported", "_context", "_binding")

    def __init__(self, source: object, lease: native.FDLease, guard: object,
                 *, _key: object) -> None:
        _require(_key is _KEY and type(lease) is native.FDLease
                 and lease._kind == "git_remote_socket" and lease._access == os.O_RDWR
                 and lease.state == "OPEN" and lease._validated)
        binding = lease._git_remote_binding
        _require(type(binding) is SocketBinding and binding._origin is source)
        self.source, self.lease, self.guard = source, lease, guard
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._entered, self._context, self._binding = False, None, None
        self._admitted = self._exported = False

    def __repr__(self) -> str:
        return "<private original Git credential channel>"

    def _origin(self, guard: object) -> None:
        if self._pid != os.getpid():
            self.lease._relinquish_inherited()
            _require(False)
        _require(self._thread is threading.current_thread() and self.guard is guard)

    def admit_command(self, guard: object, argv: object, **options: Any) -> None:
        self._origin(guard)
        _require(not self._entered)
        self._entered = True  # Before any owner callback; no reentry/retry.
        # The module/domain does not exist until its separately reviewed owner
        # is composed.  Never replace this with a duck-typed caller callback.
        try:
            from ._desktop_git_remote_control import GitRemoteInput
        except ImportError:
            _require(False)
        _require(type(self.source) is GitRemoteInput)
        self.source._owner()
        _require(self.source.guard is guard and guard._saved_command_input() is self.source
                 and self.source.credential_channel is self)
        self.source.require_operation().command_arguments(argv, **options)
        self.lease._validate()
        self.source.guard.check()
        self._admitted = True

    def bind_context(self, context: object) -> None:
        """Memory-only binding BEFORE CleanupScope; no owner callback/IO here."""
        self._origin(context.guard)
        _require(self._entered and self._admitted and self._context is None and context.role == "O"
                 and context.pid == self._pid and context.owner is self._thread)
        original = self.lease._git_remote_binding
        _require(type(original) is SocketBinding and original._origin is self.source)
        self._context = context
        self._binding = SocketBinding(self, context.nonce, original._identity, _key=_KEY)
        context.git_remote_binding = self._binding

    def export(self, context: object, acquisition: native.Acquisition) -> native.FDLease:
        self._origin(context.guard)
        _require(context is self._context and type(acquisition) is native.Acquisition
                 and context.git_remote_binding is self._binding and not self._exported)
        self._exported = True  # Before callbacks, borrow or duplication.
        context.check()
        self.source._owner()
        self.source.guard.check()
        self.lease._validate()
        runtime = acquisition._runtime()
        result = acquisition._new_lease()
        result._git_remote_binding = self._binding
        borrowed = returned = False
        try:
            self.lease._borrow(acquisition)
            borrowed = True
            result._state = "ACQUIRING"
            fd = acquisition._invoke("git_remote_endpoint_duplicate", runtime.call,
                 "fcntl", self.lease.fileno(), runtime.abi.constants["F_DUPFD_CLOEXEC"],
                 DESCRIPTOR + 1, roots=(self, self.lease, result, self._binding))
            returned = True
            if type(fd) is int and fd == -1:
                result._state = "NEW"
                _require(False)
            _require(type(fd) is int and DESCRIPTOR < fd < 2**31
                     and fd != self.lease.fileno())
            result._publish(fd, runtime, os.O_RDWR, "git_remote_socket")
            result._validate()
            context.check()
            return result
        except BaseException as error:
            acquisition._record_error(error)
            acquisition.close_launch()
            if result._state == "ACQUIRING":
                result._state = "UNKNOWN"
                acquisition._remember("git_remote_endpoint_publication", error)
            raise
        finally:
            if borrowed and returned and self._pid == os.getpid():
                self.lease._release(acquisition)
