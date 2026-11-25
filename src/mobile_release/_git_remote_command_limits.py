"""Fixed pre-exec file limits in the ORIGINAL GitRemote command W.

This neither issues a remote permit nor runs a command.  Only the same live
map-v2 W and its adopted FD8 can enter; ordinary command roles/maps do not.
The original W effect ledger, first-failure clock and C/A/W cleanup own failure.
A returned limit setup is not an aggregate-disk, memory or finality receipt.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from . import _native_process as native
from ._git_remote_command_channel import DESCRIPTOR, MAP_VERSION, binding_of

if TYPE_CHECKING:
    from ._command_process import _Worker


FILE_BYTES = 32 * 1024 * 1024
_ERROR = "Git fetch requires supported original file limits"


def _require(condition: bool) -> None:
    from ._command_process import ProcessError
    if not condition:
        raise ProcessError(_ERROR)


def _original(worker: _Worker, endpoint: native.FDLease) -> None:
    from ._command_process import _Context
    ctx = worker.ctx
    _require(type(ctx) is _Context)
    ctx.owner_check()
    _require(ctx.role == "W" and not worker.exec_retired
             and not ctx.launch_retired and not ctx.cleanup_unknown and not ctx.exited
             and type(worker.mapping) is dict
             and set(worker.mapping) == {3, 4, 5, 6, 7, DESCRIPTOR}
             and worker.mapping[DESCRIPTOR] is endpoint
             and type(endpoint) is native.FDLease and endpoint._owner is worker.io
             and type(worker.io) is native.Acquisition and worker.io in ctx.acquisitions
             and endpoint in worker.io.leases and not endpoint._borrowers
             and type(worker.mapping[5]) is native.FDLease
             and worker.mapping[5]._kind == "null"
             and worker.mapping[5].account_binding is None)
    binding = binding_of(endpoint, ctx.nonce)
    bootstrap = binding._origin
    uid, effective = os.getuid(), os.geteuid()
    _require(binding is ctx.git_remote_binding and binding._adopted
             and type(bootstrap) is native.CommandBootstrapMap
             and bootstrap.role == "W" and bootstrap.fd_map_version == MAP_VERSION
             and bootstrap._pid == ctx.pid == os.getpid()
             and bootstrap.command_nonce == ctx.nonce and bootstrap._parent[0] == ctx.parent
             and bootstrap.git_remote_binding is binding and bootstrap.account_binding is None
             and type(uid) is int and type(effective) is int
             and 0 < uid == effective == binding._identity[0] < 2**32)
    # Run BEFORE the original W makes FD8 inheritable.  Validation must still
    # prove CLOEXEC and the actual adopted descriptor, not just equal map DATA.
    endpoint._validate()
    _require(endpoint.fileno() == endpoint._original_fd == DESCRIPTOR)
    ctx.check()


def _pair(value: object, infinity: int) -> tuple[int, int]:
    _require(type(value) is tuple and len(value) == 2
             and all(type(n) is int and (n == infinity or 0 <= n < 2**64) for n in value))
    soft, hard = value
    _require(hard == infinity or soft != infinity and soft <= hard)
    return soft, hard


def _effect(worker: _Worker, name: str, call: Any, *args: Any) -> Any:
    worker.ctx.check()
    result = worker._setup(name, call, *args)
    worker.ctx.check()  # A late syscall return never renews the original clock.
    return result


def apply_worker_limits(worker: _Worker, endpoint: native.FDLease) -> None:
    """One fixed lowering, no caller-selected limits and no restoration/retry."""
    from ._command_process import _Worker
    _require(type(worker) is _Worker
             and getattr(worker, "git_remote_limits_entered", None) is False)
    worker.git_remote_limits_entered = True  # BEFORE owner callbacks/effects.
    _original(worker, endpoint)
    try:
        import resource
    except ImportError:
        _require(False)
    fsize, core = getattr(resource, "RLIMIT_FSIZE", None), getattr(resource, "RLIMIT_CORE", None)
    infinity = getattr(resource, "RLIM_INFINITY", None)
    _require(type(fsize) is int and type(core) is int and 0 <= fsize != core >= 0
             and type(infinity) is int and (infinity == -1 or FILE_BYTES < infinity < 2**64)
             and callable(getattr(resource, "getrlimit", None))
             and callable(getattr(resource, "setrlimit", None)))
    old_file = _pair(_effect(worker, "git_remote_fsize_before", resource.getrlimit, fsize), infinity)
    _pair(_effect(worker, "git_remote_core_before", resource.getrlimit, core), infinity)
    # Refuse an inherited stricter policy; never raise even a soft limit.
    _require(all(n == infinity or n >= FILE_BYTES for n in old_file))
    _require(_effect(worker, "git_remote_core_limit", resource.setrlimit, core, (0, 0)) is None)
    _require(_effect(worker, "git_remote_fsize_limit", resource.setrlimit,
                     fsize, (FILE_BYTES, FILE_BYTES)) is None)
    _require(_pair(_effect(worker, "git_remote_core_after", resource.getrlimit, core), infinity) == (0, 0))
    _require(_pair(_effect(worker, "git_remote_fsize_after", resource.getrlimit, fsize), infinity)
             == (FILE_BYTES, FILE_BYTES))
    _original(worker, endpoint)
