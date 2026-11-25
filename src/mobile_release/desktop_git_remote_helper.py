"""Fixed inherited helper entry, on the ORIGINAL GitRemote FD8/C/A/W.

The private endpoint is BORROWED, never duped/wrapped/adopted for close here.
Only the original parent pair/command owners may retire all copies. This entry
closes its own three ordinary pipes before a bounded private returned frame;
the bootstrap then exits without Python buffered-stream/atexit flushing.

No standalone availability is implied. Native admission must hold this exact
entry/core/Python/CA/CLT closure and the selected Connection throughout.
"""
from __future__ import annotations

import errno
import math
import os
from pathlib import Path
import select
import stat
import threading
import time

from . import _native_process as native
from . import _git_remote_private_protocol as private
from . import _github_connection_transport as http
from . import git_remote_transport as transport
from . import git_remote_control as controls
from . import git_remote_wire as wire
from ._desktop_git_remote_helper import _Helper
from ._git_remote_command_channel import DESCRIPTOR
from ._git_remote_input_channel import _SocketIO

PIPE_CALLS = 20_000
WORKING_RESERVE = 16 * 1024 * 1024  # Fixed call records/buffers, NOT a pack spool.
_RETAINED = []


class _BorrowedEndpoint:
    """No close/dup/socket destructor: this is the inherited original map copy."""
    def __init__(self, entry):
        self.entry, self.identity = entry, None

    def fileno(self):
        self.entry.origin()
        transport.require(self.identity is not None)
        return DESCRIPTOR

    def check(self):
        entry = self.entry
        entry.origin()
        info = os.fstat(DESCRIPTOR)
        transport.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() > 0
                          and not os.get_blocking(DESCRIPTOR) and os.get_inheritable(DESCRIPTOR))
        runtime = entry.io.runtime
        mode = entry.acquisition._invoke("git_remote_borrowed_mode", runtime.call, "fcntl", DESCRIPTOR,
            runtime.abi.constants["F_GETFL"], 0, roots=(self,), mutating=False)
        transport.require(type(mode) is int and mode >= 0 and mode & os.O_ACCMODE == os.O_RDWR)
        identity = info.st_uid, info.st_dev, info.st_ino
        transport.require(self.identity is None or self.identity == identity)
        self.identity = identity


class _PipeIO:
    """Fixed 0/1 byte IO; native call records retain counts, not pack chunks."""
    def __init__(self, entry):
        self.entry, self.count = entry, 0
        runtime, c = entry.io.runtime, entry.io.runtime.abi.c
        self.buffer = (c.c_ubyte * wire.READ_CHUNK)()
        for name in ("read", "write"):
            function = runtime.library[name]
            function.argtypes = [c.c_int, c.c_void_p, c.c_size_t]
            function.restype = c.c_ssize_t
            runtime.functions["git_remote_helper_" + name] = function

    def _call(self, name, lease, maximum):
        transport.require(name in ("read", "write") and self.count < PIPE_CALLS)
        self.count += 1
        entry = self.entry
        entry.current()
        return entry.acquisition._invoke("git_remote_helper_" + name, entry.io.runtime.call,
            "git_remote_helper_" + name, lease.fileno(), self.buffer, maximum, roots=(self, lease))

    def read(self, maximum):
        transport.require(type(maximum) is int and 0 < maximum <= wire.READ_CHUNK)
        entry, lease = self.entry, self.entry.pipes[0]
        while True:
            count = self._call("read", lease, maximum)
            if count == -1 and entry.io.runtime.last_errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                entry.wait(read=lease.fileno()); continue
            transport.require(type(count) is int and 0 <= count <= maximum)
            result = bytes(self.buffer[:count])
            entry.current()
            return result

    def write(self, data):
        transport.require(type(data) is bytes and 0 < len(data) <= wire.READ_CHUNK)
        entry, lease, offset = self.entry, self.entry.pipes[1], 0
        while offset < len(data):
            remaining = data[offset:]
            self.buffer[:len(remaining)] = remaining
            count = self._call("write", lease, len(remaining))
            if count == -1 and entry.io.runtime.last_errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                entry.wait(write=lease.fileno()); continue
            transport.require(type(count) is int and 0 < count <= len(remaining))
            offset += count
            entry.current()

    def wipe(self):
        self.buffer[:] = b"\0" * wire.READ_CHUNK


class _Entry:
    binding_type = private.Binding
    pipe_io_type = _PipeIO

    def __init__(self, remote, url, runtime_dir, started):
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.remote, self.url, self.runtime_dir = remote, url, runtime_dir
        self.started, self.handshake_end = started, started + 1.0
        self.work_end = self.hard_end = self.handshake_end
        self.binding = self.first_failure = self.first_failure_ns = None
        self.cleanup_end_ns = None
        self.acquisition = native.Acquisition(failure_recorder=self.remember)
        self.io = self.pipe_io = self.endpoint = self.budget = self.transport = self.helper = None
        self.pipes = []
        self.entered = self.closed = self.unknown = self.failed = self.pipes_close_entered = False
        self.get_entered = self.get_returned = self.return_entered = False
        self.primary = None
        self.sent = self.received = 0
        self._current_callback = self.current
        self._failure_callback = self.http_failure
        self.acquisition.grant(self.thread, self.current)

    def __repr__(self):
        return "<original private Git remote helper>"

    def origin(self):
        if self.pid != os.getpid():
            self.acquisition._relinquish_inherited()
            transport.require(False)
        transport.require(self.thread is threading.current_thread())

    def _bridge(self, binding):
        transport.require(type(binding) is self.binding_type and self.binding is None)
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        transport.require(type(raw_clock) is int)
        before, raw = time.monotonic(), time.clock_gettime_ns(raw_clock)
        transport.require(type(raw) is int and 0 <= raw < binding.work_end_ns < binding.hard_end_ns)
        work = math.nextafter(before + (binding.work_end_ns - raw) / 1e9, -math.inf)
        hard = math.nextafter(before + (binding.hard_end_ns - raw) / 1e9, -math.inf)
        # These are the PARENT endpoints, not helper-launch + 45/55.
        self.work_end, self.hard_end = work, hard
        self.cleanup_end_ns = binding.hard_end_ns
        self.binding = binding

    def remember(self, error):
        self.failed = True
        if self.primary is None:
            self.primary = error
        self.unknown |= (isinstance(error, (KeyboardInterrupt, SystemExit, http._CloseFailure))
                         or not isinstance(error, (transport.RemoteError, wire.WireError, private.PrivateError, http.ReadFailure))
                         or getattr(error, "reason", None) == "cleanup-unknown")
        if self.first_failure is not None:
            return
        self.first_failure = time.monotonic()
        self.hard_end = min(self.hard_end, self.first_failure + 10.0)
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        raw = time.clock_gettime_ns(raw_clock) if type(raw_clock) is int else None
        after = time.monotonic()
        if type(raw) is int:
            raw -= math.ceil(max(0.0, after - self.first_failure) * 1_000_000_000)
        if self.binding is not None and type(raw) is int and 0 < raw < self.binding.hard_end_ns:
            self.first_failure_ns = raw
            self.cleanup_end_ns = min(self.binding.hard_end_ns, raw + 10_000_000_000)

    def http_failure(self, reason):
        # Called inside the SAME HTTP owner before its original finalizers.
        # Only a closed reason crosses; no response/token/exception text does.
        # No IO/reentry/currentness call here can consume another command.
        self.remember(transport.RemoteError(reason if reason in transport._REASONS else "cleanup-unknown"))

    def current(self):
        self.origin()
        transport.require(not self.failed and not self.closed and not self.return_entered
                          and time.monotonic() < self.work_end, "cancelled" if self.failed else "network-unavailable")
        if self.get_returned:
            # The parent signals original STOP by shutting down its write
            # direction; no named socket, new account or token request exists.
            transport.require(self.io.receive(self.endpoint, 1) is None, "cancelled")

    def clock(self):
        self.current()
        return time.monotonic()

    def wait(self, *, read=None, write=None, cleanup=False):
        self.origin()
        end = self.hard_end if cleanup else self.work_end
        if not cleanup:
            self.current()
        remaining = end - time.monotonic()
        transport.require(remaining > 0, "network-unavailable")
        select.select([] if read is None else [read], [] if write is None else [write], [], min(0.01, remaining))

    def _private_read(self):
        data = bytearray()
        while True:
            self.current()
            block = self.io.receive(self.endpoint, min(1024, private.FRAME_LIMIT + 1 - len(data)))
            if block is None:
                self.wait(read=DESCRIPTOR); continue
            transport.require(bool(block))
            self.received += len(block)
            transport.require(self.received <= 2 * private.FRAME_LIMIT)
            data.extend(block)
            transport.require(len(data) <= private.FRAME_LIMIT)
            if b"\n" in data:
                transport.require(data.endswith(b"\n") and data.count(b"\n") == 1)
                return bytes(data)

    def _private_write(self, data, *, cleanup=False):
        transport.require(type(data) is bytes and 0 < len(data) <= private.FRAME_LIMIT)
        offset = 0
        while offset < len(data):
            self.origin()
            if not cleanup:
                self.current()
            transport.require(time.monotonic() < (self.hard_end if cleanup else self.work_end), "network-unavailable")
            count = self.io.send(self.endpoint, data[offset:])
            if count == 0:
                self.wait(write=DESCRIPTOR, cleanup=cleanup); continue
            self.sent += count; offset += count
            transport.require(self.sent <= private.FRAME_LIMIT)

    def _acquire_pipes(self):
        for number, access in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
            # Closed helper-only originals. This does NOT widen adopt_fd's
            # public 3..7 map or claim the borrowed FD8 for close.
            lease = self.acquisition._new_lease()
            self.pipes.append(lease)
            lease._publish(number, self.io.runtime, access, "pipe")
            lease._validate(require_cloexec=False)
            self.acquisition._invoke("git_remote_helper_cloexec", os.set_inheritable, number, False, roots=(lease,))
            if number != 2:  # Never write or alter shared stderr status flags.
                self.acquisition._invoke("git_remote_helper_nonblocking", os.set_blocking, number, False, roots=(lease,))
            lease._validate()
        self.pipe_io = self.pipe_io_type(self)

    def acquire(self):
        self.origin(); transport.require(not self.entered)
        self.entered = True
        transport.require(type(self.started) in (int, float) and math.isfinite(self.started)
                          and isinstance(self.runtime_dir, Path) and self.runtime_dir.is_absolute()
                          and type(self.remote) is str and private._REMOTE.fullmatch(self.remote) is not None
                          and type(self.url) is str and len(self.url) <= 256)
        self.current()
        self.io = _SocketIO.__new__(_SocketIO)
        _SocketIO.__init__(self.io, self.acquisition)
        self.endpoint = _BorrowedEndpoint(self)
        self.endpoint.check()
        binding = private.challenge(self._private_read())
        transport.require(binding.identity == self.endpoint.identity and binding.remote == self.remote
                          and self.url == "https://github.com/" + binding.target.repository + ".git")
        self._bridge(binding)
        self.current()
        self._acquire_pipes()
        self.get_entered = True  # Before send or currentness callback.
        self._private_write(binding.request())
        token = binding.accept_grant(self._private_read())
        self.get_returned = True
        try:
            self.current()
            started = math.nextafter(self.work_end - transport.WORK_SECONDS, -math.inf)
            self.budget = http._Budget(started, monotonic=self.clock, _profile=http._ExchangeProfile.GIT_REMOTE)
            self.budget.end = min(self.budget.end, self.work_end)
            self.transport = transport._make_transport(binding.target, token, started=started,
                runtime_dir=str(self.runtime_dir), budget=self.budget, current=self._current_callback,
                failure=self._failure_callback)
        finally:
            token = None  # Bounded Python private copies, not claimed zeroized.
        self.helper = _Helper(self.transport, read=self.pipe_io.read, write=self.pipe_io.write, current=self._current_callback)

    def close_pipes(self):
        self.origin(); transport.require(not self.pipes_close_entered)
        self.pipes_close_entered = True
        for lease in reversed(self.pipes):
            try:
                transport.require(time.monotonic() < self.hard_end, "network-unavailable")
                lease.close()
            except BaseException as error:
                self.unknown = True
                self.remember(error)
        self.closed = (len(self.pipes) == 3 and all(lease.state == "CLOSED" for lease in self.pipes)
                       and self.acquisition.settled and not self.acquisition.cleanup_unknown)
        if not self.closed:
            self.unknown = True
        if self.pipe_io is not None:
            self.pipe_io.wipe()
        if self.io is not None:
            self.io.wipe()
        self.acquisition.close_launch()

    def complete(self):
        """No ordinary IO/work may follow this frame; bootstrap uses _exit."""
        self.origin()
        transport.require(not self.return_entered and self.binding is not None and self.get_returned
                          and self.pipes_close_entered)
        self.return_entered = True
        if self.unknown or not self.closed:
            status, reason = "unknown", "cleanup-unknown"
        elif self.primary is None and self.helper is not None and self.helper.finished:
            status, reason = "ok", None
        else:
            status = "refused"
            if self.primary is None:
                self.remember(transport.RemoteError())
            observed = getattr(self.primary, "reason", "response-invalid")
            reason = observed if observed in transport._REASONS - {"cleanup-unknown"} else "response-invalid"
        control = controls.empty() if self.transport is None else self.transport.control
        if status == "refused":
            control = controls.refusal(control, reason)
        self._private_write(self.binding.returned(status, reason,
            first_failure_ns=None if status == "ok" else self.first_failure_ns,
            cleanup_end_ns=self.binding.hard_end_ns if status == "ok" else self.cleanup_end_ns,
            control=control), cleanup=True)
        return 0 if status == "ok" else 70


def main(*, remote, url, runtime_dir, started):
    entry = _Entry(remote, url, runtime_dir, started)
    try:
        try:
            entry.acquire()
            entry.helper.run()
        except BaseException as error:
            entry.remember(error)
        finally:
            entry.close_pipes()
        return entry.complete()
    except BaseException as error:
        entry.remember(error)
        return 74
    finally:
        if entry.unknown or not entry.closed:
            _RETAINED.append(entry)
