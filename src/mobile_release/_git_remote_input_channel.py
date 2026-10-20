"""Original GitRemote socketpair/IO, using the existing Acquisition/FDLease.

There is no named listener, guessed descriptor capability, socket object with a
destructor, thread, new subprocess owner or generic pass-fds API here. The fixed
input owns this object before creation. Only its exact command can export the
client lease, and only an actual returned C/A/W invocation permits peer-EOF
reconciliation. Equal-looking public DATA is never that original.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import stat
import threading
import time

from . import _native_process as native
from . import _git_remote_command_channel as mapping
from . import _git_remote_private_protocol as wire
from . import git_service as core
from .owned_process import ProcessCleanupError

MAX_IO_CALLS = 2 * wire.FRAME_LIMIT + 128
WORKING_RESERVE = 8 * 1024 * 1024  # Includes the original finite native call records.


class RemoteRefusal(core.GitError):
    def __init__(self, returned):
        _require(type(returned) is wire.Returned and returned.status == "refused")
        super().__init__("command-failed")
        self.reason = returned.reason  # The finite helper/HTTP reason, never provider text.


def _require(value):
    native._require(value, "The original private Git credential channel is unavailable.")


class _SocketIO:
    """Fixed public libc calls on this Acquisition's already-loaded handle."""
    def __init__(self, acquisition):
        _require(type(acquisition) is native.Acquisition)
        self.owner = acquisition
        self.buffer = self.descriptors = self.one = self.runtime = None
        self.count = 0
        self.runtime = acquisition._runtime()
        runtime, c = self.runtime, self.runtime.abi.c
        _require(runtime.abi.family in ("darwin", "linux-glibc")
                 and c.sizeof(c.c_int) == 4 and c.sizeof(c.c_size_t) == c.sizeof(c.c_ssize_t) == 8
                 and socket.AF_UNIX == socket.SOCK_STREAM == 1 and socket.SHUT_WR == 1)
        specs = {"socketpair": ([c.c_int, c.c_int, c.c_int, c.POINTER(c.c_int)], c.c_int),
                 "recv": ([c.c_int, c.c_void_p, c.c_size_t, c.c_int], c.c_ssize_t),
                 "send": ([c.c_int, c.c_void_p, c.c_size_t, c.c_int], c.c_ssize_t),
                 "shutdown": ([c.c_int, c.c_int], c.c_int),
                 "setsockopt": ([c.c_int, c.c_int, c.c_int, c.c_void_p, c.c_uint32], c.c_int)}
        for name, (args, result) in specs.items():
            key = "git_remote_" + name
            _require(key not in runtime.functions)
            function = runtime.library[name]  # SAME original runtime handle; no loader/search.
            function.argtypes, function.restype = args, result
            runtime.functions[key] = function
        self.buffer = (c.c_ubyte * wire.FRAME_LIMIT)()
        self.descriptors = (c.c_int * 2)(-1, -1)
        self.one = c.c_int(1)
        self.send_flag = getattr(socket, "MSG_NOSIGNAL", 0) if runtime.abi.family == "linux-glibc" else 0
        _require(self.send_flag != 0 or runtime.abi.family == "darwin")

    def call(self, name, *args, roots=()):
        _require(self.count < MAX_IO_CALLS and name in ("socketpair", "recv", "send", "shutdown", "setsockopt"))
        self.count += 1  # Before the native effect; no reset after a failure.
        return self.owner._invoke("git_remote_" + name, self.runtime.call,
            "git_remote_" + name, *args, roots=(self, *roots))

    def configure(self, lease):
        fd = lease._fd
        _require(type(fd) is int and lease.state == "OPEN")
        self.owner._invoke("git_remote_cloexec", os.set_inheritable, fd, False, roots=(lease,))
        self.owner._invoke("git_remote_nonblocking", os.set_blocking, fd, False, roots=(lease,))
        if self.runtime.abi.family == "darwin":
            _require(socket.SOL_SOCKET == 0xffff and getattr(socket, "SO_NOSIGPIPE", None) == 0x1022)
            c = self.runtime.abi.c
            _require(self.call("setsockopt", fd, socket.SOL_SOCKET, socket.SO_NOSIGPIPE,
                               c.byref(self.one), c.sizeof(self.one), roots=(lease,)) == 0)
        lease._validate()
        _require(not os.get_blocking(fd) and not os.get_inheritable(fd))

    def receive(self, lease, maximum):
        _require(type(maximum) is int and 0 < maximum <= wire.FRAME_LIMIT)
        fd = lease.fileno()
        if not select.select([fd], [], [], 0)[0]:
            return None
        count = self.call("recv", fd, self.buffer, maximum, 0, roots=(lease,))
        if count == -1 and self.runtime.last_errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return None
        _require(type(count) is int and 0 <= count <= maximum)
        # The acquisition retains only the integer return and this original
        # buffer, never a token string as a native-call return/log value.
        return bytes(self.buffer[:count])

    def send(self, lease, data):
        _require(type(data) in (bytes, bytearray) and 0 < len(data) <= wire.FRAME_LIMIT)
        fd = lease.fileno()
        if not select.select([], [fd], [], 0)[1]:
            return 0
        self.buffer[:len(data)] = data
        count = self.call("send", fd, self.buffer, len(data), self.send_flag, roots=(lease,))
        if count == -1 and self.runtime.last_errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return 0
        _require(type(count) is int and 0 < count <= len(data))
        return count

    def wipe(self):
        if self.buffer is not None:
            self.buffer[:] = b"\0" * wire.FRAME_LIMIT


class OriginalInputChannel:
    """One private command, one credential get, actual all-copy EOF."""
    def __init__(self, source):
        from ._desktop_git_remote_control import GitRemoteInput
        _require(type(source) is GitRemoteInput)
        source._owner()
        _require(source.channel is self and source.go_returned and source.guard is not None)
        self.source, self.pid, self.thread = source, os.getpid(), threading.current_thread()
        self.acquisition = native.Acquisition(failure_recorder=self._failure)
        self.acquisition.grant(self.thread, self._current)
        self.io = self.client = self.peer = self.binding = self.command = None
        self.entered = self.polling = self.failed = self.unknown = self.closed = False
        self.get_entered = self.get_sent = self.eof = self.stop_entered = self.stopped = False
        self.producer_returned = self.finish_entered = False
        self.helper_return = None
        self.return_checked = False
        self.incoming, self.outgoing = bytearray(), bytearray()
        self.sent = self.received = self.requests = 0
        self.outgoing_secret = False

    def __repr__(self):
        return "<original private Git input channel>"

    def _origin(self):
        if self.pid != os.getpid():
            self.acquisition._relinquish_inherited()
            _require(False)
        _require(self.thread is threading.current_thread() and self.source.channel is self)
        self.source._owner()

    def _current(self):
        self._origin()
        _require(not self.failed and not self.unknown and not self.closed and not self.stop_entered
                 and self.source.go_returned and self.source.stop_reason == "none")
        self.source.guard.check()
        _require(time.monotonic() < self.source.work_end and not self.source.guard.cancelled)

    def _failure(self, error):
        self.failed = True
        self.source.failure_observed()
        self.source.guard._abort(error)

    def acquire(self):
        self._origin(); _require(not self.entered)
        self.entered = True
        self._current()
        self.io = _SocketIO.__new__(_SocketIO)
        _SocketIO.__init__(self.io, self.acquisition)
        self.client, self.peer = self.acquisition._new_lease(), self.acquisition._new_lease()
        try:
            self.client._state = self.peer._state = "ACQUIRING"
            value = self.io.call("socketpair", socket.AF_UNIX, socket.SOCK_STREAM, 0, self.io.descriptors,
                                 roots=(self.client, self.peer))
            if value == -1:
                self.client._state = self.peer._state = "NEW"  # Positive failed creation: no descriptors.
                _require(False)
            _require(type(value) is int and value == 0)
            first, second = (int(item) for item in self.io.descriptors)
            _require(2 < first < (1 << 31) and 2 < second < (1 << 31) and first != second)
            # Publish BOTH returned routes before any origin/validation callback.
            self.client._publish_known(first, self.io.runtime, os.O_RDWR, "git_remote_socket")
            self.peer._publish_known(second, self.io.runtime, os.O_RDWR, "git_remote_socket")
            self.acquisition._check_origin()
            initial = self.source.initial
            nonce = bytes.fromhex(initial.digest[:32])  # Comparison nonce, not credential capability.
            for lease in (self.client, self.peer):
                info = self.acquisition._invoke("git_remote_socket_stat", os.fstat, lease._fd,
                                                roots=(lease,), mutating=False)
                _require(stat.S_ISSOCK(info.st_mode) and info.st_uid == initial.uid)
                stamp = info.st_uid, info.st_dev, info.st_ino
                lease._git_remote_binding = mapping.SocketBinding(self.source, nonce, stamp, _key=mapping._KEY)
                self.io.configure(lease)
            self.binding = wire.Binding(initial.id, initial.digest, initial.action.remote, initial.target,
                initial.work_end_ns, initial.hard_end_ns, nonce, self.client._git_remote_binding._identity)
            self.outgoing.extend(self.binding.challenge())
            self.command = mapping.OriginalChannel(self.source, self.client, self.source.guard, _key=mapping._KEY)
            self._current()
        except BaseException as error:
            self._failure(error)
            for lease in (self.client, self.peer):
                if lease is not None and lease.state == "ACQUIRING":
                    lease._state = "UNKNOWN"
                    self.acquisition._remember("git_remote_socket_publication", error)
            self.unknown |= self.acquisition.cleanup_unknown
            raise

    def poll(self):
        self._origin()
        if self.polling or not self.entered or self.closed or self.unknown or self.io is None or self.binding is None:
            return
        if self.source.stop_reason != "none" or self.failed:
            self.stop()
            return
        self.polling = True
        try:
            self._current()
            if self.outgoing:
                count = self.io.send(self.peer, self.outgoing)
                if count:
                    del self.outgoing[:count]
                    self.sent += count
                    _require(self.sent <= 2 * wire.FRAME_LIMIT)
                if not self.outgoing and self.outgoing_secret:
                    self.get_sent = True
                    self.io.wipe()
            block = self.io.receive(self.peer, min(1024, wire.FRAME_LIMIT + 1 - self.received))
            if block is None:
                return
            self._accept_block(block, finishing=False)
        except BaseException as error:
            self._failure(error)
            self.unknown |= self.acquisition.cleanup_unknown
            raise
        finally:
            self.polling = False

    def _accept_block(self, block, *, finishing):
        """One aggregate parser, including the final drain after C/A/W return."""
        _require(type(block) is bytes and type(finishing) is bool)
        if block == b"":
            # Only EOF AFTER our original client close participates in all-copy
            # accounting. An early half-close is not that evidence.
            _require(finishing and self.producer_returned and self.client.state == "CLOSED"
                     and not self.incoming and not self.outgoing and self.get_sent
                     and type(self.helper_return) is wire.Returned)
            self.eof = True
            return
        _require(not self.eof and self.helper_return is None)
        self.received += len(block)
        _require(self.received <= wire.FRAME_LIMIT)
        self.incoming.extend(block)
        while b"\n" in self.incoming:
            _require(not self.outgoing and self.helper_return is None)
            raw, _, tail = self.incoming.partition(b"\n")
            value = self.binding.accept_message(bytes(raw + b"\n"))
            self.incoming[:] = tail
            if type(value) is wire.Returned:
                _require(self.get_entered and self.get_sent and not self.incoming)
                self.helper_return = value
                self.source.helper_returned(self, value)
                continue
            _require(not finishing and value in ("get", "store", "erase"))
            self.requests += 1
            _require(self.requests <= 3)
            if value != "get":
                continue  # Fixed discard: no file, keyring or response.
            _require(not self.get_entered)
            self.get_entered = True  # Before currentness/secret handoff.
            self.source.require_operation().credential_current(self)
            self._current()
            value = self.source.take_helper_token(self)
            self.outgoing.extend(self.binding.grant(value))
            self.outgoing_secret = True
            value = None
            self._current()
        _require(self.helper_return is None or not self.incoming)

    def stop(self):
        self._origin()
        if self.stop_entered or self.closed or self.peer is None or self.peer.state != "OPEN":
            return
        self.stop_entered = True
        try:
            # Signal only the original helper's read direction. The original
            # C/A/W still owns descendants and all inherited client copies.
            _require(self.io.call("shutdown", self.peer.fileno(), socket.SHUT_WR, roots=(self.peer,)) == 0)
            self.stopped = True
        except BaseException as error:
            self.unknown = True
            self._failure(error)
            raise

    def finish(self, operation):
        """Called only by the exact invocation after original C/A/W return."""
        self._origin()
        _require(operation is self.source.require_operation() and operation.remote_returned
                 and not operation.unknown and not self.finish_entered)
        self.finish_entered = self.producer_returned = True
        if self.unknown or self.acquisition.cleanup_unknown:
            return False
        # The original client itself would keep the peer alive. Retire it only
        # after all original command borrowers actually returned; then EOF must
        # still account for every copy in the admitted Git/loader/helper chain.
        try:
            if self.client is not None:
                self.client.close()
            while self.peer is not None and not self.eof and time.monotonic() < self.source.hard_end:
                block = self.io.receive(self.peer, min(1024, wire.FRAME_LIMIT + 1 - self.received))
                if block is not None:
                    self._accept_block(block, finishing=True)
                else:
                    self.source._poll_control_only(self.source.guard)
                    select.select([self.peer.fileno()], [], [], min(0.01, max(0.0, self.source.hard_end - time.monotonic())))
            _require(self.peer is None or self.eof)
            if self.peer is not None:
                self.peer.close()
            _require(self.acquisition.settled and not self.acquisition.cleanup_unknown
                     and all(lease.state in ("NEW", "CLOSED") for lease in self.acquisition.leases))
            self.closed = True
            self.outgoing.clear(); self.incoming.clear()
            if self.io is not None:
                self.io.wipe()
            self.acquisition.close_launch()
            return True
        except BaseException as error:
            self.unknown = True
            self._failure(error)
            raise

    def accept_return(self, operation, result):
        """Consume known helper return only AFTER the genuine close sequence.

        A refused HTTP round can coexist with Git0 (Git ignores disconnect's
        helper status). It is still a refusal, never a successful fetch. An OK
        helper does not hide a nonzero stock-Git verification result either.
        """
        self._origin()
        _require(operation is self.source.require_operation() and not self.return_checked)
        self.return_checked = True
        if (not self.closed or not self.eof or not self.producer_returned or not operation.remote_returned
                or self.unknown or self.acquisition.cleanup_unknown
                or type(self.helper_return) is not wire.Returned or self.helper_return.status == "unknown"
                or type(getattr(result, "returncode", None)) is not int):
            self.unknown = operation.unknown = operation.repository._unknown = True
            error = ProcessCleanupError("The original private Git helper did not settle.", dispatched=True)
            self._failure(error)
            raise error
        if self.helper_return.status == "refused":
            self.failed = True
            self.source.failure_observed()
            raise RemoteRefusal(self.helper_return)

    def close_unused(self, operation):
        """Only the positively unexported original pair; not child cleanup.

        A consumed export, even without a visible child, belongs to C/A/W and
        must use finish after its real return. No endpoint replacement or
        guessed EOF can make such a failed acquisition unused again.
        """
        self._origin()
        _require(operation is self.source.require_operation() and not operation.unknown
                 and not self.finish_entered and not self.get_entered
                 and (self.command is None or not self.command._exported))
        self.finish_entered = True
        if self.unknown or self.acquisition.cleanup_unknown or not self.acquisition.settled:
            return False
        try:
            for lease in (self.client, self.peer):
                if lease is not None:
                    lease.close()
            _require(self.acquisition.settled and not self.acquisition.cleanup_unknown
                     and all(lease.state in ("NEW", "CLOSED") for lease in self.acquisition.leases))
            self.closed = True
            self.outgoing.clear(); self.incoming.clear()
            if self.io is not None:
                self.io.wipe()
            self.acquisition.close_launch()
            return True
        except BaseException as error:
            self.unknown = True
            self._failure(error)
            raise
