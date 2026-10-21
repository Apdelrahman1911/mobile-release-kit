"""Fixed nonshipping Entry additions; no substitute process/FD/clock owner.

All fixture files are slots in the ACTUAL helper's Acquisition. FD8 remains a
borrowed original map copy. The D case deliberately delays kernel exit after
ordinary pipes and the returned frame: it performs no ordinary IO thereafter.
Only the installed observer may nominate this entry; shipping entries do not
import it and shipping CLT nomination remains unavailable.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import time

from . import _git_fetch_observation_data as data
from . import git_remote_transport as remote
from . import desktop_git_remote_helper as original

_VIEW = re.compile(r"mrk-git-fetch-[a-zA-Z0-9_]{6,32}\Z", re.ASCII)
_LIMIT = 32 * 1024 * 1024
_BLOCK = 1024 * 1024
_CALLS = 128
_INSTALLED = False


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Fixture:
    """At most four file slots; same original one-attempt FDLease close."""
    def __init__(self, entry, case):
        data.need(type(entry) is original._Entry and case in data.CASES
                  and entry.get_returned and not hasattr(entry, "_observation_fixture"))
        self.entry, self.case = entry, case
        self.leases = []
        self.calls = 0
        self.limit_entered = self.limit_verified = self.close_entered = False
        self.view = self.parent = self.file = self.limit = None
        self.buffer = self.raw = self.transcript = None
        # Retained BEFORE file acquisition, including a lost open publication.
        entry._observation_fixture = self

    def call(self, name, function, *args, mutating=True):
        data.need(self.calls < _CALLS)
        self.calls += 1
        return self.entry.acquisition._invoke("fetch_observer_" + name, function,
            *args, roots=(self,), mutating=mutating)

    def current(self):
        self.entry.current()
        data.need(not self.close_entered)

    def fd(self, lease):
        self.entry.origin()
        data.need(lease in self.leases and lease.state == "OPEN" and type(lease._fd) is int)
        # Fixture-only file/directory checks below, NOT FDLease's pipe/null
        # validator and NOT a widened public adopt_fd API.
        return lease._fd

    def open(self, name, flags, *, parent=None):
        self.current()
        data.need(len(self.leases) < 4)
        lease = self.entry.acquisition._new_lease()
        self.leases.append(lease)
        lease._state = "ACQUIRING"
        try:
            def acquire():
                return os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                               dir_fd=None if parent is None else self.fd(parent))
            fd = self.call("open", acquire)
            data.need(type(fd) is int and fd > 2 and fd != 8)
            lease._publish_known(fd, self.entry.io.runtime, flags & os.O_ACCMODE,
                                 "git_fetch_observation_file")
            lease._check_origin()
            data.need(not os.get_inheritable(fd))
            return lease
        except BaseException:
            if lease.state == "ACQUIRING":
                lease._state = "UNKNOWN"
                self.entry.acquisition._remember("fetch_observer_open")
            raise

    def info(self, lease):
        return self.call("stat", os.fstat, self.fd(lease), mutating=False)

    def read(self):
        self.current()
        cwd = Path.cwd()
        data.need(cwd.is_absolute() and _VIEW.fullmatch(cwd.name) is not None
                  and cwd.parent.name == ".git" and cwd.parent.parent.name == self.case)
        self.view = self.open(".", os.O_RDONLY | os.O_DIRECTORY)
        self.parent = self.open("..", os.O_RDONLY | os.O_DIRECTORY, parent=self.view)
        for lease in (self.view, self.parent):
            info = self.info(lease)
            data.need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() > 0
                      and stat.S_IMODE(info.st_mode) & 0o7022 == 0)
        self.file = self.open(data.DATA_NAME, os.O_RDONLY | os.O_NONBLOCK, parent=self.parent)
        before = self.info(self.file)
        data.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() > 0
                  and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                  and 0 < before.st_size <= data.DATA_LIMIT)
        runtime, c = self.entry.io.runtime, self.entry.io.runtime.abi.c
        function = runtime.library["read"]
        function.argtypes, function.restype = [c.c_int, c.c_void_p, c.c_size_t], c.c_ssize_t
        runtime.functions["fetch_observer_read"] = function
        self.buffer = (c.c_ubyte * (data.DATA_LIMIT + 1))()
        self.raw = bytearray()
        while len(self.raw) <= before.st_size:
            self.current()
            maximum = before.st_size + 1 - len(self.raw)
            count = self.call("read", runtime.call, "fetch_observer_read",
                              self.fd(self.file), self.buffer, maximum)
            data.need(type(count) is int and 0 <= count <= maximum)
            if count == 0:
                break
            self.raw.extend(self.buffer[:count])
        data.need(len(self.raw) == before.st_size and _stamp(self.info(self.file)) == _stamp(before))
        named = os.stat(data.DATA_NAME, dir_fd=self.fd(self.parent), follow_symlinks=False)
        data.need(_stamp(named) == _stamp(before))
        self.transcript = data.decode(bytes(self.raw), self.case)
        self.current()
        return self.transcript

    def limit_probe(self):
        self.current()
        data.need(self.case == data.CASES[2] and not self.limit_entered
                  and self.entry.binding.target.selected.oid == self.transcript.target)
        self.limit_entered = True
        # The ACTUAL inherited W limits, not a setrlimit done by this helper.
        data.need(self.call("core", resource.getrlimit, resource.RLIMIT_CORE, mutating=False) == (0, 0)
                  and self.call("fsize", resource.getrlimit, resource.RLIMIT_FSIZE, mutating=False) == (_LIMIT, _LIMIT)
                  and signal.getsignal(signal.SIGXFSZ) == signal.SIG_IGN)
        self.limit = self.open(data.LIMIT_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent=self.view)
        before = self.info(self.limit)
        data.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() > 0
                  and before.st_nlink == 1 and before.st_size == 0 and stat.S_IMODE(before.st_mode) == 0o600)
        runtime, c = self.entry.io.runtime, self.entry.io.runtime.abi.c
        function = runtime.library["write"]
        function.argtypes, function.restype = [c.c_int, c.c_void_p, c.c_size_t], c.c_ssize_t
        runtime.functions["fetch_observer_write"] = function
        # One fixed 1MiB buffer, no body spool or 33 retained byte returns.
        self.buffer = (c.c_ubyte * _BLOCK)()
        total = 0
        for _ in range(32):
            self.current()
            count = self.call("write", runtime.call, "fetch_observer_write",
                              self.fd(self.limit), self.buffer, _BLOCK)
            data.need(count == _BLOCK)
            total += count
        self.current()
        count = self.call("write", runtime.call, "fetch_observer_write",
                          self.fd(self.limit), self.buffer, 1)
        data.need(count == -1 and runtime.last_errno == errno.EFBIG and total == _LIMIT)
        self.call("fsync", os.fsync, self.fd(self.limit))
        after = self.info(self.limit)
        data.need(_stamp(after)[:6] == _stamp(before)[:6] and after.st_size == _LIMIT)
        data.need(_stamp(os.stat(data.LIMIT_NAME, dir_fd=self.fd(self.view), follow_symlinks=False)) == _stamp(after))
        self.call("unlink", lambda: os.unlink(data.LIMIT_NAME, dir_fd=self.fd(self.view)))
        try:
            os.stat(data.LIMIT_NAME, dir_fd=self.fd(self.view), follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise data.Refused()
        unlinked = self.info(self.limit)
        data.need(unlinked.st_dev == after.st_dev and unlinked.st_ino == after.st_ino
                  and unlinked.st_size == _LIMIT and unlinked.st_nlink == 0)
        self.limit.close()  # One attempt; uncertainty cannot pass or retry.
        data.need(self.limit.state == "CLOSED")
        self.limit_verified = True
        raise remote.RemoteError("response-limit")

    def close(self):
        data.need(not self.close_entered)
        self.close_entered = True
        for lease in reversed(self.leases):
            if lease.state == "CLOSED":
                continue
            try:
                data.need(time.monotonic() < self.entry.hard_end)
                lease.close()
            except BaseException as error:
                self.entry.unknown = True
                self.entry.remember(error)
        if any(lease.state != "CLOSED" for lease in self.leases):
            self.entry.unknown = True


def read_transcript(entry, case):
    fixture = _Fixture(entry, case)
    value = fixture.read()
    if case == data.CASES[2] and entry.binding.target.selected.oid is not None:
        fixture.limit_probe()
    return value


def _hold_borrowed(entry):
    """D only: no ordinary IO, no dup, no FD8 close and no new deadline."""
    data.need(type(entry) is original._Entry and entry.closed and entry.return_entered
              and not entry.unknown and entry.helper.finished)
    while time.monotonic() < entry.hard_end:
        entry.origin()
        remaining = entry.hard_end - time.monotonic()
        ready = select.select([8], [], [], min(0.02, max(0.0, remaining)))[0]
        if ready:
            block = entry.io.receive(entry.endpoint, 1)
            if block == b"":
                return 70  # Actual original STOP shutdown, then kernel exit.
            data.need(block is None)  # No second command/token frame.
    return 74


def helper(*, remote_name, url, runtime_dir, started):
    global _INSTALLED
    data.need(not _INSTALLED)
    _INSTALLED = True
    from ._git_fetch_observation_http import Supplier
    from . import _github_connection_transport as http
    entry = original._Entry(remote_name, url, runtime_dir, started)
    supplier = Supplier(entry=entry)
    # Process-local fixed supplier; no injection parameter on a shipping API.
    http._make_live_exchange = supplier.factory
    try:
        try:
            entry.acquire()
            entry.helper.run()
        except BaseException as error:
            entry.remember(error)
        finally:
            fixture = getattr(entry, "_observation_fixture", None)
            try:
                if fixture is not None:
                    fixture.close()
            except BaseException as error:
                entry.unknown = True
                entry.remember(error)
            finally:
                # Even interruption/unknown fixture retirement cannot skip
                # the original ordinary-pipe one-attempt close route.
                entry.close_pipes()
        code = entry.complete()
        if (code == 0 and supplier.transcript is not None and supplier.transcript.case == data.CASES[3]
                and entry.binding.target.selected.oid is not None):
            return _hold_borrowed(entry)
        return code
    except BaseException as error:
        entry.remember(error)
        return 74
    finally:
        if entry.unknown or not entry.closed:
            original._RETAINED.append(entry)


def install_worker_probe():
    """Same original poll, no new reader/channel and no mutated receipts."""
    global _INSTALLED
    data.need(not _INSTALLED)
    _INSTALLED = True
    from ._git_remote_input_channel import OriginalInputChannel
    from . import _git_remote_private_protocol as private
    old = OriginalInputChannel.poll
    sent = False

    def poll(channel):
        nonlocal sent
        result = old(channel)
        returned = channel.helper_return
        if (sent or channel.binding is None or channel.binding.target.selected.oid is None
                or type(returned) is not private.Returned):
            return result
        case = channel.binding.target.repository.removeprefix(data.ACCOUNT + "/")
        marker = data.WINDOW_MARKER if case == data.CASES[3] and returned.status == "ok" else None
        if marker is None:
            return result
        data.need(channel.get_sent and channel.get_entered and not channel.producer_returned
                  and not channel.finish_entered and not channel.eof and not channel.incoming
                  and channel.client.state == "OPEN")
        sent = True  # One attempted marker, even if write is interrupted.
        operation = channel.source.require_operation()
        engine = operation.engine
        output = engine.error_output
        data.need(engine.input is channel.source and output.number == 2 and output.owned
                  and not output.close_claimed and not engine.terminal_claimed)
        info = os.fstat(2)
        data.need((info.st_dev, info.st_ino, info.st_mode) == output.identity
                  and time.monotonic() < channel.source.work_end)
        # Parent WORKER stderr is still open. Helper stdout/stderr were closed
        # BEFORE the validated returned frame. Never strip arbitrary stderr.
        data.need(os.write(2, marker) == len(marker))
        return result

    OriginalInputChannel.poll = poll
