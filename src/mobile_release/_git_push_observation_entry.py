"""Fixed nonshipping facets of the ACTUAL Push Entry and input channel.

Fixture files occupy the same Acquisition's finite lease book. The held C
case delays kernel exit only AFTER the original refusal frame and ordinary IO
close. It never duplicates/closes FD8, fabricates an outcome, or renews first-F.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import select
import stat
import time

from . import _git_push_observation_data as data
from . import desktop_git_push_helper as original
from . import git_push_body as bodies
from . import git_push_transport as push
from . import _git_push_private_protocol as private
from ._desktop_git_push_helper import _Helper, _ReviewHelper

_VIEW = re.compile(r"mrk-git-push-[a-z0-9_]{6,32}\Z", re.ASCII)
_SCRATCH = re.compile(r"mrk-git-[a-z0-9_]{6,32}\Z", re.ASCII)
_CALLS = 64
_INSTALLED = False


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Fixture:
    """At most four added leases/64 calls, retained before any acquisition."""
    def __init__(self, entry, case):
        data.need(type(entry) is original._Entry and type(entry.binding) is private.Binding
                  and case in data.ALL_CASES and entry.get_returned and not hasattr(entry, "_observation_fixture"))
        self.entry, self.case = entry, case
        self.leases, self.edges = [], []
        self.calls = 0
        self.close_entered = False
        self.view = self.git = self.file = self.buffer = self.raw = self.transcript = None
        entry._observation_fixture = self

    def call(self, name, function, *args, mutating=True):
        data.need(self.calls < _CALLS)
        self.calls += 1
        return self.entry.acquisition._invoke("push_observer_" + name, function,
            *args, roots=(self,), mutating=mutating)

    def current(self):
        self.entry.current()
        data.need(not self.close_entered)

    def fd(self, lease):
        self.entry.origin()
        data.need(lease in self.leases and lease.state == "OPEN" and type(lease._fd) is int)
        return lease._fd  # Fixed fixture-only checks, no public descriptor adoption.

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
                                 "git_push_observation_file")
            lease._check_origin()
            data.need(not os.get_inheritable(fd))
            return lease
        except BaseException:
            if lease.state == "ACQUIRING":
                lease._state = "UNKNOWN"
                self.entry.acquisition._remember("push_observer_open")
            raise

    def info(self, lease):
        return self.call("stat", os.fstat, self.fd(lease), mutating=False)

    def named(self, parent, name):
        return self.call("named", lambda: os.stat(name, dir_fd=self.fd(parent), follow_symlinks=False),
                         mutating=False)

    def read(self):
        self.current()
        cwd, binding = Path.cwd(), self.entry.binding
        data.need(cwd == binding.path and _VIEW.fullmatch(cwd.name) is not None)
        apply = binding.mode == "apply"
        git = cwd.parent.parent if apply else cwd.parent
        data.need(git.name == ".git" and git.parent.name == self.case
                  and (not apply or _SCRATCH.fullmatch(cwd.parent.name) is not None))
        self.view = self.open(".", os.O_RDONLY | os.O_DIRECTORY)
        data.need(bodies._stamp(self.info(self.view)) == binding.parent_stamp)
        parent = self.view
        for index in range(2 if apply else 1):
            child_name = cwd.name if index == 0 else cwd.parent.name
            child_before = _stamp(self.info(parent))
            held = self.open("..", os.O_RDONLY | os.O_DIRECTORY, parent=parent)
            observed = self.info(held)
            data.need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid() > 0
                      and stat.S_IMODE(observed.st_mode) == 0o700
                      and _stamp(self.named(parent, "..")) == _stamp(observed)
                      and _stamp(self.named(held, child_name)) == child_before)
            self.edges.append((parent, child_name, child_before, held, _stamp(observed)))
            parent = held
        self.git = parent
        self.file = self.open(data.DATA_NAME, os.O_RDONLY | os.O_NONBLOCK, parent=self.git)
        before = self.info(self.file)
        data.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() > 0
                  and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                  and 0 < before.st_size <= data.DATA_LIMIT)
        runtime, c = self.entry.io.runtime, self.entry.io.runtime.abi.c
        function = runtime.library["read"]
        function.argtypes, function.restype = [c.c_int, c.c_void_p, c.c_size_t], c.c_ssize_t
        runtime.functions["push_observer_read"] = function
        self.buffer, self.raw = (c.c_ubyte * (data.DATA_LIMIT + 1))(), bytearray()
        while len(self.raw) <= before.st_size:
            self.current()
            maximum = before.st_size + 1 - len(self.raw)
            count = self.call("read", runtime.call, "push_observer_read", self.fd(self.file), self.buffer, maximum)
            data.need(type(count) is int and 0 <= count <= maximum)
            if count == 0:
                break
            self.raw.extend(self.buffer[:count])
        data.need(len(self.raw) == before.st_size
                  and _stamp(self.info(self.file)) == _stamp(self.named(self.git, data.DATA_NAME)) == _stamp(before)
                  and bodies._stamp(self.info(self.view)) == binding.parent_stamp)
        for child, name, child_before, held, old in self.edges:
            data.need(_stamp(self.info(held)) == old == _stamp(self.named(child, ".."))
                      and _stamp(self.info(child)) == child_before == _stamp(self.named(held, name)))
        self.transcript = data.decode(bytes(self.raw), self.case)
        self.current()
        return self.transcript

    def close(self):
        data.need(not self.close_entered)
        self.close_entered = True
        for lease in reversed(self.leases):
            if lease.state == "CLOSED":
                continue
            try:
                data.need(time.monotonic() < self.entry.hard_end)
                lease.close()  # Original one-attempt close, including after known first-F.
            except BaseException as error:
                self.entry.unknown = True
                self.entry.remember(error)
        if any(lease.state != "CLOSED" for lease in self.leases):
            self.entry.unknown = True


def read_transcript(entry, case):
    return _Fixture(entry, case).read()


def audit(entry, supplier):
    """Comparison only, AFTER actual helper return, never a finality issuer."""
    data.need(type(entry) is original._Entry and supplier.entry is entry
              and type(supplier.transcript) is data.Transcript and not entry.unknown)
    mode, case = entry.binding.mode, supplier.transcript.case
    remote, helper = entry.transport, entry.helper
    data.need(type(remote) is push._PushTransport and remote.budget is entry.budget
              and remote.target is entry.binding.target)
    if case in data.create.CASES:
        return data.create.audit(entry, supplier)
    if mode == "review":
        data.need(type(helper) is _ReviewHelper and helper.finished and helper.input_eof and not helper.failed
                  and remote.finished and not remote.failed and remote.phase == 5
                  and supplier.calls == supplier.phase == entry.budget.requests == 5
                  and supplier.posts == 0 and supplier.sink is None and remote.posted is None
                  and entry.body_io is None and not entry.send_entered and entry.primary is None)
        return
    data.need(type(helper) is _Helper and not helper.entered)
    if case == data.CASES[1]:
        data.need(helper.failed and not helper.finished and helper.body is None and remote.failed
                  and remote.offered is remote.posted is None and remote.phase == 3
                  and supplier.calls == supplier.phase == entry.budget.requests == 3
                  and supplier.posts == 0 and supplier.sink is None and not entry.send_entered
                  and getattr(entry.primary, "reason", None) == "target-changed")
        return
    data.need(supplier.sink is not None and entry.send_returned and helper.pack_eof and helper.send_point_returned
              and helper.body is supplier.sink.body and supplier.sink.complete and not supplier.sink.failed
              and helper.body.phase == "sent" and helper.body.sent == supplier.sink.count
              and supplier.posts == 1 and supplier.tip == supplier.transcript.target)
    if case == data.CASES[0]:
        data.need(helper.finished and not helper.failed and remote.finished and not remote.failed
                  and remote.phase == 7 and supplier.calls == supplier.phase == entry.budget.requests == 7
                  and remote.posted.complete and remote.posted.value.outcome == "ok" and remote.readback is not None
                  and entry.primary is None)
    else:
        data.need(case == data.CASES[2] and helper.failed and not helper.finished and remote.failed
                  and remote.phase == 4 and supplier.calls == supplier.phase == entry.budget.requests == 4
                  and remote.posted.failed and remote.posted.value is remote.readback is None
                  and remote.posted.raw == data.receive_status(supplier.transcript)
                  and getattr(entry.primary, "reason", None) == "response-invalid"
                  and entry.first_failure_ns is not None and entry.cleanup_end_ns is not None)


def _hold_refused(entry, supplier):
    """C only: after the REAL refused frame/ordinary close, within original F+10."""
    audit(entry, supplier)
    data.need(supplier.transcript.case in (data.CASES[2], data.create.CASES[4]) and entry.binding.mode == "apply"
              and entry.closed and entry.return_entered and not entry.unknown
              and entry.pipes_close_entered and all(p.state == "CLOSED" for p in entry.pipes)
              and entry.body_parent.state == entry.body_file.state == "CLOSED")
    while time.monotonic() < entry.hard_end:
        entry.origin()
        ready = select.select([8], [], [], min(0.02, max(0.0, entry.hard_end - time.monotonic())))[0]
        if ready:
            block = entry.io.receive(entry.endpoint, 1)
            if block == b"":
                return 70  # Actual original STOP; kernel exit is NOT a joined receipt.
            data.need(block is None)
    return 74


def helper(*, remote, url, runtime_dir, started):
    global _INSTALLED
    data.need(not _INSTALLED)
    _INSTALLED = True
    from ._git_push_observation_http import Supplier
    from . import _github_connection_transport as http
    entry = original._Entry(remote, url, runtime_dir, started)
    supplier = Supplier(entry=entry)
    http._make_live_exchange = supplier.factory  # This one fixed nonshipping process only.
    try:
        try:
            entry.acquire()
            entry.helper.run()
        except BaseException as error:
            entry.remember(error)
        finally:
            try:
                audit(entry, supplier)
                fixture = getattr(entry, "_observation_fixture", None)
                data.need(fixture is not None)
            except BaseException as error:
                entry.unknown = True
                entry.remember(error)
            finally:
                try:
                    fixture = getattr(entry, "_observation_fixture", None)
                    if fixture is not None:
                        fixture.close()
                finally:
                    entry.close_pipes()
        code = entry.complete()
        if code == 70 and supplier.transcript is not None and supplier.transcript.case in (data.CASES[2], data.create.CASES[4]):
            return _hold_refused(entry, supplier)
        return code
    except BaseException as error:
        entry.remember(error)
        return 74
    finally:
        if entry.unknown or not entry.closed:
            original._RETAINED.append(entry)


def marker_ready(channel):
    """Only actual retained original DATA permits this diagnostic, not success."""
    from ._git_push_input_channel import PushInputChannel
    if type(channel) is not PushInputChannel or channel.binding is None:
        return False
    value = channel.helper_return
    if (channel.binding.mode != "apply" or not ((channel.binding.remote is not None
            and type(channel.binding.target.selected) is push.wire.Selection
            and channel.binding.target.repository == data.coordinate(data.CASES[2]))
            or data.create.held_binding(channel.binding))
            or type(value) is not private.Returned or value.status != "refused" or value.reason != "response-invalid"):
        return False
    source = channel.source
    data.need(channel.get_entered and channel.get_sent and channel.hook_returned and channel.send_returned
              and not channel.producer_returned and not channel.finish_entered and not channel.eof
              and not channel.closed and not channel.unknown and not channel.incoming and not channel.outgoing
              and channel.client.state == "OPEN" and value.response is value.after_sha256 is None
              and value.advertisement_sha256 is not None and value.first_failure_ns is not None
              and source.first_failure_ns is not None and source.first_failure_ns <= value.first_failure_ns
              and source.cleanup_end_ns <= value.cleanup_end_ns and time.monotonic() < source.hard_end)
    operation = source.require_operation()
    tx = operation.repository._transaction
    data.need(operation.source is source and not operation.remote_returned and operation.network_pending
              and tx.send_consumed and tx.acknowledged and tx.hook_returned)
    return True


def install_worker_probe():
    global _INSTALLED
    data.need(not _INSTALLED)
    _INSTALLED = True
    from ._git_push_input_channel import PushInputChannel
    original_poll, sent = PushInputChannel.poll, False

    def poll(channel):
        nonlocal sent
        result = original_poll(channel)  # Same parser/first-F/STOP, not Fetch's poll or accept_return.
        if sent or not marker_ready(channel):
            return result
        sent = True
        source, engine = channel.source, channel.source.require_operation().engine
        output = engine.error_output
        data.need(engine.input is source and output.number == 2 and output.owned
                  and not output.close_claimed and not engine.terminal_claimed)
        info = os.fstat(2)
        data.need((info.st_dev, info.st_ino, info.st_mode) == output.identity
                  and time.monotonic() < source.hard_end)
        data.need(os.write(2, data.WINDOW_MARKER) == len(data.WINDOW_MARKER))
        return result

    PushInputChannel.poll = poll
