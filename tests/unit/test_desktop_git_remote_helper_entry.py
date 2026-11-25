"""Actual helper entry/control with inert native IO and HTTP returns only.

No descriptors, native ABI, Git, process, TLS, CA or credentials are accessed.
The real transcript/delegates run; fake closes never prove native finality.
"""
from collections import deque
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import desktop_git_remote_helper as entry
from mobile_release import _git_remote_private_protocol as private
from mobile_release import _github_connection_transport as http
from mobile_release import _native_process as native
from mobile_release import git_remote_transport as transport
from mobile_release.git_remote_wire import Selection
from test_git_remote_transport import FakeExchange, TARGET, ACCOUNT, REPOSITORY, LS_REQUEST, LS_RESPONSE
from test_git_remote_helper import PREFIX
from test_git_remote_wire import fetch, offered


class Pipe:
    def __init__(self, world):
        self.world, self.state, self.number = world, "NEW", None
    def _publish(self, number, runtime, access, kind):
        assert number in (0, 1, 2) and kind == "pipe" and self.state == "NEW"
        self.number, self.state = number, "OPEN"
        self.world.events.append(("adopt", number))
    def _validate(self, **options):
        assert self.state == "OPEN"
    def close(self):
        assert self.state == "OPEN"
        self.world.events.append(("close", self.number))
        self.state = "UNKNOWN" if self.world.close_failure == self.number else "CLOSED"
        if self.state == "UNKNOWN":
            raise OSError("inert ordinary-pipe close ambiguity")


class World:
    def __init__(self, *, metadata=False, at=120.):
        self.now, self.events, self.output, self.leases = at, [], [], []
        self.close_failure = None
        target = replace(TARGET, selected=Selection(TARGET.selected.reference, None)) if metadata else TARGET
        self.binding = private.Binding("git-1", "a" * 64, "origin", target,
            145_000_000_000, 155_000_000_000, b"a" * 16, (1001, 1, 2))
        self.socket = deque((self.binding.challenge(), self.binding.grant("not-a-credential")))
        self.source = io.BytesIO(PREFIX + LS_REQUEST + (b"" if metadata else fetch()))
        bodies = [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, ACCOUNT, REPOSITORY] if metadata else None
        self.http = FakeExchange(target=target, bodies=bodies)
        self.raw_sent = []

    def socket_init(self, channel, acquisition):
        channel.owner = acquisition
        channel.runtime = SimpleNamespace(abi=SimpleNamespace(constants={"F_GETFL": 3}))
        channel.buffer = None

    def receive(self, channel, borrowed, maximum):
        assert borrowed.entry.endpoint is borrowed
        if not self.socket:
            return None
        raw = self.socket.popleft()
        if len(raw) > maximum:
            self.socket.appendleft(raw[maximum:]); raw = raw[:maximum]
        return raw

    def send(self, channel, borrowed, raw):
        self.events.append(("private", bytes(raw)))
        self.raw_sent.append(bytes(raw))
        return len(raw)

    def pipe_io(self, channel, owner):
        channel.entry, channel.buffer = owner, bytearray(4096)

    def read(self, channel, maximum):
        self.events.append(("read", maximum))
        return self.source.read(maximum)

    def write(self, channel, raw):
        self.events.append(("write", len(raw)))
        self.output.append(raw)

    def lease(self, acquisition):
        value = Pipe(self); self.leases.append(value); return value

    def invoke(self, acquisition, name, function, *args, **options):
        assert name in ("git_remote_helper_cloexec", "git_remote_helper_nonblocking")
        assert args[0] in (0, 1, 2)
        self.events.append((name, args[0]))
        return None  # No descriptor or native function called.

    def factory(self, target, token, *, started, runtime_dir, budget, current, failure):
        assert token == "not-a-credential" and target == self.binding.target
        assert runtime_dir == "/inert-runtime" and budget.started == started
        self.http.clock = budget
        self.http.current = current
        return transport._RemoteTransport(target, self.http.exchange, budget, current)


@contextmanager
def original(world):
    body = entry._Entry("origin", "https://github.com/fixture/relay.git", Path("/inert-runtime"), world.now)
    with ExitStack() as stack:
        for name in ("subprocess.Popen", "socket.socket", "ssl.SSLContext"):
            stack.enter_context(patch(name, side_effect=AssertionError("No native/network IO in helper fixture")))
        stack.enter_context(patch.object(entry.time, "monotonic", side_effect=lambda: world.now))
        stack.enter_context(patch.object(entry.time, "CLOCK_UPTIME_RAW", 1, create=True))
        stack.enter_context(patch.object(entry.time, "clock_gettime_ns", side_effect=lambda _: int(world.now * 1e9)))
        stack.enter_context(patch.object(entry._SocketIO, "__init__", lambda s, a: world.socket_init(s, a)))
        stack.enter_context(patch.object(entry._SocketIO, "receive", lambda s, b, m: world.receive(s, b, m)))
        stack.enter_context(patch.object(entry._SocketIO, "send", lambda s, b, d: world.send(s, b, d)))
        stack.enter_context(patch.object(entry._SocketIO, "wipe", return_value=None))
        stack.enter_context(patch.object(entry._BorrowedEndpoint, "check", lambda endpoint: setattr(endpoint, "identity", world.binding.identity)))
        stack.enter_context(patch.object(native.Acquisition, "_new_lease", lambda a: world.lease(a)))
        stack.enter_context(patch.object(native.Acquisition, "_invoke", lambda a, *args, **kw: world.invoke(a, *args, **kw)))
        stack.enter_context(patch.object(entry._PipeIO, "__init__", lambda s, e: world.pipe_io(s, e)))
        stack.enter_context(patch.object(entry._PipeIO, "read", lambda s, m: world.read(s, m)))
        stack.enter_context(patch.object(entry._PipeIO, "write", lambda s, b: world.write(s, b)))
        stack.enter_context(patch.object(transport, "_make_transport", side_effect=world.factory))
        stack.enter_context(patch.object(entry, "_Entry", return_value=body))
        try:
            yield body
        finally:
            if body in entry._RETAINED:
                entry._RETAINED.remove(body)  # No real resource in this inert world.
            world.source.close()


def run(world):
    return entry.main(remote="origin", url="https://github.com/fixture/relay.git",
                      runtime_dir=Path("/inert-runtime"), started=world.now)


class EntryTests(unittest.TestCase):
    def test_actual_entry_transcript_closes_only_ordinary_pipes_before_returned(self):
        world = World()
        with original(world) as body:
            self.assertEqual(run(world), 0)
            returned = world.binding.accept_message(world.raw_sent[-1])
            self.assertEqual((returned.status, returned.reason), ("ok", None))
            self.assertEqual(len(world.http.calls), 7)
            self.assertEqual([row.number for row in world.leases], [0, 1, 2])
            self.assertEqual(world.events[-4:-1], [("close", 2), ("close", 1), ("close", 0)])
            self.assertEqual(world.events[-1][0], "private")
            self.assertFalse(hasattr(body.endpoint, "close"))
            self.assertTrue(body.closed and body.return_entered and body.helper.finished)
            with self.assertRaises(transport.RemoteError):
                body.complete()

    def test_late_helper_launch_keeps_parent_45_55_endpoints(self):
        world = World(at=133.)
        with original(world) as body:
            self.assertEqual(run(world), 0)
            self.assertLessEqual(body.budget.end, 145.)
            self.assertAlmostEqual(body.budget.started, 100., places=8)
            self.assertLessEqual(body.hard_end, 155.)
            self.assertNotEqual(body.budget.end, world.now + 45)

    def test_metadata_uses_same_entry_and_has_six_requests_no_fetch_body(self):
        world = World(metadata=True)
        with original(world) as body:
            self.assertEqual(run(world), 0)
            self.assertEqual(len(world.http.calls), 6)
            self.assertEqual([call[3] for call in world.http.calls].count(transport.FETCH), 0)
            self.assertTrue(body.helper.finished)

    def test_http_close_unknown_cannot_emit_ok_even_after_ordinary_pipe_closes(self):
        world = World()
        world.http.close_error = http._CloseFailure("inert original HTTP close")
        with original(world) as body:
            self.assertEqual(run(world), 70)
            returned = world.binding.accept_message(world.raw_sent[-1])
            self.assertEqual((returned.status, returned.reason), ("unknown", "cleanup-unknown"))
            self.assertTrue(body.unknown)
            self.assertEqual([row.state for row in world.leases], ["CLOSED"] * 3)
            self.assertEqual(len(world.http.calls), 1)

    def test_pipe_close_unknown_is_one_attempt_and_private_unknown(self):
        world = World()
        world.close_failure = 1
        with original(world) as body:
            self.assertEqual(run(world), 70)
            self.assertEqual(world.binding.accept_message(world.raw_sent[-1]).status, "unknown")
            self.assertEqual([row for row in world.events if row[0] == "close"], [("close", 2), ("close", 1), ("close", 0)])
            with self.assertRaises(transport.RemoteError):
                body.close_pipes()

    def test_refused_identity_has_one_get_and_no_fetch_or_positive_completion(self):
        world = World()
        world.http.bodies[0] = {**ACCOUNT, "id": 999}
        with original(world):
            self.assertEqual(run(world), 70)
            self.assertEqual(world.binding.accept_message(world.raw_sent[-1]).status, "refused")
            self.assertEqual(len(world.http.calls), 1)
            self.assertEqual(sum(b'"action":"get"' in raw for raw in world.raw_sent), 1)

    def test_wrong_selected_url_never_claims_token_or_http(self):
        world = World()
        with original(world) as body:
            body.url = "https://github.com/other/project.git"
            self.assertEqual(run(world), 74)
            self.assertEqual((world.http.calls, world.raw_sent), ([], []))
            self.assertFalse(body.get_entered)

    def test_parent_stop_during_http_prevents_next_request_without_new_token(self):
        world = World()
        real = world.http.exchange
        def stop_after(*args, **kwargs):
            result = real(*args, **kwargs)
            world.socket.append(b"")
            return result
        world.http.exchange = stop_after
        with original(world) as body:
            self.assertEqual(run(world), 70)
            result = world.binding.accept_message(world.raw_sent[-1])
            self.assertEqual((result.status, result.reason), ("refused", "cancelled"))
            self.assertEqual(len(world.http.calls), 1)
            self.assertTrue(body.first_failure is not None and body.hard_end <= world.now + 10)

    def test_original_get_return_does_not_authorize_second_acquire_or_token(self):
        world = World()
        with original(world) as body:
            body.acquire()
            with self.assertRaises(transport.RemoteError):
                body.acquire()
            self.assertEqual(len(world.raw_sent), 1)
            body.close_pipes()


class BorrowedIOTests(unittest.TestCase):
    def test_borrowed_endpoint_checks_exact_socket_without_adoption_or_duplicate(self):
        calls = []
        mode = os.O_RDWR
        def invoke(name, function, *args, **options):
            calls.append((name, args))
            self.assertFalse(options["mutating"])
            return mode
        owner = SimpleNamespace(origin=lambda: None,
            acquisition=SimpleNamespace(_invoke=invoke),
            io=SimpleNamespace(runtime=SimpleNamespace(call=lambda: None,
                abi=SimpleNamespace(constants={"F_GETFL": 3}))))
        endpoint = entry._BorrowedEndpoint(owner)
        info = SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=501, st_dev=7, st_ino=9)
        with patch.object(os, "fstat", return_value=info), patch.object(os, "getuid", return_value=501), \
                patch.object(os, "get_blocking", return_value=False), patch.object(os, "get_inheritable", return_value=True), \
                patch.object(os, "close", side_effect=AssertionError("no borrowed close")), \
                patch.object(os, "dup", side_effect=AssertionError("no borrowed dup")):
            endpoint.check()
            self.assertEqual((endpoint.fileno(), endpoint.identity), (8, (501, 7, 9)))
            info.st_ino += 1
            with self.assertRaises(transport.RemoteError):
                endpoint.check()
            info.st_ino -= 1; mode = os.O_RDONLY
            with self.assertRaises(transport.RemoteError):
                endpoint.check()
        self.assertTrue(all(name == "git_remote_borrowed_mode" for name, _ in calls))

    def pipe(self, returns):
        native_calls, emitted = [], bytearray()
        values = iter(returns)
        pipe = entry._PipeIO.__new__(entry._PipeIO)
        pipe.buffer, pipe.count = bytearray(4096), 0
        runtime = SimpleNamespace(call=lambda: None, last_errno=0)
        def invoke(name, function, native_name, fd, buffer, maximum, **options):
            value = next(values)
            if isinstance(value, BaseException):
                raise value
            native_calls.append((name, native_name, fd, maximum, value))
            if value > 0:
                emitted.extend(buffer[:value])
            return value
        owner = SimpleNamespace(current=lambda: None, wait=lambda **kw: None,
            acquisition=SimpleNamespace(_invoke=invoke), io=SimpleNamespace(runtime=runtime),
            pipes=(SimpleNamespace(fileno=lambda: 0), SimpleNamespace(fileno=lambda: 1)))
        pipe.entry = owner
        return pipe, native_calls, emitted

    def test_actual_short_write_loop_keeps_one_buffer_and_integer_native_returns(self):
        pipe, calls, emitted = self.pipe([2, 1, 3])
        original = pipe.buffer
        pipe.write(b"abcdef")
        self.assertEqual(emitted, b"abcdef")
        self.assertEqual([row[3:] for row in calls], [(6, 2), (4, 1), (3, 3)])
        self.assertIs(pipe.buffer, original)
        pipe.wipe(); self.assertFalse(any(original))

    def test_unknown_write_return_is_not_repeated(self):
        sentinel = KeyboardInterrupt("inert missing write return")
        pipe, calls, emitted = self.pipe([2, sentinel, 4])
        with self.assertRaises(KeyboardInterrupt) as caught:
            pipe.write(b"abcdef")
        self.assertIs(caught.exception, sentinel)
        self.assertEqual((pipe.count, emitted, len(calls)), (2, b"ab", 1))

    def test_fixed_call_cap_and_impossible_count_refuse_before_more_io(self):
        pipe, calls, _ = self.pipe([5])
        with self.assertRaises(transport.RemoteError):
            pipe.write(b"a")
        self.assertEqual(len(calls), 1)
        pipe.count = entry.PIPE_CALLS
        with self.assertRaises(transport.RemoteError):
            pipe.write(b"a")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
