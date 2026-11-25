"""Actual entries/Acquisition/leases with finite fake syscall/HTTP returns.

No process, descriptor, account, remote, native permission or finality is
created. This exercises the real shared close/state code, not an IO emulator
claimed to qualify stock Git or the native parent.
"""
from collections import deque
from dataclasses import replace
import ctypes
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import desktop_git_push_helper as helper
from mobile_release import desktop_git_push_hook as hook
from mobile_release import desktop_git_remote_helper as original
from mobile_release import git_push_body as body
from mobile_release import git_push_transport as transport
from mobile_release import _git_push_private_protocol as private
from mobile_release import _native_process as native
from test_git_push_private_protocol import binding
from test_git_push_transport import Exchange, TARGET, OK
from test_git_push_wire import command, pack, offered


class _World:
    def __init__(self, test, mode="apply", *, fixed_hook=False, at=120.):
        self.test, self.now, self.binding = test, at, binding(mode)
        self.fixed_hook, self.events, self.output = fixed_hook, [], bytearray()
        self.content, self.offset = bytearray(), 0
        self.file_stamp = self.binding.body_stamp
        self.socket = deque([self.binding.hook().reply()] if fixed_hook else
                            [self.binding.challenge(), self.binding.grant("SYNTHETIC_PRIVATE_INPUT")])
        self.sent, self.sending = [], bytearray()
        self.source = io.BytesIO(self.binding.hook().line if fixed_hook else
            b"capabilities\nconnect git-receive-pack\n" + (b"0000" if mode == "review" else command().raw + pack()))
        self.runtime = SimpleNamespace(abi=SimpleNamespace(c=ctypes, constants={"F_GETFL": 3, "F_GETFD": 1, "FD_CLOEXEC": 1}),
            library={name: SimpleNamespace() for name in ("read", "write")}, functions={}, call=self.call, last_errno=0)
        self.close_failure = self.open_failure = None
        self.lost_ack = self.hook_outstanding = self.hook_drained = False
        self.unknown_http = False
        self.entry = (hook._Entry(mode, self.binding.clock, self.binding.review_digest,
                        self.binding.hook().remote, self.binding.hook().url, Path("/inert-runtime"), self.now)
                      if fixed_hook else helper._Entry("mrk::https://github.com/fixture/relay.git",
                        "https://github.com/fixture/relay.git", Path("/inert-runtime"), self.now))
        self.entry.acquisition._native, self.entry.acquisition._native_ready = self.runtime, True
        self.http = Exchange(mode=mode, current=self.entry._current_callback)
        self.install(test)
        test.addCleanup(self.source.close)
        test.addCleanup(lambda: helper._RETAINED.remove(self.entry) if self.entry in helper._RETAINED else None)
        test.addCleanup(lambda: hook._RETAINED.remove(self.entry) if self.entry in hook._RETAINED else None)

    def install(self, test):
        for name in ("subprocess.Popen", "socket.socket", "ssl.SSLContext", "os.close", "os.dup", "os.dup2", "os.fork"):
            test.enterContext(patch(name, side_effect=AssertionError("No real process/native/network effects")))
        test.enterContext(patch.object(original.time, "monotonic", side_effect=lambda: self.now))
        test.enterContext(patch.object(original.time, "CLOCK_UPTIME_RAW", 1, create=True))
        test.enterContext(patch.object(original.time, "clock_gettime_ns", side_effect=lambda _: int(self.now * 1e9)))
        test.enterContext(patch.object(original._SocketIO, "__init__", self.socket_init))
        test.enterContext(patch.object(original._SocketIO, "receive", lambda channel, endpoint, maximum: self.receive(maximum)))
        test.enterContext(patch.object(original._SocketIO, "send", lambda channel, endpoint, data: self.send(data)))
        test.enterContext(patch.object(original._SocketIO, "wipe", return_value=None))
        test.enterContext(patch.object(original._BorrowedEndpoint, "check",
                                      lambda endpoint: setattr(endpoint, "identity", self.binding.identity)))
        test.enterContext(patch.object(os, "getuid", return_value=self.binding.identity[0]))
        test.enterContext(patch.object(os, "fstat", side_effect=self.fstat))
        test.enterContext(patch.object(os, "open", side_effect=self.open))
        test.enterContext(patch.object(os, "fsync", side_effect=lambda fd: self.test.assertEqual(fd, 11)))
        test.enterContext(patch.object(os, "lseek", side_effect=self.seek))
        test.enterContext(patch.object(os, "set_inheritable", side_effect=lambda fd, value: self.events.append(("cloexec", fd, value))))
        test.enterContext(patch.object(os, "set_blocking", side_effect=lambda fd, value: self.events.append(("blocking", fd, value))))
        source_stat, source_lstat = os.stat, Path.lstat
        def named(path, **options):
            if path == body.NAME:
                test.assertEqual(options, {"dir_fd": 10, "follow_symlinks": False})
                return self.info(self.file_stamp)
            return source_stat(path, **options)
        test.enterContext(patch.object(os, "stat", side_effect=named))
        test.enterContext(patch.object(Path, "lstat", lambda path: self.info(self.binding.parent_stamp)
                                      if path == self.binding.path else source_lstat(path)))
        test.enterContext(patch.object(transport, "_make_transport", side_effect=self.factory))

    def socket_init(self, channel, acquisition):
        channel.owner, channel.runtime, channel.buffer, channel.count = acquisition, self.runtime, None, 0

    @staticmethod
    def info(stamp):
        return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns",
            "st_ctime_ns", "st_uid", "st_gid", "st_nlink"), stamp)))

    def fstat(self, fd):
        if fd in (0, 1, 2):
            import stat
            return SimpleNamespace(st_mode=stat.S_IFIFO, st_uid=self.binding.identity[0], st_dev=1, st_ino=20 + fd)
        self.test.assertIn(fd, (10, 11))
        return self.info(self.binding.parent_stamp if fd == 10 else self.file_stamp)

    def open(self, path, flags, **options):
        self.events.append(("open", path, flags, options))
        fd = 10 if path == self.binding.path else 11
        self.test.assertFalse(flags & os.O_CREAT)
        self.test.assertTrue(flags & os.O_CLOEXEC and flags & os.O_NOFOLLOW)
        self.test.assertEqual(options, {} if fd == 10 else {"dir_fd": 10})
        if self.open_failure == fd:
            raise OSError("SYNTHETIC_OPEN_UNKNOWN")
        return fd

    def seek(self, fd, offset, whence):
        self.test.assertEqual((fd, offset, whence), (11, 0, os.SEEK_SET))
        self.offset = 0
        return 0

    def call(self, name, fd, *args):
        self.events.append((name, fd))
        if name == "fcntl":
            return (os.O_RDONLY if fd in (0, 10) else os.O_RDWR if fd == 11 else os.O_WRONLY) if args[0] == 3 else 1
        if name == "close":
            self.test.assertNotEqual(fd, 8)
            if self.close_failure == fd:
                raise OSError("SYNTHETIC_CLOSE_UNKNOWN")
            return 0
        buffer, maximum = args
        if name == "git_remote_helper_read":
            self.test.assertEqual(fd, 0)
            if self.hook_outstanding:
                self.test.assertEqual(self.socket.popleft(), self.binding.hook().reply())
                self.hook_outstanding, self.hook_drained = False, True
            data = self.source.read(maximum)
            buffer[:len(data)] = data
            return len(data)
        if name == "git_remote_helper_write":
            self.test.assertEqual(fd, 1)
            self.output.extend(bytes(buffer[:maximum]))
            if self.output == b"connect\n\n\n" + offered().git_bytes():
                self.socket.append(self.binding.hook().reply())
                self.hook_outstanding = True
            return maximum
        self.test.assertEqual(fd, 11)
        if name == "git_push_body_write":
            self.test.assertEqual(self.offset, len(self.content))
            self.content.extend(bytes(buffer[:maximum])); self.offset += maximum
            self.file_stamp = (*self.file_stamp[:3], len(self.content), self.file_stamp[4] + 1,
                               self.file_stamp[5] + 1, *self.file_stamp[6:])
            return maximum
        self.test.assertEqual(name, "git_push_body_read")
        data = self.content[self.offset:self.offset + maximum]
        buffer[:len(data)] = data; self.offset += len(data)
        return len(data)

    def receive(self, maximum):
        self.test.assertFalse(self.hook_outstanding, "helper stole the fixed hook's original ACK")
        if not self.socket:
            return None
        raw = self.socket.popleft()
        if len(raw) > maximum:
            self.socket.appendleft(raw[maximum:]); raw = raw[:maximum]
        return raw

    def send(self, data):
        self.sending.extend(data)
        if self.sending.endswith(b"\n"):
            raw = bytes(self.sending); self.sending.clear()
            self.sent.append(raw); self.events.append(("private", private._decode(raw)["phase"]))
            if not self.fixed_hook:
                value = self.binding.accept_message(raw)
                if type(value) is private.Send:
                    self.test.assertTrue(self.hook_drained and self.entry.helper.pack_eof)
                    self.test.assertEqual(value.stamp, self.file_stamp)
                    self.test.assertEqual(value.body.body_bytes, len(self.content))
                    self.socket.append(b"" if self.lost_ack else self.binding.send_reply(value.body))
        return len(data)

    def factory(self, target, mode, token, *, started, runtime_dir, budget, current, failure):
        self.test.assertEqual((target, mode, token), (TARGET, self.binding.mode, "SYNTHETIC_PRIVATE_INPUT"))
        self.test.assertEqual(runtime_dir, "/inert-runtime")
        self.http.clock, self.http.failure = budget, failure
        self.http.wrapper = transport._PushTransport(target, mode, self.http.exchange, budget, current, failure)
        if self.unknown_http:
            self.http.fail_close = transport.http._CloseFailure("SYNTHETIC_HTTP_UNKNOWN")
        return self.http.wrapper

    def run(self):
        try:
            try:
                self.entry.acquire()
                self.entry.run() if self.fixed_hook else self.entry.helper.run()
            except BaseException as error:
                self.entry.remember(error)
            finally:
                self.entry.close_pipes()
            return self.entry.complete()
        except BaseException as error:
            self.entry.remember(error)
            return 74


class GitPushEntryTests(unittest.TestCase):
    def test_apply_real_entry_keeps_hook_ack_and_two_body_leases_until_known_close(self):
        world = _World(self)
        self.assertEqual(world.run(), 0)
        self.assertTrue(world.hook_drained and world.entry.send_returned)
        self.assertEqual(bytes(world.content), command().raw + pack())
        self.assertEqual(bytes(world.output), b"connect\n\n\n" + offered().git_bytes() + OK)
        self.assertEqual([lease.state for lease in world.entry.acquisition.leases], ["CLOSED"] * 5)
        self.assertEqual([event for event in world.events if event[0] == "close"],
                         [("close", 11), ("close", 10), ("close", 2), ("close", 1), ("close", 0)])
        self.assertEqual(world.events[-1], ("private", "returned"))
        result = world.binding.accept_message(world.sent[-1])
        self.assertEqual((result.status, result.response.outcome), ("ok", "ok"))
        self.assertEqual(len(world.http.calls), 7)
        self.assertEqual(len([event for event in world.events if event[0] == "open"]), 2)
        self.assertFalse(hasattr(result, "native_joined"))

    def test_review_real_entry_has_no_body_open_no_ack_no_post(self):
        world = _World(self, "review")
        self.assertEqual(world.run(), 0)
        self.assertTrue(world.hook_drained)
        self.assertEqual(len(world.entry.acquisition.leases), 3)
        self.assertFalse(any(event[0] == "open" for event in world.events))
        self.assertEqual([private._decode(raw)["phase"] for raw in world.sent], ["get", "returned"])
        self.assertTrue(all(row[0] == "GET" for row in world.http.calls))
        self.assertEqual(len(world.http.calls), 5)
        self.assertIsNone(world.binding.accept_message(world.sent[-1]).response)

    def test_lost_send_ack_keeps_body_and_never_enters_http_post_or_reopens(self):
        world = _World(self)
        world.lost_ack = True
        self.assertEqual(world.run(), 70)
        self.assertTrue(world.entry.send_entered and not world.entry.send_returned)
        self.assertEqual(world.entry.helper.body.phase, "sealed")
        self.assertEqual(len(world.http.calls), 3)
        self.assertGreater(len(world.content), 0)
        before = list(world.events)
        with self.assertRaises(transport.PushError):
            world.entry.acquire()
        self.assertEqual(world.events, before)

    def test_unknown_body_close_retains_positive_http_receipt_but_no_ok(self):
        world = _World(self)
        world.close_failure = 11
        self.assertEqual(world.run(), 70)
        result = world.binding.accept_message(world.sent[-1])
        self.assertEqual((result.status, result.response.outcome), ("unknown", "ok"))
        self.assertTrue(world.entry.unknown and world.entry.acquisition.cleanup_unknown)
        self.assertEqual(world.entry.body_file.state, "UNKNOWN")
        self.assertEqual([event for event in world.events if event == ("close", 11)], [("close", 11)])

    def test_missing_body_open_return_does_not_adopt_retry_or_get_token(self):
        world = _World(self)
        world.open_failure = 11
        self.assertEqual(world.run(), 74)
        self.assertFalse(world.entry.get_entered)
        self.assertEqual(world.entry.body_file.state, "UNKNOWN")
        self.assertEqual(world.entry.body_parent.state, "CLOSED")
        self.assertEqual(world.sent, [])
        self.assertEqual(world.http.calls, [])

    def test_late_entry_keeps_original_work_hard_and_http_unknown(self):
        world = _World(self, "review", at=133.)
        world.unknown_http = True
        self.assertEqual(world.run(), 70)
        self.assertLessEqual(world.entry.budget.end, 145.)
        self.assertAlmostEqual(world.entry.budget.started, 100., places=8)
        result = world.binding.accept_message(world.sent[-1])
        self.assertEqual((result.status, result.cleanup_end_ns), ("unknown", 143_000_000_000))
        self.assertEqual(len(world.http.calls), 1)


class GitPushHookEntryTests(unittest.TestCase):
    def test_review_and_apply_hook_only_forward_one_exact_tuple_after_input_eof(self):
        # One fresh test context per mode; no shared/inherited test suite.
        for mode in ("review", "apply"):
            with self.subTest(mode=mode):
                world = _World(self, mode, fixed_hook=True)
                self.assertEqual(world.run(), 0)
                self.assertEqual(world.sent, [world.binding.hook().request()])
                self.assertTrue(world.entry.input_eof and world.entry.reply_returned)
                self.assertEqual(bytes(world.output), b"")
                self.assertEqual(world.http.calls, [])
                self.assertEqual(len(world.entry.acquisition.leases), 3)
                self.assertLessEqual(world.entry.work_end, 145.)

    def test_wrong_mode_reply_is_not_comparison_or_native_ack(self):
        world = _World(self, "review", fixed_hook=True)
        world.socket = deque([binding("apply").hook().reply()])
        self.assertEqual(world.run(), 74)
        self.assertTrue(world.entry.reply_entered and not world.entry.reply_returned)
        self.assertEqual(len(world.sent), 1)
        self.assertEqual(world.http.calls, [])

    def test_second_hook_line_cannot_reach_original_parent(self):
        world = _World(self, fixed_hook=True)
        world.source.close()
        world.source = io.BytesIO(world.binding.hook().line * 2)
        self.addCleanup(world.source.close)
        self.assertEqual(world.run(), 74)
        self.assertEqual(world.sent, [])
        self.assertFalse(world.entry.reply_entered)

    def test_ack_before_unknown_pipe_close_cannot_return_zero(self):
        world = _World(self, fixed_hook=True)
        world.close_failure = 0
        self.assertEqual(world.run(), 74)
        self.assertTrue(world.entry.reply_returned and world.entry.unknown)
        self.assertEqual(world.http.calls, [])
        self.assertEqual(len(world.sent), 1)

    def test_small_hook_call_caps_refuse_before_any_further_effect(self):
        socket = hook._SocketIO.__new__(hook._SocketIO)
        socket.count = hook.SOCKET_CALLS
        with self.assertRaises(transport.PushError):
            socket.call("recv")
        pipe = hook._PipeIO.__new__(hook._PipeIO)
        pipe.count = hook.PIPE_CALLS
        with self.assertRaises(transport.PushError):
            pipe._call("read", None, 1)
        self.assertEqual((socket.count, pipe.count), (256, 256))


if __name__ == "__main__":
    unittest.main()
