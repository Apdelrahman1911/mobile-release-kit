"""Real channel state/finish methods, explicitly inert leases and IO.

No descriptor, process, token source or network is acquired. These cases test
ordering/refusal; fake EOF/close facts do not qualify native descendants.
"""
from collections import deque
import os
import subprocess
import threading
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _git_remote_private_protocol as wire
from mobile_release._git_remote_input_channel import OriginalInputChannel, RemoteRefusal
from mobile_release._desktop_git_remote_control import GitRemoteInput
from mobile_release.git_remote_transport import Target
from mobile_release.git_remote_wire import Selection
from mobile_release.owned_process import ProcessCleanupError


class Lease:
    def __init__(self, fail=False):
        self.state, self.calls, self.fail = "OPEN", 0, fail
    def close(self):
        assert self.calls == 0 and self.state == "OPEN"
        self.calls += 1
        self.state = "UNKNOWN" if self.fail else "CLOSED"
        if self.fail:
            raise OSError("inert close ambiguity")
    def fileno(self):
        assert self.state == "OPEN"
        return 101  # No OS call; select is patched in the sole waiting case.


class IO:
    def __init__(self, blocks=()):
        self.blocks, self.sent, self.wiped = deque(blocks), [], 0
    def receive(self, lease, maximum):
        assert lease.state == "OPEN" and 0 < maximum <= wire.FRAME_LIMIT
        return self.blocks.popleft() if self.blocks else None
    def send(self, lease, data):
        assert lease.state == "OPEN"
        self.sent.append(bytes(data)); return len(data)
    def wipe(self):
        self.wiped += 1


def original(*, blocks=(), get=True):
    # The genuine constructor is intentionally NOT called. No native grant,
    # pair or command authority is manufactured by these DATA fixtures.
    channel = OriginalInputChannel.__new__(OriginalInputChannel)
    operation = SimpleNamespace(remote_returned=True, unknown=False, repository=SimpleNamespace(_unknown=False))
    source = SimpleNamespace(channel=channel, _owner=lambda: None, go_returned=True,
        work_end=145., hard_end=155., stop_reason="none", failures=0, grants=0,
        first_failure=None, first_failure_ns=None, cleanup_end_ns=155_000_000_000,
        http_control=wire.controls.empty(),
        initial=SimpleNamespace(digest="a" * 64, work_end_ns=145_000_000_000, hard_end_ns=155_000_000_000),
        require_operation=lambda: operation, _poll_control_only=lambda guard: None)
    source.helper_returned = MethodType(GitRemoteInput.helper_returned, source)
    source.failure_observed = lambda: setattr(source, "failures", source.failures + 1)
    source.guard = SimpleNamespace(check=lambda: None, cancelled=False, _abort=lambda error: None)
    operation.credential_current = lambda actual: None
    def grant(actual):
        assert actual is channel and channel.get_entered
        source.grants += 1
        return "not-a-credential"
    source.take_helper_token = grant
    channel.source, channel.pid, channel.thread = source, os.getpid(), threading.current_thread()
    channel.client, channel.peer, channel.io = Lease(), Lease(), IO(blocks)
    channel.acquisition = SimpleNamespace(cleanup_unknown=False, settled=True,
        leases=(channel.client, channel.peer), close_launch=lambda: None)
    channel.command = SimpleNamespace(_exported=True)
    channel.binding = wire.Binding("git-1", "a" * 64, "origin",
        Target("fixture/project", "Fixture", "12", "34", Selection("refs/heads/main", "1" * 40)),
        145_000_000_000, 155_000_000_000, b"b" * 16, (1001, 1, 2))
    channel.entered, channel.polling, channel.failed, channel.unknown, channel.closed = True, False, False, False, False
    channel.get_entered = channel.get_sent = get
    channel.eof = channel.stop_entered = channel.stopped = False
    channel.producer_returned = channel.finish_entered = channel.return_checked = False
    channel.helper_return = None
    channel.incoming, channel.outgoing = bytearray(), bytearray()
    channel.sent = channel.received = channel.requests = 0
    channel.outgoing_secret = False
    return channel, operation, source


class ReturnTests(unittest.TestCase):
    def setUp(self):
        self.stack = patch("subprocess.Popen", side_effect=AssertionError("No subprocess in channel DATA tests"))
        self.stack.start(); self.addCleanup(self.stack.stop)
        clock = patch("time.monotonic", return_value=100.)
        clock.start(); self.addCleanup(clock.stop)
        raw_clock = patch.object(__import__("time"), "CLOCK_UPTIME_RAW", 1, create=True)
        raw_clock.start(); self.addCleanup(raw_clock.stop)
        raw_now = patch("time.clock_gettime_ns", return_value=100_000_000_000)
        raw_now.start(); self.addCleanup(raw_now.stop)

    def test_late_completion_uses_same_parser_then_all_copy_eof_and_original_closes(self):
        c, op, _ = original()
        raw = c.binding.returned("ok")
        c.io.blocks.extend((raw[:17], raw[17:], b""))
        self.assertTrue(c.finish(op))
        self.assertEqual((c.client.calls, c.peer.calls, c.received), (1, 1, len(raw)))
        c.accept_return(op, subprocess.CompletedProcess([], 0))
        self.assertTrue(c.closed and c.eof and c.return_checked)
        with self.assertRaises(Exception):
            c.accept_return(op, subprocess.CompletedProcess([], 0))

    def test_helper_frame_never_substitutes_for_actual_caw_return(self):
        c, op, _ = original()
        c._accept_block(c.binding.returned("ok"), finishing=False)
        op.remote_returned = False
        with self.assertRaises(Exception):
            c.finish(op)
        self.assertEqual((c.client.calls, c.peer.calls), (0, 0))
        self.assertFalse(c.closed)

    def test_ok_frame_but_surviving_copy_never_becomes_closed_success(self):
        c, op, _ = original()
        c._accept_block(c.binding.returned("ok"), finishing=False)
        with patch("time.monotonic", side_effect=[100., 100., 211.]), \
                patch("select.select", return_value=([], [], [])):
            with self.assertRaises(Exception):
                c.finish(op)
        self.assertTrue(c.unknown)
        self.assertEqual((c.client.calls, c.peer.calls), (1, 0))
        self.assertFalse(c.eof or c.closed)

    def test_git_zero_and_helper_unknown_is_absorbing_after_known_pipe_closes(self):
        c, op, _ = original()
        c.io.blocks.extend((c.binding.returned("unknown", "cleanup-unknown", first_failure_ns=100_000_000_000,
                                             cleanup_end_ns=110_000_000_000), b""))
        self.assertTrue(c.finish(op))
        with self.assertRaises(ProcessCleanupError):
            c.accept_return(op, subprocess.CompletedProcess([], 0))
        self.assertTrue(c.unknown and op.unknown and op.repository._unknown)
        self.assertEqual((c.client.calls, c.peer.calls), (1, 1))

    def test_git_zero_and_missing_helper_return_cannot_discharge_peer(self):
        c, op, _ = original(blocks=(b"",))
        with self.assertRaises(Exception):
            c.finish(op)
        self.assertTrue(c.unknown)
        self.assertEqual((c.client.calls, c.peer.calls), (1, 0))

    def test_duplicate_in_final_drain_does_not_replace_original_return(self):
        c, op, _ = original()
        c._accept_block(c.binding.returned("ok"), finishing=False)
        first = c.helper_return
        c.io.blocks.extend((c.binding.returned("ok"), b""))
        with self.assertRaises(Exception):
            c.finish(op)
        self.assertIs(c.helper_return, first)
        self.assertTrue(c.unknown)
        self.assertFalse(c.closed)

    def test_partial_or_trailing_bytes_cannot_hide_behind_an_ok_frame(self):
        for ending in (b"x", b"\n", b'{"kind":"returned"'):
            c, op, _ = original()
            c.io.blocks.extend((c.binding.returned("ok") + ending, b""))
            with self.assertRaises(Exception):
                c.finish(op)
            self.assertTrue(c.unknown)
            self.assertFalse(c.closed)

    def test_one_attempt_close_ambiguity_wins_over_frame_and_eof(self):
        c, op, _ = original()
        c.client.fail = True
        c.io.blocks.extend((c.binding.returned("ok"), b""))
        with self.assertRaises(OSError):
            c.finish(op)
        self.assertTrue(c.unknown)
        with self.assertRaises(Exception):
            c.finish(op)
        self.assertEqual((c.client.calls, c.peer.calls), (1, 0))

    def test_early_eof_before_original_client_close_is_not_all_copy_eof(self):
        c, _, _ = original(blocks=(b"",))
        with self.assertRaises(Exception):
            c.poll()
        self.assertFalse(c.eof or c.closed)
        self.assertTrue(c.failed)
        self.assertEqual((c.client.calls, c.peer.calls), (0, 0))

    def test_once_only_get_is_claimed_before_late_owner_revocation(self):
        c, op, source = original(get=False)
        c.io.blocks.append(c.binding.request())
        sentinel = KeyboardInterrupt("inert late owner revoke")
        op.credential_current = lambda actual: (_ for _ in ()).throw(sentinel)
        with self.assertRaises(KeyboardInterrupt) as caught:
            c.poll()
        self.assertIs(caught.exception, sentinel)
        self.assertTrue(c.get_entered and c.failed)
        self.assertEqual(source.grants, 0)

    def test_second_get_or_overbound_requests_never_obtain_another_secret(self):
        c, _, source = original(get=False)
        c.io.blocks.append(c.binding.request())
        c.poll()
        self.assertEqual(source.grants, 1)
        c.io.blocks.append(c.binding.request())
        with self.assertRaises(Exception):
            c.poll()
        self.assertEqual(source.grants, 1)

    def test_store_and_erase_are_discarded_without_response_or_credential(self):
        c, _, source = original(get=False)
        c.io.blocks.append(c.binding.request("store") + c.binding.request("erase"))
        c.poll()
        self.assertEqual((c.requests, source.grants, c.io.sent), (2, 0, []))

    def test_same_aggregate_limit_includes_requests_and_completion(self):
        c, op, _ = original()
        raw = c.binding.returned("ok")
        c.received = wire.FRAME_LIMIT - len(raw) + 1
        c.io.blocks.append(raw)
        with self.assertRaises(Exception):
            c.finish(op)
        self.assertTrue(c.unknown)

    def test_refused_http_is_never_success_even_if_git_ignored_helper_status(self):
        c, op, _ = original()
        c.io.blocks.extend((c.binding.returned("refused", "unauthorized", first_failure_ns=100_000_000_000,
                                             cleanup_end_ns=110_000_000_000), b""))
        self.assertTrue(c.finish(op))
        with self.assertRaises(RemoteRefusal) as caught:
            c.accept_return(op, subprocess.CompletedProcess([], 0))
        self.assertEqual(caught.exception.reason, "unauthorized")
        self.assertTrue(c.failed and c.closed)
        self.assertFalse(op.unknown)

    def test_wrong_digest_or_invalid_closed_status_reason_combinations_refuse(self):
        c, op, _ = original()
        bad = c.binding.returned("ok").replace(b'"' + b'a' * 64 + b'"', b'"' + b'c' * 64 + b'"')
        c.io.blocks.append(bad)
        with self.assertRaises(wire.PrivateError) as caught:
            c.finish(op)
        self.assertNotIn("ccc", str(caught.exception))
        for status, reason in (("ok", "unauthorized"), ("refused", None),
                               ("refused", "cleanup-unknown"), ("unknown", None), ("success", None)):
            with self.assertRaises(wire.PrivateError):
                c.binding.returned(status, reason)

    def test_earlier_helper_failure_tightens_existing_parent_failure_and_cutoff(self):
        c, _, source = original()
        source.first_failure, source.first_failure_ns, source.hard_end = 115., 115_000_000_000, 125.
        source.cleanup_end_ns = 125_000_000_000
        raw = c.binding.returned("refused", "forbidden", first_failure_ns=110_000_000_000,
                                 cleanup_end_ns=120_000_000_000)
        with patch("time.monotonic", return_value=119.), patch("time.clock_gettime_ns", return_value=119_000_000_000):
            c._accept_block(raw, finishing=False)
        self.assertEqual((source.first_failure_ns, source.cleanup_end_ns), (110_000_000_000, 120_000_000_000))
        self.assertLessEqual(source.first_failure, 110.)
        self.assertLessEqual(source.hard_end, 120.)

    def test_earlier_parent_failure_is_never_renewed_by_later_helper_or_ok(self):
        for status in ("refused", "ok"):
            c, _, source = original()
            source.first_failure, source.first_failure_ns, source.hard_end = 105., 105_000_000_000, 115.
            source.cleanup_end_ns = 115_000_000_000
            raw = (c.binding.returned("ok") if status == "ok" else
                c.binding.returned("refused", "forbidden", first_failure_ns=110_000_000_000,
                                   cleanup_end_ns=120_000_000_000))
            with patch("time.monotonic", return_value=112.), patch("time.clock_gettime_ns", return_value=112_000_000_000):
                c._accept_block(raw, finishing=False)
            self.assertEqual((source.first_failure_ns, source.cleanup_end_ns), (105_000_000_000, 115_000_000_000))
            self.assertLessEqual(source.hard_end, 115.)

    def test_late_or_future_failure_frame_cannot_authorize_new_close_window(self):
        for failure in (110_000_000_000, 122_000_000_000):
            c, op, source = original()
            c.io.blocks.extend((c.binding.returned("refused", "forbidden", first_failure_ns=failure,
                                                 cleanup_end_ns=failure + 10_000_000_000), b""))
            with patch("time.monotonic", return_value=121.), patch("time.clock_gettime_ns", return_value=121_000_000_000):
                with self.assertRaises(Exception):
                    c.finish(op)
            self.assertTrue(c.unknown)
            self.assertEqual((c.client.calls, c.peer.calls), (1, 0))

    def test_missing_original_clock_cannot_be_repaired_from_return_frame(self):
        c, op, _ = original()
        c.io.blocks.extend((c.binding.returned("ok"), b""))
        with patch("time.CLOCK_UPTIME_RAW", None):
            with self.assertRaises(Exception):
                c.finish(op)
        self.assertTrue(c.unknown)
        self.assertFalse(c.closed)


if __name__ == "__main__":
    unittest.main()
