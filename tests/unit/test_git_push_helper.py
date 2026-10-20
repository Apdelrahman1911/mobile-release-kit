"""Real fixed helper/body/HTTP delegates, all pipe/FD/provider returns inert.

The callback is deliberately NOT a native hook, durable ACK or close witness.
No Git process, socket, credential, source resolver or native availability.
"""
from __future__ import annotations

import io
import unittest

from mobile_release import _desktop_git_push_helper as helper
from mobile_release import git_push_transport as t
from mobile_release import git_push_wire as w
from test_git_push_body import _Returns
from test_git_push_transport import Exchange, ACCOUNT, REPOSITORY, OK, AFTER
from test_git_push_wire import REMOTE, command, pack, offered, advertisement_raw, status, packet, OLD, NEW


class GitPushHelperTests(unittest.TestCase):
    def setUp(self):
        self.world = _Returns(self)
        self.original = Exchange(current=self.world.io.current)
        self.source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + command().raw + pack())
        self.output, self.acks, self.reads = [], [], []
        self.ack_failure = self.write_failure = None
        self.after_ack = lambda: None
        self.instance = helper._Helper(self.original.wrapper, self.world.io, read=self.read, write=self.write,
                                       current=self.world.io.current, send_point=self.ack)

    def read(self, maximum):
        value = self.source.read(maximum)
        self.reads.append((maximum, len(value)))
        return value

    def write(self, value):
        self.output.append(value)
        if self.write_failure is not None and self.original.wrapper.phase == 7:
            raise self.write_failure

    def ack(self, request, digest):
        self.assertTrue(self.instance.pack_eof)
        self.assertEqual(self.reads[-1][1], 0)
        self.assertEqual(self.original.wrapper.phase, 3)
        self.assertEqual(self.instance.body.phase, "sealed")
        self.assertEqual(digest.body_bytes, len(self.world.content))
        self.acks.append((request, digest))
        if self.ack_failure is not None:
            raise self.ack_failure
        self.after_ack()

    def refuses(self):
        completed = self.instance.finished
        with self.assertRaises((w.WireError, t.PushError)):
            self.instance.run()
        self.assertEqual(self.instance.finished, completed)  # A duplicate cannot erase a prior result.

    def test_connect_only_same_pack_eof_then_one_send_and_exact_status_without_response_end(self):
        value = self.instance.run()
        self.assertTrue(self.instance.finished and self.instance.send_point_returned)
        self.assertEqual(len(self.acks), 1)
        self.assertEqual(value.body.body_bytes, len(command().raw + pack()))
        self.assertEqual(b"".join(self.original.sent), command().raw + pack())
        self.assertEqual(b"".join(self.output), b"connect\n\n\n" + offered().git_bytes() + OK)
        self.assertEqual(self.original.wrapper.phase, 7)
        self.assertEqual(self.world.file_lease.state, "OPEN")
        self.assertFalse(hasattr(value, "native_joined") or hasattr(value, "cleanup"))
        before = len(self.reads)
        self.refuses()
        self.assertEqual(len(self.reads), before)

    def test_stateless_fetch_or_other_service_is_not_a_fallback(self):
        self.source = io.BytesIO(b"capabilities\nstateless-connect git-upload-pack\n")
        self.refuses()
        self.assertEqual(self.original.calls, [])
        self.assertEqual(self.acks, [])
        self.assertIsNone(self.instance.body)

    def test_extra_update_refuses_before_pack_or_ack_without_hidden_second_command(self):
        extra = packet((OLD + " " + NEW + " refs/heads/another").encode())
        raw = command().raw[:-4] + extra + b"0000" + pack()
        self.source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + raw)
        self.refuses()
        self.assertEqual(len(self.original.calls), 3)
        self.assertEqual(self.acks, [])
        self.assertIsNone(self.instance.body)

    def test_pack_eof_without_complete_checksum_is_not_a_send_or_never_entered_proof(self):
        self.source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + command().raw + pack()[:-1])
        self.refuses()
        self.assertTrue(self.instance.pack_eof and self.instance.body.failed)
        self.assertFalse(self.instance.send_point_entered)
        self.assertEqual(self.acks, [])
        self.assertEqual(len(self.original.calls), 3)
        self.assertGreater(len(self.world.content), len(command().raw))
        self.assertEqual(self.world.file_lease.state, "OPEN")

    def test_lost_candidate_send_point_return_retains_sealed_body_and_never_replays(self):
        self.ack_failure = RuntimeError("Synthetic lost private ACK")
        with self.assertRaises(RuntimeError) as caught:
            self.instance.run()
        self.assertIs(caught.exception, self.ack_failure)
        self.assertTrue(self.instance.send_point_entered)
        self.assertFalse(self.instance.send_point_returned)
        self.assertEqual(self.instance.body.phase, "sealed")
        self.assertEqual(len(self.original.calls), 3)
        self.assertEqual(self.original.sent, [])
        self.refuses()
        self.assertEqual(len(self.acks), 1)

    def test_original_work_endpoint_after_ack_cannot_restart_45_seconds_or_post(self):
        now = [1.0]
        self.original.clock.monotonic = lambda: now[0]
        self.after_ack = lambda: now.__setitem__(0, 45.0)
        with self.assertRaises(t.http.ReadFailure):
            self.instance.run()
        self.assertTrue(self.instance.send_point_returned)
        self.assertEqual(self.original.clock.end, 45.0)
        self.assertEqual(len(self.original.calls), 3)
        self.assertEqual(self.original.sent, [])

    def test_negative_remote_receipt_remains_private_no_after_requests_or_retry(self):
        self.original.responses[3] = status(b"unpack ok", b"ng " + REMOTE.encode() + b" SYNTHETIC_PRIVATE_REASON")
        self.refuses()
        self.assertEqual(self.original.wrapper.posted.value.outcome, "rejected")
        self.assertEqual(len(self.original.calls), 4)
        self.assertNotIn(b"SYNTHETIC_PRIVATE", b"".join(self.output))
        self.assertEqual(self.instance.body.phase, "sent")
        self.assertFalse(self.original.wrapper.finished)

    def test_partial_status_pipe_write_keeps_positive_receipt_but_not_helper_completion(self):
        self.write_failure = OSError("Synthetic partial status pipe")
        with self.assertRaises(OSError) as caught:
            self.instance.run()
        self.assertIs(caught.exception, self.write_failure)
        self.assertEqual(self.original.wrapper.posted.value.outcome, "ok")
        self.assertTrue(self.original.wrapper.failed)
        self.assertFalse(self.instance.finished)
        self.assertEqual(len(self.original.calls), 7)
        self.refuses()
        self.assertEqual(len(self.acks), 1)


class GitPushReviewHelperTests(unittest.TestCase):
    def setUp(self):
        self.world = _Returns(self)
        self.original = Exchange(mode="review", current=self.world.io.current)
        self.source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n0000")
        self.output, self.reads = [], []
        self.instance = helper._ReviewHelper(self.original.wrapper, read=self.read, write=self.output.append,
                                             current=self.world.io.current)

    def read(self, maximum):
        # Real pipes may return less than requested, including the flush.
        value = self.source.read(min(maximum, 2))
        self.reads.append((maximum, len(value)))
        return value

    def test_dry_run_flush_and_actual_eof_without_body_ack_post_or_status(self):
        value = self.instance.run()
        self.assertTrue(self.instance.input_eof and self.instance.finished)
        self.assertEqual((value.remote_ref, value.old_oid, value.new_oid), (REMOTE, OLD, NEW))
        self.assertEqual([row[0] for row in self.original.calls], ["GET"] * 5)
        self.assertEqual(b"".join(self.output), b"connect\n\n\n" + offered().git_bytes())
        self.assertEqual(self.original.sent, [])
        self.assertEqual(self.world.content, bytearray())
        self.assertFalse(hasattr(self.instance, "body") or hasattr(self.instance, "send_point"))
        before = (len(self.reads), len(self.original.calls))
        with self.assertRaises(t.PushError):
            self.instance.run()
        self.assertEqual((len(self.reads), len(self.original.calls)), before)

    def test_command_pack_extra_flush_and_missing_eof_are_not_a_review(self):
        for raw in (command().raw + pack(), b"0000PACK", b"00000000", b"000", b""):
            original = Exchange(mode="review", current=self.world.io.current)
            source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + raw)
            output = []
            instance = helper._ReviewHelper(original.wrapper, read=source.read, write=output.append,
                                             current=self.world.io.current)
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(t.PushError):
                instance.run()
            self.assertFalse(instance.finished)
            self.assertEqual([row[0] for row in original.calls], ["GET"] * 3)
            self.assertEqual(original.sent, [])

    def test_other_mode_and_stateless_connect_cannot_inherit_read_review(self):
        with self.assertRaises(t.PushError):
            helper._ReviewHelper(Exchange(current=self.world.io.current).wrapper, read=self.read,
                                 write=self.output.append, current=self.world.io.current)
        self.source = io.BytesIO(b"capabilities\nstateless-connect git-upload-pack\n")
        with self.assertRaises(t.PushError):
            self.instance.run()
        self.assertEqual(self.original.calls, [])

    def test_stop_after_flush_does_not_renew_clock_or_finish_account_reads(self):
        now = [1.0]
        self.original.clock.monotonic = lambda: now[0]
        original_read = self.instance.read
        def stopped_read(maximum):
            value = original_read(maximum)
            if not value:
                now[0] = 45.0
            return value
        self.instance.read = stopped_read
        with self.assertRaises(t.http.ReadFailure):
            self.instance.run()
        self.assertEqual(self.original.clock.end, 45.0)
        self.assertFalse(self.instance.finished)
        self.assertEqual(len(self.original.calls), 3)
        self.assertEqual(self.original.sent, [])


if __name__ == "__main__":
    unittest.main()
