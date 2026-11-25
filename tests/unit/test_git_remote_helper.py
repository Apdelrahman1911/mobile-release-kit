"""Finite actual helper body with inert original-pipe/HTTP return fixtures.

No bootstrap, credential channel, fd, clock bridge, Git, process or socket is
used. Fake close returns demonstrate ordering only, never native finality.
"""
from __future__ import annotations

import io
import unittest

from mobile_release._desktop_git_remote_helper import _Helper
from mobile_release import git_remote_transport as t
from mobile_release import _github_connection_transport as h
from test_git_remote_transport import FakeExchange, ACCOUNT, REPOSITORY, LS_REQUEST, LS_RESPONSE
from test_git_remote_wire import OID, REF, fetch, offered, packet, response


PREFIX = b"capabilities\nstateless-connect git-upload-pack\n"


class GitRemoteHelperTests(unittest.TestCase):
    def helper(self, raw=None, original=None):
        original = original or FakeExchange()
        source = io.BytesIO(PREFIX + LS_REQUEST + fetch() if raw is None else raw)
        out, events = [], []
        def read(maximum):
            events.append(("read", maximum)); return source.read(maximum)
        def write(block):
            events.append(("write", block, len(original.events)))
            out.append(block)
        body = _Helper(original.wrapper, read=read, write=write, current=original.current)
        return body, original, out, events

    def test_actual_helper_body_two_closed_rounds_not_a_fetch_finality_claim(self):
        body, original, out, events = self.helper()
        result = body.run()
        self.assertEqual((result.reference, result.oid), (REF, OID))
        self.assertEqual(b"".join(out), b"stateless-connect\n\n\n" + offered().raw
                         + LS_RESPONSE + b"0002" + response() + b"0002")
        markers = [event for event in events if event[0] == "write" and event[1] == b"0002"]
        self.assertEqual([event[2] for event in markers], [4, 7])
        self.assertEqual(len(original.calls), 7)
        self.assertTrue(body.finished)
        self.assertFalse(hasattr(result, "settled"))
        self.assertTrue(all(1 <= event[1] <= 4096 for event in events if event[0] == "read"))
        with self.assertRaises(t.RemoteError):
            body.run()
        self.assertEqual(len(original.calls), 7)

    def test_unknown_command_service_options_or_fallback_never_get_credential_http(self):
        for raw in (b"list\n", b"push\n", b"capabilities\noption progress true\n",
                    b"capabilities\nstateless-connect git-receive-pack\n",
                    b"capabilities\nconnect git-upload-pack\n", b"capabilities\r\n",
                    b"x" * 128 + b"\n"):
            body, original, out, _ = self.helper(raw)
            with self.assertRaises(t.RemoteError):
                body.run()
            self.assertEqual(original.calls, [])
            self.assertNotIn(b"fallback", b"".join(out))
            self.assertTrue(body.failed)

    def test_v0_response_never_acknowledges_stateless_connect(self):
        original = FakeExchange(bodies=[ACCOUNT, REPOSITORY, b"not-v2"])
        body, _, out, _ = self.helper(original=original)
        with self.assertRaises(t.RemoteError):
            body.run()
        self.assertEqual(out, [b"stateless-connect\n\n"])
        self.assertEqual(len(original.calls), 3)

    def test_request_validation_and_missing_input_never_send_fetch(self):
        for raw in (PREFIX + LS_REQUEST[:-4], PREFIX + LS_REQUEST + fetch()[:-4],
                    PREFIX + LS_REQUEST + packet(b"command=fetch\n") + b"0002",
                    PREFIX + LS_REQUEST + b"ffff"):
            body, original, out, _ = self.helper(raw)
            with self.assertRaises(ValueError):
                body.run()
            self.assertLessEqual(len(original.calls), 4)
            self.assertTrue(body.failed)

    def test_extra_round_is_not_a_retry_or_an_extra_http_request(self):
        body, original, out, _ = self.helper(PREFIX + LS_REQUEST + fetch() + fetch())
        with self.assertRaises(t.RemoteError):
            body.run()
        self.assertEqual(len(original.calls), 7)
        self.assertFalse(body.finished)
        self.assertTrue(body.failed)
        with self.assertRaises(t.RemoteError):
            body.run()

    def test_partial_pack_source_or_post_identity_failure_never_emits_final_marker(self):
        bodies = [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, response()[:-4]]
        body, original, out, _ = self.helper(original=FakeExchange(bodies=bodies))
        with self.assertRaises(t.RemoteError):
            body.run()
        self.assertEqual(out.count(b"0002"), 1)
        self.assertEqual(len(original.calls), 5)
        bodies = [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, response(),
                  {**ACCOUNT, "login": "different-user"}, REPOSITORY]
        body, original, out, _ = self.helper(original=FakeExchange(bodies=bodies))
        with self.assertRaises(t.RemoteError):
            body.run()
        self.assertEqual(out.count(b"0002"), 1)
        self.assertEqual(len(original.calls), 6)

    def test_same_original_close_unknown_or_pipe_write_interrupt_no_final_marker(self):
        body, original, out, _ = self.helper()
        write = body.write
        def fail_during_fetch(block):
            write(block)
            if block.startswith(b"000dpackfile"):
                raise KeyboardInterrupt()
        body.write = fail_during_fetch
        with self.assertRaises(KeyboardInterrupt):
            body.run()
        self.assertTrue(body.failed)
        self.assertEqual(out.count(b"0002"), 1)
        self.assertLessEqual(len(original.calls), 5)

    def test_request_or_output_does_not_reset_original_clock(self):
        body, original, out, _ = self.helper()
        now = [1.0]
        original.clock.monotonic = lambda: now[0]
        read = body.read
        def late(size):
            result = read(size)
            now[0] = 45.0
            return result
        body.read = late
        with self.assertRaises(h.ReadFailure):
            body.run()
        self.assertEqual(original.calls, [])
        self.assertEqual(out, [])
        self.assertEqual(original.clock.end, 45.0)

    def test_short_write_result_or_overread_is_refusal_without_retry(self):
        for kind in ("write", "read"):
            body, original, out, _ = self.helper()
            if kind == "write":
                def short(block):
                    out.append(block[:1]); return 1
                body.write = short
            else:
                body.read = lambda maximum: b"x" * (maximum + 1)
            with self.assertRaises(t.RemoteError):
                body.run()
            self.assertEqual(original.calls, [])
            self.assertLessEqual(len(out), 1)
            self.assertTrue(body.failed)


if __name__ == "__main__":
    unittest.main()
