"""Original helper/body/HTTP parsers, finite fake syscall/provider returns.

Only this test class is collected. Reuse the existing body-return fixture;
no native CLT, actual socket, credential, ACK, child or joined-owner proof.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from mobile_release import _git_push_observation_data as data
from mobile_release import _git_push_observation_entry as observation
from mobile_release import _git_push_observation_http as provider
from mobile_release import _git_push_private_protocol as private
from mobile_release import _github_connection_transport as http
from mobile_release import _desktop_github_engine as connection
from mobile_release import desktop_git_push_helper as entry_module
from mobile_release import git_push_body as bodies
from mobile_release import git_push_transport as push
from mobile_release import git_push_wire as wire
from mobile_release._desktop_git_push_helper import _Helper, _ReviewHelper
from mobile_release._git_push_input_channel import PushInputChannel
import test_git_push_body as body_fixture
import test_git_push_wire as wire_fixture


def transcript(case=data.CASES[0]):
    return data.Transcript(case, "a" * 40, "b" * 40, "c" * 40)


class PushObservationTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen",
                       "mobile_release.desktop_git_push_helper._Entry.acquire"):
            self.enterContext(patch(target, side_effect=AssertionError("No actual effect in DATA checks")))

    def test_fixed_data_and_public_literals_are_canonical_closed_and_bounded(self):
        for case in data.CASES:
            value = transcript(case)
            self.assertEqual(data.decode(value.raw(), case), value)
            self.assertEqual(data.token_case(data.token(case)), case)
            self.assertLessEqual(len(value.raw()), data.DATA_LIMIT)
        raw = transcript().raw()
        for bad in (b" " + raw, raw + b"\n", raw.replace(b'"schemaVersion":1', b'"schemaVersion":true'),
                    raw.replace(b'"base":', b'"base":"bad","base":'),
                    raw.replace(b'"case":', b'"extra":0,"case":'), b"x" * (data.DATA_LIMIT + 1)):
            with self.subTest(bad=bad[:16]), self.assertRaises(data.Refused):
                data.decode(bad, data.CASES[0])
        with self.assertRaises(data.Refused): data.decode(raw, data.CASES[1])
        with self.assertRaises(data.Refused): replace(transcript(), other="a" * 40)
        with self.assertRaises(data.Refused): data.token_case("not-an-observer-token")

    def test_original_connection_reader_produces_reported_permissions_not_connected_assignment(self):
        s, case = provider.Supplier(), data.CASES[0]
        raw = json.dumps({"protocol": connection.PROTOCOL, "id": "operation-1", "params": {
            "repository": data.coordinate(case), "expectedAccountId": None,
            "expectedRepositoryId": None, "token": data.token(case)}}).encode() + b"\n"
        request = connection.parse_request(raw)
        with patch.object(http, "_make_live_exchange", s.factory):
            reader = http._make_live_reader(request, started=time.monotonic(), runtime_dir="/inert")
            result = http.observe(request, reader, observed_at="2026-10-20T12:00:00Z")
        encoded = connection.encode_response(request.id, **result)
        self.assertEqual((s.calls, s.phase, s.posts), (4, 4, 0))
        self.assertEqual(result["facts"]["account"]["value"]["login"], data.ACCOUNT)
        self.assertEqual(result["facts"]["repository"]["value"]["permissions"]["push"], "reported-allowed")
        self.assertEqual(result["control"]["reason"], "none")
        self.assertNotIn(data.token(case).encode(), encoded)
        self.assertIsNone(s.entry)

    def helper(self, *, apply=True, case=data.CASES[0], raw=None):
        # Actual original body/Acquisition methods, SAME existing inert returns.
        world = body_fixture._Returns(self)
        value = transcript(case)
        selected = wire.Selection(data.REFERENCE, data.REFERENCE, value.base, value.target)
        target = push.Target(data.coordinate(case), data.ACCOUNT, data.ACCOUNT_ID, data.REPOSITORY_ID, selected)
        now = time.monotonic()
        self.enterContext(patch.object(time, "CLOCK_UPTIME_RAW", 10001, create=True))
        self.enterContext(patch.object(time, "clock_gettime_ns", side_effect=lambda _: 100_000_000_000 + int((time.monotonic() - now) * 1e9)))
        entry = entry_module._Entry("mrk::https://github.com/" + target.repository + ".git",
                                   "https://github.com/" + target.repository + ".git", Path("/inert"), now)
        clock = private.Clock("d" * 64, 145_000_000_000, 155_000_000_000)
        entry.binding = private.Binding("operation-1", clock, "apply" if apply else "review", "e" * 64,
            "origin", target, (501, 1, 9), world.path, world.parent, world.original if apply else None)
        entry.work_end, entry.hard_end = now + 45, now + 55
        entry.cleanup_end_ns = clock.hard_end_ns
        entry.get_entered = entry.get_returned = True
        entry._current_callback = world.io.current
        entry.budget = http._Budget(now, _profile=http._ExchangeProfile.GIT_PUSH)
        entry.body_io = world.io if apply else None
        supplier = provider.Supplier(entry=entry)
        with patch.object(http, "_make_live_exchange", supplier.factory), \
                patch.object(observation, "read_transcript", return_value=value):
            entry.transport = push._make_transport(target, entry.binding.mode, data.token(case),
                started=now, runtime_dir="/inert", budget=entry.budget,
                current=world.io.current, failure=entry._failure_callback)
        offered = wire.advertisement(data.advertisement(value, "review"), selected)
        request = wire.command(data.packet((value.base + " " + value.target + " " + data.REFERENCE).encode()
                                          + b"\0 report-status") + b"0000", selected, offered)
        payload = request.raw + wire_fixture.pack() if apply else b"0000"
        source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + payload if raw is None else raw)
        output, points = [], []
        def point(command, digest):
            self.assertTrue(entry.helper.pack_eof)
            self.assertIs(command, entry.helper.request)
            self.assertEqual(entry.helper.body.phase, "sealed")
            points.append(digest)
            # Explicit inert ACK return; no native/admission/journal proof.
            entry.send_entered = entry.send_returned = True
        entry.helper = (_Helper(entry.transport, world.io, read=source.read, write=output.append,
            current=world.io.current, send_point=point) if apply else _ReviewHelper(entry.transport,
            read=source.read, write=output.append, current=world.io.current))
        return entry, supplier, world, output, points

    def test_real_review_helper_requires_flush_eof_five_gets_and_zero_send_for_all_cases(self):
        for case in data.CASES:
            with self.subTest(case=case):
                entry, supplier, _, output, points = self.helper(apply=False, case=case)
                old_end = entry.budget.end
                result = entry.helper.run()
                observation.audit(entry, supplier)
                self.assertEqual((supplier.calls, supplier.phase, supplier.posts), (5, 5, 0))
                self.assertEqual(points, [])
                self.assertIsNone(supplier.sink)
                self.assertIsNone(entry.body_io)
                self.assertEqual(result.old_oid, transcript().base)
                self.assertEqual(entry.budget.end, old_end)
                self.assertNotIn(b"0002", output)
                with self.assertRaises(push.PushError): entry.helper.run()

    def test_real_body_sender_is_one_complete_stream_and_only_then_peer_advances(self):
        entry, supplier, world, _, points = self.helper()
        result = entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.phase, supplier.posts), (7, 7, 1))
        self.assertEqual(len(points), 1)
        self.assertTrue(supplier.sink.complete)
        self.assertEqual(supplier.sink.count, len(world.content))
        self.assertEqual(supplier.sink.digest.hexdigest(), hashlib.sha256(world.content).hexdigest())
        self.assertEqual(supplier.sink.prefix, entry.helper.request.raw)
        self.assertEqual(supplier.tip, transcript().target)
        self.assertEqual(result.body, entry.helper.body.digest)
        self.assertFalse(hasattr(supplier.sink, "blocks") or hasattr(supplier.sink, "pack"))
        self.assertEqual(world.file_lease.state, "OPEN")
        with self.assertRaises(push.PushError): entry.transport.publish(entry.helper.body)
        self.assertEqual(supplier.posts, 1)

    def test_stale_apply_advertisement_refuses_before_any_body_or_ack_or_post(self):
        entry, supplier, world, _, points = self.helper(case=data.CASES[1])
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.phase, supplier.posts), (3, 3, 0))
        self.assertEqual(points, [])
        self.assertEqual(world.content, b"")
        self.assertIsNone(entry.helper.body)
        self.assertIsNone(supplier.sink)
        self.assertEqual(entry.primary.reason, "target-changed")

    def test_full_send_then_bad_status_packet_preserves_first_failure_and_has_no_after_get(self):
        entry, supplier, world, _, points = self.helper(case=data.CASES[2])
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.phase, supplier.posts), (4, 4, 1))
        self.assertEqual(len(points), 1)
        self.assertEqual(entry.helper.body.phase, "sent")
        self.assertEqual(supplier.sink.count, len(world.content))
        self.assertEqual(entry.transport.posted.raw, data.receive_status(transcript(data.CASES[2])))
        self.assertIsNone(entry.transport.posted.value)
        self.assertIsNone(entry.transport.readback)
        first = (entry.primary, entry.first_failure, entry.first_failure_ns, entry.cleanup_end_ns, entry.hard_end)
        entry.remember(push.PushError("cancelled"))
        self.assertEqual((entry.primary, entry.first_failure, entry.first_failure_ns, entry.cleanup_end_ns, entry.hard_end), first)
        with self.assertRaises(push.PushError): entry.transport.after()
        self.assertEqual(supplier.calls, 4)

    def test_refusal_is_git_packet_truncation_not_an_incomplete_http_body(self):
        value = transcript(data.CASES[2])
        raw = data.receive_status(value)
        head = (b"HTTP/1.1 200 Fixture\r\nContent-Type: application/x-git-receive-pack-result\r\n"
                + f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        budget = http._Budget(time.monotonic(), _profile=http._ExchangeProfile.GIT_PUSH)
        response = http._ResponseBody(io.BytesIO(head), budget, _role=http._ResponseRole.GIT_PUSH_SEND)
        self.assertEqual(response.read(wire.READ_CHUNK), raw)
        self.assertEqual(response.read(1), b"")
        self.assertEqual(response._raw(1), b"")
        with self.assertRaises(wire.WireError): wire._packets(raw, wire.MAX_METADATA, 6)

    def test_supplier_never_falls_back_to_fetch_or_another_helper_service(self):
        entry, supplier, _, _, points = self.helper(raw=b"capabilities\nstateless-connect git-upload-pack\n")
        with self.assertRaises(push.PushError): entry.helper.run()
        self.assertEqual(supplier.calls, 0)
        self.assertEqual(points, [])
        with self.assertRaises(data.Refused):
            provider.Supplier().factory(data.token(data.CASES[0]), started=time.monotonic(),
                runtime_dir="/inert", api_version="2026-03-10", _profile=http._ExchangeProfile.GIT_REMOTE)

    def test_sink_refuses_other_body_and_repeated_or_partial_send_without_replay(self):
        entry, supplier, _, _, _ = self.helper()
        entry.helper.run()
        with self.assertRaises(data.Refused): supplier.sink.send(entry.budget.remaining)
        self.assertEqual(supplier.posts, 1)
        with self.assertRaises(data.Refused): provider._Sink(SimpleNamespace(phase="send-claimed"))

    def test_factory_invalid_or_reentrant_input_consumes_only_original_attempt(self):
        s = provider.Supplier()
        with self.assertRaises(data.Refused):
            s.factory("wrong", started=0.0, runtime_dir="/inert", api_version="2022-11-28")
        with self.assertRaises(data.Refused):
            s.factory(data.token(data.CASES[0]), started=0.0, runtime_dir="/inert", api_version="2022-11-28")
        self.assertEqual(s.calls, 0)

    def test_marker_requires_original_pending_channel_and_preserved_helper_failure(self):
        entry, supplier, _, _, _ = self.helper(case=data.CASES[2])
        with self.assertRaises(push.PushError): entry.helper.run()
        returned = entry.binding.accept_message(entry.binding.returned("refused", "response-invalid",
            first_failure_ns=entry.first_failure_ns, cleanup_end_ns=entry.cleanup_end_ns,
            control=entry.transport.control,
            advertisement_sha256=hashlib.sha256(entry.transport.offered.raw).hexdigest()))
        # Actual channel comparator with inert DATA only; no socket/GO/native receipt.
        channel = PushInputChannel.__new__(PushInputChannel)
        channel.binding, channel.helper_return = entry.binding, returned
        for name in ("get_entered", "get_sent", "hook_returned", "send_returned"):
            setattr(channel, name, True)
        for name in ("producer_returned", "finish_entered", "eof", "closed", "unknown"):
            setattr(channel, name, False)
        channel.incoming, channel.outgoing = bytearray(), bytearray()
        channel.client = SimpleNamespace(state="OPEN")
        source = SimpleNamespace(first_failure_ns=entry.first_failure_ns,
            cleanup_end_ns=entry.cleanup_end_ns, hard_end=entry.hard_end)
        operation = SimpleNamespace(source=source, remote_returned=False, network_pending=True,
            repository=SimpleNamespace(_transaction=SimpleNamespace(send_consumed=True, acknowledged=True, hook_returned=True)))
        source.require_operation = lambda: operation
        channel.source = source
        self.assertTrue(observation.marker_ready(channel))
        for name in ("producer_returned", "finish_entered", "eof", "closed", "unknown"):
            setattr(channel, name, True)
            with self.subTest(name=name), self.assertRaises(data.Refused): observation.marker_ready(channel)
            setattr(channel, name, False)
        source.first_failure_ns = entry.first_failure_ns + 1
        with self.assertRaises(data.Refused): observation.marker_ready(channel)
        self.assertFalse(observation.marker_ready(SimpleNamespace()))


if __name__ == "__main__":
    unittest.main()
