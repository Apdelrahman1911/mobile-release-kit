"""Create-only cases through the original helper/body/HTTP parsers.

Finite inert syscall/ACK/provider returns only, reusing the existing body
fixture. No native source, CLT, socket, credential or finality is exercised.
"""
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from mobile_release import _git_push_create_observation as create
from mobile_release import _git_push_observation_data as data
from mobile_release import _git_push_observation_entry as observation
from mobile_release import _git_push_observation_http as provider
from mobile_release import _git_push_private_protocol as private
from mobile_release import _github_connection_transport as http
from mobile_release import _desktop_github_engine as connection
from mobile_release import desktop_git_push_helper as original
from mobile_release import git_push_body as bodies
from mobile_release import git_push_new_branch as first
from mobile_release import git_push_transport as push
from mobile_release import git_push_wire as wire
from mobile_release._desktop_git_push_helper import _Helper, _ReviewHelper
from mobile_release._git_push_input_channel import PushInputChannel
import test_git_push_body as body_fixture
import test_git_push_wire as wire_fixture


def transcript(case):
    return data.Transcript(case, "a" * 40, "b" * 40, "c" * 40)


class PushCreateObservationTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "subprocess.Popen",
                     "mobile_release.desktop_git_push_helper._Entry.acquire"):
            self.enterContext(patch(name, side_effect=AssertionError("Native effects forbidden")))

    def helper(self, case, *, apply=False):
        world, value = body_fixture._Returns(self), transcript(case)
        selected = create.selection(value)
        target = push.Target(data.coordinate(case), data.ACCOUNT, data.ACCOUNT_ID, data.REPOSITORY_ID, selected)
        now = time.monotonic()
        self.enterContext(patch.object(time, "CLOCK_UPTIME_RAW", 10001, create=True))
        self.enterContext(patch.object(time, "clock_gettime_ns", side_effect=lambda _: 100_000_000_000 + int((time.monotonic() - now) * 1e9)))
        entry = original._Entry("mrk::https://github.com/" + target.repository + ".git",
                               "https://github.com/" + target.repository + ".git", Path("/inert"), now)
        clock = private.Clock("d" * 64, 145_000_000_000, 155_000_000_000)
        entry.binding = private.Binding("operation-1", clock, "apply" if apply else "review", "e" * 64,
            None, target, (501, 1, 9), world.path, world.parent, world.original if apply else None)
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
        payload = b"0000"
        if apply:
            offered = wire.advertisement(data.advertisement(value, "review"), selected)
            request = wire.command(data.packet((first.ZERO + " " + value.target + " " + data.REFERENCE).encode()
                + b"\0 report-status") + b"0000", selected, offered)
            payload = request.raw + wire_fixture.pack()
        source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + payload)
        output, points = [], []
        def point(command, digest):
            self.assertTrue(entry.helper.pack_eof)
            self.assertIs(command, entry.helper.request)
            self.assertEqual(entry.helper.body.phase, "sealed")
            self.assertTrue(command.raw[4:].startswith((first.ZERO + " " + value.target).encode()))
            points.append(digest)  # Explicit fake ACK, never a native grant.
            entry.send_entered = entry.send_returned = True
        entry.helper = (_Helper(entry.transport, world.io, read=source.read, write=output.append,
            current=world.io.current, send_point=point) if apply else _ReviewHelper(entry.transport,
            read=source.read, write=output.append, current=world.io.current))
        return entry, supplier, world, output, points

    def test_five_closed_cases_preserve_old_three_and_canonical_transcript(self):
        self.assertEqual(len(data.CASES), 3)
        self.assertEqual(data.ALL_CASES, data.CASES + create.CASES)
        for case in create.CASES:
            value = transcript(case)
            self.assertEqual(data.decode(value.raw(), case), value)
            self.assertEqual(data.token_case(data.token(case)), case)
            self.assertLessEqual(len(value.raw()), data.DATA_LIMIT)
            self.assertIs(type(create.selection(value)), first.Selection)
        for case in ("git-push-create-other", "git-push-create-empty-extra"):
            with self.assertRaises(data.Refused): data.token(case)
        with self.assertRaises(data.Refused): create.selection(transcript(data.CASES[0]))

    def test_empty_sentinel_and_missing_target_are_not_inaccessible_or_equal_target(self):
        value = transcript(create.CASES[0])
        selected = create.selection(value)
        empty = data.advertisement(value, "review")
        offered = wire.advertisement(empty, selected)
        self.assertEqual(offered.refs, ())
        for invalid in (b"", empty[:-1], json.dumps(data.repository(create.CASES[0])).encode(),
                        empty.replace(b"capabilities^{}", b"refs/heads/main"),
                        data.advertisement(transcript(create.CASES[1]), "review")):
            with self.subTest(prefix=invalid[:18]), self.assertRaises(wire.WireError):
                wire.advertisement(invalid, selected)
        nonempty = data.advertisement(transcript(create.CASES[4]), "review")
        self.assertEqual(wire.advertisement(nonempty, selected).refs,
                         ((create.OTHER_REF, transcript(create.CASES[4]).other),))
        with self.assertRaises(wire.WireError):
            wire.advertisement(empty, wire.Selection(data.REFERENCE, data.REFERENCE, value.base, value.target))

    def test_original_connection_reader_uses_same_fixed_new_coordinate(self):
        supplier, case = provider.Supplier(), create.CASES[0]
        request = connection.parse_request(json.dumps({"protocol":connection.PROTOCOL,"id":"operation-1",
            "params":{"repository":data.coordinate(case),"expectedAccountId":None,
                      "expectedRepositoryId":None,"token":data.token(case)}}).encode()+b"\n")
        with patch.object(http, "_make_live_exchange", supplier.factory):
            reader = http._make_live_reader(request, started=time.monotonic(), runtime_dir="/inert")
            result = http.observe(request, reader, observed_at="2026-10-21T00:00:00Z")
        self.assertEqual((supplier.calls, supplier.posts), (4, 0))
        self.assertEqual(result["facts"]["repository"]["value"]["fullName"], data.coordinate(case))
        self.assertEqual(result["control"]["reason"], "none")
        self.assertNotIn(data.token(case).encode(), connection.encode_response(request.id, **result))

    def test_four_actual_dry_run_helpers_finish_five_gets_and_no_send(self):
        for case in (create.CASES[0], *create.CASES[2:]):
            with self.subTest(case=case):
                entry, supplier, _, _, points = self.helper(case)
                end = (entry.work_end, entry.hard_end, entry.budget.end)
                value = entry.helper.run()
                observation.audit(entry, supplier)
                self.assertEqual((supplier.calls, supplier.posts, value.old_oid), (5, 0, first.ZERO))
                self.assertEqual(points, [])
                self.assertIsNone(entry.body_io)
                self.assertEqual((entry.work_end, entry.hard_end, entry.budget.end), end)
                with self.assertRaises(push.PushError): entry.helper.run()

    def test_equal_target_refuses_prepare_before_any_review_ack_pack_or_post(self):
        entry, supplier, world, _, points = self.helper(create.CASES[1])
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.posts, points, world.content), (3, 0, [], b""))
        self.assertIsNone(entry.transport.offered)
        self.assertEqual(entry.primary.reason, "target-changed")
        with self.assertRaises(push.PushError): entry.helper.run()
        self.assertEqual(supplier.calls, 3)

    def test_empty_target_sends_exact_zero_once_through_actual_body_then_after_get(self):
        entry, supplier, world, _, points = self.helper(create.CASES[0], apply=True)
        result = entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.posts, len(points)), (7, 1, 1))
        self.assertEqual(supplier.sink.prefix, entry.helper.request.raw)
        self.assertEqual((supplier.sink.count, supplier.sink.digest.hexdigest()),
                         (len(world.content), hashlib.sha256(world.content).hexdigest()))
        self.assertEqual(supplier.tip, transcript(create.CASES[0]).target)
        self.assertEqual(result.body, entry.helper.body.digest)
        with self.assertRaises(push.PushError): entry.transport.publish(entry.helper.body)
        self.assertEqual(supplier.posts, 1)

    def test_fresh_apply_occupied_target_does_not_reuse_prepare_absence_or_consume_ack(self):
        entry, supplier, world, _, points = self.helper(create.CASES[2], apply=True)
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.posts, points, world.content), (3, 0, [], b""))
        self.assertIsNone(entry.helper.body)
        self.assertFalse(entry.send_entered)
        self.assertEqual(entry.primary.reason, "target-changed")

    def test_server_race_ng_is_one_consumed_body_not_overwrite_or_retry(self):
        entry, supplier, world, _, points = self.helper(create.CASES[3], apply=True)
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.posts, len(points)), (4, 1, 1))
        self.assertEqual(supplier.sink.count, len(world.content))
        self.assertEqual(supplier.tip, transcript(create.CASES[3]).other)
        self.assertEqual(entry.transport.posted.value.outcome, "rejected")
        self.assertEqual(entry.primary.reason, "remote-rejected")
        with self.assertRaises(push.PushError): entry.transport.after()
        with self.assertRaises(push.PushError): entry.helper.run()
        self.assertEqual((supplier.calls, supplier.posts), (4, 1))

    def test_truncated_receive_status_is_http_complete_but_no_result_or_resend(self):
        entry, supplier, _, _, points = self.helper(create.CASES[4], apply=True)
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        self.assertEqual((supplier.calls, supplier.posts, len(points)), (4, 1, 1))
        self.assertIsNone(entry.transport.posted.value)
        raw = data.receive_status(transcript(create.CASES[4]))
        head = (b"HTTP/1.1 200 Fixture\r\nContent-Type: application/x-git-receive-pack-result\r\n"
                + f"Content-Length: {len(raw)}\r\n\r\n".encode()+raw)
        response = http._ResponseBody(io.BytesIO(head), http._Budget(time.monotonic(), _profile=http._ExchangeProfile.GIT_PUSH),
                                      _role=http._ResponseRole.GIT_PUSH_SEND)
        self.assertEqual(response.read(wire.READ_CHUNK), raw)
        self.assertEqual(response.read(1), b"")
        self.assertEqual(response._raw(1), b"")
        first_failure = (entry.primary, entry.first_failure_ns, entry.cleanup_end_ns, entry.hard_end)
        entry.remember(push.PushError("cancelled"))
        self.assertEqual((entry.primary, entry.first_failure_ns, entry.cleanup_end_ns, entry.hard_end), first_failure)

    def test_new_held_marker_requires_same_unreturned_original_and_never_plain_zero_data(self):
        entry, supplier, _, _, _ = self.helper(create.CASES[4], apply=True)
        with self.assertRaises(push.PushError): entry.helper.run()
        observation.audit(entry, supplier)
        returned = entry.binding.accept_message(entry.binding.returned("refused", "response-invalid",
            first_failure_ns=entry.first_failure_ns, cleanup_end_ns=entry.cleanup_end_ns,
            control=entry.transport.control, advertisement_sha256=hashlib.sha256(entry.transport.offered.raw).hexdigest()))
        # Existing comparator, deliberately inert custody DATA. Native producer
        # pending observation and SAME-ticket STOP are NOT proved by this test.
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
        other = replace(entry.binding.target, repository=data.coordinate(create.CASES[3]))
        channel.binding = replace(entry.binding, target=other)
        self.assertFalse(observation.marker_ready(channel))


if __name__ == "__main__":
    unittest.main()
