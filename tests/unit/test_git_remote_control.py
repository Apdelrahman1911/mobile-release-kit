"""Same private control path with inert HTTP/pipes, never live credentials."""
import json
import subprocess
import http.client as http_client
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from mobile_release import git_remote_control as controls
from mobile_release import git_remote_transport as transport
from mobile_release import _github_connection_transport as http
from mobile_release import _git_remote_private_protocol as private
from mobile_release import _desktop_git_remote_protocol as worker
from mobile_release._native_process import NativeProcessError
from mobile_release.owned_process import ProcessCleanupError
from test_desktop_git_remote_helper_entry import World, original, run
from test_git_remote_input_channel import original as channel_original
from test_git_remote_transport import FakeLive, ACCOUNT, REPOSITORY, raw_http
from test_desktop_git_remote_protocol import fixture, frame

_ACTUAL_FACTORY = transport._make_transport


def limited(delay=600, *, blocked=False):
    return {"reason": "rate-limited", "credentialExpiresAt": None,
            "cooldownSeconds": None if blocked else delay, "cooldownBlocked": blocked}


class ControlTests(unittest.TestCase):
    @contextmanager
    def actual_factory_entry(self, bodies=None):
        # Reuse the actual Entry/factory and existing inert native/stdlib
        # doubles. Nested fake patches close before the Entry's fixture ends.
        world = World()
        with original(world) as body, ExitStack() as patches:
            fixture_owner = SimpleNamespace(enterContext=patches.enter_context,
                assertEqual=self.assertEqual, assertNotIn=self.assertNotIn)
            live = FakeLive(fixture_owner, bodies)
            patches.enter_context(patch.object(transport, "_make_transport", _ACTUAL_FACTORY))
            yield world, body, live, patches

    def test_exact_merge_min_expiry_max_delay_and_blocked_never_renews(self):
        first, later = limited(600), limited(900)
        first["credentialExpiresAt"] = "2026-10-21T01:00:00Z"
        later["credentialExpiresAt"] = "2026-10-21T02:00:00Z"
        merged = controls.merge(first, later)
        self.assertEqual(merged, {**first, "cooldownSeconds": 900})
        self.assertEqual(controls.merge(merged, controls.empty()), merged)
        self.assertEqual(controls.merge(merged, limited(blocked=True)),
            {**first, "cooldownSeconds": None, "cooldownBlocked": True})
        self.assertEqual(first["cooldownSeconds"], 600)

    def test_other_refusal_and_malformed_data_keep_known_cooldown(self):
        for incoming in ({**controls.empty(), "reason": "unauthorized"},
                         {**controls.empty(), "reason": "response-invalid"},
                         {**controls.empty(), "cooldownSeconds": True}, {"extra": "inert"}, None):
            with self.subTest(incoming=incoming):
                self.assertEqual(controls.merge(limited(), incoming), {**limited(), "reason": "response-invalid"})
        fatal = {**controls.empty(), "reason": "expired"}
        self.assertEqual(controls.merge(fatal, controls.empty()), fatal)
        self.assertEqual(controls.merge(fatal, {**controls.empty(), "reason": "network-unavailable"}), fatal)

    def test_worst_valid_control_fits_same_512_return_budget(self):
        channel, _, _ = channel_original()
        value = {**limited(604800), "reason": "response-invalid", "credentialExpiresAt": "9999-12-31T23:59:59Z"}
        binding = private.Binding(channel.binding.operation_id, "f" * 64, channel.binding.remote,
            channel.binding.target, (1 << 63) - 1 - 10_000_000_000, (1 << 63) - 1,
            channel.binding.nonce, channel.binding.identity)
        raw = binding.returned("refused", "not-found-or-inaccessible", control=value,
            first_failure_ns=binding.work_end_ns, cleanup_end_ns=binding.hard_end_ns)
        self.assertLessEqual(len(raw), 512)
        self.assertEqual(binding.accept_message(raw).control, value)
        row = json.loads(raw); del row["control"]
        with self.assertRaises(private.PrivateError):
            binding.accept_message(frame(row))
        with self.assertRaises(private.PrivateError):
            binding.returned("ok", control=value)

    def test_helper_returns_original_cooldown_only_after_original_closes(self):
        for failed_close in (None, 1):
            world = World()
            world.http.bodies[0] = raw_http("git-remote-account", b"", status=429, extra=b"Retry-After: 600\r\n")
            world.close_failure = failed_close
            with original(world) as body:
                self.assertEqual(run(world), 70)
                value = world.binding.accept_message(world.raw_sent[-1])
                self.assertEqual(value.control, limited())
                self.assertEqual(value.status, "refused" if failed_close is None else "unknown")
                self.assertEqual(body.unknown, failed_close is not None)
                self.assertEqual(len(world.http.calls), 1)
                self.assertEqual([event for event in world.events if event[0] == "close"],
                                 [("close", 2), ("close", 1), ("close", 0)])

    def test_actual_factory_identity_refusal_is_retained_in_returned_control(self):
        cases = ([{**ACCOUNT, "id": 12}], [{**ACCOUNT, "login": "other"}],
                 [ACCOUNT, {**REPOSITORY, "id": 23}],
                 [ACCOUNT, {**REPOSITORY, "full_name": "fixture/other"}])
        for bodies in cases:
            with self.subTest(calls=len(bodies)), self.actual_factory_entry(bodies) as (world, body, live, _):
                self.assertEqual(run(world), 70)
                returned = world.binding.accept_message(world.raw_sent[-1])
                self.assertEqual((returned.status, returned.reason), ("refused", "target-changed"))
                self.assertEqual(returned.control, {**controls.empty(), "reason": "target-changed"})
                self.assertEqual(len(live.calls), len(bodies))
                self.assertEqual(live.closes, ["response", "connection"] * len(bodies))
                self.assertFalse(body.unknown)

    def test_actual_http_close_failure_preserves_preclose_429_control_and_first_failure(self):
        for endpoint in ("response", "connection"):
            with self.subTest(endpoint=endpoint), self.actual_factory_entry([
                    raw_http(transport.ACCOUNT, b"", status=429, extra=b"Retry-After: 600\r\n")
            ]) as (world, body, live, patches):
                if endpoint == "response":
                    live.fail_close = OSError("inert HTTP response close ambiguity")
                else:
                    before = http_client.HTTPSConnection.close
                    def failed_close(connection):
                        before(connection)
                        raise OSError("inert HTTP connection close ambiguity")
                    patches.enter_context(patch.object(http_client.HTTPSConnection, "close", failed_close))
                self.assertEqual(run(world), 70)
                returned = world.binding.accept_message(world.raw_sent[-1])
                self.assertEqual((returned.status, returned.reason), ("unknown", "cleanup-unknown"))
                self.assertEqual(returned.control, limited())
                self.assertEqual((body.first_failure_ns, body.cleanup_end_ns),
                                 (120_000_000_000, 130_000_000_000))
                self.assertTrue(body.unknown)
                self.assertEqual(live.closes, ["response", "connection"])
                self.assertEqual(len(live.calls), 1)
                self.assertEqual([row.state for row in world.leases], ["CLOSED"] * 3)

    def test_stdlib_early_close_preserves_already_parsed_control_before_result_exists(self):
        with self.actual_factory_entry() as (world, _, live, patches):
            def getresponse(connection):
                response = connection.response_class(raw_http(transport.ACCOUNT, b"", status=429,
                    extra=b"Retry-After: 600\r\n"))
                response.begin()
                try:
                    raise http.ReadFailure("response-limit")
                except BaseException:
                    response.close()  # Same actual FixedResponse early-close route.
                    raise
            patches.enter_context(patch.object(http_client.HTTPSConnection, "getresponse", getresponse))
            self.assertEqual(run(world), 70)
            returned = world.binding.accept_message(world.raw_sent[-1])
            self.assertEqual(returned.control, {**limited(), "reason": "response-invalid"})
            self.assertEqual(live.closes, ["response", "connection"])
            self.assertEqual(len(live.calls), 1)

    def test_original_header_wall_sample_is_not_repeated_after_getresponse(self):
        with self.actual_factory_entry([raw_http(transport.ACCOUNT, b"", status=429,
                extra=b"Retry-After: Thu, 01 Jan 1970 00:26:40 GMT\r\n")]) as (world, _, live, patches):
            samples = []
            def wall(budget):
                samples.append(budget)
                return 1000 if len(samples) == 1 else 9999
            patches.enter_context(patch.object(http._Budget, "wall_seconds", wall))
            self.assertEqual(run(world), 70)
            returned = world.binding.accept_message(world.raw_sent[-1])
            self.assertEqual(returned.control, limited(601))
            self.assertEqual(len(samples), 1)
            self.assertEqual(live.closes, ["response", "connection"])

    def test_control_callback_error_or_reentry_keeps_limits_closes_and_no_retry(self):
        for reentry in (False, True):
            with self.subTest(reentry=reentry), self.actual_factory_entry([
                    raw_http(transport.ACCOUNT, b"", status=429, extra=b"Retry-After: 600\r\n")
            ]) as (world, body, live, patches):
                before = transport._RemoteTransport.observe_control
                calls = []
                def broken(remote, control):
                    before(remote, control)
                    calls.append(control)
                    if reentry:
                        remote.before()
                    raise RuntimeError("inert control observer failure")
                patches.enter_context(patch.object(transport._RemoteTransport, "observe_control", broken))
                self.assertEqual(run(world), 70)
                returned = world.binding.accept_message(world.raw_sent[-1])
                self.assertEqual((returned.status, returned.reason), ("unknown", "cleanup-unknown"))
                self.assertEqual(returned.control, limited())
                self.assertTrue(body.unknown)
                self.assertEqual(len(calls), 4)  # Header, finally, response, connection: same owner.
                self.assertEqual(live.closes, ["response", "connection"])
                self.assertEqual(len(live.calls), 1)

    def test_unknown_frame_preserves_control_without_finality_or_repeat(self):
        channel, operation, source = channel_original()
        raw = channel.binding.returned("unknown", "cleanup-unknown", control=limited(),
            first_failure_ns=100_000_000_000, cleanup_end_ns=110_000_000_000)
        with patch("time.monotonic", return_value=100.), \
                patch("time.CLOCK_UPTIME_RAW", 1, create=True), \
                patch("time.clock_gettime_ns", return_value=100_000_000_000):
            channel._accept_block(raw, finishing=False)
            self.assertEqual(source.http_control, limited())
            self.assertFalse(channel.closed or channel.eof)
            channel.io.blocks.append(b"")
            self.assertTrue(channel.finish(operation))
            with self.assertRaises(ProcessCleanupError):
                channel.accept_return(operation, subprocess.CompletedProcess([], 0))
            self.assertEqual(source.http_control, limited())
            self.assertTrue(channel.unknown and operation.unknown)

    def test_late_malformed_or_duplicate_never_replaces_original_control(self):
        for suffix in (b"x", b"\n", b'{"kind":"returned"}'):
            channel, _, source = channel_original()
            raw = channel.binding.returned("refused", "rate-limited", control=limited(),
                first_failure_ns=100_000_000_000, cleanup_end_ns=110_000_000_000)
            with patch("time.monotonic", return_value=100.), \
                    patch("time.CLOCK_UPTIME_RAW", 1, create=True), \
                    patch("time.clock_gettime_ns", return_value=100_000_000_000):
                channel._accept_block(raw, finishing=False)
                with self.assertRaises(NativeProcessError):
                    channel._accept_block(suffix, finishing=False)
                self.assertEqual(source.http_control, limited())

    def test_private_terminal_control_survives_unknown_not_public_success(self):
        request = worker.parse_request(frame(fixture()))
        raw = worker.terminal(request, "cleanup-unknown", reason="unknown", control=limited(),
                              first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        row = json.loads(raw)
        self.assertEqual(row["control"], limited())
        self.assertEqual((row["result"], row["publication"], row["status"]), (None, None, "cleanup-unknown"))
        self.assertLessEqual(len(raw), worker.RESPONSE_LIMIT)
        with self.assertRaises(worker.ProtocolError):
            worker.terminal(request, "cleanup-unknown", reason="unknown", control={"reason": "inert"},
                            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)


if __name__ == "__main__":
    unittest.main()
