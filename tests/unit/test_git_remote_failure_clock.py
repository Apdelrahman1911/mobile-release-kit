"""Real shared factory/Entry first-F ordering; every IO and clock is inert.

No socket, TLS, source path, Git, child or credential is accessed. These tests
prove callback/close ordering, not native closure or an installed deadline.
"""
import http.client as http_client
import ssl
import unittest
from unittest.mock import patch

from mobile_release import _github_connection_transport as http
from mobile_release import git_remote_transport as transport
from test_desktop_git_remote_helper_entry import World, original
from test_git_remote_transport import FakeLive, TARGET, ACCOUNT, REPOSITORY, LS_REQUEST, raw_http
from test_git_remote_wire import offered, fetch, response

_ORIGINAL_FACTORY = transport._make_transport


class FailureClockTests(unittest.TestCase):
    def factory(self, body, *, failure=None):
        budget = http._Budget(100., monotonic=body.clock, wall=lambda: 1000.,
                              _profile=http._ExchangeProfile.GIT_REMOTE)
        return _ORIGINAL_FACTORY(TARGET, "SYNTHETIC-NON-CREDENTIAL", started=100.,
            runtime_dir="/inert-runtime", budget=budget, current=body._current_callback,
            failure=body._failure_callback if failure is None else failure)

    def delay(self, world, body):
        recorded = []
        for klass, name in ((http_client.HTTPResponse, "response"), (http_client.HTTPSConnection, "connection")):
            before = klass.close
            def close(value, before=before, name=name):
                recorded.append((name, body.first_failure_ns, body.cleanup_end_ns))
                if body.failed:
                    world.now += 2.
                return before(value)
            self.enterContext(patch.object(klass, "close", close))
        return recorded

    def test_converted_http_failure_keeps_pre_close_first_failure_and_original_cutoff(self):
        world = World()
        with original(world) as body:
            body._bridge(world.binding)
            live = FakeLive(self, [raw_http(transport.ACCOUNT, b"", status=403)])
            closed = self.delay(world, body)
            remote = self.factory(body)
            with self.assertRaises(transport.RemoteError) as failed:
                remote.before()
            body.remember(failed.exception)  # Actual outer catch cannot renew F.
            self.assertEqual((body.first_failure_ns, body.cleanup_end_ns), (120_000_000_000, 130_000_000_000))
            self.assertEqual([c[1:] for c in closed], [(120_000_000_000, 130_000_000_000)] * 2)
            self.assertEqual(live.closes, ["response", "connection"])
            self.assertEqual(world.now, 124.)

    def test_stream_parser_failure_is_observed_before_converted_result_and_slow_close(self):
        world = World()
        with original(world) as body:
            body._bridge(world.binding)
            live = FakeLive(self, [ACCOUNT, REPOSITORY, offered().raw, b"0005x"])
            closed = self.delay(world, body)
            remote = self.factory(body)
            remote.before(); remote.advertisement()
            with self.assertRaises(transport.RemoteError):
                remote.ls_refs(LS_REQUEST)
            self.assertEqual(body.first_failure_ns, 120_000_000_000)
            self.assertTrue(all(c[1] is None for c in closed[:-2]))
            self.assertTrue(all(c[1] == 120_000_000_000 for c in closed[-2:]))
            self.assertEqual(len(live.calls), 4)

    def test_tls_and_io_failures_record_before_connection_close(self):
        for error, reason in ((ssl.SSLError("inert"), "tls-failed"), (OSError("inert"), "network-unavailable")):
            with self.subTest(reason=reason), self.subtest_cleanup():
                world = World()
                with original(world) as body:
                    body._bridge(world.binding)
                    live = FakeLive(self); live.fail_connect = error
                    closed = self.delay(world, body)
                    remote = self.factory(body)
                    with self.assertRaises(transport.RemoteError):
                        remote.before()
                    self.assertEqual(body.primary.reason, reason)
                    self.assertEqual(closed, [("connection", 120_000_000_000, 130_000_000_000)])
                    self.assertEqual(live.closes, ["connection"])

    def subtest_cleanup(self):
        # Fixed fake patch cleanup at each subcase, not an execution owner.
        from contextlib import contextmanager
        @contextmanager
        def cleanup():
            depth = len(self._cleanups)
            try:
                yield
            finally:
                while len(self._cleanups) > depth:
                    function, args, kwargs = self._cleanups.pop()
                    function(*args, **kwargs)
        return cleanup()

    def test_stdlib_early_response_close_observes_active_exception_before_super_close(self):
        world = World()
        with original(world) as body:
            body._bridge(world.binding)
            live = FakeLive(self)
            closed = self.delay(world, body)
            def getresponse(connection):
                response = connection.response_class(b"invalid status\r\n\r\n")
                try:
                    response.begin()
                    raise AssertionError("invalid inert header accepted")
                except BaseException:
                    response.close()  # Mirrors stdlib's own early-close route.
                    raise
            self.enterContext(patch.object(http_client.HTTPSConnection, "getresponse", getresponse))
            remote = self.factory(body)
            with self.assertRaises(transport.RemoteError):
                remote.before()
            self.assertEqual([c[1] for c in closed], [120_000_000_000] * 2)
            self.assertEqual(live.closes, ["response", "connection"])

    def test_successful_factory_transcript_never_observes_failure(self):
        world = World()
        with original(world) as body:
            body._bridge(world.binding)
            live = FakeLive(self)
            remote = self.factory(body)
            remote.before(); remote.advertisement(); remote.ls_refs(LS_REQUEST)
            output = []; remote.fetch(fetch(), output.append); remote.after()
            self.assertEqual(b"".join(output), response())
            self.assertIsNone(body.first_failure_ns)
            self.assertIsNone(body.primary)
            self.assertEqual(body.cleanup_end_ns, 155_000_000_000)
            self.assertEqual(live.closes, ["response", "connection"] * 7)

    def test_observer_error_and_reentry_never_skip_original_closes_or_allow_retry(self):
        for reentry in (False, True):
            with self.subTest(reentry=reentry), self.subtest_cleanup():
                world = World()
                with original(world) as body:
                    body._bridge(world.binding)
                    live = FakeLive(self, [raw_http(transport.ACCOUNT, b"", status=403)])
                    def fail(reason):
                        if reentry:
                            remote.before()
                        raise RuntimeError("inert observer failure")
                    remote = self.factory(body, failure=fail)
                    with self.assertRaises(http._CloseFailure) as caught:
                        remote.before()
                    body.remember(caught.exception)
                    self.assertTrue(body.unknown)
                    self.assertEqual(live.closes, ["response", "connection"])
                    with self.assertRaises(transport.RemoteError):
                        remote.before()
                    self.assertEqual(len(live.calls), 1)

    def test_close_failure_cannot_clear_earlier_primary_or_report_known_refusal(self):
        world = World()
        with original(world) as body:
            body._bridge(world.binding)
            live = FakeLive(self, [raw_http(transport.ACCOUNT, b"", status=403)])
            live.fail_close = OSError("inert close ambiguity")
            self.delay(world, body)
            remote = self.factory(body)
            with self.assertRaises(http._CloseFailure) as caught:
                remote.before()
            body.remember(caught.exception)
            self.assertEqual(body.primary.reason, "forbidden")
            self.assertEqual(body.first_failure_ns, 120_000_000_000)
            self.assertEqual(body.cleanup_end_ns, 130_000_000_000)
            self.assertTrue(body.unknown)
            self.assertEqual(live.closes, ["response", "connection"])


if __name__ == "__main__":
    unittest.main()
