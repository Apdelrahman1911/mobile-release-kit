"""Actual bounded transport/factory with fake HTTP/TLS/FD returns only.

Uses the one shared transport hook projection, never another network client.
No credential, socket, source lease, native ACK or live Git is supplied.
"""
from __future__ import annotations

import http.client
import io
import json
import unittest
from unittest.mock import patch

from mobile_release import _github_connection_transport as h
from mobile_release import git_push_body as b
from mobile_release import git_push_transport as t
from mobile_release import git_push_wire as w
from test_git_push_body import _Returns
from test_git_push_wire import SELECTED, REMOTE, OLD, NEW, OTHER, advertisement_raw, command, pack, status
from test_git_remote_transport import FakeLive


TARGET = t.Target("fixture/relay", "chosen-user", "11", "22", SELECTED)
ACCOUNT = {"id": 11, "login": "chosen-user"}
REPOSITORY = {"id": 22, "full_name": "fixture/relay", "default_branch": "main", "visibility": "private",
              "archived": False, "permissions": {"pull": True, "push": True},
              "clone_url": "https://github.com/fixture/relay.git"}
OK = status(b"unpack ok", b"ok " + REMOTE.encode())
AFTER = advertisement_raw(refs=((REMOTE, NEW),))


def budget(now=lambda: 1.0):
    return h._Budget(0.0, monotonic=now, wall=lambda: 1_000.0, _profile=h._ExchangeProfile.GIT_PUSH)


def raw_http(role, body, *, code=200, extra=b"", chunked=False):
    media = t.response_media(role).encode() if role in t.BINARY_ROLES else b"application/json"
    if type(body) is dict:
        body = json.dumps(body, separators=(",", ":")).encode()
    head = f"HTTP/1.1 {code} Synthetic\r\n".encode() + b"Content-Type: " + media + b"\r\n" + extra
    if chunked:
        return head + b"Transfer-Encoding: chunked\r\n\r\n" + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    return head + f"Content-Length: {len(body)}\r\n\r\n".encode() + body


class Exchange:
    def __init__(self, *, mode="apply", current=lambda: None, responses=None):
        self.clock = budget()
        self.responses = responses if responses is not None else (
            [ACCOUNT, REPOSITORY, advertisement_raw(), OK, ACCOUNT, REPOSITORY, AFTER] if mode == "apply"
            else [ACCOUNT, REPOSITORY, advertisement_raw(), ACCOUNT, REPOSITORY])
        self.calls, self.sent, self.events, self.failures = [], [], [], []
        self.fail_close = self.after_close = None
        self.wrapper = t._PushTransport(TARGET, mode, self.exchange, self.clock, current, self.failure)

    def failure(self, reason):
        self.failures.append(reason)
        self.events.append(("first-F-observation", reason))

    def exchange(self, method, path, body, *, _role, _push_body, _push_delivery):
        role = _role.value
        t.validate_endpoint(role, method, path); t.validate_body(role, body, _push_body)
        if _push_delivery is not None:
            _push_delivery.claim(role, _push_body)
        self.clock.claim_request()
        index = len(self.calls)
        self.calls.append((method, path, body, role))
        self.events.append(("request", role))
        try:
            if _push_body is not None:
                _push_body.send(self.sent.append, self.clock.remaining)
            upstream = self.responses[index]
            raw = upstream if type(upstream) is bytes and upstream.startswith(b"HTTP/") else raw_http(role, upstream)
            parsed = h._ResponseBody(io.BytesIO(raw), self.clock, _role=_role)
            return h._response_result(parsed, self.clock, _push_delivery=_push_delivery,
                                      _remote_failure=self.failure)
        finally:
            self.events.append(("fake-original-close-return", role))
            if self.after_close is not None:
                self.after_close()
            if self.fail_close is not None:
                raise self.fail_close

    def first_three(self):
        self.wrapper.before()
        self.wrapper.advertisement()


def sealed(world, wrapper, raw=None):
    body = b._PushBody(world.io, wrapper.target.selected, wrapper.offered)
    body.begin(command(offer=wrapper.offered))
    raw = pack() if raw is None else raw
    for offset in range(0, len(raw), w.READ_CHUNK):
        body.append(raw[offset:offset + w.READ_CHUNK])
    body.seal()
    return body


class Live(FakeLive):
    """Reuse original fake stdlib return fixture; production factory executes."""
    def __init__(self, test, responses):
        super().__init__(test, responses)
        self.sent, self.failures, self.close_facts = [], [], []
        self.fail_send = None
        self.on_close = None
        world = self

        def endheaders(connection, body=None):
            test.assertIsNone(body)
            world.calls.append((connection.method, connection.path, dict(connection.headers), None))

        def send(connection, block):
            world.sent.append(block)
            if world.fail_send is not None:
                raise world.fail_send

        def getresponse(connection):
            role = (t.ACCOUNT if connection.path == "/user" else t.REPOSITORY if connection.path.startswith("/repos/")
                    else t.ADVERTISEMENT if "/info/refs?" in connection.path else t.SEND)
            upstream = world.rows.pop(0)
            raw = upstream if type(upstream) is bytes and upstream.startswith(b"HTTP/") else raw_http(role, upstream)
            response = connection.response_class(raw)
            response.begin()
            return response

        for name, value in (("endheaders", endheaders), ("send", send), ("getresponse", getresponse)):
            test.enterContext(patch.object(http.client.HTTPSConnection, name, value, create=True))
        for cls, name in ((http.client.HTTPResponse, "response"), (http.client.HTTPSConnection, "connection")):
            original = cls.close
            def close(value, original=original, name=name):
                world.close_facts.append((name, tuple(world.failures)))
                if world.on_close is not None:
                    world.on_close(name)
                return original(value)
            test.enterContext(patch.object(cls, "close", close))

    def push(self, current=lambda: None, mode="apply"):
        return t._make_transport(TARGET, mode, "SYNTHETIC-NON-CREDENTIAL", started=0.0,
            runtime_dir="/synthetic/original-runtime", budget=budget(), current=current,
            failure=self.failures.append)


class GitPushTransportTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("No actual process")))

    def test_closed_receive_pack_roles_and_headers_do_not_adopt_fetch_or_force(self):
        for role, method, path in ((t.ACCOUNT, "GET", "/user"), (t.REPOSITORY, "GET", "/repos/fixture/relay"),
                (t.ADVERTISEMENT, "GET", "/fixture/relay.git/info/refs?service=git-receive-pack"),
                (t.SEND, "POST", "/fixture/relay.git/git-receive-pack")):
            t.validate_endpoint(role, method, path)
            for wrong in ("https://github.com" + path, path + "&other=1", path + "/", path + "#fragment"):
                with self.assertRaises(t.PushError):
                    t.validate_endpoint(role, method, wrong)
            with self.assertRaises(t.PushError):
                t.validate_endpoint(role, "DELETE", path)
            headers = dict(t.private_headers(role, "SYNTHETIC-NON-CREDENTIAL", TARGET.login, "2026-03-10"))
            self.assertNotIn("Git-Protocol", headers)
            self.assertEqual(headers["Accept-Encoding"], "identity")
        with self.assertRaises(t.PushError):
            t.validate_endpoint(t.SEND, "POST", "/fixture/relay.git/git-upload-pack")
        with self.assertRaises(t.PushError):
            t.validate_body(t.SEND, b"arbitrary bytes", None)

    def test_shared_old_role_caps_unchanged_and_push_has_seven_original_45s_calls(self):
        self.assertEqual(h._role_limits(h._ExchangeProfile.STANDARD, h._ResponseRole.STANDARD), (256 * 1024, 1024))
        self.assertEqual(h._role_limits(h._ExchangeProfile.GIT_REMOTE, h._ResponseRole.GIT_REMOTE_FETCH), (32 * 1024 * 1024, 256))
        for profile, role in ((h._ExchangeProfile.GIT_REMOTE, h._ResponseRole.GIT_PUSH_SEND),
                              (h._ExchangeProfile.GIT_PUSH, h._ResponseRole.GIT_REMOTE_FETCH)):
            with self.assertRaises(ValueError):
                h._role_limits(profile, role)
        value = budget()
        for _ in range(7):
            value.claim_request()
        with self.assertRaises(h.ReadFailure):
            value.claim_request()
        self.assertEqual((value.requests, value.end, value.body_total_limit), (7, 45.0, 2 * 1024 * 1024))

    def test_review_is_exact_five_gets_and_cannot_publish(self):
        original = Exchange(mode="review")
        original.first_three()
        result = original.wrapper.finish_read()
        self.assertEqual(dict(result.refs)[REMOTE], OLD)
        self.assertEqual([row[0] for row in original.calls], ["GET"] * 5)
        with self.assertRaises(t.PushError):
            original.wrapper.publish(None)
        with self.assertRaises(t.PushError):
            original.wrapper.before()
        self.assertEqual(len(original.calls), 5)

    def test_reconcile_read_matches_never_reconstruct_send_or_absence_permission(self):
        for oid, state in ((NEW, "matches-intended"), (OLD, "still-old"), (OTHER, "other")):
            original = Exchange(mode="reconcile", responses=[ACCOUNT, REPOSITORY,
                advertisement_raw(refs=((REMOTE, oid),)), ACCOUNT, REPOSITORY])
            original.first_three()
            value = original.wrapper.finish_read()
            self.assertEqual((value.state, value.observed_oid), (state, oid))
            self.assertEqual(len(original.calls), 5)
            self.assertTrue(all(row[0] == "GET" for row in original.calls))
            with self.assertRaises(t.PushError):
                original.wrapper.publish(None)

    def test_changed_account_archived_unknown_push_or_clone_url_refuse_before_advertisement(self):
        cases = ([{**ACCOUNT, "id": 12}, REPOSITORY], [ACCOUNT, {**REPOSITORY, "archived": True}],
                 [ACCOUNT, {**REPOSITORY, "permissions": {"pull": True}}],
                 [ACCOUNT, {**REPOSITORY, "clone_url": "https://elsewhere.invalid/fixture/relay.git"}])
        for rows in cases:
            original = Exchange(responses=rows)
            with self.assertRaises(t.PushError):
                original.first_three()
            self.assertLessEqual(len(original.calls), 2)
            self.assertTrue(original.wrapper.failed)

    def test_same_body_one_post_and_fresh_after_target_with_original_http_closes(self):
        world = _Returns(self)
        original = Exchange(current=world.io.current)
        original.first_three()
        body = sealed(world, original.wrapper)
        raw = original.wrapper.publish(body)
        original.wrapper.after()
        self.assertEqual(raw, OK)
        self.assertEqual(b"".join(original.sent), bytes(world.content))
        self.assertEqual([row[3] for row in original.calls],
                         [t.ACCOUNT, t.REPOSITORY, t.ADVERTISEMENT, t.SEND, t.ACCOUNT, t.REPOSITORY, t.ADVERTISEMENT])
        self.assertTrue(original.wrapper.finished)
        with self.assertRaises(t.PushError):
            original.wrapper.publish(body)
        self.assertEqual(len(original.calls), 7)

    def test_changed_after_ref_retains_actual_post_receipt_and_never_retries(self):
        world = _Returns(self)
        original = Exchange(current=world.io.current,
            responses=[ACCOUNT, REPOSITORY, advertisement_raw(), OK, ACCOUNT, REPOSITORY, advertisement_raw()])
        original.first_three()
        body = sealed(world, original.wrapper)
        original.wrapper.publish(body)
        with self.assertRaises(t.PushError):
            original.wrapper.after()
        self.assertEqual(original.wrapper.posted.value.outcome, "ok")
        self.assertTrue(original.wrapper.failed)
        self.assertFalse(original.wrapper.finished)
        with self.assertRaises(t.PushError):
            original.wrapper.publish(body)
        self.assertEqual(sum(row[0] == "POST" for row in original.calls), 1)

    def test_negative_receipt_is_retained_and_first_failure_precedes_close_and_no_after_get(self):
        world = _Returns(self)
        original = Exchange(current=world.io.current, responses=[ACCOUNT, REPOSITORY, advertisement_raw(),
            status(b"unpack ok", b"ng " + REMOTE.encode() + b" SYNTHETIC_PRIVATE_REASON")])
        original.first_three()
        body = sealed(world, original.wrapper)
        with self.assertRaises(t.PushError):
            original.wrapper.publish(body)
        self.assertEqual(original.wrapper.posted.value.outcome, "rejected")
        self.assertNotIn("SYNTHETIC_PRIVATE", repr(original.wrapper.posted.value))
        first = original.events.index(("first-F-observation", "remote-rejected"))
        close = original.events.index(("fake-original-close-return", t.SEND))
        self.assertLess(first, close)
        with self.assertRaises(t.PushError):
            original.wrapper.after()
        self.assertEqual(len(original.calls), 4)

    def test_lost_actual_close_keeps_positive_response_but_no_native_completion(self):
        world = _Returns(self)
        original = Exchange(current=world.io.current)
        original.first_three()
        body = sealed(world, original.wrapper)
        original.fail_close = h._CloseFailure("Fixed synthetic close failed")
        with self.assertRaises(h._CloseFailure):
            original.wrapper.publish(body)
        self.assertEqual(original.wrapper.posted.value.outcome, "ok")
        self.assertFalse(original.wrapper.posted.taken)
        self.assertFalse(original.wrapper.finished)
        with self.assertRaises(t.PushError):
            original.wrapper.publish(body)
        self.assertEqual(len(original.calls), 4)

    def test_same_factory_streams_sealed_fd_under_receive_media_without_generic_body(self):
        world = _Returns(self)
        live = Live(self, [ACCOUNT, REPOSITORY, advertisement_raw(), OK, ACCOUNT, REPOSITORY, AFTER])
        original = live.push(world.io.current)
        original.before(); original.advertisement()
        body = sealed(world, original)
        original.publish(body); original.after()
        self.assertEqual(b"".join(live.sent), bytes(world.content))
        post = live.calls[3]
        self.assertEqual(post[0], "POST")
        self.assertIsNone(post[3])
        self.assertEqual(post[2]["Content-Type"], "application/x-git-receive-pack-request")
        self.assertEqual(post[2]["Content-Length"], str(body.digest.body_bytes))
        self.assertTrue(all("Git-Protocol" not in row[2] for row in live.calls))
        self.assertEqual([value["server_hostname"] for value in live.wraps],
                         ["api.github.com", "api.github.com", "github.com", "github.com",
                          "api.github.com", "api.github.com", "github.com"])
        self.assertEqual(live.closes, ["response", "connection"] * 7)

    def test_same_factory_partial_send_retains_body_and_observes_failure_before_close(self):
        world = _Returns(self)
        live = Live(self, [ACCOUNT, REPOSITORY, advertisement_raw()])
        original = live.push(world.io.current)
        original.before(); original.advertisement()
        body = sealed(world, original)
        live.fail_send = OSError("Synthetic partial send")
        with self.assertRaises(t.PushError):
            original.publish(body)
        self.assertTrue(body.failed and original.failed)
        self.assertEqual(len(live.sent), 1)
        self.assertEqual(live.close_facts[-1][0], "connection")
        self.assertIn("network-unavailable", live.close_facts[-1][1])
        with self.assertRaises(t.PushError):
            original.publish(body)
        self.assertEqual(len(live.calls), 4)

    def test_non_200_header_refusal_never_reads_or_exposes_error_body(self):
        class HeadersOnly(io.BytesIO):
            def read1(self, size=-1):
                if self.tell() >= self.getvalue().index(b"\r\n\r\n") + 4:
                    raise AssertionError("Error body read")
                return super().read1(size)
        clock = budget()
        source = HeadersOnly(raw_http(t.SEND, b"SYNTHETIC_PRIVATE_ERROR", code=401))
        response = h._ResponseBody(source, clock, _role=h._ResponseRole.GIT_PUSH_SEND)
        result = h._response_result(response, clock, _push_delivery=None, _remote_failure=lambda _: None)
        self.assertEqual(result.observation, {"status": None, "body": None, "failure": "unauthorized"})
        self.assertNotIn("SYNTHETIC_PRIVATE", repr(result))

    def test_original_429_control_is_retained_before_close_even_when_that_close_is_unknown(self):
        raw = raw_http(t.ACCOUNT, b"SYNTHETIC_PRIVATE_ERROR", code=429, extra=b"Retry-After: 600\r\n")
        live = Live(self, [raw])
        original = live.push(mode="review")
        controls_at_close = []
        live.on_close = lambda _: controls_at_close.append(dict(original.control))
        live.fail_close = OSError("Synthetic original close failure")
        with self.assertRaises(h._CloseFailure):
            original.before()
        expected = h._control("rate-limited", 600)
        self.assertEqual(original.control, expected)
        self.assertEqual(controls_at_close, [expected, expected])
        self.assertTrue(original.failed)
        self.assertFalse(original.finished)
        self.assertIn("rate-limited", live.close_facts[0][1])
        self.assertEqual(live.closes, ["response", "connection"])
        with self.assertRaises(t.PushError):
            original.before()
        self.assertEqual(len(live.calls), 1)
        self.assertEqual(live.sent, [])

    def test_control_observer_error_never_skips_original_closes_or_retries(self):
        raw = raw_http(t.ACCOUNT, b"", code=429, extra=b"Retry-After: 600\r\n")
        live = Live(self, [raw])
        actual = t._PushTransport.observe_control
        def failed_after_recording(original, control):
            actual(original, control)
            raise RuntimeError("Synthetic private observer failure")
        with patch.object(t._PushTransport, "observe_control", failed_after_recording):
            original = live.push(mode="review")
            with self.assertRaises(h._CloseFailure):
                original.before()
        self.assertEqual(original.control, h._control("rate-limited", 600))
        self.assertEqual(live.closes, ["response", "connection"])
        self.assertTrue(original.failed)
        self.assertEqual(len(live.calls), 1)
        self.assertEqual(live.sent, [])


if __name__ == "__main__":
    unittest.main()
