"""Inert shared HTTP delegates/factory only; every network/native effect faked.

Run with the exact one-parent Root transport projection on package.__path__.
No actual credential, socket, TLS context, CA file, Git or child is accessed.
"""
from __future__ import annotations

import io
import json
import http.client
import socket
import ssl
import unittest
from unittest.mock import patch

from mobile_release import _github_connection_transport as h
from mobile_release import git_remote_transport as t
from mobile_release import git_remote_wire as w
from test_git_remote_wire import OID, OTHER, REF, SELECTED, fetch, metadata, offered, packet, request, response


TARGET = t.Target("fixture/relay", "chosen-user", "11", "22", SELECTED)
ACCOUNT = {"id": 11, "login": "chosen-user"}
REPOSITORY = {"id": 22, "full_name": "fixture/relay", "default_branch": "main", "visibility": "private",
              "archived": False, "permissions": {"pull": True}, "clone_url": "https://github.com/fixture/relay.git"}
LS_REQUEST = request(b"ls-refs", b"peel", b"symrefs", b"ref-prefix " + REF.encode())
LS_RESPONSE = metadata(OID.encode() + b" " + REF.encode())


def budget(now=lambda: 1.0):
    # This fake clock deliberately starts before helper launch. It exercises
    # the real Budget comparison, not a native clock bridge/lease constructor.
    return h._Budget(0.0, monotonic=now, wall=lambda: 1_000.0, _profile=h._ExchangeProfile.GIT_REMOTE)


def raw_http(role, body, *, status=200, extra=b"", chunked=False):
    media = t.response_media(role).encode() if role in t.BINARY_ROLES else b"application/json"
    if type(body) is dict:
        body = json.dumps(body, separators=(",", ":")).encode()
    head = f"HTTP/1.1 {status} Synthetic\r\n".encode() + b"Content-Type: " + media + b"\r\n" + extra
    if chunked:
        return head + b"Transfer-Encoding: chunked\r\n\r\n" + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    return head + f"Content-Length: {len(body)}\r\n\r\n".encode() + body


class FakeExchange:
    """Finite fake response/close returns through the REAL bounded delegates."""
    def __init__(self, target=TARGET, current=lambda: None, bodies=None):
        self.clock = budget()
        self.current = current
        self.bodies = bodies or [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, response(), ACCOUNT, REPOSITORY]
        self.calls, self.events = [], []
        self.close_error = None
        self.wrapper = t._RemoteTransport(target, self.exchange, self.clock, current)

    def exchange(self, method, path, body, *, _role, _remote_delivery):
        role = _role.value
        t.validate_endpoint(role, method, path); t.validate_body(role, body)
        if _remote_delivery is not None:
            _remote_delivery.claim(role, body)
        self.clock.claim_request()
        index = len(self.calls)
        self.calls.append((method, path, body, role))
        upstream = self.bodies[index]
        raw = upstream if type(upstream) is bytes and upstream.startswith(b"HTTP/") else raw_http(role, upstream)
        parsed = h._ResponseBody(io.BytesIO(raw), self.clock, _role=_role)
        try:
            return h._response_result(parsed, self.clock, _remote_delivery=_remote_delivery)
        finally:
            self.events.append(("fake-original-close-return", role))
            if self.close_error is not None:
                raise self.close_error

    def first_four(self):
        self.wrapper.before()
        self.wrapper.advertisement()
        self.wrapper.ls_refs(LS_REQUEST)


class FakeLive:
    """Recording STDLIB return shapes; real socket/TLS/file entry forbidden.

    The original factory, FixedResponse, FixedConnection, delegates and finally
    still execute. These passive doubles do NOT establish actual TLS/EOF/close.
    """
    def __init__(self, test, bodies=None):
        self.rows = list(bodies or [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE,
                                    response(), ACCOUNT, REPOSITORY])
        self.calls, self.closes, self.wraps, self.contexts, self.timeouts = [], [], [], [], []
        self.fail_close = self.fail_connect = None
        world = self

        class Socket:
            def settimeout(self, remaining):
                world.timeouts.append(remaining)

        class Context:
            def __init__(self, protocol):
                self.protocol, self.options = protocol, 128
                world.contexts.append(self)
            def set_alpn_protocols(self, values):
                self.alpn = values
            def load_verify_locations(self, **values):
                self.trust = values
            def wrap_socket(self, source, **values):
                world.wraps.append(values)
                return source

        class Response:
            def __init__(self, raw, *args, **kwargs):
                self.fp, self.headers = io.BytesIO(raw), None
            def _check_close(self):
                return True
            def close(self):
                world.closes.append("response")
                self.fp.close()
                if world.fail_close is not None:
                    raise world.fail_close

        class Connection:
            def __init__(self, host, port, *, timeout, context):
                self.host, self.port, self.context = host, port, context
                self.headers = {}
                self.timeout = timeout
            def set_debuglevel(self, value):
                test.assertEqual(value, 0)
            def putrequest(self, method, path, **options):
                self.method, self.path = method, path
                test.assertEqual(options, {"skip_host": True, "skip_accept_encoding": True})
            def putheader(self, name, value):
                test.assertNotIn(name, self.headers)
                self.headers[name] = value
            def endheaders(self, body):
                world.calls.append((self.method, self.path, dict(self.headers), body))
            def getresponse(self):
                item = world.rows.pop(0)
                role = (t.ACCOUNT if self.path == "/user" else t.REPOSITORY if self.path.startswith("/repos/")
                        else t.ADVERTISEMENT if "/info/refs?" in self.path else t.LS_REFS if b"command=ls-refs" in world.calls[-1][3] else t.FETCH)
                raw = item if type(item) is bytes and item.startswith(b"HTTP/") else raw_http(role, item)
                response = self.response_class(raw)
                response.begin()
                return response
            def close(self):
                world.closes.append("connection")

        def connect(connection):
            if world.fail_connect is not None:
                raise world.fail_connect
            connection.sock = Socket()

        for obj, name, replacement in ((http.client, "HTTPSConnection", Connection),
                                       (http.client, "HTTPResponse", Response),
                                       (http.client.HTTPConnection, "connect", connect),
                                       (ssl, "SSLContext", Context),
                                       (ssl, "OP_IGNORE_UNEXPECTED_EOF", 128)):
            test.enterContext(patch.object(obj, name, replacement))
        test.enterContext(patch.object(h, "_fixed_ca", return_value="SYNTHETIC-FIXED-CA"))
        for obj, name in ((socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
                          (ssl, "create_default_context")):
            test.enterContext(patch.object(obj, name, side_effect=AssertionError("forbidden actual network/TLS effect")))

    def transport(self, *, clock=None, current=lambda: None, failure=lambda reason: None):
        clock = clock or budget()
        return t._make_transport(TARGET, "SYNTHETIC-NON-CREDENTIAL", started=0.0,
                                 runtime_dir="/synthetic/original-runtime", budget=clock, current=current, failure=failure)


class GitRemoteTransportTests(unittest.TestCase):
    def test_closed_roles_hosts_paths_and_methods_not_urls(self):
        expected = ((t.ACCOUNT, "GET", "/user", "api.github.com"),
                    (t.REPOSITORY, "GET", "/repos/fixture/relay", "api.github.com"),
                    (t.ADVERTISEMENT, "GET", "/fixture/relay.git/info/refs?service=git-upload-pack", "github.com"),
                    (t.LS_REFS, "POST", "/fixture/relay.git/git-upload-pack", "github.com"),
                    (t.FETCH, "POST", "/fixture/relay.git/git-upload-pack", "github.com"))
        for role, method, path, host in expected:
            t.validate_endpoint(role, method, path)
            self.assertEqual(t.host(role), host)
            for bad in ("https://github.com" + path, path + "/", path + "#frag", path + "&extra=1",
                        path.replace("fixture", "other@example"), path.replace("fixture", "%66ixture")):
                if bad == path:
                    continue
                with self.assertRaises(t.RemoteError):
                    t.validate_endpoint(role, method, bad)
            with self.assertRaises(t.RemoteError):
                t.validate_endpoint(role, "DELETE", path)
        with self.assertRaises(t.RemoteError):
            t.validate_endpoint("standard", "GET", "/user")
        with self.assertRaises(t.RemoteError):
            t.validate_endpoint(t.ADVERTISEMENT, "GET", "/fixture/relay.git/info/refs?service=git-receive-pack")

    def test_old_profile_cannot_borrow_roles_or_binary_limits(self):
        for role in (h._ResponseRole.GIT_REMOTE_ACCOUNT, h._ResponseRole.GIT_REMOTE_FETCH):
            with self.assertRaises(ValueError):
                h._role_limits(h._ExchangeProfile.STANDARD, role)
        with self.assertRaises(t.RemoteError):
            h._request_limits(h._ExchangeProfile.GIT_REMOTE, h._ResponseRole.STANDARD, "GET", "/user")
        self.assertEqual(h._role_limits(h._ExchangeProfile.STANDARD, h._ResponseRole.STANDARD), (256 * 1024, 1024))
        self.assertEqual(h._role_limits(h._ExchangeProfile.GIT_REMOTE, h._ResponseRole.GIT_REMOTE_FETCH), (32 * 1024 * 1024, 256))

    def test_exact_get_post_bodies_and_finite_attempt_budget(self):
        for role in (t.ACCOUNT, t.REPOSITORY, t.ADVERTISEMENT):
            t.validate_body(role, None)
            with self.assertRaises(t.RemoteError):
                t.validate_body(role, b"{}")
        for role in (t.LS_REFS, t.FETCH):
            for body in (None, b"", b"x" * (w.MAX_REQUEST + 1)):
                with self.assertRaises(t.RemoteError):
                    t.validate_body(role, body)
        clock = budget()
        for _ in range(7):
            clock.claim_request()
        with self.assertRaises(h.ReadFailure):
            clock.claim_request()
        self.assertEqual(clock.requests, 7)
        self.assertEqual(clock.end, 45.0)
        self.assertEqual(clock.body_total_limit, 34 * 1024 * 1024)

    def test_finite_transcript_exact_identity_then_same_selected_object(self):
        original = FakeExchange()
        original.first_four()
        sent = []
        original.wrapper.fetch(fetch(), lambda block: sent.append(block))
        original.wrapper.after()
        self.assertEqual(b"".join(sent), response())
        self.assertEqual(len(original.calls), 7)
        self.assertEqual(original.wrapper.phase, 7)
        self.assertEqual(original.wrapper.selected.oid, OID)
        self.assertEqual([c[3] for c in original.calls],
                         [t.ACCOUNT, t.REPOSITORY, t.ADVERTISEMENT, t.LS_REFS, t.FETCH, t.ACCOUNT, t.REPOSITORY])
        with self.assertRaises(t.RemoteError):
            original.wrapper.before()
        self.assertEqual(len(original.calls), 7)

    def test_wrong_login_id_coordinate_clone_url_or_permission_refuse_before_git(self):
        cases = ([{**ACCOUNT, "id": 12}, REPOSITORY], [{**ACCOUNT, "login": "other"}, REPOSITORY],
                 [ACCOUNT, {**REPOSITORY, "id": 23}], [ACCOUNT, {**REPOSITORY, "full_name": "fixture/other"}],
                 [ACCOUNT, {**REPOSITORY, "clone_url": "https://example.invalid/fixture/relay.git"}],
                 [ACCOUNT, {**REPOSITORY, "permissions": {"pull": False}}])
        for bodies in cases:
            original = FakeExchange(bodies=bodies)
            with self.assertRaises(t.RemoteError):
                original.wrapper.before()
            self.assertLessEqual(len(original.calls), 2)
            self.assertTrue(original.wrapper.failed)
            with self.assertRaises(t.RemoteError):
                original.wrapper.advertisement()

    def test_ref_drift_and_wrong_request_are_zero_fetch(self):
        original = FakeExchange(bodies=[ACCOUNT, REPOSITORY, offered().raw,
            metadata(OTHER.encode() + b" " + REF.encode())])
        with self.assertRaises(t.RemoteError):
            original.first_four()
        self.assertEqual(len(original.calls), 4)
        original = FakeExchange()
        original.first_four()
        with self.assertRaises(w.WireError):
            original.wrapper.fetch(fetch(b"have " + OTHER.encode()), lambda block: None)
        self.assertEqual(len(original.calls), 4)
        self.assertTrue(original.wrapper.failed)

    def test_unreviewed_metadata_cannot_authorize_download(self):
        target = t.Target(TARGET.repository, TARGET.login, TARGET.account_id, TARGET.repository_id, w.Selection(REF, None))
        original = FakeExchange(target=target)
        original.first_four()
        with self.assertRaises(t.RemoteError):
            original.wrapper.fetch(fetch(), lambda block: None)
        self.assertEqual(len(original.calls), 4)

    def test_binary_media_encoding_redirect_and_cooldown_do_not_stream(self):
        rows = [raw_http(t.FETCH, response(), extra=b"Content-Encoding: gzip\r\n"),
                raw_http(t.FETCH, response()).replace(b"x-git-upload-pack-result", b"json"),
                raw_http(t.FETCH, response(), status=302, extra=b"Location: https://elsewhere.invalid\r\n"),
                raw_http(t.FETCH, response(), extra=b"Retry-After: 20\r\nX-RateLimit-Remaining: 0\r\n")]
        for raw in rows:
            original = FakeExchange(bodies=[ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, raw])
            original.first_four(); sent = []
            with self.assertRaises(t.RemoteError):
                original.wrapper.fetch(fetch(), lambda block: sent.append(block))
            self.assertEqual(sent, [])
            self.assertTrue(original.wrapper.failed)
        self.assertEqual(original.wrapper.control["reason"], "rate-limited")
        self.assertEqual(original.wrapper.control["cooldownSeconds"], 20)

    def test_binary_length_chunking_clean_eof_and_extra_bytes(self):
        for chunked in (False, True):
            original = FakeExchange(bodies=[ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE,
                                           raw_http(t.FETCH, response(), chunked=chunked)])
            original.first_four(); sent = []
            original.wrapper.fetch(fetch(), lambda block: sent.append(block))
            self.assertEqual(b"".join(sent), response())
            original = FakeExchange(bodies=[ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE,
                                           raw_http(t.FETCH, response(), chunked=chunked) + b"X"])
            original.first_four()
            with self.assertRaises(t.RemoteError):
                original.wrapper.fetch(fetch(), lambda block: None)
            self.assertTrue(original.wrapper.failed)

    def test_source_error_body_never_read_or_echoed(self):
        class HeadersOnly(io.BytesIO):
            def read1(self, size=-1):
                if self.tell() >= self.getvalue().index(b"\r\n\r\n") + 4:
                    raise AssertionError("arbitrary error body was read")
                return super().read1(size)
        clock = budget()
        source = HeadersOnly(raw_http(t.FETCH, b"SYNTHETIC_PRIVATE_BODY", status=401))
        parsed = h._ResponseBody(source, clock, _role=h._ResponseRole.GIT_REMOTE_FETCH)
        result = h._response_result(parsed, clock, _remote_delivery=None)
        self.assertEqual(result.observation, {"status": None, "body": None, "failure": "unauthorized"})
        self.assertEqual(result.control["reason"], "unauthorized")
        self.assertNotIn("SYNTHETIC_PRIVATE", repr(result))

    def test_sink_failure_after_prefix_and_unknown_close_never_retry(self):
        original = FakeExchange()
        original.first_four(); chunks = []
        def partial(block):
            chunks.append(block)
            raise OSError("synthetic private write ambiguity")
        with self.assertRaises(OSError):
            original.wrapper.fetch(fetch(), partial)
        self.assertTrue(chunks and original.wrapper.failed)
        with self.assertRaises(t.RemoteError):
            original.wrapper.fetch(fetch(), lambda block: None)
        self.assertEqual(len(original.calls), 5)
        original = FakeExchange(); original.first_four()
        unknown = h._CloseFailure("Original GitHub close did not return")
        original.close_error = unknown
        with self.assertRaises(h._CloseFailure) as caught:
            original.wrapper.fetch(fetch(), lambda block: None)
        self.assertIs(caught.exception, unknown)
        self.assertTrue(original.wrapper.failed)
        with self.assertRaises(t.RemoteError):
            original.wrapper.after()

    def test_original_clock_or_stop_late_during_stream_cannot_renew(self):
        now = [1.0]
        original = FakeExchange(); original.clock.monotonic = lambda: now[0]
        original.first_four()
        def late(_):
            now[0] = 45.0
        with self.assertRaises(t.RemoteError):
            original.wrapper.fetch(fetch(), late)
        self.assertEqual(original.clock.started, 0.0)
        self.assertEqual(original.clock.end, 45.0)
        self.assertTrue(original.wrapper.failed)
        with self.assertRaises(t.RemoteError):
            original.wrapper.after()

    def test_base_exception_and_reentry_keep_original_attempt_spent(self):
        original = FakeExchange(); original.first_four()
        signal = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            original.wrapper.fetch(fetch(), lambda block: (_ for _ in ()).throw(signal))
        self.assertIs(caught.exception, signal)
        self.assertTrue(original.wrapper.failed)
        original = FakeExchange()
        original.current = original.wrapper.current = lambda: original.wrapper.before()
        with self.assertRaises(t.RemoteError):
            original.wrapper.before()
        self.assertEqual(original.calls, [])
        self.assertTrue(original.wrapper.failed)

    def test_private_header_form_never_accepts_userinfo_token_url_or_other_host(self):
        synthetic = "SYNTHETIC-NON-CREDENTIAL"
        git = dict(t.private_headers(t.FETCH, synthetic, TARGET.login, "2026-03-10"))
        api = dict(t.private_headers(t.ACCOUNT, synthetic, TARGET.login, "2026-03-10"))
        self.assertEqual(git["Host"], "github.com")
        self.assertEqual(git["Git-Protocol"], "version=2")
        self.assertTrue(git["Authorization"].startswith("Basic "))
        self.assertEqual(api["Authorization"], "Bearer " + synthetic)
        self.assertNotIn("X-GitHub-Api-Version", git)
        for login in ("other:user", "user@host", "user\n", "-user", "user-"):
            with self.assertRaises(t.RemoteError):
                t.private_headers(t.FETCH, synthetic, login, "2026-03-10")

    def test_original_factory_has_exact_two_hosts_headers_tls_and_no_new_clock(self):
        world = FakeLive(self)
        clock = budget(lambda: 40.0)
        clock.end = 42.0  # A tighter original bridge, NOT a new launch+45 clock.
        transport = world.transport(clock=clock)
        transport.before(); transport.advertisement(); transport.ls_refs(LS_REQUEST)
        out = []
        transport.fetch(fetch(), lambda block: out.append(block)); transport.after()
        self.assertEqual(b"".join(out), response())
        self.assertEqual(len(world.calls), 7)
        self.assertEqual(world.closes, ["response", "connection"] * 7)
        self.assertEqual([v["server_hostname"] for v in world.wraps],
                         ["api.github.com", "api.github.com", "github.com", "github.com", "github.com", "api.github.com", "api.github.com"])
        self.assertTrue(all(v["suppress_ragged_eofs"] is False for v in world.wraps))
        self.assertEqual(len(world.contexts), 1)
        context = world.contexts[0]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.trust, {"cadata": "SYNTHETIC-FIXED-CA"})
        self.assertEqual(context.alpn, ["http/1.1"])
        self.assertIsNone(context.keylog_filename)
        self.assertEqual(context.options & 128, 0)
        self.assertTrue(all(0 < value <= 2.0 for value in world.timeouts))
        self.assertEqual(clock.end, 42.0)
        for method, path, headers, body in world.calls:
            self.assertEqual(headers["Accept-Encoding"], "identity")
            self.assertEqual(headers["Connection"], "close")
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("SYNTHETIC-NON-CREDENTIAL", path)
            if headers["Host"] == "github.com":
                self.assertTrue(headers["Authorization"].startswith("Basic "))
                self.assertEqual(headers["Git-Protocol"], "version=2")
                if method == "POST":
                    self.assertEqual(headers["Content-Type"], "application/x-git-upload-pack-request")
                    self.assertEqual(headers["Content-Length"], str(len(body)))
            else:
                self.assertTrue(headers["Authorization"].startswith("Bearer "))

    def test_factory_requires_same_claimed_budget_and_refuses_old_profile_upgrade(self):
        world = FakeLive(self)
        clock = budget()
        world.transport(clock=clock)
        with self.assertRaises(ValueError):
            world.transport(clock=clock)
        self.assertEqual(len(world.contexts), 1)
        with self.assertRaises(ValueError):
            h._make_live_exchange("SYNTHETIC", started=0.0, runtime_dir="/synthetic", api_version="2026-03-10",
                _profile=h._ExchangeProfile.GIT_REMOTE, _git_remote_login=TARGET.login, _git_remote_current=lambda: None)
        with self.assertRaises(ValueError):
            h._make_live_exchange("SYNTHETIC", started=0.0, runtime_dir="/synthetic", api_version="2026-03-10",
                _profile=h._ExchangeProfile.STANDARD, _git_remote_login=TARGET.login, _git_remote_current=lambda: None)
        clock = budget(); clock.end = 46.0
        with self.assertRaises(t.RemoteError):
            world.transport(clock=clock)
        self.assertEqual(world.calls, [])

    def test_actual_original_factory_failed_send_and_close_are_not_retryable(self):
        world = FakeLive(self)
        world.fail_connect = OSError("synthetic connect refusal")
        transport = world.transport()
        with self.assertRaises(t.RemoteError):
            transport.before()
        self.assertEqual(world.closes, ["connection"])
        self.assertEqual(transport.budget.requests, 1)
        with self.assertRaises(t.RemoteError):
            transport.before()
        self.assertEqual(world.closes, ["connection"])
        self.assertTrue(transport.failed)

    def test_actual_original_close_failure_never_hands_metadata_to_git(self):
        world = FakeLive(self)
        transport = world.transport()
        transport.before()
        world.fail_close = OSError("synthetic close ambiguity")
        with self.assertRaises(h._CloseFailure):
            transport.advertisement()
        self.assertEqual(world.closes, ["response", "connection"] * 3)
        self.assertTrue(transport.failed)
        self.assertIsNone(transport.offered)
        with self.assertRaises(t.RemoteError):
            transport.advertisement()
        self.assertEqual(len(world.calls), 3)

    def test_current_unknown_during_private_delivery_remains_unknown(self):
        original = FakeExchange(); original.first_four()
        unknown = t.RemoteError("cleanup-unknown")
        def stopped(_):
            raise unknown
        with self.assertRaises(t.RemoteError) as caught:
            original.wrapper.fetch(fetch(), stopped)
        self.assertIs(caught.exception, unknown)
        self.assertTrue(original.wrapper.failed)

    def test_delivery_claim_interrupt_is_spent_before_any_response(self):
        signal = KeyboardInterrupt()
        delivery = t._Delivery(t.ADVERTISEMENT, SELECTED, None, None, write=None,
            current=lambda: (_ for _ in ()).throw(signal), _key=t._KEY)
        with self.assertRaises(KeyboardInterrupt) as caught:
            delivery.claim(t.ADVERTISEMENT, None)
        self.assertIs(caught.exception, signal)
        self.assertTrue(delivery.claimed and delivery.failed)
        self.assertFalse(delivery.complete)
        with self.assertRaises(t.RemoteError):
            delivery.claim(t.ADVERTISEMENT, None)

    def test_fetch_has_only_decoder_packet_and_same_small_pipe_blocks_not_a_pack_spool(self):
        sizes = []
        delivery = t._Delivery(t.FETCH, SELECTED, offered(), fetch(),
            write=lambda block: sizes.append(len(block)), current=lambda: None, _key=t._KEY)
        delivery.claim(t.FETCH, fetch())
        raw = packet(b"packfile\n") + packet(b"\x01" + b"x" * (w.MAX_PACKET - 5)) + b"0000"
        for start in range(0, len(raw), 4096):
            delivery.feed(raw[start:start + 4096])
            self.assertEqual(len(delivery.buffer), 0)
            self.assertLessEqual(len(delivery.stream.decoder.buffer), w.MAX_PACKET)
        delivery.finish()
        self.assertEqual(sum(sizes), len(raw))
        self.assertTrue(all(0 < size <= 4096 for size in sizes))
        self.assertEqual(delivery.after_exchange(), (None, None))


if __name__ == "__main__":
    unittest.main()
