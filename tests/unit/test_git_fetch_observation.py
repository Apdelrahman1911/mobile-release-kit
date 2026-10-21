"""Only inert observer DATA/suppliers and original parsers; no native proof.

Run on the composed current package. Network, process and the real helper
Acquisition are forbidden. The tiny opaque PACK header is NOT a valid Git
object fixture; real stock Git/FD8/limits/joins require the installed cases.
"""
from __future__ import annotations

import hashlib
import io
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _git_fetch_observation_data as d
from mobile_release import _git_fetch_observation_http as supplier
from mobile_release import _git_fetch_observation_entry as entry
from mobile_release import _github_connection_transport as http
from mobile_release import _desktop_github_engine as connection
from mobile_release import git_remote_transport as remote
from mobile_release.git_remote_wire import Selection
from mobile_release._desktop_git_remote_helper import _Helper


def transcript(case=d.CASES[0]):
    raw = b"PACK\0\0\0\2\0\0\0\1opaque-inert-data"
    return d.Transcript(case, "a" * 40, "b" * 40,
                        raw + hashlib.sha1(raw, usedforsecurity=False).digest())


def request(command, *rows):
    return (d.packet(b"command=" + command + b"\n") + d.packet(b"agent=git/inert\n")
        + d.packet(b"object-format=sha1\n") + b"0001"
        + b"".join(d.packet(row + b"\n") for row in rows) + b"0000")


class FetchObservationTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen",
                       "mobile_release.desktop_git_remote_helper._Entry.acquire"):
            p = patch(target, side_effect=AssertionError("forbidden actual effect"))
            p.start(); self.addCleanup(p.stop)

    def test_canonical_data_is_closed_bounded_and_does_not_claim_git_objects(self):
        for case in d.CASES:
            value = transcript(case)
            self.assertEqual(d.decode(value.raw(), case), value)
            self.assertLessEqual(len(value.raw()), d.DATA_LIMIT)
            self.assertEqual(d.token_case(d.token(case)), case)
        raw = transcript().raw()
        for bad in (raw + b"\n", b" " + raw, raw.replace(b'"schemaVersion":1', b'"schemaVersion":true'),
                    raw.replace(b'"base":', b'"base":"c","base":'),
                    raw.replace(b'"case":', b'"other":0,"case":'), b"x" * (d.DATA_LIMIT + 1)):
            with self.assertRaises(d.Refused): d.decode(bad, d.CASES[0])
        with self.assertRaises(d.Refused): d.decode(raw, d.CASES[1])
        with self.assertRaises(d.Refused): d.token_case("not-the-fixed-literal")

    def test_checksum_refusal_and_corruption_is_exact_one_changed_byte(self):
        value = transcript(d.CASES[1])
        with self.assertRaises(d.Refused):
            d.Transcript(value.case, value.base, value.target, value.pack[:-1] + bytes([value.pack[-1] ^ 1]))
        normal = d.fetch(transcript())
        bad = d.fetch(value)
        self.assertEqual(len(normal), len(bad))
        self.assertEqual(sum(x != y for x, y in zip(normal, bad)), 1)
        self.assertNotIn(b"packfile-uris", d.advertisement())
        self.assertNotIn(b"filter", d.advertisement())

    def test_original_connection_reader_observe_and_encoder_not_a_connected_assignment(self):
        s = supplier.Supplier()
        case = d.CASES[0]
        raw = json.dumps({"protocol": connection.PROTOCOL, "id": "operation-1", "params": {
            "repository": d.coordinate(case), "expectedAccountId": None,
            "expectedRepositoryId": None, "token": d.token(case)}}).encode() + b"\n"
        selected = connection.parse_request(raw)
        with patch.object(http, "_make_live_exchange", s.factory):
            reader = http._make_live_reader(selected, started=time.monotonic(), runtime_dir="/inert")
            result = http.observe(selected, reader, observed_at="2026-10-20T12:00:00Z")
        encoded = connection.encode_response(selected.id, **result)
        self.assertEqual((s.calls, s.phase), (4, 4))
        self.assertEqual(result["facts"]["account"]["value"]["login"], d.ACCOUNT)
        self.assertEqual(result["facts"]["repository"]["value"]["id"], d.REPOSITORY_ID)
        self.assertEqual(result["control"]["reason"], "none")
        self.assertNotIn(d.token(case).encode(), encoded)
        with self.assertRaises(d.Refused):
            s.factory(d.token(case), started=time.monotonic(), runtime_dir="/inert", api_version="2022-11-28")

    def helper(self, *, apply=True, case=d.CASES[0], source=None):
        value = transcript(case)
        target = remote.Target(d.coordinate(case), d.ACCOUNT, d.ACCOUNT_ID, d.REPOSITORY_ID,
                               Selection(d.REFERENCE, value.target if apply else None))
        budget = http._Budget(time.monotonic(), _profile=http._ExchangeProfile.GIT_REMOTE)
        events = []
        current = lambda: events.append("current")
        failure = lambda reason: events.append(("failure", reason))
        native = SimpleNamespace(budget=budget, binding=SimpleNamespace(target=target),
                                  _current_callback=current, _failure_callback=failure)
        s = supplier.Supplier(entry=native)
        with patch.object(http, "_make_live_exchange", s.factory), patch.object(entry, "read_transcript", return_value=value):
            transport = remote._make_transport(target, d.token(case), started=budget.started,
                runtime_dir="/inert", budget=budget, current=current, failure=failure)
        raw = (b"capabilities\nstateless-connect git-upload-pack\n"
            + request(b"ls-refs", b"ref-prefix refs/heads/main")
            + (request(b"fetch", b"want " + value.target.encode(), b"done") if apply else b""))
        pipe = io.BytesIO(raw if source is None else source)
        output = []
        body = _Helper(transport, read=pipe.read, write=output.append, current=current)
        return body, s, output, events, budget

    def test_real_helper_parser_metadata_and_fetch_use_only_fixed_transcripts(self):
        for apply, expected in ((False, 6), (True, 7)):
            body, s, output, events, budget = self.helper(apply=apply)
            end = budget.end
            result = body.run()
            self.assertEqual((result.reference, result.oid), (d.REFERENCE, "b" * 40))
            self.assertEqual((s.calls, s.phase), (expected, expected))
            self.assertTrue(body.finished)
            self.assertEqual(output.count(b"0002"), 2 if apply else 1)
            self.assertEqual(budget.end, end)
            self.assertFalse(any(type(e) is tuple and e[0] == "failure" for e in events))
            with self.assertRaises(remote.RemoteError): body.run()
            self.assertEqual(s.calls, expected)

    def test_unknown_helper_service_does_not_call_the_supplier(self):
        for source in (b"capabilities\nconnect git-upload-pack\n", b"capabilities\nstateless-connect git-receive-pack\n"):
            body, s, output, _, _ = self.helper(source=source)
            with self.assertRaises(remote.RemoteError): body.run()
            self.assertEqual(s.calls, 0)

    def test_response_end_follows_the_same_body_close(self):
        body, s, output, _, _ = self.helper()
        events = []
        actual = io.BytesIO
        class Body(actual):
            def close(self):
                events.append("close")
                super().close()
        write = body.write
        def emit(value):
            if value == b"0002": events.append(("end", events.count("close")))
            return write(value)
        body.write = emit
        with patch.object(supplier.io, "BytesIO", Body): body.run()
        self.assertEqual([e for e in events if type(e) is tuple], [("end", 4), ("end", 7)])

    def test_lost_body_close_is_not_a_success_marker_or_retry(self):
        body, s, output, events, _ = self.helper()
        actual = io.BytesIO
        class Body(actual):
            def close(self):
                super().close()
                raise OSError("inert close")
        with patch.object(supplier.io, "BytesIO", Body):
            with self.assertRaises(OSError): body.run()
        self.assertEqual(s.calls, 1)
        self.assertNotIn(b"0002", output)
        self.assertTrue(s.failed)
        self.assertTrue(any(type(e) is tuple and e[0] == "failure" for e in events))

    def test_pre_callback_factory_claim_is_not_reusable_after_invalid_input(self):
        s = supplier.Supplier()
        with self.assertRaises(d.Refused):
            s.factory("wrong", started=0.0, runtime_dir="/inert", api_version="2022-11-28")
        with self.assertRaises(d.Refused):
            s.factory(d.token(d.CASES[0]), started=0.0, runtime_dir="/inert", api_version="2022-11-28")
        self.assertEqual(s.calls, 0)


if __name__ == "__main__": unittest.main()
