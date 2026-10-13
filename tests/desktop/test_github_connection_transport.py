"""Finite G1B DATA fixtures, not socket/TLS/bootstrap/native qualification.

Select this class explicitly. It uses bytes, supplied clocks and a fixed fake
reader only: no trust-file read, SSL context, DNS, socket, thread or child. The
HTTPResponse delegate is exercised; its live-only stdlib subclass/factory is not.
"""
from __future__ import annotations

import io
import json
import sys
import unittest

from mobile_release import _desktop_github_engine as engine
from mobile_release import _github_connection_transport as transport
from mobile_release.workflow_payloads import GITHUB_WORKFLOWS

_TIME = "2026-09-17T12:00:00Z"
_SENTINEL = "INERT_PRIVATE_SENTINEL"
_STEPS = ["account", "repository-before", "workflows-1", "workflows-2", "repository-after"]


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _frame(**changes: object) -> bytes:
    params = {"repository": "owner/app", "expectedAccountId": None, "expectedRepositoryId": None, "token": _SENTINEL}
    params.update(changes)
    return _json({"protocol": engine.PROTOCOL, "id": "operation-1", "params": params}) + b"\n"


def _account() -> dict:
    return {"id": 7, "login": "owner", "unrelated": _SENTINEL,
            "avatar_url": "https://unselected.invalid/avatar"}


def _repo() -> dict:
    return {"id": 11, "full_name": "owner/app", "default_branch": "main", "visibility": "private",
            "archived": False, "permissions": {"pull": True, "push": False},
            "url": "https://unselected.invalid/replacement", "unrelated": _SENTINEL}


def _page(count: int = 4, total: int | None = None, offset: int = 0) -> dict:
    rows = []
    for index in range(offset, offset + count):
        path = GITHUB_WORKFLOWS[index][1] if index < len(GITHUB_WORKFLOWS) else f".github/workflows/extra-{index}.yml"
        rows.append({"id": 100 + index, "path": path, "state": "active", "url": "https://unselected.invalid/next"})
    return {"total_count": count if total is None else total, "workflows": rows,
            "Link": "https://unselected.invalid/page999", "unrelated": _SENTINEL}


def _ok(body: dict, control: dict | None = None) -> transport.ReadResult:
    return transport.ReadResult({"status": 200, "body": body, "failure": "none"}, control or transport._control())


def _http(status: int) -> transport.ReadResult:
    return transport.ReadResult({"status": status, "body": None, "failure": "none"},
                                transport._control(transport._status_reason(status), 60 if status == 429 else None))


def _results(*, two_pages: bool = False) -> dict[str, transport.ReadResult]:
    return {"account": _ok(_account()), "repository-before": _ok(_repo()),
            "workflows-1": _ok(_page(100, 200) if two_pages else _page()),
            "workflows-2": _ok(_page(100, 200, 100)), "repository-after": _ok(_repo())}


class _FakeReader:
    def __init__(self, results: dict[str, transport.ReadResult]) -> None:
        self.results = results
        self.calls: list[str] = []

    def read(self, step: str) -> transport.ReadResult:
        if step in self.calls or step not in self.results:
            raise AssertionError("Unexpected or repeated finite read")
        self.calls.append(step)
        return self.results[step]


def _observe(results: dict[str, transport.ReadResult] | None = None, **params: object) -> tuple[dict, _FakeReader]:
    reader = _FakeReader(_results() if results is None else results)
    outcome = transport.observe(engine.parse_request(_frame(**params)), reader, observed_at=_TIME)
    return outcome, reader


def _budget(*, wall=1000, now=100.0) -> transport._Budget:
    return transport._Budget(100.0, monotonic=lambda: now, wall=lambda: wall)


def _wire(body: bytes = b"{}", *, status: int = 200, headers: tuple[tuple[str, str], ...] = (),
          framing: str = "length") -> bytes:
    fields = [("Content-Type", "application/json; charset=utf-8")]
    if framing == "length":
        fields.append(("Content-Length", str(len(body))))
    elif framing == "chunked":
        fields.append(("Transfer-Encoding", "chunked"))
    fields.extend(headers)
    return (f"HTTP/1.1 {status} Inert\r\n".encode("ascii")
            + b"".join(name.encode("ascii") + b": " + value.encode("ascii") + b"\r\n" for name, value in fields)
            + b"\r\n" + body)


def _parsed(raw: bytes, *, budget: transport._Budget | None = None) -> transport.ReadResult:
    chosen = _budget() if budget is None else budget
    try:
        response = transport._ResponseBody(io.BytesIO(raw), chosen)
        return transport._response_result(response, chosen)
    except transport.ReadFailure as error:
        return transport._failed(error.reason)


def _control_for(status: int = 200, *headers: tuple[str, str], wall=1000) -> dict:
    return _parsed(_wire(status=status, headers=headers), budget=_budget(wall=wall)).control


class GitHubConnectionTransportTests(unittest.TestCase):
    def test_private_request_frame_is_closed_and_secret_bounded(self):
        request = engine.parse_request(_frame(token="a" * 4096, expectedAccountId="7", expectedRepositoryId="11"))
        self.assertEqual((request.id, request.repository, request.expected_account_id, request.expected_repository_id),
                         ("operation-1", "owner/app", "7", "11"))
        self.assertEqual(request.token, "a" * 4096)
        self.assertNotIn(_SENTINEL, repr(engine.parse_request(_frame())))
        for changes in ({"token": ""}, {"token": "a" * 4097}, {"token": '"' * 4096},
                        {"token": " a"}, {"token": "a\r\nb"}, {"token": "é"}, {"token": "a\x7f"},
                        {"repository": "https://github.com/owner/app"}, {"repository": "owner/a?b"},
                        {"expectedAccountId": "0"}, {"expectedAccountId": "07"},
                        {"expectedAccountId": str(2**64)}, {"expectedAccountId": 7},
                        {"expectedRepositoryId": "11"}, {"unexpected": _SENTINEL}):
            with self.assertRaises(engine.ProtocolError) as caught:
                engine.parse_request(_frame(**changes))
            self.assertNotIn(_SENTINEL, str(caught.exception))
        missing = json.loads(_frame())
        del missing["params"]["expectedRepositoryId"]
        for raw in (_json(missing) + b"\n", _frame()[:-1], _frame() + b"\n", b" " + _frame(),
                    _frame()[:-1] + b" \n", _frame() + _frame(), b"[]\n",
                    _frame().replace(b'{"protocol"', b'{\n"protocol"'),
                    _frame().replace(b'{"protocol"', b'{\r"protocol"')):
            with self.assertRaises(engine.ProtocolError):
                engine.parse_request(raw)
        self.assertEqual(engine.parse_request(_frame(expectedAccountId=str(2**64 - 1))).expected_account_id,
                         str(2**64 - 1))

    def test_private_json_rejects_duplicates_surrogates_nonfinite_and_excess_depth(self):
        invalid = [b'{"protocol":"mrk-github-readonly/1","protocol":"mrk-github-readonly/1"}\n',
                   _frame().replace(b'"operation-1"', b'"\\ud800"'),
                   _frame().replace(b'"operation-1"', b'NaN'),
                   _frame().replace(b'"operation-1"', b'1e999'),
                   _frame().replace(b'"operation-1"', b'9' * 129),
                   _frame().replace(b'"operation-1"', b'[' * 7 + b'0' + b']' * 7),
                   _frame().replace(b'"operation-1"', b'"\xff"')]
        for raw in invalid:
            with self.assertRaises(engine.ProtocolError) as caught:
                engine.parse_request(raw)
            self.assertNotIn(_SENTINEL, str(caught.exception))

    def test_private_response_is_fresh_closed_correlated_and_non_echoing(self):
        outcome, _ = _observe()
        raw = engine.encode_response("operation-1", facts=outcome["facts"], control=outcome["control"])
        self.assertLessEqual(len(raw), engine.MAX_RESPONSE_BYTES)
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(_SENTINEL.encode(), raw)
        value = json.loads(raw)
        self.assertEqual(set(value), {"protocol", "id", "facts", "control"})
        self.assertEqual((value["protocol"], value["id"]), (engine.PROTOCOL, "operation-1"))
        for state in ("stale", "not-observed"):
            facts = json.loads(_json(outcome["facts"]))
            facts["account"]["state"] = state
            facts["account"]["reason"] = "stale"
            with self.assertRaises(engine.ProtocolError):
                engine.encode_response("operation-1", facts=facts, control=outcome["control"])
        results = _results()
        results["account"] = _http(403)
        unavailable, _ = _observe(results)
        with self.assertRaises(engine.ProtocolError):
            engine.encode_response("operation-1", facts=unavailable["facts"], control=transport._control())
        with self.assertRaises(engine.ProtocolError):
            engine.encode_response("operation-1", facts=dict(outcome["facts"], unexpected=_SENTINEL),
                                   control=outcome["control"])
        bad_controls = [dict(outcome["control"], unexpected=_SENTINEL),
                        transport._control("rate-limited"), transport._control("rate-limited", True),
                        transport._control("rate-limited", 0), transport._control("rate-limited", 604801),
                        transport._control("rate-limited", 1, True), transport._control("forbidden", 60),
                        dict(outcome["control"], credentialExpiresAt="2026-02-30T00:00:00Z")]
        missing = dict(outcome["control"])
        del missing["cooldownBlocked"]
        bad_controls.append(missing)
        for control in bad_controls:
            with self.assertRaises(engine.ProtocolError) as caught:
                engine.encode_response("operation-1", facts=outcome["facts"], control=control)
            self.assertNotIn(_SENTINEL, str(caught.exception))
        for control in (transport._control("rate-limited", 604800), transport._control("rate-limited", blocked=True),
                        transport._control("response-invalid", 7200), transport._control("response-invalid", blocked=True)):
            self.assertEqual(json.loads(engine.encode_response("operation-1", facts=outcome["facts"], control=control))["control"], control)
        reserved = dict(outcome["control"], credentialExpiresAt="2026-09-17T12:30:00Z")
        self.assertEqual(json.loads(engine.encode_response("operation-1", facts=outcome["facts"], control=reserved))["control"], reserved)
        # Reserved canonical DATA support is not a supported upstream header.
        self.assertEqual(_control_for(200, ("GitHub-Authentication-Token-Expiration", reserved["credentialExpiresAt"]))["reason"],
                         "response-invalid")

    def test_control_singletons_expiry_and_rate_classification(self):
        self.assertEqual(_control_for(), transport._control())
        for text in ("", "2026-09-17T12:30:00Z", "Sun, 06 Nov 1994 08:49:37 GMT", _SENTINEL):
            self.assertEqual(_control_for(200, ("GitHub-Authentication-Token-Expiration", text)), transport._control("response-invalid"))
        self.assertEqual(_control_for(200, ("GitHub-Authentication-Token-Expiration", "x"),
                                     ("github-authentication-token-expiration", "x")), transport._control("response-invalid"))
        self.assertEqual(_control_for(403), transport._control("forbidden"))
        self.assertEqual(_control_for(403, ("X-RateLimit-Remaining", "7")), transport._control("forbidden"))
        self.assertEqual(_control_for(403, ("Retry-After", " 007 ")), transport._control("rate-limited", 7))
        self.assertEqual(_control_for(429), transport._control("rate-limited", 60))
        self.assertEqual(_control_for(200, ("X-RateLimit-Remaining", "000"), ("X-RateLimit-Reset", "1100")),
                         transport._control("rate-limited", 101))
        self.assertEqual(_control_for(401, ("X-RateLimit-Remaining", "0")), transport._control("response-invalid", 60))
        self.assertEqual(_control_for(503, ("Retry-After", "7")), transport._control("response-invalid", 7))
        self.assertEqual(_control_for(200, ("X-RateLimit-Remaining", "1"), ("X-RateLimit-Reset", "9" * 1000)),
                         transport._control())
        for duplicate in ("X-RateLimit-Remaining", "X-RateLimit-Reset"):
            self.assertEqual(_control_for(403, ("Retry-After", "7200"), (duplicate, "0"), (duplicate.lower(), "0")),
                             transport._control("response-invalid", 7200))
        retry = _wire(status=403, headers=(("Retry-After", "7"),))
        for raw in (retry.replace(b"Retry-After: 7", b"Retry-After: \xc2\xa07"),
                    retry.replace(b"Retry-After: 7", b"Retry-After: 7\x7f"),
                    retry.replace(b"Retry-After: 7\r\n", b"Retry-After: 7\r\n folded\r\n")):
            self.assertEqual(_parsed(raw).control, transport._control("response-invalid"))
        separate_invalid = retry.replace(b"\r\n\r\n", b"\r\nX-\xff: bad\r\n\r\n")
        self.assertEqual(_parsed(separate_invalid).control, transport._control("response-invalid", 7))

    def test_private_fact_control_coherence_rejects_the_whole_envelope(self):
        outcome, _ = _observe()
        names = ("account", "repository", "automation")
        allowed = {
            "unauthorized": {"unauthorized", "response-invalid"},
            "target-changed": {"target-changed", "response-invalid"},
            "response-invalid": {"response-invalid"},
            "expired": {"expired", "response-invalid"},
            "rate-limited": {"rate-limited", "response-invalid"},
        }
        controls = [transport._control(reason, 60 if reason == "rate-limited" else None)
                    for reason in sorted(engine.REASONS)]
        controls.extend((transport._control("rate-limited", blocked=True),
                         transport._control("response-invalid", 7200),
                         transport._control("response-invalid", blocked=True)))
        for index, name in enumerate(names):
            for fact_reason, permitted in allowed.items():
                facts = json.loads(_json(outcome["facts"]))
                for dependent in names[index:]:
                    facts[dependent] = {"state": "unavailable", "value": None, "observedAt": None,
                                        "reason": fact_reason if dependent == name else "cancelled"}
                for control in controls:
                    coherent = (control["reason"] in permitted and
                                (fact_reason != "rate-limited" or control["cooldownSeconds"] is not None
                                 or control["cooldownBlocked"]))
                    if coherent:
                        encoded = json.loads(engine.encode_response("operation-1", facts=facts, control=control))
                        self.assertEqual(encoded["facts"], facts)
                        self.assertEqual(encoded["control"], control)
                    else:
                        with self.assertRaises(engine.ProtocolError) as caught:
                            engine.encode_response("operation-1", facts=facts, control=control)
                        self.assertNotIn(_SENTINEL, str(caught.exception))
        # The final valid HTTP200 may exhaust quota while retaining all facts.
        results = _results()
        results["repository-after"] = _ok(_repo(), transport._control("rate-limited", 7200))
        final, _ = _observe(results)
        self.assertTrue(all(final["facts"][name]["state"] == "observed" for name in names))
        self.assertEqual(json.loads(engine.encode_response("operation-1", facts=final["facts"],
                                                         control=final["control"]))["control"], final["control"])
        # Unsent dependents carry no competing cause; a stronger refusal and
        # independently established cooldown must remain encodable together.
        partial = json.loads(_json(outcome["facts"]))
        for name in ("repository", "automation"):
            partial[name] = {"state": "unavailable", "value": None, "observedAt": None, "reason": "cancelled"}
        for control in (transport._control("network-unavailable"), transport._control("response-invalid", 7200)):
            self.assertEqual(json.loads(engine.encode_response("operation-1", facts=partial, control=control))["control"], control)

    def test_cooldown_hints_survive_invalid_controls_and_never_clamp(self):
        self.assertEqual(_control_for(429, ("Retry-After", "7200"), ("GitHub-Authentication-Token-Expiration", "unsupported")),
                         transport._control("response-invalid", 7200))
        self.assertEqual(_control_for(429, ("Retry-After", "60"), ("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "9000")),
                         transport._control("rate-limited", 8001))
        for huge in ("604801", "0" * 200 + "604801", "9" * 1000):
            self.assertEqual(_control_for(429, ("Retry-After", huge)), transport._control("rate-limited", blocked=True))
            self.assertEqual(_control_for(429, ("Retry-After", huge), ("GitHub-Authentication-Token-Expiration", "bad")),
                             transport._control("response-invalid", blocked=True))
        self.assertEqual(_control_for(429, ("Retry-After", "0")), transport._control("rate-limited", 1))
        self.assertEqual(_control_for(403, ("Retry-After", "7"), ("retry-after", "7")), transport._control("response-invalid"))
        self.assertEqual(_control_for(429, ("Retry-After", "7"), ("retry-after", "7")), transport._control("response-invalid", 60))
        self.assertEqual(_control_for(403, ("Retry-After", "7"), ("retry-after", "7"),
                                     ("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "1020")),
                         transport._control("response-invalid", 21))
        for bad in ("-1", "+7", "1.5", "1e3", "7,8", "7 8", "", "\t7"):
            self.assertEqual(_control_for(403, ("Retry-After", bad)), transport._control("response-invalid"))
            self.assertEqual(_control_for(429, ("Retry-After", bad)), transport._control("response-invalid", 60))
        self.assertEqual(_control_for(200, ("X-RateLimit-Reset", "bad")), transport._control("response-invalid"))
        self.assertEqual(_control_for(200, ("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "bad")),
                         transport._control("response-invalid", 60))

    def test_strict_http_dates_and_checked_absolute_cooldown(self):
        date = "Sun, 06 Nov 1994 08:49:37 GMT"
        self.assertEqual(transport._http_date(date), 784111777)
        self.assertEqual(_control_for(429, ("Retry-After", date), wall=784111770.9), transport._control("rate-limited", 8))
        self.assertEqual(_control_for(429, ("Retry-After", date), wall=784111800), transport._control("rate-limited", 1))
        for invalid in ("Mon, 06 Nov 1994 08:49:37 GMT", "Sun, 6 Nov 1994 08:49:37 GMT",
                        "Sun, 06 Nov 1994 08:49:60 GMT", "Sun, 06 Nov 1994 08:49:37 UTC",
                        "Sun, 06 Nov 1994 08:49:37 +0000", "Sunday, 06-Nov-94 08:49:37 GMT",
                        "Sun Nov  6 08:49:37 1994", "sun, 06 Nov 1994 08:49:37 GMT"):
            self.assertEqual(_control_for(429, ("Retry-After", invalid)), transport._control("response-invalid", 60))
        self.assertEqual(_control_for(429, ("Retry-After", date), wall=float("nan")), transport._control("rate-limited", blocked=True))
        self.assertEqual(_control_for(429, ("Retry-After", "Mon, 01 Jan 0001 00:00:00 GMT"), wall=2**63 - 1),
                         transport._control("rate-limited", blocked=True))
        samples = []
        budget = transport._Budget(100.0, monotonic=lambda: 100.0, wall=lambda: samples.append(1000) or 1000)
        control = _parsed(_wire(status=429, headers=(("Retry-After", date), ("X-RateLimit-Remaining", "0"),
                                                    ("X-RateLimit-Reset", "9000"))), budget=budget).control
        self.assertEqual(samples, [1000])
        self.assertEqual(control, transport._control("rate-limited", blocked=True))

    def test_fixed_schedule_pages_and_unfollowed_urls(self):
        outcome, reader = _observe()
        self.assertEqual(reader.calls, ["account", "repository-before", "workflows-1", "repository-after"])
        self.assertEqual(outcome["control"], transport._control())
        self.assertEqual(outcome["facts"]["automation"]["value"]["coverage"], "complete")
        outcome, reader = _observe(_results(two_pages=True))
        self.assertEqual(reader.calls, _STEPS)
        self.assertEqual(outcome["facts"]["automation"]["value"]["coverage"], "complete")
        for count, total in ((99, 200), (100, 201), (0, 0)):
            results = _results(two_pages=True)
            results["workflows-1"] = _ok(_page(count, total))
            results["workflows-2"] = _ok(_page(100, total, 100))
            outcome, reader = _observe(results)
            self.assertEqual(len(reader.calls), 5 if count == 100 and total > 100 else 4)
            self.assertEqual(outcome["facts"]["automation"]["value"]["coverage"], "complete" if total == 0 else "limited")
            self.assertNotIn("unselected.invalid", _json(outcome).decode())
        duplicate = _page()
        duplicate["workflows"][1]["id"] = duplicate["workflows"][0]["id"]
        results = _results()
        results["workflows-1"] = _ok(duplicate)
        outcome, _ = _observe(results)
        self.assertEqual(outcome["facts"]["automation"]["value"]["coverage"], "limited")
        self.assertTrue(all(row["presence"] == "unknown" for row in outcome["facts"]["automation"]["value"]["workflows"]))

    def test_refresh_pins_are_checked_before_dependent_requests(self):
        outcome, reader = _observe(expectedAccountId="8")
        self.assertEqual(reader.calls, ["account"])
        self.assertEqual(outcome["control"]["reason"], "target-changed")
        self.assertTrue(all(outcome["facts"][name]["value"] is None for name in ("account", "repository", "automation")))
        outcome, reader = _observe(expectedAccountId="7", expectedRepositoryId="12")
        self.assertEqual(reader.calls, ["account", "repository-before"])
        self.assertEqual(outcome["control"]["reason"], "target-changed")
        self.assertIsNone(outcome["facts"]["repository"]["value"])
        for step, changed in (("repository-before", dict(_repo(), full_name="other/app")),
                              ("repository-after", dict(_repo(), id=12)),
                              ("repository-after", dict(_repo(), full_name="owner/recreated"))):
            results = _results()
            results[step] = _ok(changed)
            outcome, reader = _observe(results, expectedAccountId="7", expectedRepositoryId="11")
            self.assertEqual(outcome["control"]["reason"], "target-changed")
            self.assertIsNone(outcome["facts"]["repository"]["value"])
            self.assertIsNone(outcome["facts"]["automation"]["value"])
            self.assertEqual(len(reader.calls), 2 if step == "repository-before" else 4)
        outcome, _ = _observe(repository="Owner/App", expectedAccountId="7", expectedRepositoryId="11")
        self.assertEqual(outcome["control"]["reason"], "none")

    def test_unauthorized_at_every_step_stops_and_is_not_hidden_by_cancellation(self):
        for index, step in enumerate(_STEPS):
            results = _results(two_pages=True)
            results[step] = _http(401)
            outcome, reader = _observe(results)
            self.assertEqual(reader.calls, _STEPS[:index + 1])
            self.assertEqual(outcome["control"], transport._control("unauthorized"))
            self.assertIsNone(outcome["facts"]["repository"]["value"])
            self.assertIsNone(outcome["facts"]["automation"]["value"])
            engine.encode_response("operation-1", facts=outcome["facts"], control=outcome["control"])

    def test_nonfatal_listing_failures_still_require_ending_bracket(self):
        for code in (403, 404, 503):
            results = _results()
            results["workflows-1"] = _http(code)
            outcome, reader = _observe(results)
            self.assertEqual(reader.calls, ["account", "repository-before", "workflows-1", "repository-after"])
            self.assertEqual(outcome["facts"]["repository"]["state"], "observed")
            self.assertEqual(outcome["facts"]["automation"]["state"], "unavailable")
            self.assertEqual(outcome["control"]["reason"], transport._status_reason(code))
        for reason in ("network-unavailable", "tls-failed", "response-limit", "response-invalid"):
            results = _results()
            results["workflows-1"] = transport._failed(reason)
            outcome, reader = _observe(results)
            self.assertEqual(len(reader.calls), 3)
            self.assertEqual(outcome["control"]["reason"], reason)
            self.assertIsNone(outcome["facts"]["repository"]["value"])
        results = _results()
        results["workflows-1"] = _http(403)
        results["repository-after"] = _http(404)
        outcome, _ = _observe(results)
        self.assertEqual(outcome["control"]["reason"], "not-found-or-inaccessible")
        self.assertIsNone(outcome["facts"]["repository"]["value"])

    def test_rate_limit_stops_next_read_and_final_success_can_keep_facts(self):
        for index, step in enumerate(_STEPS):
            results = _results(two_pages=True)
            prior = results[step]
            results[step] = transport.ReadResult(prior.observation, transport._control("rate-limited", 7200))
            outcome, reader = _observe(results)
            self.assertEqual(reader.calls, _STEPS[:index + 1])
            self.assertEqual(outcome["control"], transport._control("rate-limited", 7200))
            if step == "repository-after":
                self.assertTrue(all(outcome["facts"][name]["state"] == "observed" for name in ("account", "repository", "automation")))
            else:
                self.assertIsNone(outcome["facts"]["repository"]["value"])
        result = _parsed(_wire(_json(_repo()), headers=(("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "1007"))))
        self.assertEqual(result.observation["status"], 200)
        self.assertEqual(result.control, transport._control("rate-limited", 8))
        invalid = _parsed(_wire(b"not-json", headers=(("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "9000"))))
        self.assertEqual(invalid.control, transport._control("response-invalid", 8001))
        hints = (("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "9000"))
        for raw in (_wire(headers=hints).replace(b"Content-Length: 2", b"Content-Length: 5"),
                    _wire(b"2\r\n{}XX0\r\n\r\n", headers=hints, framing="chunked"),
                    _wire(headers=hints).replace(b"Content-Length: 2", b"Content-Length: 999999999")):
            self.assertEqual(_parsed(raw).control, transport._control("response-invalid", 8001))

        class FailedBody(io.BytesIO):
            def read1(self, amount: int = -1) -> bytes:
                if amount > 1:
                    raise OSError("Inert body read failure")
                return super().read1(amount)

        budget = _budget()
        response = transport._ResponseBody(FailedBody(_wire(headers=hints)), budget)
        with self.assertRaises(OSError):
            transport._response_result(response, budget)
        self.assertEqual(response.control, transport._control("rate-limited", 8001))
        # The actual live SSL/OSError catch is not entered by this inert case.
        # Its retained control and pure refusal reducer are exercised directly.
        self.assertEqual(transport._failed("network-unavailable", response.control).control,
                         transport._control("response-invalid", 8001))

    def test_malformed_success_data_is_a_typed_refusal_not_internal_error(self):
        cases = (("account", {"id": True, "login": "owner"}),
                 ("repository-before", dict(_repo(), permissions={"pull": 1})),
                 ("workflows-1", {"total_count": True, "workflows": []}),
                 ("workflows-2", {"total_count": 200, "workflows": [{"id": False, "path": "x", "state": "active"}]}),
                 ("repository-after", dict(_repo(), default_branch=None)))
        for step, body in cases:
            results = _results(two_pages=True)
            results[step] = _ok(body)
            outcome, reader = _observe(results)
            self.assertEqual(reader.calls, _STEPS[:_STEPS.index(step) + 1])
            self.assertEqual(outcome["control"]["reason"], "response-invalid")
            raw = engine.encode_response("operation-1", facts=outcome["facts"], control=outcome["control"])
            self.assertNotIn(_SENTINEL.encode(), raw)

    def test_aggregate_json_bounds_stop_before_another_get(self):
        results = _results()
        results["account"] = _ok(dict(_account(), unused=list(range(11000))))
        results["repository-before"] = _ok(dict(_repo(), unused=list(range(11000))))
        outcome, reader = _observe(results)
        self.assertEqual(reader.calls, ["account", "repository-before"])
        self.assertEqual(outcome["control"]["reason"], "response-limit")
        for hint in (transport._control("rate-limited", 7200), transport._control("rate-limited", blocked=True)):
            results["repository-before"] = _ok(dict(_repo(), unused=list(range(11000))), hint)
            outcome, reader = _observe(results)
            self.assertEqual(reader.calls, ["account", "repository-before"])
            self.assertEqual(outcome["control"], dict(hint, reason="response-invalid"))
        nested: object = 0
        for _ in range(22):
            nested = [nested]
        results = _results()
        results["account"] = _ok(dict(_account(), unused=nested))
        outcome, reader = _observe(results)
        self.assertEqual(reader.calls, ["account"])
        self.assertEqual(outcome["control"]["reason"], "response-limit")

    def test_json_body_admission_counts_discarded_fields(self):
        malformed = (b'{"unused":1,"unused":2}', b'{"unused":NaN}', b'{"unused":Infinity}',
                     b'{"unused":1e999}', b'{"unused":"\\ud800"}', b'{"unused":"\xff"}',
                     b'{}{}', b'null', b'[]', b'"text"', b'')
        for raw in malformed:
            self.assertEqual(_parsed(_wire(raw)).control["reason"], "response-invalid")
        oversized = (b'{"unused":' + b'9' * 129 + b'}',
                     b'{"unused":' + b'[' * 25 + b'0' + b']' * 25 + b'}',
                     _json({"unused": list(range(20001))}))
        for raw in oversized:
            self.assertEqual(_parsed(_wire(raw)).control["reason"], "response-limit")
        self.assertEqual(_parsed(_wire(b' \n {"unused":true} \n')).observation["body"], {"unused": True})

    def test_content_length_and_eof_bodies_are_bounded_and_complete(self):
        for framing in ("length", "eof"):
            self.assertEqual(_parsed(_wire(b'{"ok":true}', framing=framing)).observation["body"], {"ok": True})
        short = b"HTTP/1.1 200 Inert\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{}"
        self.assertEqual(_parsed(short).control["reason"], "response-invalid")
        for value in ("-1", "+2", "2,2", "", "2 2"):
            raw = b"HTTP/1.1 200 Inert\r\nContent-Type: application/json\r\nContent-Length: " + value.encode() + b"\r\n\r\n{}"
            self.assertEqual(_parsed(raw).control["reason"], "response-invalid")
        exact = b'{"x":"' + b"a" * (transport.MAX_BODY_BYTES - 8) + b'"}'
        self.assertEqual(len(exact), transport.MAX_BODY_BYTES)
        self.assertEqual(_parsed(_wire(exact, framing="eof")).control["reason"], "none")
        self.assertEqual(_parsed(_wire(exact + b" ", framing="eof")).control["reason"], "response-limit")
        self.assertEqual(_parsed(_wire(exact + b" ")).control["reason"], "response-limit")
        budget = _budget()
        budget.body_bytes = transport.MAX_BODY_TOTAL - 1
        self.assertEqual(_parsed(_wire(b"{}"), budget=budget).control["reason"], "response-limit")
        accumulated = _budget()
        for _ in range(transport.MAX_BODY_TOTAL // transport.MAX_BODY_BYTES):
            self.assertEqual(_parsed(_wire(exact), budget=accumulated).control["reason"], "none")
        self.assertEqual(accumulated.body_bytes, transport.MAX_BODY_TOTAL)
        overflow = _parsed(_wire(headers=(("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "9000"))),
                           budget=accumulated)
        self.assertEqual(overflow.observation["failure"], "response-limit")
        self.assertEqual(overflow.control, transport._control("response-invalid", 8001))
        self.assertEqual(accumulated.body_bytes, transport.MAX_BODY_TOTAL)
        error_source = io.BytesIO(_wire(_SENTINEL.encode(), status=401))
        budget = _budget()
        response = transport._ResponseBody(error_source, budget)
        header_end = error_source.tell()
        result = transport._response_result(response, budget)
        self.assertEqual(error_source.tell(), header_end)  # No explicit error-body read.
        self.assertEqual(result.observation, {"status": 401, "body": None, "failure": "none"})
        self.assertNotIn(_SENTINEL, _json(result.control).decode())

        # Actual empty204 transport adapter, not a synthesized successful JSON.
        profile = transport._ExchangeProfile.SETUP
        roles = (transport._ResponseRole.SETUP_ACTIONS_WRITE, transport._ResponseRole.SETUP_WORKFLOW_WRITE)
        def setup_raw(status=204, headers=(), body=b""):
            return (f"HTTP/1.1 {status} fixed\r\n".encode() +
                    b"".join((k + ": " + v + "\r\n").encode() for k, v in headers) + b"\r\n" + body)
        def parse_setup(raw, role, used=0):
            selected = transport._Budget(100.0, monotonic=lambda: 100.0, wall=lambda: 1000,
                                         _profile=profile)
            selected.body_bytes = used
            source = io.BytesIO(raw)
            response = transport._ResponseBody(source, selected, _role=role)
            return transport._response_result(response, selected), selected, source
        for role in roles:
            for headers in ((), (("Content-Length", "0"),)):
                row, selected, source = parse_setup(setup_raw(headers=headers), role)
                self.assertEqual(row.observation, {"status": 204, "body": None, "failure": "none"})
                self.assertEqual(row.control, transport._control())
                self.assertEqual((selected.body_bytes, source.read()), (0, b""))
                exact, _, _ = parse_setup(setup_raw(headers=headers), role, transport.MAX_BODY_TOTAL)
                self.assertEqual(exact.control["reason"], "none")
            for headers, body in (((), b"x"), ((("Content-Length", "0"),), b"x"),
                                  ((("Content-Length", "1"),), b"x"),
                                  ((("Transfer-Encoding", "chunked"),), b"0\r\n\r\n"),
                                  ((("Content-Length", "0"), ("Transfer-Encoding", "chunked")), b""),
                                  ((("GitHub-Authentication-Token-Expiration", "never"),), b"")):
                row, _, _ = parse_setup(setup_raw(headers=headers, body=body), role)
                self.assertEqual(row.control["reason"], "response-invalid")
            row, selected, _ = parse_setup(setup_raw(body=b"x"), role, transport.MAX_BODY_TOTAL)
            self.assertEqual((row.control["reason"], selected.body_bytes), ("response-limit", transport.MAX_BODY_TOTAL + 1))
            row, _, _ = parse_setup(setup_raw(headers=(("X-RateLimit-Remaining", "0"),)), role)
            self.assertEqual(row.control, transport._control("response-invalid", 60))
            row, _, source = parse_setup(setup_raw(409, body=_SENTINEL.encode()), role)
            self.assertEqual(row.control["reason"], "none" if role is roles[1] else "response-invalid")
            self.assertEqual(source.read(), _SENTINEL.encode())  # Never consume upstream error detail.
        for ordinary in (transport._ExchangeProfile.STANDARD, transport._ExchangeProfile.RELEASE_PREPARE):
            selected = transport._Budget(100.0, monotonic=lambda: 100.0, _profile=ordinary)
            response = transport._ResponseBody(io.BytesIO(setup_raw()), selected)
            self.assertEqual(transport._response_result(response, selected).control["reason"], "response-invalid")
            for role in roles:
                with self.assertRaises(ValueError):
                    transport._ResponseBody(io.BytesIO(setup_raw()), selected, _role=role)

        # Environment writes use the actual bounded200 JSON reader, never the
        # empty204 adapter;422 carries no raw error detail under this role only.
        env_role = transport._ResponseRole.SETUP_ENVIRONMENT_WRITE
        for framing in ("length", "eof", "chunked"):
            payload = b'{"id":71}'
            encoded = (f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n") if framing == "chunked" else payload
            raw = _wire(encoded, framing=framing)
            result, selected, source = parse_setup(raw, env_role)
            self.assertEqual(result.observation, {"status": 200, "body": {"id": 71}, "failure": "none"})
            self.assertEqual(selected.body_bytes, len(b'{"id":71}'))
            self.assertEqual(source.read(), b"")
        row, _, _ = parse_setup(setup_raw(), env_role)
        self.assertEqual(row.control["reason"], "response-invalid")
        row, _, source = parse_setup(setup_raw(422, body=_SENTINEL.encode()), env_role)
        self.assertEqual(row.observation, {"status": 422, "body": None, "failure": "none"})
        self.assertEqual(source.read(), _SENTINEL.encode())
        for old_role in roles:
            row, _, _ = parse_setup(setup_raw(422), old_role)
            self.assertEqual(row.control["reason"], "response-invalid")
        row, selected, _ = parse_setup(_wire(b'{"id":71}'), env_role, transport.MAX_BODY_TOTAL - 1)
        self.assertEqual(row.control["reason"], "response-limit")
        for ordinary in (transport._ExchangeProfile.STANDARD, transport._ExchangeProfile.RELEASE_PREPARE):
            with self.assertRaises(ValueError):
                transport._ResponseBody(io.BytesIO(_wire()), transport._Budget(100.0, monotonic=lambda: 100.0, _profile=ordinary), _role=env_role)

        # Secret metadata404 is the sole newly admitted absence; key/environment
        # 404 never becomes absence. No upstream error text is consumed/emitted.
        metadata_role=transport._ResponseRole.SETUP_SECRET_METADATA_READ
        key_role=transport._ResponseRole.SETUP_SECRET_KEY_READ
        for role in (metadata_role,key_role):
            row, selected, source=parse_setup(_wire(b'{"key_id":"x"}'),role)
            self.assertEqual(row.observation["body"],{"key_id":"x"})
            self.assertEqual(selected.body_bytes,len(b'{"key_id":"x"}'))
            row, _, source=parse_setup(setup_raw(404,body=_SENTINEL.encode()),role)
            self.assertEqual(row.observation,{"status":404,"body":None,"failure":"none"})
            self.assertEqual(row.control["reason"],"none" if role is metadata_role else "not-found-or-inaccessible")
            self.assertEqual(source.read(),_SENTINEL.encode())
            for ordinary in (transport._ExchangeProfile.STANDARD,transport._ExchangeProfile.RELEASE_PREPARE):
                with self.assertRaises(ValueError):
                    transport._ResponseBody(io.BytesIO(_wire()),transport._Budget(100.0,monotonic=lambda:100.0,_profile=ordinary),_role=role)

        secret_role = transport._ResponseRole.SETUP_SECRET_WRITE
        for status in (201, 204):
            for headers in ((), (("Content-Length", "0"),)):
                accepted, used, source = parse_setup(setup_raw(status, headers), secret_role)
                self.assertEqual(accepted.observation, {"status": status, "body": None, "failure": "none"})
                self.assertEqual(accepted.control["reason"], "none")
                self.assertEqual((used.body_bytes, source.read()), (0, b""))
        for framing_headers, body in (((("Content-Type", "application/json"), ("Content-Length", "2")), b"{}"),
                                      ((("Content-Type", "application/json"),), b"{}"),
                                      ((("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")), b"2\r\n{}\r\n0\r\n\r\n")):
            accepted, used, source = parse_setup(setup_raw(201, framing_headers, body), secret_role)
            self.assertEqual(accepted.observation, {"status": 201, "body": {}, "failure": "none"})
            self.assertEqual(used.body_bytes, 2)
            self.assertEqual(source.read(), b"")
        for headers, body in (((), b"{}"), ((("Content-Type", "text/plain"),), b"{}"),
                              ((("Content-Type", "application/json"),), b"[]"),
                              ((("Content-Type", "application/json"),), b'{"x":1}'),
                              ((("Content-Type", "application/json"), ("Content-Length", "2")), b"{}x"),
                              ((("Content-Type", "application/json"), ("Content-Length", "3")), b"{}"),
                              ((("Content-Type", "application/json"), ("Content-Length", "65")), b" " * 65),
                              ((("Content-Length", "0"),), b"x")):
            failed, _, _ = parse_setup(setup_raw(201, headers, body), secret_role)
            self.assertNotEqual(failed.control["reason"], "none")
        for role in roles + (transport._ResponseRole.STANDARD,):
            ordinary, _, _ = parse_setup(setup_raw(201), role)
            self.assertNotEqual(ordinary.control["reason"], "none")
        after, _, _ = parse_setup(setup_raw(404), transport._ResponseRole.SETUP_SECRET_METADATA_AFTER)
        self.assertNotEqual(after.control["reason"], "none")

        # Variable roles reuse exact actual empty-body readers, not JSON-null
        # approximations; no other role gains POST/PATCH success or absence.
        create = transport._ResponseRole.SETUP_VARIABLE_CREATE
        replace = transport._ResponseRole.SETUP_VARIABLE_REPLACE
        read = transport._ResponseRole.SETUP_VARIABLE_READ
        for role, status in ((create, 201), (replace, 204)):
            for headers in ((), (("Content-Length", "0"),)):
                accepted, used, source = parse_setup(setup_raw(status, headers), role)
                self.assertEqual(accepted.observation, {"status": status, "body": None, "failure": "none"})
                self.assertEqual(accepted.control["reason"], "none")
                self.assertEqual((used.body_bytes, source.read()), (0, b""))
            for payload in (b"null", b"[]", b'{"extra":true}', b" " * 65):
                failed, _, _ = parse_setup(setup_raw(status, (("Content-Type", "application/json"),), payload), role)
                self.assertNotEqual(failed.control["reason"], "none")
        accepted, _, _ = parse_setup(setup_raw(201, (("Content-Type", "application/json"),), b"{}"), create)
        self.assertEqual(accepted.observation, {"status": 201, "body": {}, "failure": "none"})
        for role, status in ((create, 204), (replace, 201), (read, 201), (read, 204)):
            failed, _, _ = parse_setup(setup_raw(status), role)
            self.assertNotEqual(failed.control["reason"], "none")
        absent, _, raw = parse_setup(setup_raw(404, body=_SENTINEL.encode()), read)
        self.assertEqual(absent.observation, {"status": 404, "body": None, "failure": "none"})
        self.assertEqual(absent.control["reason"], "none")
        self.assertEqual(raw.read(), _SENTINEL.encode())
        for role in (create, replace):
            refused, _, _ = parse_setup(setup_raw(404), role)
            self.assertNotEqual(refused.control["reason"], "none")

    def test_initial_metadata_is_bounded_during_reads_and_never_loops_informationals(self):
        for status in (100, 101, 199):
            prefix = f"HTTP/1.1 {status} Inert\r\n".encode()
            source = io.BytesIO(prefix + b"\r\n" + _wire())
            with self.assertRaises(transport.ReadFailure) as caught:
                transport._ResponseBody(source, _budget())
            self.assertEqual(caught.exception.reason, "response-invalid")
            self.assertEqual(source.tell(), len(prefix))
        limit_cases = (b"HTTP/1.1 200 " + b"a" * transport.MAX_HEADER_LINE + b"\r\n\r\n",
                       _wire(headers=(("X-Long", "a" * transport.MAX_HEADER_LINE),)),
                       _wire(headers=tuple((f"X-{index}", "v") for index in range(65))),
                       _wire(headers=tuple((f"X-{index}", "a" * 8100) for index in range(5))))
        for raw in limit_cases:
            self.assertEqual(_parsed(raw).control["reason"], "response-limit")
        invalid_headers = ((("Content-Length", "2"),), (("Transfer-Encoding", "chunked"),),
                           (("Content-Encoding", "gzip"),), (("Content-Type", "text/html"),),
                           (("X-Bad", "a\tvalue"),), (("Upgrade", "websocket"),))
        for fields in invalid_headers:
            self.assertEqual(_parsed(_wire(headers=fields)).control["reason"], "response-invalid")
        for media in (b"application/json", b"application/json;charset=utf-8",
                      b"APPLICATION/VND.GITHUB+JSON ; CHARSET=UTF-8"):
            self.assertEqual(_parsed(_wire().replace(b"application/json; charset=utf-8", media)).control["reason"], "none")
        for media in (b"text/html", b'application/json; charset="utf-8"', b"application/json; charset=latin-1",
                      b"application/json; charset=utf-8; other=1", b"application/json;\tcharset=utf-8",
                      b"application/json\xff"):
            self.assertEqual(_parsed(_wire().replace(b"application/json; charset=utf-8", media)).control["reason"], "response-invalid")
        for raw in (b"HTTP/1.1 200 Inert\n\n{}",
                    b"HTTP/1.1 200 Inert\r\nX-Test: v\r\n folded\r\n\r\n{}",
                    _wire(framing="eof", headers=(("Transfer-Encoding", "gzip, chunked"),))):
            self.assertEqual(_parsed(raw).control["reason"], "response-invalid")
        self.assertEqual(_parsed(_wire(status=302, headers=(("Location", "https://unselected.invalid/"),))).control["reason"], "response-invalid")
        budget = _budget()
        budget.metadata_bytes = transport.MAX_METADATA_TOTAL - 10
        source = io.BytesIO(_wire())
        with self.assertRaises(transport.ReadFailure) as caught:
            transport._ResponseBody(source, budget)
        self.assertEqual(caught.exception.reason, "response-limit")
        self.assertLessEqual(source.tell(), 10)

    def test_chunked_read_accepts_only_complete_supported_framing(self):
        body = b'5;name=value;quoted="a\\\"b"\r\n{"a":\r\n2\r\n1}\r\n0\r\nX-Inert: discarded\r\n\r\n'
        result = _parsed(_wire(body, framing="chunked"))
        self.assertEqual(result.observation["body"], {"a": 1})
        malformed = (b"2\r\n{}XX0\r\n\r\n", b"2\r\n{", b"2\r\n{}\r\n0\r\n",
                     b"2\r\n{}\r\n0\r\nX-Inert: v\r\n", b"+2\r\n{}\r\n0\r\n\r\n",
                     b"-2\r\n{}\r\n0\r\n\r\n", b"0x2\r\n{}\r\n0\r\n\r\n",
                     b"2;=bad\r\n{}\r\n0\r\n\r\n", b'2;x="unclosed\r\n{}\r\n0\r\n\r\n',
                     b"2\n{}\r\n0\r\n\r\n")
        for raw in malformed:
            self.assertEqual(_parsed(_wire(raw, framing="chunked")).control["reason"], "response-invalid")

    def test_chunk_metadata_trailer_and_count_bounds_are_independent(self):
        long_line = b"2;x=" + b"a" * transport.MAX_CHUNK_LINE + b"\r\n{}\r\n0\r\n\r\n"
        self.assertEqual(_parsed(_wire(long_line, framing="chunked")).control["reason"], "response-limit")
        for count, expected in ((transport.MAX_CHUNKS - 1, "none"), (transport.MAX_CHUNKS, "response-limit")):
            decoded = b"{" + b" " * (count - 2) + b"}"
            raw = b"".join(b"1\r\n" + bytes([byte]) + b"\r\n" for byte in decoded) + b"0\r\n\r\n"
            self.assertEqual(_parsed(_wire(raw, framing="chunked")).control["reason"], expected)
        decoded = b"{" + b" " * 298 + b"}"
        framing_pressure = b"".join(b"1;x=" + b"a" * 110 + b"\r\n" + bytes([byte]) + b"\r\n" for byte in decoded) + b"0\r\n\r\n"
        self.assertEqual(_parsed(_wire(framing_pressure, framing="chunked")).control["reason"], "response-limit")
        trailers = (b"X-Long: " + b"a" * transport.MAX_TRAILER_LINE + b"\r\n",
                    b"".join(f"X-{index}: v\r\n".encode() for index in range(17)),
                    b"".join(f"X-{index}: ".encode() + b"a" * 1900 + b"\r\n" for index in range(5)))
        for tail in trailers:
            self.assertEqual(_parsed(_wire(b"2\r\n{}\r\n0\r\n" + tail + b"\r\n", framing="chunked")).control["reason"], "response-limit")
        for name in ("Authorization", "Content-Length", "Transfer-Encoding", "Retry-After",
                     "GitHub-Authentication-Token-Expiration", "X-RateLimit-Reset",
                     "Authentication-Info", "authentication-info", "AuThEnTiCaTiOn-InFo",
                     "Proxy-Authentication-Info", "proxy-authentication-info", "PrOxY-AuThEnTiCaTiOn-InFo"):
            raw = b"2\r\n{}\r\n0\r\n" + name.encode() + b": " + _SENTINEL.encode() + b"\r\n\r\n"
            result = _parsed(_wire(raw, framing="chunked"))
            self.assertEqual(result.control, transport._control("response-invalid"))
            self.assertNotIn(_SENTINEL, _json(result.control).decode())

    def test_tls_eof_policy_uses_explicit_options_and_wrap_arguments(self):
        source, wrapped = object(), object()
        ignore, unrelated = 0x80, 0x2400

        class RecordingContext:
            def __init__(self):
                self.options = ignore | unrelated
                self.calls = []

            def wrap_socket(self, supplied, **arguments):
                self.calls.append((supplied, arguments, self.options))
                return wrapped

        context = RecordingContext()
        result = transport._wrap_fixed_tls(context, source, ignore_eof_option=ignore)
        self.assertIs(result, wrapped)
        self.assertEqual(context.options, unrelated)
        self.assertEqual(context.calls, [(source, {"server_hostname": "api.github.com", "suppress_ragged_eofs": False}, unrelated)])
        for unsupported in (0, -1):
            context = RecordingContext()
            with self.assertRaises(transport.ReadFailure) as caught:
                transport._wrap_fixed_tls(context, source, ignore_eof_option=unsupported)
            self.assertEqual(caught.exception.reason, "tls-failed")
            self.assertEqual(context.calls, [])

        class IgnoringContext(RecordingContext):
            @property
            def options(self):
                return ignore | unrelated

            @options.setter
            def options(self, _value):
                pass

        context = IgnoringContext()
        with self.assertRaises(transport.ReadFailure) as caught:
            transport._wrap_fixed_tls(context, source, ignore_eof_option=ignore)
        self.assertEqual(caught.exception.reason, "tls-failed")
        self.assertEqual(context.calls, [])

        class InertUnexpectedEOF(OSError):
            pass

        class TruncatedBytes(io.BytesIO):
            def read1(self, amount: int = -1) -> bytes:
                block = super().read1(amount)
                if not block:
                    raise InertUnexpectedEOF("Inert unexpected EOF")
                return block

        # A complete JSON prefix does not suppress a supplied terminal failure.
        # This is NOT an SSL exception/backend or native close-notify fixture;
        # the live SSLError catch and exact pinned TLS runtime remain unentered.
        for hints in ((), (("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "9000"))):
            budget = _budget()
            response = transport._ResponseBody(TruncatedBytes(_wire(b'{"ok":true}', headers=hints, framing="eof")), budget)
            with self.assertRaises(InertUnexpectedEOF):
                transport._response_result(response, budget)
            refused = transport._failed("tls-failed", response.control)
            self.assertEqual(refused.observation["failure"], "tls-failed")
            self.assertEqual(refused.control, transport._control("response-invalid", 8001) if hints else transport._control("tls-failed"))

    def test_every_raw_read_obeys_original_deadline_without_renewal(self):
        now = [100.0]
        timeouts = []
        budget = transport._Budget(100.0, monotonic=lambda: now[0], wall=lambda: 1000)
        source = io.BytesIO(_wire(b'{"ok":true}'))
        response = transport._ResponseBody(source, budget, before_read=timeouts.append)
        self.assertTrue(timeouts)
        self.assertTrue(all(value == 10.0 for value in timeouts))
        now[0] = 109.5
        self.assertEqual(response.read(4096), b'{"ok":true}')
        self.assertEqual(timeouts[-1], 0.5)
        self.assertEqual(budget.end, 110.0)
        now[0] = 110.0
        with self.assertRaises(transport.ReadFailure) as caught:
            transport._ResponseBody(io.BytesIO(_wire()), budget)
        self.assertEqual(caught.exception.reason, "network-unavailable")

        class LateBytes(io.BytesIO):
            def read1(self, amount: int = -1) -> bytes:
                block = super().read1(amount)
                if amount > 1:
                    now[0] = 111.0
                return block

        now[0] = 109.0
        response = transport._ResponseBody(LateBytes(_wire()), budget)
        result = transport._response_result(response, budget)
        self.assertEqual(result.control["reason"], "network-unavailable")
        self.assertEqual(budget.end, 110.0)
        now[0] = 109.0
        response = transport._ResponseBody(LateBytes(_wire(headers=(("X-RateLimit-Remaining", "0"),
                                                                  ("X-RateLimit-Reset", "9000")))), budget)
        result = transport._response_result(response, budget)
        self.assertEqual(result.observation["failure"], "network-unavailable")
        self.assertEqual(result.control, transport._control("response-invalid", 8001))
        self.assertEqual(budget.end, 110.0)

        # Even the one-byte empty-response probe uses both original checks.
        role = transport._ResponseRole.SETUP_ACTIONS_WRITE
        wire = b"HTTP/1.1 204 fixed\r\nContent-Length: 0\r\n\r\n"
        for mode in ("late", "unexpected-eof", "nonempty"):
            now = [100.0]
            class Probe(io.BytesIO):
                def read1(self, amount=-1):
                    if self.tell() == len(wire):
                        if mode == "late":
                            now[0] = 110.0
                        elif mode == "unexpected-eof":
                            raise OSError("inert unclean TLS EOF")
                        else:
                            return b"x"
                    return super().read1(amount)
            selected = transport._Budget(100.0, monotonic=lambda: now[0], _profile=transport._ExchangeProfile.SETUP)
            response = transport._ResponseBody(Probe(wire), selected, _role=role)
            if mode == "unexpected-eof":
                with self.assertRaises(OSError):
                    transport._response_result(response, selected)
            else:
                row = transport._response_result(response, selected)
                self.assertEqual(row.control["reason"], "network-unavailable" if mode == "late" else "response-invalid")
            self.assertEqual(selected.end, 110.0)

        # New role clips actual payload and EOF reads to the same old endpoint.
        now = [100.0]
        env_wire = _wire(b'{"id":71}', framing="eof")
        class EnvironmentLate(io.BytesIO):
            def read1(self, amount=-1):
                block = super().read1(amount)
                if self.tell() == len(env_wire):
                    now[0] = 110.0
                return block
        selected = transport._Budget(100.0, monotonic=lambda: now[0], _profile=transport._ExchangeProfile.SETUP)
        response = transport._ResponseBody(EnvironmentLate(env_wire), selected, _role=transport._ResponseRole.SETUP_ENVIRONMENT_WRITE)
        result = transport._response_result(response, selected)
        self.assertEqual(result.control["reason"], "network-unavailable")
        self.assertEqual(selected.end, 110.0)

        for role in (transport._ResponseRole.SETUP_SECRET_METADATA_READ,transport._ResponseRole.SETUP_SECRET_KEY_READ):
            now=[100.0]
            selected=transport._Budget(100.0,monotonic=lambda:now[0],_profile=transport._ExchangeProfile.SETUP)
            response=transport._ResponseBody(EnvironmentLate(env_wire),selected,_role=role)
            self.assertEqual(transport._response_result(response,selected).control["reason"],"network-unavailable")
            self.assertEqual(selected.end,110.0)

        for status in (201, 204):
            now = [100.0]
            raw = f"HTTP/1.1 {status} fixed\r\nContent-Length: 0\r\n\r\n".encode()
            class LateSecretEOF(io.BytesIO):
                def read1(self, size=-1):
                    block = super().read1(size)
                    if not block: now[0] = 110.0
                    return block
            budget = transport._Budget(100.0, monotonic=lambda: now[0], _profile=transport._ExchangeProfile.SETUP)
            response = transport._ResponseBody(LateSecretEOF(raw), budget, _role=transport._ResponseRole.SETUP_SECRET_WRITE)
            self.assertEqual(transport._response_result(response, budget).control["reason"], "network-unavailable")
            self.assertEqual(budget.end, 110.0)

    def test_pure_schedule_does_not_enter_live_factory_or_trust_reader(self):
        original_factory, original_ca = transport._make_live_reader, transport._fixed_ca
        before = {name: sys.modules.get(name) for name in ("http.client", "ssl", "_ssl")}

        def forbidden(*_args, **_kwargs):
            raise AssertionError("Pure observation entered a live constructor")

        try:
            transport._make_live_reader = forbidden
            transport._fixed_ca = forbidden
            outcome, reader = _observe()
            self.assertEqual(len(reader.calls), 4)
            self.assertEqual(outcome["control"]["reason"], "none")
        finally:
            transport._make_live_reader, transport._fixed_ca = original_factory, original_ca
        self.assertEqual({name: sys.modules.get(name) for name in before}, before)

        from unittest.mock import patch
        from mobile_release import github_setup_remote as setup
        P, R = transport._ExchangeProfile, transport._ResponseRole
        target = setup.Target.parse({"projectBinding": "a" * 64, "repository": "owner/app", "accountId": "7",
                                     "repositoryId": "11", "selection": {"kind": "actions_enabled", "enabled": True}})
        before_policy = setup.Policy.parse("actions_enabled", {"enabled": False, "allowed_actions": "selected", "sha_pinning_required": True})
        prepared = setup.Prepared.parse(setup.Prepared(target, before_policy, _TIME).value())
        action = setup.Action.parse({"kind": "apply", "target": target.value(), "prepared": prepared.value()})
        calls, factories = [], []
        def factory(token, **kwargs):
            factories.append((token, kwargs))
            def exchange(method, path, body, *, _role):
                transport._request_limits(P.SETUP, _role, method, path)
                transport._setup_body(P.SETUP, _role, body)
                calls.append((method, path, body, _role))
                return transport.ReadResult({"status": 204, "body": None, "failure": "none"}, transport._control())
            return exchange
        with patch.object(transport, "_make_live_exchange", side_effect=factory):
            reader = setup._make_live_reader(action, _SENTINEL, started=100.0, runtime_dir="/inert/runtime")
            for step in ("account", "repository-before", "resource-before", "write", "resource-after", "repository-after"):
                reader.read(step)
            with self.assertRaises(ValueError):
                reader.read("write")
        self.assertEqual(factories, [(_SENTINEL, {"started": 100.0, "runtime_dir": "/inert/runtime",
                                               "api_version": "2026-03-10", "_profile": P.SETUP})])
        self.assertEqual(len(calls), 6)
        self.assertEqual(calls[3], ("PUT", "/repos/owner/app/actions/permissions", setup._canonical(prepared.after.value()), R.SETUP_ACTIONS_WRITE))
        self.assertEqual([call[3] for call in calls if call[0] == "GET"], [R.STANDARD] * 5)
        for role, path, body in (
            (R.SETUP_ACTIONS_WRITE, "/repos/owner/app/actions/permissions", prepared.after.value()),
            (R.SETUP_WORKFLOW_WRITE, "/repos/owner/app/actions/permissions/workflow",
             {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}),
        ):
            transport._request_limits(P.SETUP, role, "PUT", path)
            transport._setup_body(P.SETUP, role, _json(body))
            for bad in (None, b"", b" " * 8193, _json({**body, "url": "https://untrusted.invalid"}),
                        _json({k: int(v) if type(v) is bool else v for k, v in body.items()})):
                with self.assertRaises(ValueError):
                    transport._setup_body(P.SETUP, role, bad)
            for method, badpath in (("POST", path), ("GET", path), ("DELETE", path), ("PUT", path + "?x=1"),
                                    ("PUT", path + "/selected-actions"), ("PUT", "https://api.github.com" + path)):
                with self.assertRaises(ValueError):
                    transport._request_limits(P.SETUP, role, method, badpath)
            for ordinary in (P.STANDARD, P.RELEASE_PREPARE):
                with self.assertRaises(ValueError):
                    transport._request_limits(ordinary, role, "PUT", path)
        for badpath in ("/repos/owner/app/actions/workflows", "/user?x=1", "/repos/owner/app/contents/file"):
            with self.assertRaises(ValueError):
                transport._request_limits(P.SETUP, R.STANDARD, "GET", badpath)
        with self.assertRaises(ValueError):
            transport._make_live_exchange(_SENTINEL, started=100.0, runtime_dir="/inert/runtime",
                                          api_version="2022-11-28", _profile=P.SETUP)

        env_selection = {"kind": "environment_protection", "mode": "configure", "stage": "production",
                         "waitTimerMinutes": 43200, "preventSelfReview": True, "reviewerLogin": None, "branches": None}
        env_target = setup.EnvironmentTarget.parse({**target.value(), "selection": env_selection})
        policy_value = {"waitTimerMinutes": 0, "protectedBranches": True, "requiredReviewers": {
            "preventSelfReview": False, "reviewers": [{"type": "Team", "id": str(2**63 - 1 - i)} for i in range(6)]}}
        facts = setup.EnvironmentFacts.parse({"name": "mobile-production", "id": "71", "policy": policy_value})
        env_prepared = setup.EnvironmentPrepared.parse(setup.EnvironmentPrepared(env_target, facts, None, _TIME).value())
        env_action = setup.EnvironmentAction("apply", env_target, env_prepared)
        calls.clear(); factories.clear()
        with patch.object(transport, "_make_live_exchange", side_effect=factory):
            reader = setup._make_live_reader(env_action, _SENTINEL, started=100.0, runtime_dir="/inert/runtime")
            for step in ("account", "repository-before", "environment-before", "custom-before", "write",
                         "environment-after", "custom-after", "repository-after"):
                reader.read(step)
        self.assertEqual(len(factories), 1)
        self.assertEqual([row[3] for row in calls], [R.STANDARD, R.STANDARD, R.SETUP_ENVIRONMENT_READ,
            R.SETUP_ENVIRONMENT_CUSTOM_READ, R.SETUP_ENVIRONMENT_WRITE, R.SETUP_ENVIRONMENT_READ,
            R.SETUP_ENVIRONMENT_CUSTOM_READ, R.STANDARD])
        self.assertEqual(json.loads(calls[4][2]), env_prepared.after.put_value())
        self.assertEqual(len(json.loads(calls[4][2])["reviewers"]), 6)
        for role, method, path in (
            (R.SETUP_ENVIRONMENT_READ, "GET", "/repos/owner/app/environments/mobile-production"),
            (R.SETUP_ENVIRONMENT_LIST, "GET", "/repos/owner/app/environments?per_page=100&page=1"),
            (R.SETUP_ENVIRONMENT_CUSTOM_READ, "GET", "/repos/owner/app/environments/mobile-production/deployment_protection_rules"),
            (R.SETUP_ENVIRONMENT_REVIEWER_READ, "GET", "/repos/owner/app/collaborators/Alice/permission"),
            (R.SETUP_ENVIRONMENT_WRITE, "PUT", "/repos/owner/app/environments/mobile-production")):
            transport._request_limits(P.SETUP, role, method, path)
            for wrong in (P.STANDARD, P.RELEASE_PREPARE):
                with self.assertRaises(ValueError):
                    transport._request_limits(wrong, role, method, path)
            for wrong_method, wrong_path in (("DELETE", path), ("POST", path), (method, path + "?arbitrary=1"),
                                            (method, path.replace("mobile-production", "other")),
                                            (method, path.replace("Alice", "../Alice"))):
                if wrong_method == method and wrong_path == path:
                    continue
                with self.assertRaises(ValueError):
                    transport._request_limits(P.SETUP, role, wrong_method, wrong_path)
            with self.assertRaises(ValueError):
                transport._request_limits(P.SETUP, R.STANDARD, method, path)
            if method == "GET":
                transport._setup_body(P.SETUP, role, None)
                with self.assertRaises(ValueError):
                    transport._setup_body(P.SETUP, role, b"{}")
        body = env_prepared.after.put_value()
        transport._setup_body(P.SETUP, R.SETUP_ENVIRONMENT_WRITE, _json(body))
        for changed in ({**body, "can_admins_bypass": False}, {**body, "wait_timer": True},
                        {**body, "prevent_self_review": 1}, {**body, "reviewers": body["reviewers"] * 2},
                        {**body, "reviewers": [{"type": "Team", "id": str(2**63 - 1)}]},
                        {**body, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}):
            with self.assertRaises(ValueError):
                transport._setup_body(P.SETUP, R.SETUP_ENVIRONMENT_WRITE, _json(changed))
        for old_role in (R.SETUP_ACTIONS_WRITE, R.SETUP_WORKFLOW_WRITE):
            with self.assertRaises(ValueError):
                transport._setup_body(P.SETUP, old_role, _json(body))

        selected={"kind":"environment_secret","mode":"create","stage":"candidate",
            "requirement":"MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD","source":{"recordId":"1"*32,"recordRevision":2,"contextRevision":3}}
        source={"root":"/inert/project","rootIdentity":{"device":"1","inode":"2","mode":0o40700,"uid":1,"gid":1},
            "draft":{"bytes":27,"sha256":"b"*64},"platform":"android","purpose":"signing",
            "material":{"encoding":"utf8","plaintextBytes":4}}
        action=setup.SecretAction.parse({"kind":"prepare","target":{**target.value(),"selection":selected},"prepared":None,"source":source})
        budget=transport._Budget(100.0,monotonic=lambda:100.0,_profile=P.SETUP)
        checkpoints=[]
        class Configuration:
            def checkpoint(self):
                checkpoints.append(budget.remaining())
        configuration=Configuration();calls.clear();factories.clear()
        with patch.object(transport,"_make_live_exchange",side_effect=factory):
            reader=setup._make_secret_reader(action,_SENTINEL,started=100.0,runtime_dir="/inert/runtime",budget=budget,configuration=configuration)
            for step in ("account","repository-before","environment-before","secret-before","key-before","repository-after"):
                reader.read(step)
            with self.assertRaises(ValueError):reader.read("account")
        self.assertIs(factories[0][1]["_setup_budget"],budget)
        # Bad/reused typed owners refuse before lazy TLS modules/CA/processes.
        for supplied,start,profile in ((object(),100.0,P.SETUP),(budget,101.0,P.SETUP),(budget,100.0,P.STANDARD)):
            with self.assertRaises(ValueError):
                transport._make_live_exchange(_SENTINEL,started=start,runtime_dir="/inert/runtime",
                    api_version="2026-03-10",_profile=profile,_setup_budget=supplied)
        budget._secret_exchange_claimed=True
        with self.assertRaises(ValueError):
            transport._make_live_exchange(_SENTINEL,started=100.0,runtime_dir="/inert/runtime",
                api_version="2026-03-10",_profile=P.SETUP,_setup_budget=budget)
        self.assertEqual([v[3] for v in calls],[R.STANDARD,R.STANDARD,R.SETUP_ENVIRONMENT_READ,R.SETUP_SECRET_METADATA_READ,R.SETUP_SECRET_KEY_READ,R.STANDARD])
        self.assertEqual(len(calls),6);self.assertEqual(len(checkpoints),13) # failed next claim still checks same source first
        self.assertTrue(all(v[0]=="GET" and v[2] is None for v in calls))
        for role,last in ((R.SETUP_SECRET_METADATA_READ,selected["requirement"]),(R.SETUP_SECRET_KEY_READ,"public-key")):
            path="/repos/owner/app/environments/mobile-candidate/secrets/"+last
            transport._request_limits(P.SETUP,role,"GET",path)
            for method,path2 in (("PUT",path),("GET",path+"?x=1"),("GET",path.replace("mobile-candidate","other")),
                                 ("GET",path.replace(last,"arbitrary"))):
                with self.assertRaises(ValueError):transport._request_limits(P.SETUP,role,method,path2)
            with self.assertRaises(ValueError):transport._setup_body(P.SETUP,role,b"{}")

        from mobile_release.github_setup_secret_inputs import SecretConfigurationError
        for actual_control in (transport._control("unauthorized"), transport._control("rate-limited", 37),
                               transport._control("rate-limited", blocked=True)):
            class ChangedConfiguration:
                def __init__(self): self.count = 0
                def checkpoint(self):
                    self.count += 1
                    if self.count == 2: raise SecretConfigurationError("configuration-changed")
            post_configuration = ChangedConfiguration()
            returned = transport.ReadResult({"status": 401 if actual_control["reason"] == "unauthorized" else 429,
                "body": None, "failure": actual_control["reason"]}, actual_control)
            invoked = []
            def controlled_factory(_token, **kwargs):
                self.assertIs(kwargs["_setup_budget"], budget)
                def exchange(method, path, body, *, _role):
                    invoked.append((method, path, body, _role))
                    return returned
                return exchange
            with patch.object(transport, "_make_live_exchange", side_effect=controlled_factory):
                reader = setup._make_secret_reader(action, _SENTINEL, started=100.0,
                    runtime_dir="/inert/runtime", budget=budget, configuration=post_configuration)
                with self.assertRaises(SecretConfigurationError) as failed_source:
                    setup.execute_secret_read(action, reader,
                        {"savedConfig": source["draft"], "canonicalConfig": source["draft"]}, observed_at=_TIME)
                self.assertEqual(failed_source.exception.reason, "configuration-changed")
                self.assertFalse(failed_source.exception.cleanup_unknown)
            self.assertEqual(len(invoked), 1)
            self.assertEqual(post_configuration.count, 2)
            self.assertEqual(reader.control, actual_control)
            self.assertIsNot(reader.control, actual_control)
            failed = setup.secret_configuration_failure("configuration-changed", reader.control)
            self.assertEqual((failed["reason"], failed["control"]), (actual_control["reason"], actual_control))
            self.assertEqual((failed["writeClaimed"], failed["writeAcknowledged"]), (False, False))

        import base64
        from mobile_release import _desktop_github_setup_engine as setup_engine
        secret_name = selected["requirement"]
        write_role = R.SETUP_SECRET_WRITE
        fixed_path = "/repos/owner/app/environments/mobile-candidate/secrets/" + secret_name
        body = _json({"encrypted_value": base64.b64encode(bytes(52)).decode("ascii"), "key_id": "inert-key"})
        transport._request_limits(P.SETUP, write_role, "PUT", fixed_path)
        transport._setup_body(P.SETUP, write_role, body)
        for wrong in (R.STANDARD, R.SETUP_ACTIONS_WRITE, R.SETUP_SECRET_METADATA_READ, R.SETUP_SECRET_METADATA_AFTER):
            with self.assertRaises(ValueError): transport._request_limits(P.SETUP, wrong, "PUT", fixed_path)
            with self.assertRaises(ValueError): transport._setup_body(P.SETUP, wrong, body)
        for bad in (b"{}", _json({"encrypted_value": "x", "key_id": "inert"}),
                    _json({"encrypted_value": base64.b64encode(bytes(49201)).decode("ascii"), "key_id": "inert"}),
                    _json({"encrypted_value": base64.b64encode(bytes(52)).decode("ascii"), "key_id": "bad key"}),
                    body + b" " * setup.SECRET_WRITE_BYTES):
            with self.assertRaises(ValueError): transport._setup_body(P.SETUP, write_role, bad)
        # Real fixed private cursor; only read/time ports are inert. No child,
        # socket, stdin ownership or alternate generic input reader is entered.
        source_bytes = b"x" * setup.SECRET_APPLY_GO_BYTES
        source_io = io.BytesIO(source_bytes)
        with patch.object(setup_engine.os, "read", side_effect=lambda _fd,n: source_io.read(n)), patch.object(setup_engine.time, "monotonic", return_value=100.0):
            self.assertEqual(setup_engine._read_secret_apply_go(99, 110.0), source_bytes)
        source_io = io.BytesIO(source_bytes + b"x")
        with patch.object(setup_engine.os, "read", side_effect=lambda _fd,n: source_io.read(n)), patch.object(setup_engine.time, "monotonic", return_value=100.0):
            with self.assertRaises(ValueError): setup_engine._read_secret_apply_go(99, 110.0)

        binding = {"savedConfig": source["draft"], "canonicalConfig": source["draft"]}
        prepared = {"target": action.target, "before": {"environmentName": "mobile-candidate", "environmentId": "3",
            "name": secret_name, "metadata": None}, "after": {"name": secret_name, **source["material"]},
            "configuration": binding, "observedAt": _TIME, "confirmation": setup.SECRET_CONFIRMATION}
        applying = setup.SecretAction.parse({**action.value(), "kind": "apply", "prepared": prepared})
        sealed = {"key": {"id": "inert-key", "value": "A" * 43 + "="}, "encryptedValue": base64.b64encode(bytes(52)).decode("ascii")}
        for write_status in (201, 429):
            class WritePostFailure:
                def __init__(self): self.count = 0
                def checkpoint(self):
                    self.count += 1
                    if self.count == 12: raise SecretConfigurationError("configuration-changed")
            config = WritePostFailure(); progress = setup.SecretApplyProgress(); original_calls = []
            def apply_factory(_token, **kwargs):
                def exchange(method, path, body, *, _role):
                    transport._request_limits(P.SETUP, _role, method, path)
                    transport._setup_body(P.SETUP, _role, body)
                    original_calls.append((method, path))
                    if method == "PUT":
                        return transport.ReadResult({"status": write_status, "body": {} if write_status == 201 else None, "failure": "none"},
                            transport._control() if write_status == 201 else transport._control("rate-limited", 29))
                    if path == "/user": value = {"id": 7, "login": "owner"}
                    elif path == "/repos/owner/app": value = _repo()
                    elif path.endswith("public-key"): value = {"key_id": "inert-key", "key": "A" * 43 + "="}
                    elif path.endswith("/secrets/" + secret_name):
                        return transport.ReadResult({"status": 404, "body": None, "failure": "none"}, transport._control())
                    else: value = {"name": "mobile-candidate", "id": 3}
                    return transport.ReadResult({"status": 200, "body": value, "failure": "none"}, transport._control())
                return exchange
            budget = transport._Budget(100.0, monotonic=lambda: 100.0, _profile=P.SETUP)
            with patch.object(transport, "_make_live_exchange", side_effect=apply_factory):
                reader = setup._make_secret_reader(applying, _SENTINEL, started=100.0, runtime_dir="/inert/runtime",
                    budget=budget, configuration=config, sealed=sealed, progress=progress)
                with self.assertRaises(SecretConfigurationError):
                    setup.execute_secret_apply(applying, reader, binding, key=sealed["key"], progress=progress)
            self.assertEqual(len(original_calls), 6)
            self.assertTrue(progress.claimed)
            self.assertEqual(progress.acknowledged, write_status == 201)
            converted = setup.secret_configuration_failure("configuration-changed", reader.control, progress=progress)
            self.assertEqual(converted["effect"], "unknown")
            self.assertEqual(converted["reason"], "configuration-changed" if write_status == 201 else "rate-limited")
            self.assertEqual(converted["control"]["cooldownSeconds"], None if write_status == 201 else 29)

        # Strict shared role/method/path/body dispatch. No live factory runs.
        from mobile_release import github_setup_variables as variables
        names = {row[0] for row in variables.VARIABLE_FIELDS}
        collection = "/repos/owner/app/environments/mobile-candidate/variables"
        name = "MOBILE_RELEASE_ANDROID_KEY_ALIAS"
        for role, method, path, payload in (
            (R.SETUP_VARIABLE_READ, "GET", collection + "/" + name, None),
            (R.SETUP_VARIABLE_CREATE, "POST", collection, {"name": name, "value": "release.alias"}),
            (R.SETUP_VARIABLE_REPLACE, "PATCH", collection + "/" + name, {"value": "release.alias"}),
        ):
            transport._request_limits(P.SETUP, role, method, path)
            encoded = None if payload is None else _json(payload)
            transport._setup_body(P.SETUP, role, encoded, path=path)
            for wrong_profile in (P.STANDARD, P.RELEASE_PREPARE):
                with self.assertRaises(ValueError): transport._request_limits(wrong_profile, role, method, path)
            for wrong_method in {"GET", "PUT", "POST", "PATCH", "DELETE"} - {method}:
                with self.assertRaises(ValueError): transport._request_limits(P.SETUP, role, wrong_method, path)
            for wrong_path in (path + "?page=2", path.replace("mobile-candidate", "other"), path.replace("variables", "secrets")):
                with self.assertRaises(ValueError): transport._request_limits(P.SETUP, role, method, wrong_path)
            for wrong_role in (R.STANDARD, R.SETUP_SECRET_WRITE, R.SETUP_ENVIRONMENT_WRITE):
                with self.assertRaises(ValueError): transport._request_limits(P.SETUP, wrong_role, method, path)
            if payload is not None:
                for wrong in (None, b"null", b"[]", _json({**payload, "arbitrary": "x"}), _json({**payload, "value": 1}),
                              _json({**payload, "value": "x" * 4097}), b" " * 8193):
                    with self.assertRaises(ValueError): transport._setup_body(P.SETUP, role, wrong, path=path)
        for foreign in ("OPERATION_COMMITMENT_KEY_VERSION", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "arbitrary"):
            self.assertNotIn(foreign, names)
            with self.assertRaises(ValueError): transport._request_limits(P.SETUP, R.SETUP_VARIABLE_READ, "GET", collection + "/" + foreign)
            with self.assertRaises(ValueError): transport._setup_body(P.SETUP, R.SETUP_VARIABLE_CREATE,
                _json({"name": foreign, "value": "inert"}), path=collection)
        with self.assertRaises(ValueError): transport._setup_body(P.SETUP, R.SETUP_VARIABLE_REPLACE,
            _json({"value": "not-an-issuer-uuid"}), path=collection + "/MOBILE_RELEASE_ASC_ISSUER_ID")
