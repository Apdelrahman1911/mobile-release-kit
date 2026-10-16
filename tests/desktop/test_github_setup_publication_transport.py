"""Real bounded HTTP framing and fixed request admission with inert streams."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from mobile_release import _github_connection_transport as transport
from mobile_release import _github_setup_publication_transport as publication
from mobile_release.github_preflight import HttpRequest
from mobile_release.github_setup_publication import MAX_REQUESTS, Refused, publish, prepare
from test_github_setup_publication import target, source, Reader, MemoryJournal, COMMIT
from test_github_connection_transport import _wire


class PublicationTransportTests(unittest.TestCase):
    def parsed(self, body, *, role, status=200, headers=()):
        budget = transport._Budget(100, monotonic=lambda: 100, wall=lambda: 1000,
                                   _profile=transport._ExchangeProfile.PUBLICATION)
        response = transport._ResponseBody(io.BytesIO(_wire(body, status=status, headers=headers)), budget, _role=role)
        return transport._response_result(response, budget)

    def test_publication_created_array_and_absence_are_role_scoped(self):
        read, create, listing = publication.ROLES
        result = self.parsed(b'{"sha":"' + COMMIT.encode() + b'"}', role=create, status=201)
        self.assertEqual(result.observation["status"], 201)
        self.assertEqual(result.observation["body"], {"sha": COMMIT})
        self.assertEqual(result.control["reason"], "none")
        self.assertEqual(self.parsed(b'[]', role=listing).observation["body"], [])
        self.assertEqual(self.parsed(b'[{},{},{}]', role=listing).control["reason"], "response-invalid")
        self.assertEqual(self.parsed(b'[]', role=read).control["reason"], "response-invalid")
        self.assertEqual(self.parsed(b'{"private":"never parse errors"}', role=read, status=404).observation,
                         {"status": 404, "body": None, "failure": "none"})
        for role in publication.ROLES:
            with self.assertRaises(ValueError):
                transport._role_limits(transport._ExchangeProfile.SETUP, role)
        # Ordinary profiles do NOT start treating arbitrary 201 bodies as success.
        old = transport._Budget(100, monotonic=lambda: 100)
        response = transport._ResponseBody(io.BytesIO(_wire(b'{"sha":"x"}', status=201)), old)
        self.assertIsNone(transport._response_result(response, old).observation["body"])

    def test_expiry_cooldown_malformed_framing_and_error_body_remain_refusals(self):
        for headers in ((("GitHub-Authentication-Token-Expiration", "future"),),
                        (("Content-Length", "2"),), (("Content-Encoding", "gzip"),)):
            try:
                result = self.parsed(b'{"ok":true}', role=publication.ROLES[1], status=201, headers=headers)
            except transport.ReadFailure:
                continue
            self.assertNotEqual(result.control["reason"], "none")
        result = self.parsed(b'{"raw":"not returned"}', role=publication.ROLES[1], status=403,
                             headers=(("Retry-After", "19"),))
        self.assertIsNone(result.observation["body"])
        self.assertEqual(result.control["cooldownSeconds"], 19)
        duplicate = self.parsed(b'{"sha":1,"sha":2}', role=publication.ROLES[1], status=201)
        self.assertEqual(duplicate.control["reason"], "response-invalid")

    def test_only_publication_gets_sixty_second_original_budget(self):
        now = [100.0]
        old = [transport._Budget(100, monotonic=lambda: now[0], _profile=kind)
               for kind in (transport._ExchangeProfile.STANDARD, transport._ExchangeProfile.SETUP,
                            transport._ExchangeProfile.RELEASE_PREPARE)]
        original = transport._Budget(100, monotonic=lambda: now[0], _profile=transport._ExchangeProfile.PUBLICATION)
        self.assertEqual(original.end, 160)
        self.assertTrue(all(budget.end == 110 for budget in old))
        now[0] = 111
        for budget in old:
            with self.assertRaises(transport.ReadFailure):
                budget.remaining()
        self.assertEqual(original.remaining(), 49)
        now[0] = 160
        with self.assertRaises(transport.ReadFailure):
            original.remaining()
        self.assertEqual(original.end, 160)

    def test_actual_generated_requests_pass_but_extra_paths_or_scope_never_do(self):
        reader = Reader(); prepared = prepare(target(), source(), reader)
        publish(prepared, source(), reader, MemoryJournal())
        for request in reader.calls:
            role = publication.request_role(target(), request)
            transport._request_limits(transport._ExchangeProfile.PUBLICATION, role, request.method, request.path)
        for request in (HttpRequest("PATCH", "/repos/owner/app/git/refs/heads/main", b'{}'),
                        HttpRequest("POST", "/repos/owner/app/actions/workflows/x/dispatches", b'{}'),
                        HttpRequest("GET", "/repos/foreign/app", None),
                        HttpRequest("GET", "/repos/owner/app/git/ref/heads/main", None),
                        HttpRequest("DELETE", "/repos/owner/app/git/refs/heads/mrk/setup-x", None)):
            with self.assertRaises(ValueError):
                publication.request_role(target(), request)
        write = next(row for row in reader.calls if row.method == "POST" and row.path.endswith("/git/trees"))
        body = json.loads(write.body); body["tree"][0]["path"] = "release/version.properties"
        with self.assertRaises(ValueError):
            publication.request_role(target(), HttpRequest(write.method, write.path, json.dumps(body).encode()))
        body = json.loads(write.body); body["tree"][1]["content"] += "\n# unreviewed\n"
        with self.assertRaises((ValueError, Refused)):
            publication.request_role(target(), HttpRequest(write.method, write.path, json.dumps(body).encode()))

    def test_existing_exchange_budget_is_passed_once_no_new_clock_per_request(self):
        original = transport._Budget(100, monotonic=lambda: 100, _profile=transport._ExchangeProfile.PUBLICATION)
        checkpoints = []
        response = transport.ReadResult({"status": 200, "body": {}, "failure": "none"}, transport._control())
        with patch.object(publication, "_make_live_exchange", return_value=lambda *args, **kwargs: response) as factory:
            send = publication.make_exchange(target(), "INERT_NOT_A_TOKEN", started=100, runtime_dir="/inert",
                                              budget=original, checkpoint=lambda: checkpoints.append(True))
            for _ in range(MAX_REQUESTS):
                send(HttpRequest("GET", "/user", None))
            with self.assertRaises(ValueError):
                send(HttpRequest("GET", "/user", None))
            self.assertEqual(factory.call_count, 1)
            self.assertIs(factory.call_args.kwargs["_setup_budget"], original)
            self.assertEqual(original.end, 160)
        self.assertEqual(len(checkpoints), 2 * MAX_REQUESTS + 1)
