"""Synthetic fixed HTTP adapter tests; never a live GitHub/native job claim."""
from __future__ import annotations

import base64
import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release import _github_connection_transport as native
from mobile_release import version_allocation as a
from mobile_release import version_allocation_transport as t
from mobile_release import version_policy as p
from mobile_release.github_preflight import HttpRequest

from test_version_allocation import COMMIT, NOW, Journal, Repository, initial, observations, reply, request


class VersionAllocationTransportTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.authority = initial()
        self.checkpoint = a.Checkpoint(0, self.ledger.head_sha256, COMMIT)
        self.remote = Repository(self.ledger, self.authority)
        self.root = "/repos/" + self.authority.repository
        self.write_path = self.root + "/contents/" + a.LEDGER_PATH
        self.after = self.ledger.append(request(), observations(), now=NOW)
        self.pending = a.PendingAllocation(self.authority, self.checkpoint, a.blob_sha(self.ledger.to_bytes()),
                                            self.after.reservations[-1])
        self.body = a.conditional_write_body(self.pending, self.after)
        self.journal = Journal(self.authority, self.checkpoint)

    def adapter(self, *, reconcile=False, selected=None):
        steps = iter(("repository-before", "ref-before", "compare-before", "ledger-before", "repository-after")
                     if reconcile else ("repository-before", "ref-before", "compare-before", "ledger-before",
                                        "write", "ref-after", "compare-after", "ledger-after", "repository-after"))

        def send(role, http):
            step = next(steps)
            self.assertEqual(role, t._STEP_ROLES[step])
            return self.remote.exchange(step, http)
        return t._FixedAllocationTransport(selected or request(), self.authority, self.checkpoint,
                                           send, reconcile=reconcile)

    def before(self, adapter):
        schedule = a.Schedule(self.authority, self.checkpoint)
        for step in ("repository-before", "ref-before", "compare-before", "ledger-before"):
            adapter.exchange(step, schedule.claim(step, COMMIT if step in {"compare-before", "ledger-before"} else None))
        return schedule

    def test_only_exact_fixed_role_method_and_pinned_paths_are_valid(self):
        paths = [(t.ROLE_REPOSITORY, "GET", self.root),
                 (t.ROLE_REF, "GET", self.root + "/git/ref/heads/" + a.LEDGER_BRANCH),
                 (t.ROLE_COMPARE, "GET", self.root + "/compare/" + COMMIT + "..." + "2" * 40 + "?per_page=1&page=1"),
                 (t.ROLE_LEDGER_READ, "GET", self.write_path + "?ref=" + COMMIT),
                 (t.ROLE_LEDGER_WRITE, "PUT", self.write_path)]
        for role, method, path in paths:
            t.validate_endpoint(role, method, path)
            for wrong in (path + "/", path + "&page=2", "https://api.github.com" + path,
                          path.replace("/repos/", "/repositories/"), path.replace("fixture", "fi%78ture")):
                with self.subTest(role=role, path=wrong), self.assertRaises(ValueError):
                    t.validate_endpoint(role, method, wrong)
            with self.assertRaises(ValueError):
                t.validate_endpoint(role, "DELETE", path)
            for foreign_role in t._ROLE_NAMES:
                if foreign_role != role:
                    with self.subTest(role=role, foreign=foreign_role), self.assertRaises(ValueError):
                        t.validate_endpoint(foreign_role, method, path)
        for mutable in ("main", "refs/heads/main", "A" * 40, "1" * 39, COMMIT + "#fragment"):
            with self.subTest(mutable=mutable), self.assertRaises(ValueError):
                t.validate_endpoint(t.ROLE_LEDGER_READ, "GET", self.write_path + "?ref=" + mutable)
        with self.assertRaises(ValueError):
            t.validate_endpoint("standard", "GET", self.root)

    def test_closed_write_body_is_one_append_not_genesis_reset_or_other_content(self):
        t.validate_body(t.ROLE_LEDGER_WRITE, self.body, path=self.write_path)
        row = p._object(native._decode_json(self.body, limit=a.MAX_HTTP_BYTES, nodes=16, depth=2, exact=True),
                        {"message", "branch", "sha", "content"})
        variants = [self.body + b"\n", b" " + self.body,
                    self.body.replace(b'"sha":', b'"sha":"' + b"0" * 40 + b'","sha":')]
        for changes in ({"branch": "main"}, {"sha": "0" * 40}, {"message": "arbitrary message"},
                        {"extra": 1}, {"content": row["content"] + "\n"},
                        {"content": base64.b64encode(self.ledger.to_bytes()).decode()},
                        {"content": base64.b64encode(b"arbitrary source file").decode()}):
            variants.append(p.canonical({**row, **changes}))
        for body in variants:
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                t.validate_body(t.ROLE_LEDGER_WRITE, body, path=self.write_path)
        with self.assertRaises(ValueError):
            t.validate_body(t.ROLE_REPOSITORY, b"{}", path=self.root)

    def test_controller_delegates_only_finite_bound_requests_then_wrapper_is_consumed(self):
        adapter = self.adapter()
        result = a.allocate_version(request(), self.authority, adapter, self.journal,
                                    observations=observations(), clock=lambda: NOW)
        self.assertEqual((result.status, result.reason), ("reserved", "none"))
        self.assertEqual(len(self.remote.requests), 9)
        self.assertEqual(len(self.remote.writes), 1)
        with self.assertRaises(ValueError):
            adapter.exchange("repository-before", HttpRequest("GET", self.root, None))
        self.assertEqual(len(self.remote.requests), 9)

    def test_wrong_repository_or_commit_pin_stops_before_exchange_and_cannot_retry(self):
        adapter = self.adapter()
        with self.assertRaises(ValueError):
            adapter.exchange("repository-before", HttpRequest("GET", "/repos/other/project", None))
        self.assertEqual(self.remote.requests, [])
        with self.assertRaises(ValueError):
            adapter.exchange("repository-before", HttpRequest("GET", self.root, None))
        adapter = self.adapter()
        schedule = a.Schedule(self.authority, self.checkpoint)
        for step in ("repository-before", "ref-before"):
            adapter.exchange(step, schedule.claim(step))
        with self.assertRaises(ValueError):
            adapter.exchange("compare-before", schedule.claim("compare-before", "9" * 40))
        self.assertEqual(len(self.remote.requests), 2)

    def test_valid_structural_append_for_different_candidate_or_authority_is_not_allowed(self):
        other_request = request(candidate="00000000-0000-4000-8000-000000000009")
        other_ledger = a.Ledger(replace(self.ledger.genesis, ledger_id="00000000-0000-4000-8000-000000000008"))
        other_authority = replace(self.authority, ledger_id=other_ledger.genesis.ledger_id,
                                  genesis_sha256=other_ledger.genesis.sha256)
        for ledger, authority, selected in ((self.ledger, self.authority, other_request),
                                            (other_ledger, other_authority, request()),
                                            (self.after, self.authority, other_request)):
            with self.subTest(authority=authority):
                adapter = self.adapter()
                schedule = self.before(adapter)
                after = ledger.append(selected, observations(), now=NOW)
                pending = a.PendingAllocation(authority, a.Checkpoint(len(ledger.reservations), ledger.head_sha256, COMMIT),
                                               a.blob_sha(ledger.to_bytes()), after.reservations[-1])
                body = a.conditional_write_body(pending, after)
                t.validate_body(t.ROLE_LEDGER_WRITE, body, path=self.write_path)  # Structural only.
                before = len(self.remote.requests)
                with self.assertRaises(ValueError):
                    adapter.exchange("write", schedule.claim("write", body=body))
                self.assertEqual(len(self.remote.requests), before)
        self.assertEqual(self.remote.writes, [])

    def test_read_only_reconciliation_refuses_even_valid_write_body(self):
        adapter = self.adapter(reconcile=True)
        schedule = self.before(adapter)
        with self.assertRaises(ValueError):
            adapter.exchange("write", schedule.claim("write", body=self.body))
        self.assertEqual(len(self.remote.requests), 4)
        self.assertEqual(self.remote.writes, [])

    def test_native_control_reasons_and_cooldown_are_preserved_without_followup(self):
        for reason, expected in (("target-changed", "rejected"), ("not-found-or-inaccessible", "unavailable"),
                                 ("rate-limited", "unavailable")):
            with self.subTest(reason=reason):
                self.remote.requests.clear()
                control = native._control(reason, 60 if reason == "rate-limited" else None)
                self.remote.overrides["repository-before"] = reply(status=404, control=control)
                result = a.allocate_version(request(), self.authority, self.adapter(), self.journal,
                                            observations=observations(), clock=lambda: NOW)
                self.assertEqual((result.status, result.reason), (expected, reason))
                self.assertEqual(result.control, control)
                self.assertEqual(len(self.remote.requests), 1)

    def test_positive_conflict_stays_status_only_and_unknown_send_is_never_retried(self):
        for status in (409, 422):
            with self.subTest(status=status):
                self.remote.requests.clear()
                self.remote.overrides["write"] = reply(status=status)
                result = a.allocate_version(request(), self.authority, self.adapter(), self.journal,
                                            observations=observations(), clock=lambda: NOW)
                self.assertEqual((result.status, result.reason), ("conflict", "conditional-conflict"))
                self.assertIsNone(self.journal.pending_for(self.authority, request().candidate_id))
                self.assertEqual(len(self.remote.writes), 1)
        self.remote.overrides.clear()
        self.remote.requests.clear()
        self.remote.write_mode = "timeout-after"
        adapter = self.adapter()
        result = a.allocate_version(request(), self.authority, adapter, self.journal,
                                    observations=observations(), clock=lambda: NOW)
        self.assertEqual(result.status, "recovery-required")
        with self.assertRaises(ValueError):
            adapter.exchange("write", HttpRequest("PUT", self.write_path, self.body))
        self.assertEqual(len(self.remote.writes), 1)
        self.remote.write_mode = "normal"
        result = a.allocate_version(request(), self.authority, self.adapter(reconcile=True), self.journal,
                                    observations=observations(), clock=lambda: NOW)
        self.assertEqual(result.status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)

    def test_private_factory_requires_shared_profile_and_delegates_to_existing_owner(self):
        sent = []

        def exchange(method, path, body, *, _role):
            sent.append((method, path, body, _role))
            return self.remote.exchange("repository-before", HttpRequest(method, path, body))

        # Stub the ORIGINAL factory, never TLS/socket/files. Before integration,
        # a missing closed role must fail rather than choose STANDARD.
        with patch.object(native, "_make_live_exchange", return_value=exchange) as factory:
            args = dict(started=0.0, runtime_dir="/synthetic-native-custody", selected=request(),
                        authority=self.authority, checkpoint=self.checkpoint)
            if "VERSION_ALLOCATION" not in native._ExchangeProfile.__members__:
                with self.assertRaises(a.VersionAllocationError) as caught:
                    t._make_allocation_transport("synthetic-placeholder", **args)
                self.assertEqual(caught.exception.reason, "authority-unavailable")
                factory.assert_not_called()
            else:
                adapter = t._make_allocation_transport("synthetic-placeholder", **args)
                factory.assert_called_once_with("synthetic-placeholder", started=0.0,
                    runtime_dir="/synthetic-native-custody", api_version="2026-03-10",
                    _profile=native._ExchangeProfile.VERSION_ALLOCATION)
                adapter.exchange("repository-before", HttpRequest("GET", self.root, None))
                self.assertEqual(sent[0][3], native._ResponseRole.VERSION_ALLOCATION_REPOSITORY)


if __name__ == "__main__":
    unittest.main()
