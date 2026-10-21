"""Inert same-ledger/tag DATA tests; no Git, Store, network or native receipts."""
from __future__ import annotations

import base64
import copy
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release import version_allocation as a
from mobile_release import version_allocation_transport as transport
from mobile_release import version_future_tag as tag
from mobile_release import version_policy as p
from mobile_release import _github_connection_transport as http
from mobile_release.config import ReleaseVersion
from mobile_release.github_preflight import HttpRequest

from test_version_allocation import (COMMIT, NOW, Journal, Repository, initial, observations,
                                    reply, request, CurrentInventoryLedgerTests)

TAG = "refs/tags/release-1.2"


def selected(candidate="00000000-0000-4000-8000-000000000004", future=TAG):
    ordinary = CurrentInventoryLedgerTests().selected(candidate=candidate)
    return replace(ordinary, version_policy=replace(ordinary.version_policy,
        rules=(p.RefRule("refs/heads/main", "major"), p.RefRule(future, "build"))), future_tag=future)


def inventory():
    return CurrentInventoryLedgerTests().observed()


def binding(row, **changes):
    args = dict(candidate_id=row.request.candidate_id, reservation_sha256=row.sha256,
        final_commit="c" * 40, final_tree="d" * 40,
        attempt_id="00000000-0000-4000-8000-000000000009", run_id="12", run_attempt=1)
    args.update(changes)
    return tag.Binding(**args)


class FutureTagTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.authority = initial()
        self.checkpoint = a.Checkpoint(0, self.ledger.head_sha256, COMMIT)
        self.journal = Journal(self.authority, self.checkpoint)
        self.remote = Repository(self.ledger, self.authority)
        self.remote.overrides["tag-before"] = reply(status=404)

    def run_allocation(self, item=None, *, journal=None, fixed=False):
        item = item or selected()
        adapter = self.remote
        if fixed:
            # The original fixed transport chooses endpoints/steps. This fake
            # receives those requests; it does not replace schedule or parser.
            adapter = transport._FixedAllocationTransport(item, self.authority,
                (journal or self.journal).checkpoint(self.authority),
                lambda role, request: self.remote.exchange(adapter._schedule.steps[-1], request),
                reconcile=item.candidate_id in (journal or self.journal).pending)
        with patch("subprocess.Popen", side_effect=AssertionError("no process")):
            return a.allocate_version(item, self.authority, adapter, journal or self.journal,
                                      observations=inventory(), clock=lambda: NOW)

    def test_future_tag_is_rule_selector_not_numeric_version_or_actual_source(self):
        item = selected()
        self.assertEqual((item.source.ref, item.policy_ref, item.wire_version,
                          item.version_policy.schema_version), ("refs/heads/main", TAG, 5, 2))
        result = self.run_allocation(fixed=True)
        self.assertEqual((result.status, result.reason), ("reserved", "none"))
        self.assertEqual(result.reservation.version, ReleaseVersion("1.4.0", 11))
        self.assertEqual(result.reservation.request.source, item.source)
        self.assertEqual(result.reservation.request.future_tag, TAG)
        self.assertEqual(len(self.remote.requests), 10)
        self.assertEqual([step for step, _ in self.remote.requests][4:6], ["tag-before", "write"])
        self.assertEqual([r.method for _, r in self.remote.requests].count("PUT"), 1)
        self.assertFalse(any(r.method in {"POST", "PATCH", "DELETE"} for _, r in self.remote.requests))

    def test_new_shape_is_required_nonnull_canonical_and_legacy_bytes_unchanged(self):
        old = self.ledger.append(request(), observations(), now=NOW)
        self.assertEqual(request().sha256, "752e9190cc56daf9c89d2ce97d838f98734a5fd3c6b47af0e0643c1a684b5f6d")
        self.assertEqual(old.head_sha256, "81d47254594af98db1cf8b177479a00041c794b222689a20eebbbbfaab8b2795")
        item = selected()
        self.assertEqual(a.AllocationRequest.parse(item.value()), item)
        self.assertNotEqual(item.sha256, replace(item, future_tag=None).sha256)
        for future in (None, "", "refs/heads/main", "refs/tags/a..b", "refs/tags/a?ref=main", "refs/tags/a.lock"):
            with self.subTest(future=future), self.assertRaises(ValueError):
                a.AllocationRequest.parse({**item.value(), "futureTag": future})
        with self.assertRaises(ValueError):
            replace(item, source=replace(item.source, ref=TAG))
        with self.assertRaises(ValueError):
            replace(request(), future_tag=TAG)
        mixed = old.append(item, inventory(), now=NOW)
        self.assertEqual(mixed.value()["schemaVersion"], 5)
        self.assertEqual(mixed.value()["tagBindings"], [])
        self.assertEqual(mixed.reservations[0].value(), old.reservations[0].value())
        self.assertEqual(a.Ledger(mixed.genesis, mixed.reservations[:-1]).to_bytes(), old.to_bytes())
        self.assertEqual(a.Ledger.parse(mixed.to_bytes(), self.authority), mixed)

    def test_same_candidate_tag_drift_and_cross_candidate_tag_collision_refuse(self):
        result = self.run_allocation()
        self.assertEqual(result.status, "reserved")
        before = self.remote.ledger.to_bytes()
        for item in (selected(future="refs/tags/other"), selected(candidate="00000000-0000-4000-8000-000000000005")):
            with self.subTest(candidate=item.candidate_id):
                refused = self.run_allocation(item)
                self.assertEqual(refused.reason, "candidate-binding-conflict")
        self.assertEqual(self.remote.ledger.to_bytes(), before)
        self.assertEqual(len(self.remote.writes), 1)

    def test_preexisting_any_tag_including_exact_final_is_collision_before_pending(self):
        for kind in ("commit", "tag"):
            for oid in (selected().source.commit, "c" * 40):
                with self.subTest(kind=kind, oid=oid):
                    self.remote.overrides["tag-before"] = reply({"ref": TAG, "object": {"type": kind, "sha": oid}})
                    result = self.run_allocation(fixed=True)
                    self.assertEqual((result.status, result.reason), ("rejected", "tag-exists"))
                    self.assertFalse(result.write_claimed)
                    self.assertFalse(self.journal.pending)
                    self.assertFalse(self.remote.writes)

    def test_ambiguous_absence_or_http_control_never_arms_write(self):
        variants = [reply(status=404, control=http._control("unauthorized")), reply(status=403),
            reply([], status=200), reply({"ref": TAG + "-other", "object": {"type": "commit", "sha": "c" * 40}}),
            reply({"message": "untrusted error"}, status=404), reply(status=204)]
        for response in variants:
            with self.subTest(response=response.observation):
                self.remote.overrides["tag-before"] = response
                result = self.run_allocation(fixed=True)
                self.assertNotEqual(result.status, "reserved")
                self.assertFalse(result.write_claimed)
                self.assertFalse(self.journal.pending)
                self.assertFalse(self.remote.writes)

    def test_pending_reconciliation_and_reuse_never_recheck_tag_or_retry_write(self):
        self.remote.write_mode = "timeout-after"
        first = self.run_allocation(fixed=True)
        self.assertEqual(first.status, "recovery-required")
        old_pending = next(iter(self.journal.pending.values()))
        self.assertEqual(json.loads(old_pending)["schemaVersion"], 5)
        self.assertEqual(a.PendingAllocation.parse(old_pending).reservation.request, selected())
        self.remote.write_mode = "normal"
        self.remote.overrides["tag-before"] = lambda _: self.fail("no tag recheck during reconciliation")
        count = len(self.remote.requests)
        retry = self.run_allocation(journal=self.journal.restarted(), fixed=True)
        self.assertEqual(retry.status, "reserved")
        self.assertEqual(len(self.remote.requests) - count, 5)
        self.assertEqual(len(self.remote.writes), 1)
        count = len(self.remote.requests)
        reused = self.run_allocation(fixed=True)
        self.assertEqual(reused.reservation, retry.reservation)
        self.assertEqual(len(self.remote.requests) - count, 5)

    def test_binding_cas_data_preserves_every_old_row_and_following_appends_preserve_binding(self):
        ledger = self.ledger.append(selected(), inventory(), now=NOW)
        claim = binding(ledger.reservations[0])
        bound = tag.append_binding(ledger, claim)
        self.assertEqual(bound.reservations, ledger.reservations)
        self.assertEqual(bound.head_sha256, ledger.head_sha256)
        self.assertEqual(a.Ledger.parse(bound.to_bytes(), self.authority), bound)
        next_request = CurrentInventoryLedgerTests().selected(candidate="00000000-0000-4000-8000-000000000005")
        after = bound.append(next_request, inventory(), now=NOW)
        self.assertEqual(after.tag_bindings, (claim,))
        self.assertEqual(after.value()["schemaVersion"], 5)
        checkpoint = a.Checkpoint(1, bound.head_sha256, COMMIT)
        pending = a.PendingAllocation(self.authority, checkpoint, a.blob_sha(bound.to_bytes()), after.reservations[-1])
        body = a.conditional_write_body(pending, after)
        transport.validate_body(transport.ROLE_LEDGER_WRITE, body,
            path="/repos/" + self.authority.repository + "/contents/" + a.LEDGER_PATH)
        self.assertTrue(tag.preserves(bound, after))
        self.assertFalse(tag.preserves(bound, replace(after, tag_bindings=())))
        with self.assertRaises(ValueError):
            a.conditional_write_body(pending, replace(after, tag_bindings=()))
        self.assertEqual(ledger.tag_bindings, ())  # No mutation of the original DATA.

    def test_binding_identity_is_per_candidate_not_final_commit_or_attempt_key(self):
        ledger = self.ledger.append(selected(), inventory(), now=NOW)
        claim = binding(ledger.reservations[0])
        bound = tag.append_binding(ledger, claim)
        for other in (claim, replace(claim, final_commit="e" * 40), replace(claim, attempt_id="00000000-0000-4000-8000-000000000008")):
            with self.subTest(other=other), self.assertRaises(ValueError):
                tag.append_binding(bound, other)
        for changes in ({"reservation_sha256": "0" * 64}, {"candidate_id": "00000000-0000-4000-8000-000000000008"},
                        {"final_commit": selected().source.commit}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                tag.append_binding(ledger, replace(claim, **changes))
        ordinary = self.ledger.append(request(), observations(), now=NOW)
        with self.assertRaises(ValueError):
            tag.append_binding(ordinary, binding(ordinary.reservations[0]))

    def test_closed_v5_bindings_no_null_or_new_fields_in_old_envelopes(self):
        ledger = self.ledger.append(selected(), inventory(), now=NOW)
        value = tag.append_binding(ledger, binding(ledger.reservations[0])).value()
        variants = []
        for changed in (None, {}, [None], [value["tagBindings"][0]] * 2):
            variants.append({**value, "tagBindings": changed})
        missing = copy.deepcopy(value); del missing["tagBindings"]; variants.append(missing)
        wrong = copy.deepcopy(value); wrong["tagBindings"][0]["rawToken"] = "not accepted"; variants.append(wrong)
        variants += [{**value, "schemaVersion": n, "protocol": a._PROTOCOLS[n]} for n in (1, 2, 3, 4)]
        variants.append({**self.ledger.value(), "tagBindings": []})
        for body in variants:
            with self.subTest(body=body), self.assertRaises(ValueError):
                a.Ledger.parse(p.canonical(body) + b"\n", self.authority)

    def test_schedule_cannot_skip_absence_or_use_tag_read_in_old_mode(self):
        for future in (None, TAG):
            schedule = a.Schedule(self.authority, self.checkpoint, future_tag=future)
            for step in ("repository-before", "ref-before", "compare-before", "ledger-before"):
                schedule.claim(step, COMMIT if step in {"compare-before", "ledger-before"} else None)
            with self.assertRaises(ValueError):
                schedule.claim("tag-before" if future is None else "write", body=None if future is None else b"{}")
        schedule = a.Schedule(self.authority, self.checkpoint, future_tag=TAG, reconcile=True)
        for step in ("repository-before", "ref-before", "compare-before", "ledger-before"):
            schedule.claim(step, COMMIT if step in {"compare-before", "ledger-before"} else None)
        with self.assertRaises(ValueError): schedule.claim("tag-before")
        self.assertEqual(schedule.claim("repository-after").method, "GET")

    def test_tag_read_role_is_exact_and_not_a_write_or_generic_profile(self):
        path = "/repos/" + self.authority.repository + "/git/ref/tags/release-1.2"
        transport.validate_endpoint(transport.ROLE_TAG, "GET", path)
        for method, wrong in (("POST", path), ("PATCH", path), ("GET", path + "?x=1"),
                              ("GET", path.replace("tags/", "heads/"))):
            with self.subTest(method=method, path=wrong), self.assertRaises(ValueError):
                transport.validate_endpoint(transport.ROLE_TAG, method, wrong)
        role = http._ResponseRole.VERSION_ALLOCATION_TAG
        self.assertEqual(http._role_limits(http._ExchangeProfile.VERSION_ALLOCATION, role)[0], a.MAX_HTTP_BYTES)
        for profile in (http._ExchangeProfile.STANDARD, http._ExchangeProfile.PUBLICATION):
            with self.assertRaises(ValueError): http._role_limits(profile, role)

    def test_historical_tag_source_rows_are_not_reinterpreted_as_new_intent(self):
        old = request(source=replace(request().source, ref=TAG),
                      version_policy=p.VersionPolicy("automatic", (p.RefRule(TAG, "build"),)))
        ledger = self.ledger.append(old, observations(), now=NOW)
        self.assertIsNone(ledger.reservations[0].request.future_tag)
        self.assertEqual(a.Ledger.parse(ledger.to_bytes(), self.authority), ledger)
        with self.assertRaises(ValueError): ledger.append(selected(), inventory(), now=NOW)
        fresh = self.ledger.append(selected(), inventory(), now=NOW)
        with self.assertRaises(ValueError): fresh.append(old, observations(), now=NOW)


if __name__ == "__main__":
    unittest.main()
