"""Synthetic ledger/HTTP/journal interleavings, NOT remote or disk qualification.

No network, files, tools, native jobs or project changes occur. Restart tests
round-trip retained bytes in memory; a real durable/native adapter is separate.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace

from mobile_release import version_allocation as a
from mobile_release import version_policy as p
from mobile_release import ios_store_versions as current_ios
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
from mobile_release.config import ReleaseVersion

PROJECT = "00000000-0000-4000-8000-000000000001"
CANDIDATE = "00000000-0000-4000-8000-000000000002"
LEDGER_ID = "00000000-0000-4000-8000-000000000003"
IDENTITY = "a" * 64
COMMIT = "1" * 40
NOW = 10_000
BASE = ReleaseVersion("1.2.3", 7)


def request(candidate=CANDIDATE, increment="patch", **kwargs):
    args = dict(project_id=PROJECT, candidate_id=candidate, identity_revision=IDENTITY,
                source=p.SourceBinding("2" * 40, "3" * 40, "refs/heads/main", "4" * 64, "5" * 64),
                base_version=BASE, enabled_platforms=("android",),
                version_policy=p.VersionPolicy("automatic", (p.RefRule("refs/heads/main", increment),)))
    args.update(kwargs)
    return a.AllocationRequest(**args)


def observations():
    return (p.StoreObservation("android", IDENTITY, "6" * 64, NOW, 7, "1.2.3"),)


def initial():
    genesis = a.Genesis(PROJECT, "123", LEDGER_ID, BASE)
    authority = a.AuthorityRegistration(PROJECT, "fixture/version-test", "123", LEDGER_ID, genesis.sha256, True)
    return a.Ledger(genesis), authority


def reply(body=None, status=200, control=None):
    return ReadResult({"status": status, "body": body, "failure": "none"}, control or _control())


class Journal:
    """Byte-persisting in-memory fixture, never a production durability claim."""
    def __init__(self, authority, checkpoint, events=None):
        self.authority = authority
        self.saved_checkpoint = p.canonical(checkpoint.value())
        self.pending = {}
        self.reservations = {}
        self.events = [] if events is None else events
        self.fail = set()

    def admit_request(self, authority, selected):
        self.events.append("admit_request")
        assert authority == self.authority and type(selected) is a.AllocationRequest
        if "admit_request" in self.fail:
            raise OSError("synthetic selected request refusal")
        # This generic controller fixture is not the native candidate selector.
        # Full durable selected-request matching is exercised by its own tests.

    def checkpoint(self, authority):
        self.events.append("checkpoint")
        assert authority == self.authority
        if "checkpoint" in self.fail:
            raise OSError("synthetic journal error")
        return a.Checkpoint.parse(json.loads(self.saved_checkpoint))

    def pending_for(self, authority, candidate):
        self.events.append("pending_for")
        assert authority == self.authority
        raw = self.pending.get(candidate)
        return None if raw is None else a.PendingAllocation.parse(raw)

    def record_checkpoint(self, authority, checkpoint):
        self.events.append("record_checkpoint")
        assert authority == self.authority
        if "record_checkpoint" in self.fail:
            raise OSError("synthetic checkpoint error")
        before = a.Checkpoint.parse(json.loads(self.saved_checkpoint))
        assert checkpoint.sequence >= before.sequence
        if checkpoint.sequence == before.sequence:
            assert checkpoint.head_sha256 == before.head_sha256
        self.saved_checkpoint = p.canonical(checkpoint.value())

    def record_pending(self, pending):
        self.events.append("record_pending")
        if "record_pending" in self.fail:
            raise OSError("synthetic pending error")
        candidate = pending.reservation.request.candidate_id
        assert candidate not in self.pending
        self.pending[candidate] = pending.to_bytes()
        if "record_pending_after" in self.fail:
            raise OSError("synthetic post-persist error")

    def mark_resolved(self, pending, checkpoint):
        self.events.append("mark_resolved")
        if "mark_resolved" in self.fail:
            raise OSError("synthetic resolved error")
        assert a.Checkpoint.parse(json.loads(self.saved_checkpoint)) == checkpoint
        candidate = pending.reservation.request.candidate_id
        assert a.PendingAllocation.parse(self.pending[candidate]) == pending
        self.reservations[candidate] = p.canonical(pending.reservation.value())
        del self.pending[candidate]

    def record_reused(self, authority, reservation, checkpoint):
        self.events.append("record_reused")
        assert authority == self.authority and not self.pending
        assert a.Checkpoint.parse(json.loads(self.saved_checkpoint)) == checkpoint
        if "record_reused" in self.fail:
            raise OSError("synthetic reused reservation acknowledgement failure")
        candidate = reservation.request.candidate_id
        raw = p.canonical(reservation.value())
        assert candidate not in self.reservations or self.reservations[candidate] == raw
        self.reservations[candidate] = raw
        if "record_reused_after" in self.fail:
            raise OSError("synthetic acknowledgement lost after reservation was retained")

    def mark_rejected(self, pending):
        self.events.append("mark_rejected")
        if "mark_rejected" in self.fail:
            raise OSError("synthetic rejection error")
        candidate = pending.reservation.request.candidate_id
        assert a.PendingAllocation.parse(self.pending[candidate]) == pending
        del self.pending[candidate]

    def restarted(self, events=None):
        result = Journal(self.authority, a.Checkpoint.parse(json.loads(self.saved_checkpoint)), events)
        result.pending = copy.deepcopy(self.pending)
        result.reservations = copy.deepcopy(self.reservations)
        return result


class Repository:
    """Serial conditional-blob model with explicit interleaving hooks."""
    def __init__(self, ledger, authority, events=None):
        self.authority = authority
        self.head = COMMIT
        self.commits = {COMMIT: ledger.to_bytes()}
        self.parents = {COMMIT: None}
        self.events = [] if events is None else events
        self.requests = []
        self.hooks = {}
        self.overrides = {}
        self.write_mode = "normal"

    @property
    def writes(self):
        return [http for step, http in self.requests if step == "write"]

    @property
    def ledger(self):
        return a.Ledger.parse(self.commits[self.head], self.authority)

    def commit(self, raw):
        name = hashlib.sha1(self.head.encode() + raw + str(len(self.commits)).encode()).hexdigest()
        self.parents[name] = self.head
        self.commits[name] = raw
        self.head = name
        return name

    def ancestor(self, old, new):
        while new is not None:
            if old == new:
                return True
            new = self.parents.get(new)
        return False

    def exchange(self, step, http):
        self.events.append("http:" + step)
        self.requests.append((step, http))
        hook = self.hooks.pop(step, None)
        if hook is not None:
            hook()
        if step in self.overrides:
            value = self.overrides[step]
            return value(http) if callable(value) else value
        if step in {"repository-before", "repository-after"}:
            return reply({"id": 123, "full_name": self.authority.repository, "archived": False,
                          "visibility": "private", "default_branch": "main", "permissions": {"push": True}})
        if step in {"ref-before", "ref-after"}:
            return reply({"ref": "refs/heads/" + a.LEDGER_BRANCH, "object": {"type": "commit", "sha": self.head}})
        if step in {"compare-before", "compare-after"}:
            old, new = http.path.split("/compare/")[1].split("?")[0].split("...")
            valid = self.ancestor(old, new)
            return reply({"status": "identical" if old == new else "ahead" if valid else "behind",
                          "base_commit": {"sha": old}, "merge_base_commit": {"sha": old if valid else new}})
        if step in {"ledger-before", "ledger-after"}:
            commit = http.path.split("?ref=")[1]
            raw = self.commits[commit]
            return reply({"type": "file", "path": a.LEDGER_PATH, "encoding": "base64", "size": len(raw),
                          "sha": a.blob_sha(raw), "content": base64.b64encode(raw).decode() + "\n"})
        assert step == "write" and http.method == "PUT"
        value = json.loads(http.body)
        assert value["branch"] == a.LEDGER_BRANCH
        assert http.path == "/repos/" + self.authority.repository + "/contents/" + a.LEDGER_PATH
        if self.write_mode == "timeout-before":
            raise ReadFailure("network-unavailable")
        if value["sha"] != a.blob_sha(self.commits[self.head]):
            return reply(status=409)
        raw = base64.b64decode(value["content"], validate=True)
        a.Ledger.parse(raw, self.authority)
        commit = self.commit(raw)
        if self.write_mode == "timeout-after":
            raise ReadFailure("network-unavailable")
        return reply({"content": {"path": a.LEDGER_PATH, "sha": a.blob_sha(raw)}, "commit": {"sha": commit}})


class VersionAllocationTests(unittest.TestCase):
    def setUp(self):
        self.genesis, self.authority = initial()
        self.events = []
        self.journal = Journal(self.authority, a.Checkpoint(0, self.genesis.head_sha256, COMMIT), self.events)
        self.remote = Repository(self.genesis, self.authority, self.events)

    def allocate(self, selected=None, journal=None, **kwargs):
        args = dict(observations=observations(), clock=lambda: NOW)
        args.update(kwargs)
        return a.allocate_version(selected or request(), self.authority, self.remote, journal or self.journal, **args)

    def test_manual_default_has_no_transport_journal_or_clock_effect(self):
        class Bomb:
            def __getattribute__(self, name):
                raise AssertionError("manual touched an allocation dependency")
        selected = request(version_policy=p.VersionPolicy())
        result = a.allocate_version(selected, None, Bomb(), Bomb(), observations=(), clock=Bomb())
        self.assertEqual((result.status, result.reason), ("manual", "manual-policy"))
        self.assertFalse(result.write_claimed)

    def test_disconnected_and_untrusted_authority_never_fall_back_locally(self):
        result = a.allocate_version(request(), self.authority, None, self.journal, observations=observations(), clock=lambda: NOW)
        self.assertEqual((result.status, result.reason), ("unavailable", "authority-unavailable"))
        self.assertEqual(self.remote.requests, [])
        result = a.allocate_version(request(), replace(self.authority, protected_branch=False), self.remote,
                                    self.journal, observations=observations(), clock=lambda: NOW)
        self.assertEqual(result.reason, "authority-untrusted")
        self.assertEqual(self.remote.requests, [])

    def test_native_project_id_shape_is_exact_and_does_not_broaden_candidate_or_ledger_ids(self):
        compact = PROJECT.replace("-", "")
        self.assertEqual(request(project_id=compact).project_id, compact)
        self.assertEqual(a.Genesis(compact, "123", LEDGER_ID, BASE).project_id, compact)
        self.assertEqual(replace(self.authority, project_id=compact).project_id, compact)
        for invalid in ("0" * 32, "A" * 32, "1" * 31, "1" * 33, "g" * 32, " " + compact,
                        "00000000-0000-1000-8000-000000000001", True, None):
            with self.subTest(value=invalid), self.assertRaises(a.VersionAllocationError):
                request(project_id=invalid)
        with self.assertRaises(a.VersionAllocationError):
            request(candidate=compact)
        with self.assertRaises(a.VersionAllocationError):
            replace(self.authority, ledger_id=compact)

    def test_same_bytes_compact_and_legacy_project_ids_cannot_alias_a_binding(self):
        self.allocate()
        compact = request(project_id=PROJECT.replace("-", ""))
        with self.assertRaises(a.VersionAllocationError) as raised:
            self.remote.ledger.find(compact)
        self.assertEqual(raised.exception.reason, "candidate-binding-conflict")
        before = len(self.remote.requests)
        result = self.allocate(compact)
        self.assertEqual(result.reason, "authority-changed")
        self.assertEqual(len(self.remote.requests), before)

    def test_reserve_persists_checkpoint_and_original_intent_before_one_cas(self):
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("reserved", "none"))
        self.assertEqual(result.reservation.version, ReleaseVersion("1.2.4", 8))
        self.assertEqual(self.remote.ledger.reservations, (result.reservation,))
        self.assertEqual(len(self.remote.writes), 1)
        self.assertLess(self.events.index("record_checkpoint"), self.events.index("record_pending"))
        self.assertLess(self.events.index("record_pending"), self.events.index("http:write"))
        self.assertEqual(self.events[-2:], ["record_checkpoint", "mark_resolved"])
        self.assertEqual(self.journal.pending, {})
        self.assertEqual(result.value()["releaseEligibility"], "not-established")
        self.assertTrue(result.write_claimed and result.write_acknowledged)
        self.assertEqual(result.checkpoint.commit, self.remote.head)

    def test_restart_reuses_exact_candidate_and_does_not_refresh_into_new_number(self):
        first = self.allocate()
        restarted = self.journal.restarted(self.events)
        result = self.allocate(journal=restarted, observations=(), clock=lambda: NOW + 100_000)
        self.assertEqual(result.reservation, first.reservation)
        self.assertEqual(result.status, "reserved")
        self.assertFalse(result.write_claimed)
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIn("record_checkpoint", self.events)
        self.assertEqual(a.AllocationRequest.parse(request().value()), request())
        self.assertEqual(a.Ledger.parse(self.remote.ledger.to_bytes(), self.authority), self.remote.ledger)

    def test_original_selected_request_admission_precedes_every_http_call(self):
        self.journal.fail.add("admit_request")
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertIsNone(result.reservation)
        self.assertEqual(self.events, ["admit_request"])
        self.assertEqual(self.remote.requests, [])

    def test_remote_existing_reservation_requires_local_reused_ack_before_result(self):
        original = self.allocate()
        for failure in ("record_reused", "record_reused_after"):
            with self.subTest(failure=failure):
                journal = self.journal.restarted(self.events)
                journal.reservations.clear()  # No selected local reserved row yet.
                journal.fail.add(failure)
                result = self.allocate(journal=journal)
                self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
                self.assertIsNone(result.reservation)
                self.assertFalse(result.write_claimed)
                self.assertEqual(len(self.remote.writes), 1)
                if failure.endswith("after"):
                    self.assertEqual(journal.reservations[CANDIDATE], p.canonical(original.reservation.value()))
                resumed = journal.restarted(self.events)
                result = self.allocate(journal=resumed)
                self.assertEqual(result.reservation, original.reservation)
                self.assertEqual(self.events[-1], "record_reused")
                self.assertEqual(resumed.reservations[CANDIDATE], p.canonical(original.reservation.value()))
                self.assertEqual(len(self.remote.writes), 1)

    def test_same_candidate_changed_identity_policy_source_platform_or_base_is_conflict(self):
        self.allocate()
        original = request()
        candidates = (
            replace(original, identity_revision="b" * 64),
            replace(original, source=replace(original.source, commit="a" * 40)),
            replace(original, source=replace(original.source, version_sha256="a" * 64)),
            replace(original, version_policy=p.VersionPolicy("automatic", (p.RefRule("refs/heads/main", "minor"),))),
            replace(original, base_version=ReleaseVersion("1.2.4", 8)),
            replace(original, enabled_platforms=("android", "ios")),
        )
        for changed in candidates:
            with self.subTest(request=changed.sha256):
                result = self.allocate(changed)
                self.assertEqual(result.reason, "candidate-binding-conflict")
                self.assertIsNone(result.reservation)
        self.assertEqual(len(self.remote.writes), 1)

    def test_competing_clients_cas_conflict_then_explicit_refresh_is_unique(self):
        second = request(candidate="00000000-0000-4000-8000-000000000004")
        second_journal = self.journal.restarted()
        winners = []
        self.remote.hooks["write"] = lambda: winners.append(self.allocate(second, second_journal))
        lost = self.allocate()
        self.assertEqual((lost.status, lost.reason), ("conflict", "conditional-conflict"))
        self.assertEqual(winners[0].reservation.version, ReleaseVersion("1.2.4", 8))
        self.assertEqual(len(self.remote.writes), 2)  # Two original requests; no hidden retry.
        retried = self.allocate()
        self.assertEqual(retried.reservation.version, ReleaseVersion("1.2.5", 9))
        self.assertEqual([item.version.build for item in self.remote.ledger.reservations], [8, 9])
        self.assertEqual(len({item.request.candidate_id for item in self.remote.ledger.reservations}), 2)

    def test_competing_same_candidate_only_one_reservation_is_consumed(self):
        winners = []
        other_machine = self.journal.restarted()
        self.remote.hooks["write"] = lambda: winners.append(self.allocate(journal=other_machine))
        lost = self.allocate()
        self.assertEqual(lost.reason, "conditional-conflict")
        reused = self.allocate()
        self.assertEqual(reused.reservation, winners[0].reservation)
        self.assertEqual(len(self.remote.ledger.reservations), 1)
        self.assertEqual(len(self.remote.writes), 2)

    def test_timeout_after_commit_reconciles_original_pending_without_another_write(self):
        self.remote.write_mode = "timeout-after"
        failed = self.allocate()
        self.assertEqual((failed.status, failed.reason), ("recovery-required", "network-unavailable"))
        self.assertTrue(failed.write_claimed)
        self.assertFalse(failed.write_acknowledged)
        pending = a.PendingAllocation.parse(self.journal.pending[CANDIDATE])
        restarted = self.journal.restarted()
        recovered = self.allocate(journal=restarted, observations=(), clock=lambda: NOW + 100_000)
        self.assertEqual(recovered.status, "reserved")
        self.assertEqual(recovered.reservation, pending.reservation)
        self.assertEqual(restarted.pending, {})
        self.assertEqual(len(self.remote.writes), 1)
        self.assertFalse(recovered.write_claimed)

    def test_timeout_absence_is_not_no_send_and_never_reallocates(self):
        self.remote.write_mode = "timeout-before"
        self.assertEqual(self.allocate().status, "recovery-required")
        restarted = self.journal.restarted()
        result = self.allocate(journal=restarted)
        self.assertEqual((result.status, result.reason), ("recovery-required", "pending-unresolved"))
        self.assertIn(CANDIDATE, restarted.pending)
        self.assertEqual(self.remote.ledger.reservations, ())
        self.assertEqual(len(self.remote.writes), 1)
        # A simulated delayed original request may appear later. Reconciliation
        # is still read-only and accepts only the conserved original entry.
        raw = base64.b64decode(json.loads(self.remote.writes[0].body)["content"])
        self.remote.commit(raw)
        self.assertEqual(self.allocate(journal=restarted).status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)

    def test_unknown_pending_cannot_be_rebound_to_hide_original_send(self):
        self.remote.write_mode = "timeout-before"
        self.allocate()
        count = len(self.remote.requests)
        result = self.allocate(replace(request(), identity_revision="b" * 64), journal=self.journal.restarted())
        self.assertEqual(result.reason, "candidate-binding-conflict")
        self.assertEqual(len(self.remote.requests), count)
        self.assertEqual(len(self.remote.writes), 1)

    def test_journal_failure_before_send_and_after_remote_acceptance_stays_unknown(self):
        self.journal.fail.add("record_pending_after")
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertFalse(result.write_claimed)
        self.assertEqual(self.remote.writes, [])
        self.assertIn(CANDIDATE, self.journal.pending)
        self.assertEqual(self.allocate(journal=self.journal.restarted()).reason, "pending-unresolved")

    def test_reuse_is_not_acknowledged_until_checkpoint_persistence_settles(self):
        original = self.allocate()
        restarted = self.journal.restarted()
        restarted.fail.add("record_checkpoint")
        result = self.allocate(journal=restarted)
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertIsNone(result.reservation)
        self.assertEqual(self.remote.ledger.reservations[0], original.reservation)
        self.assertEqual(len(self.remote.writes), 1)

    def test_resolution_journal_failure_preserves_pending_for_read_only_restart(self):
        self.journal.fail.add("mark_resolved")
        result = self.allocate()
        self.assertEqual(result.status, "recovery-required")
        self.assertTrue(result.write_acknowledged)
        self.assertIn(CANDIDATE, self.journal.pending)
        self.assertEqual(self.allocate(journal=self.journal.restarted()).status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)

    def test_branch_rewind_is_rejected_even_when_blob_sha_is_legitimate(self):
        self.allocate()
        self.remote.head = COMMIT
        count = len(self.remote.writes)
        result = self.allocate(request(candidate="00000000-0000-4000-8000-000000000004"))
        self.assertEqual(result.reason, "authority-rewound")
        self.assertEqual(len(self.remote.writes), count)
        self.assertEqual(self.remote.requests[-1][0], "compare-before")

    def test_history_ancestor_does_not_allow_ledger_truncation_or_genesis_recreation(self):
        self.allocate()
        self.remote.commit(self.genesis.to_bytes())  # Fast-forward commit, malicious/foreign truncation.
        result = self.allocate(request(candidate="00000000-0000-4000-8000-000000000004"))
        self.assertEqual(result.reason, "authority-rewound")
        changed = a.Ledger(replace(self.genesis.genesis, ledger_id="00000000-0000-4000-8000-000000000099"))
        self.remote.commit(changed.to_bytes())
        self.assertEqual(self.allocate().reason, "ledger-invalid")
        self.assertEqual(len(self.remote.writes), 1)

    def test_missing_ledger_or_wrong_repository_never_initializes_or_writes(self):
        self.remote.overrides["ledger-before"] = reply(status=404)
        self.assertEqual(self.allocate().reason, "authority-missing")
        self.assertEqual(self.remote.writes, [])
        self.remote.overrides.clear()
        self.remote.overrides["repository-before"] = reply({"id": 124, "full_name": self.authority.repository,
            "visibility": "private", "archived": False, "default_branch": "main"})
        self.assertEqual(self.allocate().reason, "authority-changed")
        self.assertEqual(self.remote.writes, [])

    def test_malformed_ledger_duplicates_unknown_schema_and_invalid_transition_refuse(self):
        valid = self.genesis.append(request(), observations(), now=NOW).value()
        bad = []
        changed = copy.deepcopy(valid)
        changed["reservations"][0]["version"]["build"] = 999
        bad.append(p.canonical(changed) + b"\n")
        changed = copy.deepcopy(valid)
        changed["schemaVersion"] = True
        bad.append(p.canonical(changed) + b"\n")
        bad.append(self.genesis.to_bytes().replace(b'{"genesis":', b'{"schemaVersion":1,"genesis":'))
        bad.append(self.genesis.to_bytes() + b"\n")
        for raw in bad:
            with self.subTest(size=len(raw)), self.assertRaises(a.VersionAllocationError):
                a.Ledger.parse(raw, self.authority)

    def test_bounded_capacity_preserves_all_spent_numbers_without_pruning(self):
        ledger = self.genesis
        for index in range(a.MAX_RESERVATIONS):
            candidate = f"00000000-0000-4000-8000-{index + 10:012d}"
            ledger = ledger.append(request(candidate=candidate, increment="build"), observations(), now=NOW)
        self.assertEqual(len(ledger.reservations), a.MAX_RESERVATIONS)
        self.assertLessEqual(len(ledger.to_bytes()), a.MAX_LEDGER_BYTES)
        with self.assertRaises(a.VersionAllocationError) as raised:
            ledger.append(request(), observations(), now=NOW)
        self.assertEqual(raised.exception.reason, "ledger-full")
        self.assertEqual(ledger.last_version.build, BASE.build + a.MAX_RESERVATIONS)

    def test_compare_and_contents_are_exact_commit_pinned_and_schedule_cannot_write_twice(self):
        self.allocate()
        for step, http in self.remote.requests:
            if step == "ledger-before":
                self.assertTrue(http.path.endswith("?ref=" + COMMIT))
            if step == "ledger-after":
                self.assertTrue(http.path.endswith("?ref=" + self.remote.head))
            if step.startswith("compare-"):
                self.assertTrue(http.path.endswith("?per_page=1&page=1"))
                self.assertIn("/compare/" + COMMIT + "...", http.path)
        schedule = a.Schedule(self.authority, a.Checkpoint(0, self.genesis.head_sha256, COMMIT), reconcile=True)
        for step, ref in (("repository-before", None), ("ref-before", None), ("compare-before", COMMIT), ("ledger-before", COMMIT)):
            schedule.claim(step, ref)
        with self.assertRaises(a.VersionAllocationError):
            schedule.claim("write", body=b"{}")
        schedule.claim("repository-after")
        with self.assertRaises(a.VersionAllocationError):
            schedule.claim("repository-after")

    def test_false_compare_or_contents_digest_cannot_establish_authority(self):
        self.remote.overrides["compare-before"] = reply({"status": "identical", "base_commit": {"sha": COMMIT},
                                                        "merge_base_commit": {"sha": "a" * 40}})
        self.assertEqual(self.allocate().reason, "authority-rewound")
        self.remote.overrides.clear()
        raw = self.genesis.to_bytes()
        self.remote.overrides["ledger-before"] = reply({"type": "file", "path": a.LEDGER_PATH, "encoding": "base64",
            "size": len(raw), "sha": "a" * 40, "content": base64.b64encode(raw).decode()})
        self.assertEqual(self.allocate().reason, "ledger-invalid")
        self.assertEqual(self.remote.writes, [])

    def test_write_readback_mismatch_preserves_pending_and_requires_reconciliation(self):
        self.remote.overrides["repository-after"] = reply({"id": 124, "full_name": self.authority.repository,
            "visibility": "private", "archived": False, "default_branch": "main"})
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "authority-changed"))
        self.assertTrue(result.write_acknowledged)
        self.assertIn(CANDIDATE, self.journal.pending)
        self.remote.overrides.clear()
        self.assertEqual(self.allocate(journal=self.journal.restarted()).status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)

    def test_rate_limit_preserves_cooldown_and_no_logical_retry(self):
        self.remote.overrides["write"] = reply(status=429, control=_control("rate-limited", 60, False))
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "rate-limited"))
        self.assertEqual(result.value()["control"]["cooldownSeconds"], 60)
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIn(CANDIDATE, self.journal.pending)

    def test_expired_store_check_before_send_does_not_spend_a_version(self):
        times = iter((NOW, NOW + 901))
        result = self.allocate(clock=lambda: next(times))
        self.assertEqual((result.status, result.reason), ("rejected", "store-observation-stale"))
        self.assertFalse(result.write_claimed)
        self.assertEqual(self.journal.pending, {})
        self.assertEqual(self.remote.writes, [])

    def test_reserved_data_below_new_store_floor_is_reused_not_silently_bumped(self):
        original = self.allocate()
        newer = (replace(observations()[0], max_build=original.reservation.version.build,
                         marketing_version=original.reservation.version.name, revision="7" * 64),)
        reused = self.allocate(observations=newer)
        self.assertEqual(reused.reservation, original.reservation)
        with self.assertRaises(p.VersionPolicyError) as raised:
            p.check_reserved_for_new_release(reused.reservation.version, request().version_policy,
                enabled=request().enabled_platforms, identity_revision=IDENTITY, observations=newer, now=NOW)
        self.assertEqual(raised.exception.reason, "reservation-consumed")
        self.assertEqual(len(self.remote.writes), 1)


class CurrentInventoryLedgerTests(unittest.TestCase):
    def selected(self, candidate="00000000-0000-4000-8000-000000000004", increment="build"):
        return request(candidate, increment, enabled_platforms=("ios",), store_context_revision="9" * 64,
            version_policy=p.VersionPolicy("automatic", (p.RefRule("refs/heads/main", increment),),
                                           store_scope=current_ios.POLICY_SCOPE))

    def observed(self, build=10, name="1.4.0", counts=(1, 0, 1)):
        return (current_ios.CurrentInventory(IDENTITY, "9" * 64, "a" * 64, NOW, build, name, counts),)

    def test_immutable_v1_data_hashes_and_mixed_v2_replay_same_genesis_highwater(self):
        empty, authority = initial()
        legacy = empty.append(request(), observations(), now=NOW)
        # DATA golden values from the accepted v1 codec, not source hashes.
        self.assertEqual(request().version_policy.sha256, "248fdd8a77dcec05ea81ab9b5bb0b7c93b5a4d82773b5e9f7fea35d11f45e9e4")
        self.assertEqual(request().sha256, "752e9190cc56daf9c89d2ce97d838f98734a5fd3c6b47af0e0643c1a684b5f6d")
        self.assertEqual(legacy.head_sha256, "81d47254594af98db1cf8b177479a00041c794b222689a20eebbbbfaab8b2795")
        self.assertEqual(hashlib.sha256(legacy.to_bytes()).hexdigest(), "db9e823bf66bf14dd79f50576562002a2c5043d512624064cbe48945093e0897")
        before = legacy.to_bytes()
        mixed = legacy.append(self.selected(), self.observed(), now=NOW)
        self.assertEqual(mixed.value()["schemaVersion"], 2)
        self.assertEqual(mixed.value()["protocol"], a.PROTOCOL_V2)
        self.assertEqual(mixed.genesis, legacy.genesis)
        self.assertEqual(mixed.reservations[0].value(), legacy.reservations[0].value())
        self.assertEqual(a.Ledger(mixed.genesis, mixed.reservations[:-1]).to_bytes(), before)
        self.assertEqual(mixed.last_version, ReleaseVersion("1.4.0", 11))
        self.assertEqual(a.Ledger.parse(mixed.to_bytes(), authority), mixed)
        mixed.admit(authority, a.Checkpoint(1, legacy.head_sha256, COMMIT))
        # An envelope downgrade cannot disguise the v2 row as old-client data.
        downgraded = mixed.value(); downgraded.update(schemaVersion=1, protocol=a.PROTOCOL)
        with self.assertRaises(a.VersionAllocationError): a.Ledger.parse(p.canonical(downgraded) + b"\n", authority)
        v1_hash = a._hash(b"mrk:allocation-reservation:1\0", mixed.reservations[-1]._value())
        self.assertNotEqual(v1_hash, mixed.head_sha256)

    def test_marketing_only_inventory_bumps_each_exact_policy_without_lowering_counter(self):
        empty, authority = initial()
        for increment, expected in (("build", "3.0.0"), ("patch", "3.0.1"), ("minor", "3.1.0"), ("major", "4.0.0")):
            selected = self.selected(increment=increment)
            observed = self.observed(0, "3.0.0", (0, 0, 1))
            ledger = empty.append(selected, observed, now=NOW)
            self.assertEqual(ledger.last_version, ReleaseVersion(expected, BASE.build + 1))
            self.assertEqual(a.Ledger.parse(ledger.to_bytes(), authority), ledger)
        first = empty.append(self.selected(), self.observed(99), now=NOW)
        second = first.append(self.selected("00000000-0000-4000-8000-000000000005"),
                              self.observed(0, None, (0, 0, 0)), now=NOW)
        self.assertEqual(second.last_version.build, 101)  # disappearance is not counter reset

    def test_same_candidate_retry_persists_and_never_reallocates_on_consumed_floor(self):
        empty, authority = initial()
        journal = Journal(authority, a.Checkpoint(0, empty.head_sha256, COMMIT))
        remote = Repository(empty, authority)
        selected = self.selected()
        original = a.allocate_version(selected, authority=authority, journal=journal, transport=remote,
                                      observations=self.observed(), clock=lambda: NOW)
        self.assertEqual(original.status, "reserved")
        higher = self.observed(100)
        repeated = a.allocate_version(selected, authority=authority, journal=journal.restarted(), transport=remote,
                                      observations=higher, clock=lambda: NOW)
        self.assertEqual(repeated.reservation, original.reservation)
        self.assertEqual(len(remote.writes), 1)
        with self.assertRaises(p.VersionPolicyError):
            current_ios.check_reserved(repeated.reservation.version, selected.version_policy, enabled=("ios",),
                identity_revision=IDENTITY, context_revision=selected.store_context_revision, observations=higher, now=NOW)
        changed = replace(selected, store_context_revision="b" * 64)
        with self.assertRaises(a.VersionAllocationError): remote.ledger.find(changed)

    def test_v2_pending_unknown_reconciles_without_put_or_new_candidate(self):
        empty, authority = initial()
        journal = Journal(authority, a.Checkpoint(0, empty.head_sha256, COMMIT))
        remote = Repository(empty, authority)
        selected = self.selected()
        # Actual fixture publishes then loses its acknowledgement.
        remote.write_mode = "timeout-after"
        result = a.allocate_version(selected, authority=authority, journal=journal, transport=remote,
                                    observations=self.observed(), clock=lambda: NOW)
        self.assertEqual(result.status, "recovery-required")
        self.assertEqual(len(remote.writes), 1)
        repeated = a.allocate_version(selected, authority=authority, journal=journal.restarted(), transport=remote,
                                      observations=(), clock=lambda: NOW + 99999)
        self.assertEqual(repeated.status, "reserved")
        self.assertEqual(len(remote.writes), 1)
        self.assertEqual(repeated.reservation.request.candidate_id, selected.candidate_id)


if __name__ == "__main__":
    unittest.main()
