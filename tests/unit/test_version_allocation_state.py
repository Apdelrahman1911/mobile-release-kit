"""Synthetic closed-port tests; no native filesystem/durability qualification."""
from __future__ import annotations

import unittest
from dataclasses import replace

from mobile_release import version_allocation as a
from mobile_release import version_allocation_state as s
from mobile_release import version_policy as p

from test_version_allocation import COMMIT, NOW, CANDIDATE, Repository, initial, observations, request


class NativePortFixture:
    """Retained bytes in memory, NOT an implementation of native durability."""
    def __init__(self, events=None):
        self.snapshot = s.NativeStateSnapshot(0, b"")
        self.events = [] if events is None else events
        self.failure = None
        self.ack = lambda snapshot: s.NativeStateWriteAck(snapshot, "committed", "durable", "settled")
        self.writes = 0

    def read_version_allocations(self):
        self.events.append("native-read")
        if self.failure == "read":
            raise OSError("synthetic native state unavailable")
        return self.snapshot

    def replace_version_allocations(self, expected_revision, payload):
        self.events.append("native-replace")
        self.writes += 1
        if self.snapshot.revision != expected_revision or self.failure == "before":
            raise OSError("synthetic native CAS refusal")
        s.AllocationState.parse(payload)
        self.snapshot = s.NativeStateSnapshot(expected_revision + 1, payload)
        if self.failure == "after":
            raise OSError("synthetic native write uncertainty")
        result = self.ack(self.snapshot)
        self.events.append("native-ack")
        return result


class VersionAllocationStateTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.authority = initial()
        self.checkpoint = a.Checkpoint(0, self.ledger.head_sha256, COMMIT)
        self.events = []
        self.port = NativePortFixture(self.events)
        self.journal = s.NativeAllocationJournal(self.port)
        self.journal.enroll_authority(self.authority, self.checkpoint)
        self.remote = Repository(self.ledger, self.authority, self.events)
        self.events.clear()

    def allocate(self, *, journal=None, selected=None):
        return a.allocate_version(selected or request(), self.authority, self.remote, journal or self.journal,
                                  observations=observations(), clock=lambda: NOW)

    def pending(self):
        after = self.ledger.append(request(), observations(), now=NOW)
        return a.PendingAllocation(self.authority, self.checkpoint, a.blob_sha(self.ledger.to_bytes()),
                                   after.reservations[-1])

    def test_codec_is_canonical_closed_and_bounded(self):
        state = s.AllocationState((s.AuthorityState(self.authority, self.checkpoint, self.pending()),))
        self.assertEqual(s.AllocationState.parse(state.to_bytes()), state)
        row = state.value()
        variants = [b"", state.to_bytes() + b"\n", b" " + state.to_bytes(), b"x" * (s.MAX_STATE_BYTES + 1),
                    state.to_bytes().replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1')]
        for changes in ({"schemaVersion": True}, {"protocol": "other"}, {"extra": 1},
                        {"authorities": row["authorities"] * 2}, {"authorities": row["authorities"] * 9}):
            variants.append(p.canonical({**row, **changes}) + b"\n")
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(a.VersionAllocationError) as caught:
                s.AllocationState.parse(raw)
            self.assertEqual(caught.exception.reason, "journal-unavailable")
        with self.assertRaises(a.VersionAllocationError):
            s.NativeStateSnapshot(True, state.to_bytes())

    def test_only_native_zero_empty_is_initial_not_missing_or_nonzero_empty(self):
        port = NativePortFixture()
        journal = s.NativeAllocationJournal(port)
        self.assertEqual(port.writes, 0)  # Opening does not enroll/create/reset.
        with self.assertRaises(a.VersionAllocationError):
            journal.checkpoint(self.authority)
        for revision, raw in ((1, b""), (0, b"{}"), (1, b"{}\n")):
            port.snapshot = s.NativeStateSnapshot(revision, raw)
            with self.subTest(revision=revision), self.assertRaises(a.VersionAllocationError):
                s.NativeAllocationJournal(port)
        port.snapshot = s.NativeStateSnapshot(0, b"")
        port.failure = "read"
        with self.assertRaises(a.VersionAllocationError):
            s.NativeAllocationJournal(port)
        self.assertEqual(port.writes, 0)

    def test_durable_ack_precedes_send_and_checkpoint_settlement_precedes_result(self):
        def at_send():
            retained = s.AllocationState.parse(self.port.snapshot.payload).selected(self.authority)
            self.assertEqual(retained.pending.reservation.request, request())
            self.assertEqual(self.events[-2:], ["native-ack", "http:write"])
        self.remote.hooks["write"] = at_send
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("reserved", "none"))
        retained = s.AllocationState.parse(self.port.snapshot.payload).selected(self.authority)
        self.assertIsNone(retained.pending)
        self.assertEqual(retained.checkpoint, result.checkpoint)
        self.assertEqual(self.events[-1], "native-ack")
        self.assertEqual(len(self.remote.writes), 1)

    def test_uncertain_pending_write_preserves_bytes_blocks_http_and_latches_adapter(self):
        self.port.failure = "after"
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertEqual(self.remote.writes, [])
        retained = s.AllocationState.parse(self.port.snapshot.payload).selected(self.authority)
        self.assertEqual(retained.pending.reservation.request, request())
        before = (self.port.writes, len(self.remote.requests))
        self.port.failure = None  # Clearing a test fault cannot unpoison this adapter.
        self.assertEqual(self.allocate().reason, "journal-unavailable")
        self.assertEqual((self.port.writes, len(self.remote.requests)), before)

    def test_non_durable_wrong_revision_or_payload_ack_never_authorizes_http(self):
        for change in (lambda ack: replace(ack, effect="unknown"),
                       lambda ack: replace(ack, durability="unknown"),
                       lambda ack: replace(ack, cleanup="unknown"),
                       lambda ack: replace(ack, snapshot=replace(ack.snapshot, revision=ack.snapshot.revision + 1)),
                       lambda ack: replace(ack, snapshot=replace(ack.snapshot, payload=s.AllocationState().to_bytes())),
                       lambda ack: {"snapshot": ack.snapshot}):
            with self.subTest(change=change):
                port = NativePortFixture()
                journal = s.NativeAllocationJournal(port)
                journal.enroll_authority(self.authority, self.checkpoint)
                port.ack = lambda snapshot: change(s.NativeStateWriteAck(snapshot, "committed", "durable", "settled"))
                result = self.allocate(journal=journal)
                self.assertEqual(result.reason, "journal-unavailable")
                self.assertEqual(self.remote.writes, [])
                self.assertIsNotNone(s.AllocationState.parse(port.snapshot.payload).selected(self.authority).pending)
                with self.assertRaises(a.VersionAllocationError):
                    journal.checkpoint(self.authority)

    def test_settled_pending_survives_controller_restart_and_reconciles_without_send(self):
        self.remote.write_mode = "timeout-after"
        result = self.allocate()
        self.assertEqual(result.status, "recovery-required")
        self.assertIsNotNone(self.journal.pending_for(self.authority, CANDIDATE))
        # The native writes settled; it is the REMOTE send that is uncertain.
        restarted = s.NativeAllocationJournal(self.port)
        self.remote.write_mode = "normal"
        result = self.allocate(journal=restarted)
        self.assertEqual(result.status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIsNone(restarted.pending_for(self.authority, CANDIDATE))

    def test_absent_remote_pending_blocks_other_candidate_and_is_never_cleared(self):
        self.remote.write_mode = "timeout-before"
        self.assertEqual(self.allocate().status, "recovery-required")
        restarted = s.NativeAllocationJournal(self.port)
        before = len(self.remote.requests)
        other = request(candidate="00000000-0000-4000-8000-000000000009")
        self.assertEqual(self.allocate(journal=restarted, selected=other).reason, "journal-unavailable")
        self.assertEqual(len(self.remote.requests), before)
        result = self.allocate(journal=restarted)
        self.assertEqual((result.status, result.reason), ("recovery-required", "pending-unresolved"))
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIsNotNone(restarted.pending_for(self.authority, CANDIDATE))

    def test_state_revision_cas_refuses_stale_controller_before_send_without_retry(self):
        stale = s.NativeAllocationJournal(self.port)
        advanced = replace(self.checkpoint, commit="9" * 40)
        self.journal.record_checkpoint(self.authority, advanced)
        before = self.port.writes
        result = self.allocate(journal=stale)
        self.assertEqual(result.reason, "journal-unavailable")
        self.assertEqual(self.port.writes, before + 1)
        self.assertEqual(self.remote.writes, [])
        self.assertEqual(s.AllocationState.parse(self.port.snapshot.payload).selected(self.authority).checkpoint, advanced)

    def test_enrollment_cannot_reset_rebind_or_exceed_bounded_project_capacity(self):
        before = self.port.writes
        for authority, checkpoint in ((self.authority, self.checkpoint),
                (replace(self.authority, repository="other/repo"), self.checkpoint),
                (replace(self.authority, project_id="1" * 32), replace(self.checkpoint, sequence=1)),
                (replace(self.authority, project_id="2" * 32, protected_branch=False), self.checkpoint)):
            with self.subTest(authority=authority), self.assertRaises(a.VersionAllocationError):
                self.journal.enroll_authority(authority, checkpoint)
        self.assertEqual(self.port.writes, before)
        for index in range(1, s.MAX_AUTHORITIES):
            self.journal.enroll_authority(replace(self.authority, project_id=f"{index:032x}"), self.checkpoint)
        before = self.port.writes
        with self.assertRaises(a.VersionAllocationError):
            self.journal.enroll_authority(replace(self.authority, project_id="f" * 32), self.checkpoint)
        self.assertEqual(self.port.writes, before)
        self.assertEqual(len(s.AllocationState.parse(self.port.snapshot.payload).authorities), s.MAX_AUTHORITIES)

    def test_checkpoint_never_regresses_and_original_pending_required_to_settle(self):
        pending = self.pending()
        self.journal.record_pending(pending)
        with self.assertRaises(a.VersionAllocationError):
            self.journal.record_pending(pending)
        final = a.Checkpoint(1, pending.reservation.sha256, "8" * 40)
        with self.assertRaises(a.VersionAllocationError):
            self.journal.mark_resolved(pending, final)
        self.journal.record_checkpoint(self.authority, final)
        for invalid in (self.checkpoint, replace(final, head_sha256="0" * 64),
                        replace(final, sequence=2, head_sha256="1" * 64)):
            with self.subTest(invalid=invalid), self.assertRaises(a.VersionAllocationError):
                self.journal.record_checkpoint(self.authority, invalid)
        with self.assertRaises(a.VersionAllocationError):
            self.journal.mark_rejected(replace(pending, expected_blob="2" * 40))
        self.journal.mark_resolved(pending, final)
        self.assertIsNone(self.journal.pending_for(self.authority, CANDIDATE))

    def test_competing_winner_checkpoint_does_not_erase_uncertain_original_pending(self):
        pending = self.pending()
        self.journal.record_pending(pending)
        competitor = self.ledger.append(request(candidate="00000000-0000-4000-8000-000000000009"),
                                        observations(), now=NOW).reservations[-1]
        checkpoint = a.Checkpoint(1, competitor.sha256, "8" * 40)
        self.journal.record_checkpoint(self.authority, checkpoint)
        restarted = s.NativeAllocationJournal(self.port)
        self.assertEqual(restarted.pending_for(self.authority, CANDIDATE), pending)
        with self.assertRaises(a.VersionAllocationError):
            restarted.mark_resolved(pending, checkpoint)


if __name__ == "__main__":
    unittest.main()
