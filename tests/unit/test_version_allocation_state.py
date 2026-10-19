"""Synthetic closed-port tests; no native filesystem/durability qualification."""
from __future__ import annotations

import unittest
from dataclasses import replace

from mobile_release import version_allocation as a
from mobile_release import version_allocation_state as s
from mobile_release import version_policy as p

from test_version_allocation import COMMIT, NOW, CANDIDATE, Repository, initial, observations, request

LOCAL_PROJECT = "a" * 32
OTHER_LOCAL_PROJECT = "b" * 32


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
        if isinstance(self.failure, BaseException):
            raise self.failure
        result = self.ack(self.snapshot)
        self.events.append("native-ack")
        return result


class VersionAllocationStateTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.authority = initial()
        self.checkpoint = a.Checkpoint(0, self.ledger.head_sha256, COMMIT)
        self.events = []
        self.port = NativePortFixture(self.events)
        self.journal = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        self.journal.enroll_authority(self.authority, self.checkpoint)
        self.journal.select_candidate(self.authority, request())
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
                    state.to_bytes().replace(b'"schemaVersion":3', b'"schemaVersion":3,"schemaVersion":3')]
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
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        self.assertEqual(port.writes, 0)  # Opening does not enroll/create/reset.
        with self.assertRaises(a.VersionAllocationError):
            journal.checkpoint(self.authority)
        for revision, raw in ((1, b""), (0, b"{}"), (1, b"{}\n")):
            port.snapshot = s.NativeStateSnapshot(revision, raw)
            with self.subTest(revision=revision), self.assertRaises(a.VersionAllocationError):
                s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        port.snapshot = s.NativeStateSnapshot(0, b"")
        port.failure = "read"
        with self.assertRaises(a.VersionAllocationError):
            s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
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
                journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
                journal.enroll_authority(self.authority, self.checkpoint)
                journal.select_candidate(self.authority, request())
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
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        self.remote.write_mode = "normal"
        result = self.allocate(journal=restarted)
        self.assertEqual(result.status, "reserved")
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIsNone(restarted.pending_for(self.authority, CANDIDATE))

    def test_absent_remote_pending_blocks_other_candidate_and_is_never_cleared(self):
        self.remote.write_mode = "timeout-before"
        self.assertEqual(self.allocate().status, "recovery-required")
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        before = len(self.remote.requests)
        other = request(candidate="00000000-0000-4000-8000-000000000009")
        self.assertEqual(self.allocate(journal=restarted, selected=other).reason, "journal-unavailable")
        self.assertEqual(len(self.remote.requests), before)
        result = self.allocate(journal=restarted)
        self.assertEqual((result.status, result.reason), ("recovery-required", "pending-unresolved"))
        self.assertEqual(len(self.remote.writes), 1)
        self.assertIsNotNone(restarted.pending_for(self.authority, CANDIDATE))

    def test_state_revision_cas_refuses_stale_controller_before_send_without_retry(self):
        stale = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
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
            journal = s.NativeAllocationJournal(self.port, local_project_id=f"{index:032x}")
            journal.enroll_authority(replace(self.authority, project_id=f"{index:032x}"), self.checkpoint)
        before = self.port.writes
        journal = s.NativeAllocationJournal(self.port, local_project_id="f" * 32)
        with self.assertRaises(a.VersionAllocationError):
            journal.enroll_authority(replace(self.authority, project_id="f" * 32), self.checkpoint)
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
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        self.assertEqual(restarted.pending_for(self.authority, CANDIDATE), pending)
        with self.assertRaises(a.VersionAllocationError):
            restarted.mark_resolved(pending, checkpoint)

    def test_two_hosts_keep_distinct_local_ids_and_share_one_repository_authority(self):
        other_port = NativePortFixture()
        other = s.NativeAllocationJournal(other_port, local_project_id=OTHER_LOCAL_PROJECT)
        other.enroll_authority(self.authority, self.checkpoint)
        other_request = request(candidate="00000000-0000-4000-8000-000000000009")
        other.select_candidate(self.authority, other_request)
        first = self.allocate()
        second = self.allocate(journal=other, selected=other_request)
        self.assertEqual((first.status, second.status), ("reserved", "reserved"))
        self.assertEqual(second.reservation.version.build, first.reservation.version.build + 1)
        self.assertEqual(len(self.remote.writes), 2)
        for port, local in ((self.port, LOCAL_PROJECT), (other_port, OTHER_LOCAL_PROJECT)):
            state = s.AllocationState.parse(port.snapshot.payload)
            self.assertEqual(state.enrollments, (s.ProjectEnrollment(local, self.authority.project_id),))
            self.assertEqual(state.authorities[0].authority, self.authority)
        self.assertEqual(first.reservation.request.project_id, self.authority.project_id)
        self.assertEqual(second.reservation.request.project_id, self.authority.project_id)

    def test_local_id_is_native_shape_and_no_missing_equal_or_uuid_alias_mapping_is_inferred(self):
        for invalid in (None, True, 1, "", "0" * 32, "A" * 32, "g" * 32,
                        LOCAL_PROJECT + "\n", self.authority.project_id, "../project"):
            port = NativePortFixture()
            with self.subTest(invalid=invalid), self.assertRaises(a.VersionAllocationError):
                s.NativeAllocationJournal(port, local_project_id=invalid)
            self.assertEqual(port.events, [])
        with self.assertRaises(TypeError):
            s.NativeAllocationJournal(NativePortFixture())  # No unscoped adapter.
        other = s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT)
        self.assertEqual(self.allocate(journal=other).reason, "journal-unavailable")
        # Equal exact strings AND UUID-equivalent byte spellings are still not
        # enrollment. Only the explicit native-approved action can create one.
        genesis = replace(self.ledger.genesis, project_id=LOCAL_PROJECT)
        equal_authority = replace(self.authority, project_id=LOCAL_PROJECT, genesis_sha256=genesis.sha256)
        for authority, checkpoint, local in (
                (equal_authority, a.Checkpoint(0, genesis.sha256, COMMIT), LOCAL_PROJECT),
                (self.authority, self.checkpoint, self.authority.project_id.replace("-", ""))):
            port = NativePortFixture()
            port.snapshot = s.NativeStateSnapshot(1, s.AllocationState((s.AuthorityState(authority, checkpoint),)).to_bytes())
            journal = s.NativeAllocationJournal(port, local_project_id=local)
            result = a.allocate_version(request(project_id=authority.project_id), authority, self.remote, journal,
                                        observations=observations(), clock=lambda: NOW)
            self.assertEqual(result.reason, "journal-unavailable")
            self.assertEqual(port.writes, 0)
        self.assertEqual(self.remote.requests, [])

    def test_every_journal_transition_requires_exact_enrolled_authority(self):
        foreign = replace(self.authority, repository="other/repository")
        for journal, authority in ((self.journal, foreign),
                (s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT), self.authority)):
            pending = replace(self.pending(), authority=authority)
            calls = (lambda: journal.checkpoint(authority),
                     lambda: journal.admit_request(authority, request()),
                     lambda: journal.pending_for(authority, CANDIDATE),
                     lambda: journal.record_checkpoint(authority, self.checkpoint),
                     lambda: journal.record_pending(pending),
                     lambda: journal.mark_resolved(pending, self.checkpoint),
                     lambda: journal.record_reused(authority, pending.reservation, self.checkpoint),
                     lambda: journal.mark_rejected(pending))
            before = (self.port.writes, self.port.snapshot)
            for call in calls:
                with self.assertRaises(a.VersionAllocationError):
                    call()
            self.assertEqual((self.port.writes, self.port.snapshot), before)
        self.assertEqual(self.remote.requests, [])

    def test_legacy_schema1_is_canonical_unenrolled_and_upgrades_only_on_explicit_enrollment(self):
        pending = self.pending()
        advanced = a.Checkpoint(1, pending.reservation.sha256, "9" * 40)
        legacy = {"schemaVersion": 1, "protocol": s.PROTOCOL,
                  "authorities": [s.AuthorityState(self.authority, advanced, pending).value()]}
        raw = p.canonical(legacy) + b"\n"
        for invalid in (raw + b"\n", b" " + raw,
                        raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                        p.canonical({**legacy, "enrollments": []}) + b"\n"):
            with self.assertRaises(a.VersionAllocationError):
                s.AllocationState.parse(invalid)
        port = NativePortFixture()
        port.snapshot = s.NativeStateSnapshot(7, raw)
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        self.assertEqual(s.AllocationState.parse(raw).enrollments, ())
        self.assertEqual(self.allocate(journal=journal).reason, "journal-unavailable")
        self.assertEqual((port.writes, port.snapshot.payload, self.remote.requests), (0, raw, []))
        journal.enroll_authority(self.authority, self.checkpoint)
        saved = s.AllocationState.parse(port.snapshot.payload)
        self.assertEqual(saved.value()["schemaVersion"], 3)
        self.assertEqual(p.canonical(saved.value()["authorities"]), p.canonical(legacy["authorities"]))
        self.assertEqual(saved.candidates, ())
        with self.assertRaises(a.VersionAllocationError):
            journal.pending_for(self.authority, CANDIDATE)
        journal.select_candidate(self.authority, request(), reconcile_pending=True)
        self.assertEqual(journal.pending_for(self.authority, CANDIDATE).to_bytes(), pending.to_bytes())
        self.assertEqual(journal.checkpoint(self.authority), advanced)
        self.assertEqual(saved.enrollments, (s.ProjectEnrollment(LOCAL_PROJECT, self.authority.project_id),))
        self.assertEqual((port.writes, port.snapshot.revision), (2, 9))

    def test_second_local_enrollment_preserves_current_checkpoint_and_original_pending(self):
        pending = self.pending()
        self.journal.record_pending(pending)
        advanced = a.Checkpoint(1, pending.reservation.sha256, "9" * 40)
        self.journal.record_checkpoint(self.authority, advanced)
        before = p.canonical(s.AllocationState.parse(self.port.snapshot.payload).value()["authorities"])
        other = s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT)
        other.enroll_authority(self.authority, self.checkpoint)  # Approve genesis, never reset to it.
        saved = s.AllocationState.parse(self.port.snapshot.payload)
        self.assertEqual(p.canonical(saved.value()["authorities"]), before)
        self.assertEqual(saved.enrolled(OTHER_LOCAL_PROJECT, self.authority).pending.to_bytes(), pending.to_bytes())
        self.assertEqual(saved.enrolled(OTHER_LOCAL_PROJECT, self.authority).checkpoint, advanced)
        self.assertIsNone(saved.candidate(OTHER_LOCAL_PROJECT))
        with self.assertRaises(a.VersionAllocationError):
            other.select_candidate(self.authority, request(), reconcile_pending=True)
        with self.assertRaises(a.VersionAllocationError):
            other.pending_for(self.authority, CANDIDATE)
        self.assertEqual(len(saved.enrollments), 2)
        writes = self.port.writes
        for authority in (self.authority, replace(self.authority, repository="other/repository")):
            with self.assertRaises(a.VersionAllocationError):
                other.enroll_authority(authority, self.checkpoint)
        third = s.NativeAllocationJournal(self.port, local_project_id="c" * 32)
        with self.assertRaises(a.VersionAllocationError):
            third.enroll_authority(replace(self.authority, repository="other/repository"), self.checkpoint)
        with self.assertRaises(a.VersionAllocationError):
            other.pending_for(self.authority, "00000000-0000-4000-8000-000000000009")
        self.assertEqual(self.port.writes, writes)

    def test_enrollment_rows_are_closed_sorted_bounded_and_exact_references(self):
        state = s.AllocationState.parse(self.port.snapshot.payload)
        row = state.value()
        mapping = row["enrollments"][0]
        variants = [[mapping, mapping], [{**mapping, "extra": True}],
                    [{**mapping, "localProjectId": "0" * 32}],
                    [{**mapping, "localProjectId": self.authority.project_id}],
                    [{**mapping, "authorityProjectId": "f" * 32}],
                    [{**mapping, "authorityProjectId": self.authority.project_id.replace("-", "")}],
                    [{**mapping, "localProjectId": OTHER_LOCAL_PROJECT}, mapping],
                    [{**mapping, "localProjectId": f"{index:032x}"} for index in range(1, s.MAX_ENROLLMENTS + 2)]]
        for mappings in variants:
            with self.subTest(mappings=len(mappings)), self.assertRaises(a.VersionAllocationError):
                s.AllocationState.parse(p.canonical({**row, "enrollments": mappings}) + b"\n")
        maximum = s.AllocationState(state.authorities, tuple(s.ProjectEnrollment(f"{index:032x}", self.authority.project_id)
                                                           for index in range(1, s.MAX_ENROLLMENTS + 1)))
        self.assertEqual(s.AllocationState.parse(maximum.to_bytes()), maximum)
        port = NativePortFixture()
        port.snapshot = s.NativeStateSnapshot(1, maximum.to_bytes())
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        with self.assertRaises(a.VersionAllocationError):
            journal.enroll_authority(self.authority, self.checkpoint)
        self.assertEqual(port.writes, 0)

    def test_uncertain_or_non_durable_enrollment_ack_never_grants_journal_access(self):
        for failure in ("after", "ack"):
            port = NativePortFixture()
            journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
            if failure == "ack":
                port.ack = lambda snapshot: s.NativeStateWriteAck(snapshot, "committed", "unknown", "settled")
            else:
                port.failure = failure
            with self.subTest(failure=failure), self.assertRaises(a.VersionAllocationError):
                journal.enroll_authority(self.authority, self.checkpoint)
            self.assertEqual(len(s.AllocationState.parse(port.snapshot.payload).enrollments), 1)
            port.failure = None  # A changed fixture fault cannot unpoison this original adapter.
            self.assertEqual(self.allocate(journal=journal).reason, "journal-unavailable")
            with self.assertRaises(a.VersionAllocationError):
                journal.enroll_authority(self.authority, self.checkpoint)
            self.assertEqual(port.writes, 1)
        self.assertEqual(self.remote.requests, [])

    def test_stale_other_local_adapter_cannot_overwrite_original_pending_or_send(self):
        other = s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT)
        other.enroll_authority(self.authority, self.checkpoint)
        other_request = request(candidate="00000000-0000-4000-8000-000000000009")
        other.select_candidate(self.authority, other_request)
        current = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        pending = self.pending()
        current.record_pending(pending)
        before = self.port.snapshot
        # Other is legitimately enrolled but its snapshot predates this pending.
        # GETs may precede the stale CAS refusal; not a single PUT may follow it.
        result = self.allocate(journal=other, selected=other_request)
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertEqual(len(self.remote.requests), 4)
        self.assertEqual(self.remote.writes, [])
        self.assertEqual(self.port.snapshot, before)
        self.assertEqual(s.AllocationState.parse(before.payload).selected(self.authority).pending.to_bytes(), pending.to_bytes())
        with self.assertRaises(a.VersionAllocationError):
            other.checkpoint(self.authority)

    def test_post_publish_base_exception_is_preserved_and_original_adapter_stays_latched(self):
        for failure in (KeyboardInterrupt("synthetic interruption"), SystemExit("synthetic exit")):
            port = NativePortFixture()
            journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
            port.failure = failure
            with self.subTest(failure=type(failure)), self.assertRaises(type(failure)) as caught:
                journal.enroll_authority(self.authority, self.checkpoint)
            self.assertIs(caught.exception, failure)
            self.assertEqual(len(s.AllocationState.parse(port.snapshot.payload).enrollments), 1)
            self.assertNotIn("native-ack", port.events)
            port.failure = None
            self.assertEqual(self.allocate(journal=journal).reason, "journal-unavailable")
            with self.assertRaises(a.VersionAllocationError):
                journal.enroll_authority(self.authority, self.checkpoint)
            self.assertEqual(port.writes, 1)
        self.assertEqual(self.remote.requests, [])

    def test_reentrant_port_callback_cannot_issue_a_second_write_or_read_unadopted_state(self):
        port = NativePortFixture()
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        def acknowledge(snapshot):
            with self.assertRaises(a.VersionAllocationError):
                journal.enroll_authority(self.authority, self.checkpoint)
            with self.assertRaises(a.VersionAllocationError):
                journal.checkpoint(self.authority)
            self.assertEqual(port.writes, 1)
            return s.NativeStateWriteAck(snapshot, "committed", "durable", "settled")
        port.ack = acknowledge
        journal.enroll_authority(self.authority, self.checkpoint)
        self.assertEqual(journal._state.enrolled(LOCAL_PROJECT, self.authority).checkpoint, self.checkpoint)
        self.assertEqual(port.writes, 1)

    def test_selected_full_request_is_durable_before_http_and_same_id_changes_refuse(self):
        stored = self.port.snapshot
        selected = self.journal.selected_candidate(self.authority)
        self.assertEqual(selected, s.SelectedCandidate(LOCAL_PROJECT, request()))
        changes = (replace(request(), identity_revision="b" * 64),
                   replace(request(), source=replace(request().source, commit="b" * 40)),
                   request(increment="major"),
                   replace(request(), base_version=replace(request().base_version, build=8)),
                   replace(request(), enabled_platforms=("ios",)))
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(a.VersionAllocationError):
                self.journal.select_candidate(self.authority, changed, previous_candidate_id=CANDIDATE)
            result = self.allocate(selected=changed)
            self.assertEqual(result.reason, "journal-unavailable")
        self.assertEqual(self.remote.requests, [])
        self.assertEqual(self.port.snapshot, stored)
        def before_first_http():
            retained = s.AllocationState.parse(self.port.snapshot.payload).candidate(LOCAL_PROJECT)
            self.assertEqual(retained.request, request())
            self.assertIsNone(retained.reservation)
        self.remote.hooks["repository-before"] = before_first_http
        self.assertEqual(self.allocate().status, "reserved")

    def test_selected_candidate_refresh_and_restart_never_change_request_or_write(self):
        before = (self.port.snapshot, self.port.writes)
        first = self.journal.select_candidate(self.authority, request())
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        self.assertEqual(restarted.selected_candidate(self.authority), first)
        self.assertEqual(restarted.select_candidate(self.authority, request()), first)
        self.assertEqual((self.port.snapshot, self.port.writes), before)
        changed = request(candidate="00000000-0000-4000-8000-000000000009")
        with self.assertRaises(a.VersionAllocationError):
            restarted.select_candidate(self.authority, changed)
        with self.assertRaises(a.VersionAllocationError):
            restarted.select_candidate(self.authority, changed, previous_candidate_id=changed.candidate_id)
        restarted.select_candidate(self.authority, changed, previous_candidate_id=CANDIDATE)
        self.assertEqual(restarted.selected_candidate(self.authority).request, changed)
        self.assertEqual(restarted.checkpoint(self.authority), self.checkpoint)
        self.assertEqual(self.port.writes, before[1] + 1)

    def test_candidate_selection_unknown_ack_retains_request_and_blocks_all_http(self):
        port = NativePortFixture()
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        journal.enroll_authority(self.authority, self.checkpoint)
        port.failure = KeyboardInterrupt("synthetic lost selection acknowledgement")
        with self.assertRaises(KeyboardInterrupt):
            journal.select_candidate(self.authority, request())
        retained = s.AllocationState.parse(port.snapshot.payload).candidate(LOCAL_PROJECT)
        self.assertEqual(retained.request, request())
        before = port.writes
        port.failure = None
        self.assertEqual(self.allocate(journal=journal).reason, "journal-unavailable")
        with self.assertRaises(a.VersionAllocationError):
            journal.select_candidate(self.authority, request())
        self.assertEqual(port.writes, before)
        self.assertEqual(self.remote.requests, [])

    def test_resolved_candidate_survives_restart_and_identical_reuse_requires_new_cas_ack(self):
        first = self.allocate()
        saved = self.port.snapshot
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        self.assertEqual(restarted.selected_candidate(self.authority).reservation, first.reservation)
        before = self.port.writes
        result = self.allocate(journal=restarted)
        self.assertEqual(result.reservation, first.reservation)
        self.assertEqual(self.port.snapshot.payload, saved.payload)
        self.assertEqual((self.port.snapshot.revision, self.port.writes), (saved.revision + 1, before + 1))
        self.assertEqual(len(self.remote.writes), 1)
        self.assertEqual(self.events[-1], "native-ack")

    def test_remote_existing_without_local_pending_is_retained_before_result(self):
        remote_ledger = self.ledger.append(request(), observations(), now=NOW)
        self.remote.commit(remote_ledger.to_bytes())
        self.assertIsNone(self.journal.selected_candidate(self.authority).reservation)
        self.assertIsNone(self.journal.pending_for(self.authority, CANDIDATE))
        result = self.allocate()
        self.assertEqual((result.status, result.reservation), ("reserved", remote_ledger.reservations[-1]))
        self.assertEqual(self.journal.selected_candidate(self.authority).reservation, result.reservation)
        self.assertEqual(self.remote.writes, [])
        self.assertEqual(self.events[-1], "native-ack")

    def test_reused_ack_loss_after_applied_cas_retains_data_not_success_and_latches(self):
        remote_ledger = self.ledger.append(request(), observations(), now=NOW)
        self.remote.commit(remote_ledger.to_bytes())
        # The preceding checkpoint ACK succeeds. Only the final reserved-row
        # write loses its acknowledgement after publishing the synthetic bytes.
        self.remote.hooks["repository-after"] = lambda: setattr(self.port, "failure", "after")
        result = self.allocate()
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertIsNone(result.reservation)
        retained = s.AllocationState.parse(self.port.snapshot.payload).candidate(LOCAL_PROJECT)
        self.assertEqual(retained.reservation, remote_ledger.reservations[-1])
        self.assertEqual(self.remote.writes, [])
        before = (len(self.remote.requests), self.port.writes)
        self.port.failure = None
        self.assertEqual(self.allocate().reason, "journal-unavailable")
        self.assertEqual((len(self.remote.requests), self.port.writes), before)

    def test_identical_payload_new_native_revision_refuses_stale_reused_ack(self):
        self.allocate()
        stale = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        before = self.port.snapshot
        self.port.replace_version_allocations(before.revision, before.payload)
        current = self.port.snapshot
        self.assertEqual(current.payload, before.payload)
        result = self.allocate(journal=stale)
        self.assertEqual((result.status, result.reason), ("recovery-required", "journal-unavailable"))
        self.assertIsNone(result.reservation)
        self.assertEqual(self.port.snapshot, current)
        self.assertEqual(len(self.remote.writes), 1)
        with self.assertRaises(a.VersionAllocationError):
            stale.selected_candidate(self.authority)

    def test_each_local_enrollment_retains_own_resolved_candidate_and_new_selection(self):
        other_request = request(candidate="00000000-0000-4000-8000-000000000009")
        other = s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT)
        other.enroll_authority(self.authority, self.checkpoint)
        other.select_candidate(self.authority, other_request)
        first = self.allocate(journal=s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT))
        second = self.allocate(journal=s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT),
                               selected=other_request)
        self.assertEqual((first.status, second.status), ("reserved", "reserved"))
        for local, result in ((LOCAL_PROJECT, first), (OTHER_LOCAL_PROJECT, second)):
            restarted = s.NativeAllocationJournal(self.port, local_project_id=local)
            self.assertEqual(restarted.selected_candidate(self.authority).reservation, result.reservation)
        restarted = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        before = s.AllocationState.parse(self.port.snapshot.payload)
        following = request(candidate="00000000-0000-4000-8000-00000000000a")
        restarted.select_candidate(self.authority, following, previous_candidate_id=CANDIDATE)
        after = s.AllocationState.parse(self.port.snapshot.payload)
        self.assertEqual(after.candidate(OTHER_LOCAL_PROJECT), before.candidate(OTHER_LOCAL_PROJECT))
        self.assertEqual(after.authorities, before.authorities)
        self.assertEqual(self.remote.ledger.reservations, (first.reservation, second.reservation))

    def test_unresolved_shared_pending_blocks_new_selection_for_every_local_enrollment(self):
        self.remote.write_mode = "timeout-before"
        self.assertEqual(self.allocate().status, "recovery-required")
        other = s.NativeAllocationJournal(self.port, local_project_id=OTHER_LOCAL_PROJECT)
        other.enroll_authority(self.authority, self.checkpoint)
        current = s.NativeAllocationJournal(self.port, local_project_id=LOCAL_PROJECT)
        before = self.port.snapshot
        following = request(candidate="00000000-0000-4000-8000-000000000009")
        for journal, previous in ((current, CANDIDATE), (other, None)):
            with self.assertRaises(a.VersionAllocationError):
                journal.select_candidate(self.authority, following, previous_candidate_id=previous)
        with self.assertRaises(a.VersionAllocationError):
            other.select_candidate(self.authority, request(), reconcile_pending=True)
        self.assertEqual(self.port.snapshot, before)

    def test_schema2_pending_is_readonly_unowned_until_explicit_exact_reconcile_selection(self):
        state = s.AllocationState((s.AuthorityState(self.authority, self.checkpoint, self.pending()),),
                                  (s.ProjectEnrollment(LOCAL_PROJECT, self.authority.project_id),))
        row = state.value(); row.pop("candidates"); row["schemaVersion"] = 2
        raw = p.canonical(row) + b"\n"
        port = NativePortFixture(); port.snapshot = s.NativeStateSnapshot(7, raw)
        journal = s.NativeAllocationJournal(port, local_project_id=LOCAL_PROJECT)
        self.assertEqual((port.writes, port.snapshot.payload), (0, raw))
        self.assertEqual(s.AllocationState.parse(raw).candidates, ())
        for invalid in (b" " + raw, raw + b"\n", p.canonical({**row, "candidates": []}) + b"\n"):
            with self.assertRaises(a.VersionAllocationError):
                s.AllocationState.parse(invalid)
        with self.assertRaises(a.VersionAllocationError):
            journal.select_candidate(self.authority, request())
        with self.assertRaises(a.VersionAllocationError):
            journal.select_candidate(self.authority, request(increment="major"), reconcile_pending=True)
        self.assertEqual(port.writes, 0)
        journal.select_candidate(self.authority, request(), reconcile_pending=True)
        saved = s.AllocationState.parse(port.snapshot.payload)
        self.assertEqual(saved.authorities, state.authorities)
        self.assertEqual(saved.enrollments, state.enrollments)
        self.assertEqual(saved.candidate(LOCAL_PROJECT).request, request())
        self.assertEqual(self.allocate(journal=journal).reason, "pending-unresolved")
        self.assertEqual(self.remote.writes, [])

    def test_candidate_rows_are_closed_unique_enrolled_bounded_and_reservation_bound(self):
        self.allocate()
        state = s.AllocationState.parse(self.port.snapshot.payload)
        row = state.value(); candidate = row["candidates"][0]
        bad_reservation = {**candidate["reservation"], "requestSha256": "f" * 64}
        for candidates in ([candidate, candidate], [{**candidate, "extra": True}],
                           [{**candidate, "localProjectId": OTHER_LOCAL_PROJECT}],
                           [{**candidate, "localProjectId": "0" * 32}],
                           [{**candidate, "request": request(increment="major").value()}],
                           [{**candidate, "reservation": bad_reservation}],
                           [candidate] * (s.MAX_CANDIDATES + 1)):
            with self.subTest(rows=len(candidates)), self.assertRaises(a.VersionAllocationError):
                s.AllocationState.parse(p.canonical({**row, "candidates": candidates}) + b"\n")
        # Exercise the actual largest row/rule counts, not a source-text test.
        rules = tuple(p.RefRule(f"refs/heads/release-{i}", "build") for i in range(p.MAX_RULES))
        policy = p.VersionPolicy("automatic", rules)
        locals_ = tuple(f"{index:032x}" for index in range(1, s.MAX_CANDIDATES + 1))
        requests = tuple(request(candidate=f"00000000-0000-4000-8000-{index:012x}", version_policy=policy)
                         for index in range(1, s.MAX_CANDIDATES + 1))
        maximum = s.AllocationState((s.AuthorityState(self.authority, self.checkpoint),),
            tuple(s.ProjectEnrollment(local, self.authority.project_id) for local in locals_),
            tuple(s.SelectedCandidate(local, selected) for local, selected in zip(locals_, requests)))
        self.assertEqual(s.AllocationState.parse(maximum.to_bytes()), maximum)


if __name__ == "__main__":
    unittest.main()
