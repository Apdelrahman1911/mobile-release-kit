"""Synthetic FD/HTTP/native-ACK DATA checks, NOT native durability/finality."""
from __future__ import annotations

import base64
import hashlib
import unittest
from contextlib import ExitStack
from dataclasses import replace
from unittest.mock import patch

from mobile_release import _desktop_version_allocation_protocol as w
from mobile_release import _desktop_version_allocation_runtime as r
from mobile_release import version_allocation as a
from mobile_release import version_allocation_state as s
from mobile_release import version_policy as p

from test_version_allocation import COMMIT, NOW, Repository, initial, observations, request
from test_version_allocation_state import LOCAL_PROJECT, NativePortFixture


class DialogueFixture:
    """Inert native ACKs and fake descriptors. No subprocess/socket/filesystem."""
    def __init__(self, *, pending=False, remote_existing=False):
        self.ledger, self.authority = initial()
        self.request = request()
        self.native = NativePortFixture()
        self.journal = s.NativeAllocationJournal(self.native, local_project_id=LOCAL_PROJECT)
        self.journal.enroll_authority(self.authority, a.Checkpoint(0, self.ledger.head_sha256, COMMIT))
        self.journal.select_candidate(self.authority, self.request)
        after = self.ledger.append(self.request, observations(), now=NOW)
        if pending:
            self.journal.record_pending(a.PendingAllocation(self.authority, self.journal.checkpoint(self.authority),
                a.blob_sha(self.ledger.to_bytes()), after.reservations[-1]))
        self.repository = Repository(self.ledger, self.authority)
        if pending or remote_existing:
            self.repository.commit(after.to_bytes())  # Preserve the anchored genesis/actual ancestry.
        self.raw_initial = w.encoded({"protocol": w.PROTOCOL, "id": "allocation-1", "action": {
            "kind": "reconcile" if pending else "reserve", "localProjectId": LOCAL_PROJECT,
            "authority": self.authority.value(), "accountId": "17", "candidateId": self.request.candidate_id,
            "requestSha256": self.request.sha256,
            "clock": {"name": "CLOCK_UPTIME_RAW", "workEndNs": "70000000000", "hardEndNs": "80000000000"}}}, w.INITIAL_LIMIT)
        self.initial = w.parse_initial(self.raw_initial)
        self.go = {"protocol": w.PROTOCOL, "id": self.initial.id, "go": {"requestSha256": self.initial.digest,
            "token": "INERT-not-a-credential", "request": self.request.value(),
            "state": {"revision": self.native.snapshot.revision,
                "payload": base64.b64encode(self.native.snapshot.payload).decode("ascii")},
            "observations": [] if pending else [item.value() for item in observations()]}}
        self.incoming = bytearray()
        self.outgoing = bytearray()
        self.frames = []
        self.eof = False
        self.now = 10.0
        self.raw_offset = 0
        self.cut = None
        self.sequence = 0
        self.registered = None
        self.fin = None
        self.ack_change = lambda value: value

    def _accept(self, raw):
        value = w.frame(raw, w.FIN_LIMIT)
        self.frames.append(value)
        if "ready" in value:
            self.incoming.extend(w.encoded(self.go, w.GO_LIMIT))
            return
        if "finished" in value:
            self.fin = value["finished"]
            self.eof = self.cut != "withhold-final-eof"
            return
        row = value["state"]
        self.sequence += 1
        assert row["sequence"] == self.sequence
        assert row["requestSha256"] == self.initial.digest
        assert row["expectedRevision"] == self.native.snapshot.revision
        change = w.transition(row["transition"], self.initial, self.request)
        self.registered = change  # Scheduling DATA only, not a native job claim.
        if self.cut == "registered-not-released":
            return
        if self.cut == "stale-cas":
            self.native.failure = "before"
        try:
            if change["kind"] == "checkpoint":
                self.journal.record_checkpoint(self.authority, a.Checkpoint.parse(change["checkpoint"]))
            elif change["kind"] == "pending":
                self.journal.record_pending(a.PendingAllocation.parse(p.canonical(change["pending"]) + b"\n"))
            elif change["kind"] == "rejected":
                self.journal.mark_rejected(a.PendingAllocation.parse(p.canonical(change["pending"]) + b"\n"))
            elif change["kind"] == "resolved":
                self.journal.mark_resolved(a.PendingAllocation.parse(p.canonical(change["pending"]) + b"\n"),
                    a.Checkpoint.parse(change["checkpoint"]))
            else:
                self.journal.record_reused(self.authority, a.Reservation.parse(change["reservation"]),
                    a.Checkpoint.parse(change["checkpoint"]))
        except a.VersionAllocationError:
            self.eof = True
            return
        assert self.native.snapshot.revision == row["expectedRevision"] + 1
        assert hashlib.sha256(self.native.snapshot.payload).hexdigest() == row["payloadSha256"]
        if self.cut == "after-cas-before-ack":
            self.eof = True
            return
        ack = {"protocol": w.PROTOCOL, "id": self.initial.id, "ack": {"requestSha256": self.initial.digest,
            "sequence": self.sequence, "revision": self.native.snapshot.revision, "payloadSha256": row["payloadSha256"],
            "effect": "committed", "durability": "durable", "cleanup": "settled"}}
        raw = w.encoded(self.ack_change(ack), w.ACK_LIMIT)
        if self.cut == "partial-ack":
            raw = raw[:-2]
        self.incoming.extend(raw)
        if self.cut in {"after-ack-before-put", "partial-ack"}:
            self.eof = True

    def write(self, fd, raw):
        assert fd == 4
        size = min(len(raw), 19)  # Exercise a real worker partial-write cursor.
        self.outgoing.extend(raw[:size])
        if b"\n" in self.outgoing:
            raw = bytes(self.outgoing)
            self.outgoing.clear()
            self._accept(raw)
        return size

    def read(self, fd, count):
        assert fd == 3 and count > 0
        if self.incoming:
            block = bytes(self.incoming[:min(count, 137)])
            del self.incoming[:len(block)]
            return block
        if self.eof:
            return b""
        raise BlockingIOError()

    def select(self, readers, writers, exceptional, timeout):
        ready = bool(readers and (self.incoming or self.eof))
        if not ready and not writers:
            self.now += timeout
        return (readers if ready else []), writers, []

    def run(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(r.os, "set_blocking"))
            stack.enter_context(patch.object(r.os, "read", self.read))
            stack.enter_context(patch.object(r.os, "write", self.write))
            stack.enter_context(patch.object(r.select, "select", self.select))
            stack.enter_context(patch.object(r.time, "monotonic", lambda: self.now))
            stack.enter_context(patch.object(r.time, "time", lambda: NOW + self.now - 10))
            stack.enter_context(patch.object(r.time, "CLOCK_UPTIME_RAW", 33, create=True))
            stack.enter_context(patch.object(r.time, "clock_gettime_ns", lambda clock: int(self.now * 1e9) + self.raw_offset))
            self.factory = stack.enter_context(patch.object(r, "_make_allocation_transport", return_value=self.repository))
            r.run_owned(3, 4, self.raw_initial, started=10.0, runtime_dir="/synthetic/runtime")

    def put_count(self):
        return len(self.repository.writes)


class DesktopVersionAllocationProtocolTests(unittest.TestCase):
    def test_initial_and_go_pin_exact_selected_request_enrollment_and_mode(self):
        f = DialogueFixture()
        go = w.parse_go(w.encoded(f.go, w.GO_LIMIT), f.initial)
        self.assertEqual(go.request, f.request)
        self.assertEqual(go.snapshot, f.native.snapshot)
        for kind in ("schema", "request", "enrollment", "reconcile"):
            row = p._object(w.frame(w.encoded(f.go, w.GO_LIMIT), w.GO_LIMIT), {"protocol", "id", "go"})
            initial = f.initial
            if kind == "schema":
                row["go"]["state"]["revision"] = True
            elif kind == "request":
                row["go"]["request"]["source"]["tree"] = "b" * 40
            elif kind == "enrollment":
                initial = replace(initial, local_project_id="b" * 32)
            else:
                initial = replace(initial, kind="reconcile")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                w.parse_go(w.encoded(row, w.GO_LIMIT), initial)

    def test_canonical_frames_reject_duplicates_extra_frames_and_giant_base64_before_decode(self):
        f = DialogueFixture()
        for raw in (f.raw_initial + b"\n", b" " + f.raw_initial,
                    f.raw_initial.replace(b'"protocol":', b'"protocol":"other","protocol":', 1)):
            with self.assertRaises(ValueError):
                w.parse_initial(raw)
        f.go["go"]["state"]["payload"] = "A" * (w.STATE_BASE64_LIMIT + 4)
        with patch.object(w.base64, "b64decode") as decode, self.assertRaises(ValueError):
            w.parse_go(w.encoded(f.go, w.GO_LIMIT), f.initial)
        decode.assert_not_called()

    def test_go_cap_accounts_for_token_json_escaping_without_widening_subfields(self):
        f = DialogueFixture()
        f.go["go"]["token"] = '\\"' * (w.TOKEN_LIMIT // 2)
        parsed = w.parse_go(w.encoded(f.go, w.GO_LIMIT), f.initial)
        self.assertEqual(len(parsed.token), w.TOKEN_LIMIT)
        f.go["go"]["token"] += "x"
        with self.assertRaises(ValueError):
            w.parse_go(w.encoded(f.go, w.GO_LIMIT), f.initial)

    def test_worker_transition_vocabulary_excludes_selection_and_reconcile_writes(self):
        f = DialogueFixture(pending=True)
        pending = f.journal.pending_for(f.authority, f.request.candidate_id)
        for change in ({"kind": "select", "request": f.request.value()}, {"kind": "enroll", "authority": f.authority.value()},
                       {"kind": "pending", "pending": pending.value()}, {"kind": "rejected", "pending": pending.value()}):
            with self.subTest(kind=change["kind"]), self.assertRaises(ValueError):
                w.transition(change, f.initial, f.request)
        with self.assertRaises(ValueError):
            w.state_frame(f.initial, f.request, 6, 4, "a" * 64, {"kind": "checkpoint", "checkpoint": pending.checkpoint.value()})

    def test_fin_cannot_promote_remote_reservation_without_exact_retained_local_row(self):
        f = DialogueFixture()
        after = f.ledger.append(f.request, observations(), now=NOW)
        outcome = a.AllocationOutcome("reserved", "none", after.reservations[-1],
            a.Checkpoint(1, after.head_sha256, "b" * 40), control=r._control())
        with self.assertRaises(ValueError):
            w.finish_frame(f.initial, f.request, outcome, sequence=0, snapshot=f.native.snapshot)
        f.journal.record_checkpoint(f.authority, outcome.checkpoint)
        f.journal.record_reused(f.authority, outcome.reservation, outcome.checkpoint)
        w.finish_frame(f.initial, f.request, outcome, sequence=2, snapshot=f.native.snapshot)
        for control in (r._control("cancelled"), r._control("expired"), r._control("unauthorized"),
                        r._control("response-invalid"), r._control("rate-limited", 5)):
            r._check_control(control)  # Valid shape does not make a successful reservation coherent.
            with self.subTest(reason=control["reason"]), self.assertRaises(ValueError):
                w.finish_frame(f.initial, f.request, replace(outcome, control=control),
                               sequence=2, snapshot=f.native.snapshot)


class DesktopVersionAllocationRuntimeTests(unittest.TestCase):
    def test_actual_worker_journal_waits_for_ack_before_put_and_resolution_before_fin(self):
        f = DialogueFixture()
        def before_put():
            row = s.AllocationState.parse(f.native.snapshot.payload).selected(f.authority)
            self.assertEqual(row.pending.reservation.request, f.request)
            self.assertEqual(f.native.events[-1], "native-ack")
        f.repository.hooks["write"] = before_put
        f.run()
        self.assertEqual(f.put_count(), 1)
        self.assertEqual(f.fin["outcome"]["status"], "reserved")
        self.assertEqual([row["state"]["transition"]["kind"] for row in f.frames if "state" in row],
                         ["pending", "checkpoint", "resolved"])
        retained = s.AllocationState.parse(f.native.snapshot.payload)
        self.assertEqual(retained.candidate(LOCAL_PROJECT).reservation.request, f.request)
        self.assertIsNone(retained.selected(f.authority).pending)
        self.assertEqual(f.fin["outcome"]["releaseEligibility"], "not-established")
        self.assertNotIn(b"INERT-not-a-credential", p.canonical(f.frames))

    def test_registered_unreleased_job_and_stop_after_cas_or_ack_never_put(self):
        for cut in ("registered-not-released", "after-cas-before-ack", "after-ack-before-put", "partial-ack", "stale-cas"):
            f = DialogueFixture(); f.cut = cut
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                f.run()
            self.assertEqual(f.put_count(), 0)
            self.assertIsNone(f.fin)
            self.assertEqual(f.sequence, 1)
            retained = s.AllocationState.parse(f.native.snapshot.payload).selected(f.authority)
            self.assertEqual(retained.pending is not None, cut not in {"registered-not-released", "stale-cas"})

    def test_stale_unknown_foreign_or_boolean_ack_cannot_put_or_repeat(self):
        for field, value in (("cleanup", "unknown"), ("durability", "unknown"), ("effect", "none"),
                             ("revision", 1), ("sequence", True), ("requestSha256", "b" * 64), ("payloadSha256", "b" * 64)):
            f = DialogueFixture()
            def corrupt(row):
                row["ack"][field] = value
                return row
            f.ack_change = corrupt
            with self.subTest(field=field), self.assertRaises(ValueError):
                f.run()
            self.assertEqual((f.sequence, f.put_count()), (1, 0))
            self.assertIsNotNone(s.AllocationState.parse(f.native.snapshot.payload).selected(f.authority).pending)

    def test_pending_restart_reconciles_read_only_and_retains_same_candidate(self):
        f = DialogueFixture(pending=True)
        original_id = f.request.candidate_id
        f.run()
        self.assertEqual(f.put_count(), 0)
        self.assertTrue(f.factory.call_args.kwargs["reconcile"])
        self.assertEqual(f.fin["outcome"]["status"], "reserved")
        self.assertEqual(s.AllocationState.parse(f.native.snapshot.payload).candidate(LOCAL_PROJECT).request.candidate_id, original_id)

    def test_remote_existing_reservation_has_its_own_reused_ack_not_a_checkpoint_substitute(self):
        f = DialogueFixture(remote_existing=True)
        f.run()
        self.assertEqual(f.put_count(), 0)
        self.assertEqual([row["state"]["transition"]["kind"] for row in f.frames if "state" in row], ["checkpoint", "reused"])
        self.assertIsNotNone(s.AllocationState.parse(f.native.snapshot.payload).candidate(LOCAL_PROJECT).reservation)

    def test_missing_or_stale_store_floor_never_constructs_live_transport(self):
        for value in ([], [replace(observations()[0], observed_at=NOW - 901).value()]):
            f = DialogueFixture(); f.go["go"]["observations"] = value
            f.run()
            f.factory.assert_not_called()
            self.assertEqual(f.fin["outcome"]["status"], "rejected")
            self.assertEqual(f.sequence, 0)

    def test_original_clock_regression_is_not_a_new_deadline_or_store_freshness(self):
        for clock in ("monotonic", "raw"):
            f = DialogueFixture(); f.now = 14.0
            def regress():
                if clock == "raw":
                    f.raw_offset = -1
                else:
                    f.now -= 0.1  # Still later than start, but before the last original sample.
            f.repository.hooks["repository-before"] = regress
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                f.run()
            self.assertEqual((f.sequence, f.put_count()), (0, 0))
            self.assertIsNone(f.fin)

    def test_fin_without_original_input_eof_does_not_finish_the_worker(self):
        f = DialogueFixture(); f.cut = "withhold-final-eof"
        with self.assertRaises(ValueError):
            f.run()
        self.assertIsNotNone(f.fin)  # Output DATA is not an original job return.
        self.assertLessEqual(f.now, 80.0)
        self.assertGreater(f.now, 79.9)  # Conservative nextafter never renews the native endpoint.


if __name__ == "__main__":
    unittest.main()
