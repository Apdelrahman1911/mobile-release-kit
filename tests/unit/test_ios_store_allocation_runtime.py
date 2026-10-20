"""v2 through the REAL fixed dialogue with inert FD/HTTP/native-state ports.

No provider call, subprocess, native receipt or filesystem durability is tested.
The reused fixture's ACK strings are synthetic, not native authority.
"""
import base64
import unittest
from dataclasses import replace

from mobile_release import _desktop_version_allocation_protocol as wire
from mobile_release import ios_store_versions as inventory
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_state as state
from mobile_release import version_allocation_transport as transport
from mobile_release import version_policy as policy
from test_desktop_version_allocation_runtime import DialogueFixture
from test_version_allocation import IDENTITY, NOW
from test_version_allocation_state import LOCAL_PROJECT


def fixture(*, pending=False):
    original = DialogueFixture()
    previous = original.request.candidate_id
    original.request = replace(original.request,
        candidate_id="00000000-0000-4000-8000-000000000005", enabled_platforms=("ios",),
        version_policy=policy.VersionPolicy("automatic", (policy.RefRule("refs/heads/main", "build"),),
                                            store_scope=inventory.POLICY_SCOPE),
        store_context_revision="9" * 64)
    original.journal.select_candidate(original.authority, original.request, previous_candidate_id=previous)
    observed_at = NOW - 1000 if pending else NOW
    observation = inventory.CurrentInventory(IDENTITY, "9" * 64, "a" * 64,
        observed_at, 12, "1.3.0", (1, 1, 0))
    if pending:
        after = original.ledger.append(original.request, (observation,), now=observed_at)
        original.journal.record_pending(allocation.PendingAllocation(original.authority,
            original.journal.checkpoint(original.authority), allocation.blob_sha(original.ledger.to_bytes()),
            after.reservations[-1]))
        original.repository.commit(after.to_bytes())
    initial = wire.frame(original.raw_initial, wire.INITIAL_LIMIT)
    initial["action"].update(kind="reconcile" if pending else "reserve",
        candidateId=original.request.candidate_id, requestSha256=original.request.sha256)
    original.raw_initial = wire.encoded(initial, wire.INITIAL_LIMIT)
    original.initial = wire.parse_initial(original.raw_initial)
    original.go["go"].update(requestSha256=original.initial.digest, request=original.request.value(),
        state={"revision": original.native.snapshot.revision,
               "payload": base64.b64encode(original.native.snapshot.payload).decode("ascii")},
        observations=[] if pending else [observation.value()])
    return original


class IOSStoreAllocationRuntimeTests(unittest.TestCase):
    def test_explicit_v2_worker_acks_same_candidate_then_only_one_conditional_write(self):
        original = fixture()

        def before_put():
            retained = state.AllocationState.parse(original.native.snapshot.payload)
            self.assertEqual(retained.selected(original.authority).pending.reservation.request, original.request)
            self.assertEqual(original.native.events[-1], "native-ack")
            self.assertEqual(original.frames[-1]["state"]["transition"]["kind"], "pending")

        original.repository.hooks["write"] = before_put
        original.run()
        self.assertEqual(original.put_count(), 1)
        self.assertEqual(original.fin["outcome"]["status"], "reserved")
        self.assertEqual(original.fin["outcome"]["reservation"]["version"], {"name": "1.3.0", "build": 13})
        self.assertEqual([row["state"]["transition"]["kind"] for row in original.frames if "state" in row],
                         ["pending", "checkpoint", "resolved"])
        retained = state.AllocationState.parse(original.native.snapshot.payload)
        self.assertEqual(retained.candidate(LOCAL_PROJECT).reservation.request, original.request)
        self.assertIsNone(retained.selected(original.authority).pending)
        self.assertEqual(original.repository.ledger.value()["schemaVersion"], 2)
        # The unchanged fixed GitHub body validator also accepts this precise
        # first v2 append over a v1 genesis; it still verifies the old blob CAS.
        write = original.repository.writes[0]
        transport.validate_body(transport.ROLE_LEDGER_WRITE, write.body, path=write.path)

    def test_stale_or_foreign_current_inventory_never_constructs_transport(self):
        for field, value in (("observedAt", NOW - 901), ("contextRevision", "b" * 64),
                             ("identityRevision", "b" * 64)):
            original = fixture()
            original.go["go"]["observations"][0][field] = value
            with self.subTest(field=field):
                original.run()
                original.factory.assert_not_called()
                self.assertEqual(original.fin["outcome"]["status"], "rejected")
                self.assertEqual((original.put_count(), original.sequence), (0, 0))
        for observations in ([], [{"platform": "ios", "scope": "application-all-builds"}]):
            original = fixture()
            original.go["go"]["observations"] = observations
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                original.run()
            original.factory.assert_not_called()
            self.assertEqual(original.put_count(), 0)

    def test_v2_pending_restart_is_read_only_without_fresh_inventory_or_renumbering(self):
        original = fixture(pending=True)
        pending = original.journal.pending_for(original.authority, original.request.candidate_id)
        self.assertLess(pending.reservation.store_observations[0].observed_at, NOW - 900)
        original.run()
        self.assertTrue(original.factory.call_args.kwargs["reconcile"])
        self.assertEqual(original.put_count(), 0)
        self.assertEqual(original.fin["outcome"]["reservation"], pending.reservation.value())
        self.assertEqual(original.fin["outcome"]["releaseEligibility"], "not-established")
        retained = state.AllocationState.parse(original.native.snapshot.payload)
        self.assertEqual(retained.candidate(LOCAL_PROJECT).reservation, pending.reservation)

    def test_stop_after_pending_cas_before_ack_retains_same_v2_intent_without_put(self):
        original = fixture()
        original.cut = "after-cas-before-ack"
        with self.assertRaises(ValueError):
            original.run()
        self.assertEqual(original.put_count(), 0)
        self.assertIsNone(original.fin)
        pending = state.AllocationState.parse(original.native.snapshot.payload).selected(original.authority).pending
        self.assertIsNotNone(pending)
        self.assertEqual(pending.reservation.request, original.request)
        self.assertEqual(pending.reservation.version.build, 13)


if __name__ == "__main__":
    unittest.main()
