"""Actual private worker composition with inert Git/HTTP/ACK substitutes.

Real own-temp Reader/Invocation scopes, real finite allocator/journal dialogue.
The existing synthetic C/A/W outcomes are NOT native proof. No commands, sockets,
credentials, user projects or native provider calls run in these tests.
"""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_version_allocation_protocol as wire
from mobile_release import _desktop_version_allocation_runtime as runtime
from mobile_release import desktop_version_reserve as worker
from mobile_release import ios_store_versions as inventory
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_source as source
from mobile_release import version_allocation_state as state
from mobile_release import version_policy as policy
from mobile_release.config import default_config_data
from test_version_allocation import COMMIT, IDENTITY, NOW, Repository, initial, request
from test_version_allocation_source import SourceFixture
from test_version_allocation_state import LOCAL_PROJECT, NativePortFixture


class ReserveFixture(SourceFixture):
    def __init__(self, root):
        super().__init__(root)
        self.data = default_config_data({"ios": {"bundleId": "com.example.inert"}})
        self.data["source"]["localStoreEnabled"] = False
        self.data["ios"]["appStoreAppId"] = "17"
        self.save()
        self.ledger, self.authority = initial()
        self.selected = request(source=self.binding(), enabled_platforms=("ios",),
            version_policy=policy.VersionPolicy("automatic", (policy.RefRule("refs/heads/main", "build"),),
                                                store_scope=inventory.POLICY_SCOPE), store_context_revision="9" * 64)
        self.native = NativePortFixture()
        self.native_journal = state.NativeAllocationJournal(self.native, local_project_id=LOCAL_PROJECT)
        self.native_journal.enroll_authority(self.authority, allocation.Checkpoint(0, self.ledger.head_sha256, COMMIT))
        self.native_journal.select_candidate(self.authority, self.selected)
        self.repository = Repository(self.ledger, self.authority)
        self.observation = inventory.CurrentInventory(IDENTITY, "9" * 64, "8" * 64, NOW, 7, "1.2.3", (1, 0, 0))
        self.sequence = 0
        self.cut = None
        self.fin = None

    def initial(self):
        return wire.encoded({"protocol": wire.NATIVE_PROTOCOL, "id": "reserve-1", "action": {
            "kind": "reserve", "localProjectId": LOCAL_PROJECT, "authority": self.authority.value(),
            "accountId": "17", "candidateId": self.selected.candidate_id, "requestSha256": self.selected.sha256,
            "clock": self.clock(), "source": self.source_request().value(), "provider": self.provider_value()}}, wire.INITIAL_LIMIT)

    def _write(self, fd, raw):
        if fd != self.OUTPUT:
            return self.real_write(fd, raw)
        count = min(43, len(raw))
        self.outgoing.extend(raw[:count])
        if b"\n" not in self.outgoing:
            return count
        row = wire.frame(bytes(self.outgoing), wire.FIN_LIMIT)
        self.outgoing.clear()
        self.frames.append(row)
        assert row["protocol"] == wire.NATIVE_PROTOCOL
        if "ready" in row:
            self.incoming.extend(wire.encoded({"protocol": wire.NATIVE_PROTOCOL, "id": row["id"], "go": {
                "requestSha256": row["ready"]["requestSha256"], "token": "INERT-not-a-credential",
                "request": self.selected.value(), "observations": [self.observation.value()],
                "state": {"revision": self.native.snapshot.revision,
                          "payload": base64.b64encode(self.native.snapshot.payload).decode("ascii")}}}, wire.GO_LIMIT))
        elif "finished" in row:
            self.before_fin(source._RETAINED[-1])
            self.fin = row["finished"]
            self.eof = True
        else:
            step = row["state"]
            self.sequence += 1
            assert step["sequence"] == self.sequence and step["expectedRevision"] == self.native.snapshot.revision
            change = step["transition"]
            kind = change["kind"]
            if kind == "checkpoint":
                self.native_journal.record_checkpoint(self.authority, allocation.Checkpoint.parse(change["checkpoint"]))
            elif kind in {"pending", "rejected", "resolved"}:
                pending = allocation.PendingAllocation.parse(policy.canonical(change["pending"]) + b"\n")
                if kind == "pending":
                    self.native_journal.record_pending(pending)
                elif kind == "rejected":
                    self.native_journal.mark_rejected(pending)
                else:
                    self.native_journal.mark_resolved(pending, allocation.Checkpoint.parse(change["checkpoint"]))
            else:
                assert kind == "reused"
                self.native_journal.record_reused(self.authority, allocation.Reservation.parse(change["reservation"]),
                                                allocation.Checkpoint.parse(change["checkpoint"]))
            assert hashlib.sha256(self.native.snapshot.payload).hexdigest() == step["payloadSha256"]
            self.events.append("native-" + kind + "-ack")
            if kind == "pending" and self.cut == "lost-pending-ack":
                self.eof = True
                return count
            if kind == "pending" and self.cut == "source-after-pending":
                self.status = b"?? changed-before-put.txt\0"
            self.incoming.extend(wire.encoded({"protocol": wire.NATIVE_PROTOCOL, "id": row["id"], "ack": {
                "requestSha256": step["requestSha256"], "sequence": self.sequence,
                "revision": self.native.snapshot.revision, "payloadSha256": step["payloadSha256"],
                "effect": "committed", "durability": "durable", "cleanup": "settled"}}, wire.ACK_LIMIT))
        return count

    def run(self):
        with self.mocks(), patch.object(runtime.time, "time", lambda: NOW), \
             patch.object(runtime, "_make_allocation_transport", return_value=self.repository) as factory:
            self.factory = factory
            worker.run_owned(self.CONTROL, self.OUTPUT, self.initial(), started=10.0, runtime_dir="/inert/runtime")


class DesktopVersionReserveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-version-reserve-inert-")
        root = Path(self.tmp.name) / "project"
        root.mkdir()
        self.f = ReserveFixture(root)
        self.retained = len(source._RETAINED)

    def tearDown(self):
        del source._RETAINED[self.retained:]
        self.tmp.cleanup()

    def test_actual_source_pending_ack_put_final_source_then_closed_fin(self):
        f = self.f
        def before_put():
            self.assertEqual(f.events[-2:], ["native-pending-ack", "status"])
            self.assertEqual(len(f.calls), 7)
            self.assertIsNotNone(state.AllocationState.parse(f.native.snapshot.payload).selected(f.authority).pending)
        f.repository.hooks["write"] = before_put
        def before_fin(call):
            self.assertTrue(call.operation.originals_closed())
            self.assertTrue(call.input.borrow_ended)
            self.assertEqual(call.guard.handler_state, "RESTORED")
            self.assertEqual(call.operation.binding, f.selected.source)
        f.before_fin = before_fin
        f.run()
        self.assertEqual((len(f.repository.writes), len(f.calls), f.control_closes), (1, 8, 0))
        self.assertEqual(f.fin["outcome"]["status"], "reserved")
        self.assertEqual(f.fin["outcome"]["reservation"]["version"], {"name": "1.2.3", "build": 8})
        self.assertEqual(f.fin["source"], f.selected.source.value())
        self.assertIsNone(f.fin["firstFailureNs"])
        self.assertEqual(f.fin["lifetime"]["commands"], 8)

    def test_source_change_after_pending_ack_vetoes_put_and_keeps_same_intent(self):
        f = self.f
        f.cut = "source-after-pending"
        f.run()
        self.assertEqual(len(f.repository.writes), 0)
        self.assertEqual(f.fin["outcome"]["status"], "recovery-required")
        self.assertIsNone(f.fin["source"])
        self.assertIsNotNone(f.fin["firstFailureNs"])
        pending = state.AllocationState.parse(f.native.snapshot.payload).selected(f.authority).pending
        self.assertEqual(pending.reservation.request, f.selected)

    def test_source_change_after_put_never_publishes_reserved_edit_or_recycles(self):
        f = self.f
        f.repository.hooks["ref-after"] = lambda: setattr(f, "status", b"?? changed-after-put.txt\0")
        f.run()
        self.assertEqual(len(f.repository.writes), 1)
        self.assertEqual(f.fin["outcome"]["status"], "recovery-required")
        self.assertIsNone(f.fin["source"])
        candidate = state.AllocationState.parse(f.native.snapshot.payload).candidate(LOCAL_PROJECT)
        self.assertEqual(candidate.reservation.request, f.selected)
        self.assertEqual(candidate.reservation.version.build, 8)

    def test_lost_pending_ack_cannot_put_or_produce_clean_fin(self):
        f = self.f
        f.cut = "lost-pending-ack"
        with self.assertRaises(BaseException):
            f.run()
        self.assertEqual(len(f.repository.writes), 0)
        self.assertIsNone(f.fin)
        self.assertEqual(state.AllocationState.parse(f.native.snapshot.payload).selected(f.authority)
                         .pending.reservation.request, f.selected)

    def test_native_selector_is_explicit_and_no_legacy_or_arbitrary_provider_promotion(self):
        f = self.f
        row = wire.frame(f.initial(), wire.INITIAL_LIMIT)
        parsed = wire.parse_initial(f.initial())
        self.assertEqual(parsed.source, f.source_request())
        for field, value in (("protocol", wire.PROTOCOL), ("provider", {"kind": "/usr/bin/git"}),
                             ("provider", {"kind": "macos-clt-git/1", "native": {}})):
            changed = dict(row)
            changed["action"] = dict(row["action"])
            if field == "protocol":
                changed[field] = value
            else:
                changed["action"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                wire.parse_initial(wire.encoded(changed, wire.INITIAL_LIMIT))

    def test_original_native_clock_not_source_completion_supplies_http_budget(self):
        f = self.f
        # Original native admission started before worker launch. All stages
        # share workEnd=65, not a fresh worker10+60 or source-finished+60.
        f.clock = lambda: {"name": "CLOCK_UPTIME_RAW", "workEndNs": "65000000000", "hardEndNs": "75000000000"}
        f.after_command = lambda run: setattr(f, "now", f.now + 0.25)
        f.run()
        self.assertLessEqual(f.factory.call_args.kwargs["started"], 5.0)
        self.assertEqual(len(f.repository.writes), 1)


if __name__ == "__main__":
    unittest.main()
