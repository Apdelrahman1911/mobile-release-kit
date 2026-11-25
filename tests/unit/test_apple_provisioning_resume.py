"""Existing complete worker with its inert provider/C-A-W fixtures only.

These checks do not run Ruby, OpenSSL, an Apple account or native state.
The native Store reopen/projection regression is separately in its real crate.
"""
import copy
import unittest

from . import test_desktop_apple_provisioning as original


class AppleResumeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = original.BundleWorkerTests()

    def test_restored_attempt_denied_partial_or_contradictory_read_is_never_absence(self):
        for fault, observation in (("denied", "not-permitted"), ("incomplete-page", "inconclusive"),
                                   ("truncated-body", "inconclusive"), ("foreign-identifier", "inconclusive")):
            with self.subTest(fault=fault):
                terminal, frames, calls, engine = self.fixture.execute(mode="reconcile", fault=fault)
                self.assertEqual(terminal["outcome"], "complete")  # Synthetic original joins, not native qualification.
                self.assertEqual(terminal["result"]["observation"], observation)
                self.assertEqual(terminal["result"]["comparison"], "inconclusive")
                self.assertEqual(terminal["result"]["decision"], "comparison-only")
                self.assertIsNone(terminal["result"]["attempt"])
                self.assertEqual([frame["kind"] for frame in frames], ["accepted", "observed", "terminal"])
                self.assertEqual(len(calls), 7)
                self.assertIsNone(engine.input._pending_ack)
                row = engine.service.request.native["prior"]
                self.assertTrue(row["sendArmed"])
                self.assertEqual(row["nativeSettlement"], "unknown")
                self.assertEqual(row["attempt"]["record"]["status"], "unknown")

    def test_matching_readback_does_not_change_restored_disposition_or_enable_a_write(self):
        terminal, frames, calls, engine = self.fixture.execute(mode="reconcile")
        self.assertEqual(terminal["result"]["comparison"], "same-response")
        self.assertEqual(terminal["result"]["decision"], "comparison-only")
        self.assertIsNone(terminal["result"]["attempt"])
        self.assertEqual(len(calls), 7)
        self.assertFalse(any(frame["kind"] in {"pending", "attempt"} for frame in frames))
        self.assertEqual(engine.service.request.native["prior"]["nativeSettlement"], "unknown")
        self.assertEqual(engine.service.request.native["prior"]["attempt"]["record"]["status"], "unknown")
        self.assertIsNone(engine.input._pending_ack)

    def test_foreign_account_or_changed_reference_never_enters_the_fixed_worker(self):
        with self.fixture.files() as (_, root, runtime):
            value = original.request(root, runtime, "reconcile")
            value["native"]["prior"] = original.prior(value)
            self.assertIsNotNone(original.wire.parse_request(original.encode(value)))
            for field in ("account", "reference", "target"):
                bad = copy.deepcopy(value)
                if field == "account":
                    bad["native"]["provisioning"]["accountRef"] = "0" * 64
                elif field == "reference":
                    bad["context"]["reference"]["ownerGeneration"] = "0" * 32
                else:
                    bad["context"]["displayName"] = bad["native"]["target"]["displayName"] = "Changed label"
                with self.subTest(field=field), self.assertRaises(original.wire.ProtocolError):
                    original.wire.parse_request(original.encode(bad))
