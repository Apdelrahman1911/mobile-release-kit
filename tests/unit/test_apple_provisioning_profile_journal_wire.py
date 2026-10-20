"""Closed cross-family journal DATA; no provider, filesystem or native owner.

Run against the complete original Python modules after the companion Root
hook. The new journal's local-save uncertainty must block the unchanged Bundle
planner without making a profile record valid in its old Attempt grammar.
"""
from datetime import datetime, timezone
import unittest

from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release.apple_provisioning import BUNDLE_ID_SCOPE, Observation, ProvisioningContext, ProvisioningTarget
from mobile_release.apple_provisioning_bundle_registration import prepare_bundle
from mobile_release.apple_provisioning_recovery import AttemptRecord
from mobile_release.apple_provisioning_api import ProvisioningError


class ProfileJournalFenceTests(unittest.TestCase):
    def setUp(self):
        self.account = "a" * 64
        self.context = ProvisioningContext("fixture", "native-client", "1" * 32, 1, self.account, "record", 1, 1)
        self.target = ProvisioningTarget("com.example.fixture", "TESTTEAM01", "TESTTEAM01", "Fixture", False)
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.before = Observation(self.context, self.target.bundle_id, self.now, True, "observed", scope=BUNDLE_ID_SCOPE)

    def row(self, *, status="unknown", native="known", action="profile_setup", operation="2" * 32):
        return {"accountRef": self.account, "operationId": operation, "action": action,
                "status": status, "nativeSettlement": native}

    def plan(self, rows):
        return prepare_bundle(self.context, self.target, self.before,
                              pending=wire.pending(rows, self.account), now=self.now)

    def test_known_native_join_does_not_erase_profile_save_unknown(self):
        rows = [self.row()]
        pending = wire.pending(rows, self.account)
        self.assertTrue(pending[0].unresolved)
        self.assertEqual(self.plan(rows).action, "reconcile")
        self.assertEqual(self.plan(rows).reason, "earlier_account_operation_unresolved")
        self.assertIsNone(self.plan(rows).request)

    def test_profile_terminal_still_needs_native_axis(self):
        for native in ("pending", "unknown"):
            with self.subTest(native=native):
                self.assertEqual(self.plan([self.row(status="succeeded", native=native)]).action, "reconcile")
        self.assertFalse(wire.pending([self.row(status="succeeded")], self.account)[0].unresolved)
        # This is only the existing pure DATA planner. It mints neither an
        # original review nor consent/native journal or a provider capability.
        self.assertEqual(self.plan([self.row(status="succeeded")]).action, "register_bundle_id")

    def test_profile_projection_is_closed_and_combined_census_is_bounded(self):
        for value in (self.row(status="failed"), self.row(status="cancelled"),
                      self.row(status="running"), self.row(action="create_profile"),
                      self.row(native="absent"), {**self.row(), "profileContent": "not accepted"},
                      {**self.row(), "accountRef": "b" * 64}):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, ProvisioningError)):
                    wire.pending([value], self.account)
        with self.assertRaises((ValueError, ProvisioningError)):
            wire.pending([self.row(), self.row()], self.account)
        rows = [self.row(operation=f"{index:032x}") for index in range(1, 33)]
        self.assertEqual(len(wire.pending(rows, self.account)), 32)
        with self.assertRaises((ValueError, ProvisioningError)):
            wire.pending(rows + [self.row(operation="f" * 32)], self.account)

    def test_bundle_attempt_grammar_does_not_accept_profile_action(self):
        record = AttemptRecord(self.context, "3" * 64, "register_bundle_id", "running", "readback_required", True)
        original = wire.attempt_wire(record)
        self.assertEqual(wire.attempt(original, self.context, "3" * 64), record)
        with self.assertRaises((ValueError, ProvisioningError)):
            wire.attempt({**original, "action": "create_profile"}, self.context, "3" * 64)


if __name__ == "__main__":
    unittest.main()
