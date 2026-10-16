"""Actual package owners with inert native/key boundaries; no Apple service."""
from pathlib import Path
import tempfile
import unittest

import test_macos_installed_staging as staging

TOOL, API = staging.TOOL, staging.ANDROID_HELPER


class LauncherPackaging(unittest.TestCase):
    def test_nested_launcher_gets_own_ticket_in_same_submission_or_refuses(self):
        helper = staging.MacAndroidHelperPackagingData()
        cases = ((TOOL.ARM_TARGET, None), (TOOL.INTEL_TARGET, None),
                 (TOOL.ARM_TARGET, ("nonzero", "validate-launcher")),
                 (TOOL.ARM_TARGET, "signed-byte-change"),
                 (TOOL.ARM_TARGET, "ticket-extra"))
        for target, failure in cases:
            with self.subTest(target=target, failure=failure), tempfile.TemporaryDirectory() as temporary:
                state = helper.notary_fixture(Path(temporary), target=target, failure=failure, launcher=True)
                operation = state.operation
                original = (state.app / TOOL.LAUNCHER_EXECUTABLE).read_bytes()
                with helper.notary_fixture_call(state):
                    if failure is None:
                        try:
                            operation.execute()
                        except API.Refused:
                            self.fail(str(operation.receipt.get("failure")))
                    else:
                        with self.assertRaises(API.Refused):
                            operation.execute()
                self.assertEqual(operation.receipt["passed"], failure is None)
                self.assertEqual(sum(role == "payload-submit" for role, _ in state.observations), 1)
                self.assertEqual(operation.receipt["notaryAuthentication"],
                                 {"created": True, "closed": True, "retired": True})
                if failure is None:
                    roles = tuple(role for role, _ in state.observations)
                    self.assertEqual(roles, API.notary_roles(True))
                    self.assertEqual(len(roles), 17)
                    tickets = operation.receipt["payloadNotarization"]["tickets"]
                    self.assertEqual(tuple(row["path"] for row in tickets), API.notary_tickets(True))
                    self.assertEqual(len(tickets), 3)
                    self.assertEqual((state.app / TOOL.LAUNCHER_EXECUTABLE).read_bytes(), original)
                    for row in tickets:
                        self.assertEqual(TOOL.digest((operation.work / "input/app" / row["path"]).read_bytes()), row["sha256"])
                    self.assertTrue(operation.receipt["originalClosesKnown"] and operation.receipt["targetRetired"])
                else:
                    self.assertFalse(operation.notary_complete)
                    self.assertFalse((operation.work / "input").exists())

    def test_launcher_ticket_cannot_be_replaced_by_outer_or_legacy_pair(self):
        paths = API.notary_tickets(True)
        app = {name: (name.encode(), 0o444) for name in paths}
        rows = [{"path": name, "bytes": len(body), "sha256": TOOL.digest(body)} for name, (body, _) in app.items()]
        self.assertEqual(TOOL.ticket_input_names(app, rows, launcher=True), set(paths))
        for invalid in (rows[:2], [*rows[:2], rows[0]], [rows[2], *rows[:2]]):
            with self.assertRaises(TOOL.Refused):
                TOOL.ticket_input_names(app, invalid, launcher=True)
        self.assertEqual(TOOL.ticket_input_names(app, rows[:2]), set(paths[:2]))
        with self.assertRaises(TOOL.Refused):
            TOOL.ticket_input_names(app, rows)


if __name__ == "__main__":
    unittest.main()
