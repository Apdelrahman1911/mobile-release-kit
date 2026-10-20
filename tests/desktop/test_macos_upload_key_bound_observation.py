"""AfterNEW report DATA only; no keygen, native Bind, Store or filesystem IO.

The real original observer must produce these fields. Literal parser fixtures
cannot qualify a BoundLoan, preference CAS, recovery, native cleanup or backup.
"""
from copy import deepcopy
import unittest

from test_macos_upload_key_cancel_observation import report
from test_macos_upload_key_observation import (
    U, M, BINDING, CASE, BEFORE, AFTER, captured, report as original_report,
)


class UploadKeyBoundObservationTests(unittest.TestCase):
    def refused(self, value, case=AFTER):
        with self.assertRaises((ValueError, M.Refused)):
            U.report(value, case)

    def test_explicit_bind_and_remember_are_separate_from_cancelled_generation(self):
        value = report(AFTER)
        self.assertIs(U.report(value, AFTER), value)
        frame = M.expected_result(BINDING, AFTER)
        frame["vaultHelper"] = value
        self.assertEqual(M.parse_result(captured(frame), b"", BINDING, AFTER), frame)
        self.assertEqual(value["originalCount"], 11)
        self.assertTrue(value["explicitlyBoundSavedKey"])
        self.assertTrue(value["rememberedBoundSavedKey"])
        self.assertEqual(value["testResult"], "cancelled-cleanup")
        self.assertTrue(value["generated"]["stopped"])
        self.assertTrue(value["generated"]["unassigned"])
        self.assertFalse(value["generated"]["recorded"])
        self.assertFalse(value["automaticallyAssigned"])
        self.assertFalse(value["backupCreated"])

    def test_old_readback_only_and_partial_or_untyped_steps_are_not_complete(self):
        old = report(AFTER)
        for field in U.AFTER_NEW_FIELDS:
            del old[field]
        old["originalCount"] = 9
        self.refused(old)
        for field in U.AFTER_NEW_FIELDS:
            for replacement in (False, 1, None, "true"):
                value = report(AFTER)
                value[field] = replacement
                self.refused(value)
            value = report(AFTER)
            del value[field]
            self.refused(value)
        for count in (5, 8, 9, 10, 12, True, "11"):
            value = report(AFTER)
            value["originalCount"] = count
            self.refused(value)
        value = report(AFTER)
        value["testResult"] = "positive"
        self.refused(value)

    def test_other_cases_and_missing_prerequisites_cannot_borrow_bound_claims(self):
        for case, value in ((CASE, original_report()), (BEFORE, report(BEFORE)),
                            (AFTER, original_report(missing=True))):
            self.assertIs(U.report(value, case), value)
            for field in U.AFTER_NEW_FIELDS:
                changed = deepcopy(value)
                changed[field] = True
                self.refused(changed, case)
        value = report(AFTER)
        value["privateKey"] = "not-a-key"
        self.refused(value)

    def test_quit_diagnostics_follow_actual_case_originals_without_becoming_finality(self):
        native = {"entered": True, "returned": True, "step": "Quit"}
        for case, valid, invalid in ((AFTER, 11, 9), (BEFORE, 9, 11), (CASE, 9, 11)):
            value = {"step": "Quit", "id": valid, "action": "quit-confirm",
                     "domain": "rust-precondition", "site": "original-usability", "error": "other"}
            panel = {"step": "Quit", "id": valid, "kind": "quit"}
            self.assertIs(M._native_action_context(value, native, panel, case=case), value)
            value["id"] = panel["id"] = invalid
            self.assertIsNone(M._native_action_context(value, native, panel, case=case))
            value["id"] = panel["id"] = 5
            self.assertIs(M._native_action_context(value, native, panel, case=case), value)
        for step in ("BindSaved", "BoundReadback", "BoundSaved", "BoundPrepare",
                     "RememberBound", "BoundRecoveryReadback"):
            output = f"MRK_MACOS_AQUA_FAILURE_STEP=UploadKey({step})\n".encode("ascii")
            self.assertEqual(M.failure_step(output, b""), f"UploadKey({step})")


if __name__ == "__main__":
    unittest.main()
