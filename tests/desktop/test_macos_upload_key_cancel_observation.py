"""Cancellation-report DATA only; no keygen, native owners, IO or credentials.

Reuse the existing full parser and finite metadata port. These cases cannot
qualify actual Mac cancellation, keystore recovery, native joins or backup.
"""
from copy import deepcopy
import unittest

from test_macos_upload_key_observation import (
    U, M, BINDING, CASE, BEFORE, AFTER, MetadataPort, captured, producer,
    report as original_report, stopped,
)


def cancelled(case):
    false = {"recorded", "published", "nativeUseRetained", "privateRetained", "documentUnknown"}
    if case == BEFORE:
        false.add("authenticatedNew")
    return {**{key: key not in false for key in U.SAMPLE_FLAGS}, "operationId": 5,
            "checkpoint": "before-go" if case == BEFORE else "after-new-before-journal",
            "stoppedPreferenceRevision": 3 if case == BEFORE else None,
            "producer": None if case == BEFORE else producer(), "retainedProducer": None}


def report(case):
    value = original_report()
    value.update(testResult="cancelled-cleanup", generated=cancelled(case),
                 authenticatedReopenReadback=case == AFTER, stoppedIntentAcknowledged=case == BEFORE)
    return value


class UploadKeyCancelObservationTests(unittest.TestCase):
    def refused(self, fn, *args):
        with self.assertRaises((ValueError, M.Refused)):
            fn(*args)

    def test_two_cancelled_cases_are_exact_reports_not_generation_success(self):
        for case in (BEFORE, AFTER):
            value = report(case)
            self.assertIs(U.report(value, case), value)
            self.refused(U.positive, value["generated"])
            self.refused(U.report, value, CASE)
            frame = M.expected_result(BINDING, case)
            frame["vaultHelper"] = value
            self.assertEqual(M.parse_result(captured(frame), b"", BINDING, case), frame)
            self.assertFalse(value["automaticallyAssigned"])
            self.assertFalse(value["backupCreated"])

    def test_every_original_cleanup_axis_and_exact_case_is_required(self):
        for case in (BEFORE, AFTER):
            value = cancelled(case)
            for flag in U.SAMPLE_FLAGS:
                changed = deepcopy(value)
                changed[flag] = not changed[flag]
                self.refused(U.cancelled, changed, case)
            for field, replacement in (("retainedProducer", producer()),
                                       ("operationId", True), ("operationId", 6),
                                       ("checkpoint", "none")):
                changed = deepcopy(value)
                changed[field] = replacement
                self.refused(U.cancelled, changed, case)
            self.refused(U.cancelled, value, AFTER if case == BEFORE else BEFORE)
            self.refused(U.cancelled, value, CASE)
        for revision in (None, True, 0, -1, "3", 2**64):
            value = cancelled(BEFORE)
            value["stoppedPreferenceRevision"] = revision
            self.refused(U.cancelled, value, BEFORE)

    def test_transient_stopped_or_unknown_data_never_passes(self):
        for case in (BEFORE, AFTER):
            value = report(case)
            value["generated"] = stopped(case)["sample"]
            self.refused(U.report, value, case)
            self.refused(U.cancelled, value["generated"], case)
        value = cancelled(AFTER)
        value["producer"]["cleanupUnknown"] = True
        self.refused(U.cancelled, value, AFTER)
        value = cancelled(BEFORE)
        value["producer"] = producer()
        self.refused(U.cancelled, value, BEFORE)

    def test_acknowledgement_readback_and_original_counts_cannot_be_swapped(self):
        for case in (BEFORE, AFTER):
            for field in ("authenticatedReopenReadback", "stoppedIntentAcknowledged"):
                value = report(case)
                value[field] = not value[field]
                self.refused(U.report, value, case)
            for count in (5, 8, 10, True):
                value = report(case)
                value["originalCount"] = count
                self.refused(U.report, value, case)
            value = report(case)
            value["testResult"] = "positive"
            self.refused(U.report, value, case)
        missing = original_report(missing=True)
        missing["stoppedIntentAcknowledged"] = True
        self.refused(U.report, missing, BEFORE)

    def test_no_go_has_shared_state_without_key_after_new_preserves_one_key(self):
        for case in (BEFORE, AFTER):
            fixture = MetadataPort(case=case, generated=case == AFTER, host_started=True)
            value = U.readback(fixture, case, report(case))
            self.assertEqual(value["uploadKeyOutput"]["newEncryptedRecordPresent"], case == AFTER)
            self.assertTrue(value["uploadKeyOutput"]["referenceNamespacePresent"])
            self.assertFalse(value["uploadKeyOutput"]["privateContentsExported"])
            self.assertEqual(fixture.vault_completed, {case})
            self.assertEqual(fixture.active, set())
            self.assertEqual(len(fixture.opened), len(fixture.closed))

    def test_wrong_roster_and_unknown_return_never_complete_recovery(self):
        for case, generated, host in ((BEFORE, True, True), (BEFORE, False, False),
                                      (AFTER, False, True)):
            fixture = MetadataPort(case=case, generated=generated, host_started=host)
            self.refused(U.readback, fixture, case, report(case))
            self.assertEqual(fixture.vault_completed, set())
            self.assertEqual(fixture.active, set())
        fixture = MetadataPort(case=BEFORE, generated=False, host_started=True)
        fixture.inflight = True
        self.refused(U.readback, fixture, BEFORE, report(BEFORE))
        self.assertEqual(fixture.opened, [])
        self.assertEqual(fixture.reads, [])


if __name__ == "__main__":
    unittest.main()
