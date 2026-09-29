"""Inert saved-signing receipt predicates, NOT native qualification evidence.

All observations, IDs, fingerprints, file hashes and owner/finality flags are
invented DATA. These tests acquire no file/process/native owner, secret, tool,
GUI, fixture, network route or profile. Import of the exact source helper must
use the separately admitted focused loader; the historical native body is not
called. Actual saved UI signing and cancellation require genuine native runs.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

from mobile_release import _desktop_android_build_protocol as wire
from mobile_release.reporting import Report, Status


def module():
    name = "_mrk_android_saved_signing_qualification"
    path = Path(__file__).parents[2] / "desktop/tools/android_signed_qualification.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


subject = module()


def data(case):
    """Finite comparison DATA only; no request/native identity is reconstructed."""
    config = {"bytes": 512, "sha256": "c" * 64}
    version = {"source": "release/version.properties", "bytes": 32, "sha256": "d" * 64, "name": "1.2.3", "build": 7}
    selection = {"module": ":app", "variant": "release", "applicationId": "org.example.saved", "task": ":app:bundleRelease"}
    mismatch, cancelled = case == subject.SAVED_SIGNING_CASES[1], case == subject.SAVED_SIGNING_CASES[2]
    context = {"projectId": "inert-signed", "draftRevision": 2, "baselineGeneration": 3,
               "savedConfig": copy.deepcopy(config), "savedVersion": copy.deepcopy(version),
               "platform": "android", "operation": "android-build-inspect",
               "artifactValidation": {"mode": "upload-signature", "uploadCertificateSha256": ("9" if mismatch else "a") * 64},
               "signing": {"source": "assigned-session", "contextRevision": 2, "assignments": [
                   {"kind": "android-keystore", "recordId": "e" * 32, "recordRevision": 1, "contextRevision": 2},
                   {"kind": "android-firebase", "recordId": "f" * 32, "recordRevision": 1, "contextRevision": 2}]}}
    unused, zero = {"outcome": "not-dispatched", "exitCode": None}, {"outcome": "exited", "exitCode": 0}
    signing = {"validationCommand": dict(zero), "validationPassed": not mismatch,
               "signingCommand": dict(unused) if mismatch else {"outcome": "unknown", "exitCode": None} if cancelled else dict(zero),
               "materialization": "not-started" if mismatch else "restored"}
    report = Report("inert-predicate-only")
    if mismatch:
        report.add("credential-material.android", Status.INVALID, "Inert expected mismatch")
    elif not cancelled:
        for check in ("structure", "manifest", "signature", "signer"):
            report.add("android.aab." + check, Status.PASS, "Inert result predicate")
    activity = wire.project_activity(report, stage="validating-signing" if mismatch else "signing" if cancelled else "disposing-work",
                                     selection=copy.deepcopy(selection), command=unused if mismatch else zero, signing=signing)
    result = None
    if not (mismatch or cancelled):
        artifact = wire.project_artifact({"logicalName": "android-aab", "platform": "android", "kind": "aab",
            "fileName": "app-release.aab", "size": 2048, "sha256": "b" * 64, "architectures": []}, unknown_abi=False)
        result = wire.project_result(activity, artifact, used_config=config, used_version=version,
                                     toolchain_profile=wire.TOOLCHAIN_PROFILE, validation=context["artifactValidation"])
    projection = {"operationId": "1" * 32, "ownerGeneration": "2" * 32, "context": context,
                  "phase": "terminal", "intentUsable": False,
                  "outcome": "failed" if mismatch else "cancelled" if cancelled else "complete",
                  "reason": "signing-invalid" if mismatch else "cancelled" if cancelled else "none",
                  "stage": activity["stage"], "activity": activity,
                  "disposition": {"work": "removed", "artifacts": "retained-incomplete" if mismatch or cancelled else "retained-local-result"},
                  "result": result}
    lifetime = {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
                "commands": 1 if mismatch else 3 if cancelled else 6, "profileCalls": 0,
                "inputClosed": True, "handlersRestored": True, "invocationClosed": True, "artifactsClosed": True,
                "toolsClosed": True, "namespaceClosed": True, "signingInputsClosed": True, "materialRetired": True,
                "stopObserved": "cancelled" if cancelled else "none"}
    original = {"domain": "android", "id": "1" * 32, "generation": "2" * 32,
                "inspectionJoined": True, "acquisitionJoined": True, "attempted": True, "noChild": False,
                "childWaitedSuccess": True, "stdinClosed": True, "stdoutEofClosed": True, "stderrEofClosed": True,
                "ioJoined": True, "coreLifetimeSettled": True, "runtimeLedgerSettled": True, "runtimeSettlementJoined": True,
                "driverJoined": True, "managerJoined": True, "observerJoined": True, "watchdogJoined": True,
                "retiredBeforeCutoff": True, "activeRetained": False, "resourceUnknown": False}
    dispatch = {"observed": not mismatch, "operationId": None if mismatch else original["id"],
                "ownerGeneration": None if mismatch else original["generation"], "stage": None if mismatch else "signing",
                "cancelAfter": cancelled}
    expected = {"saved_config": copy.deepcopy(config), "saved_version": copy.deepcopy(version),
                "selection": copy.deepcopy(selection), "certificate_sha256": "a" * 64,
                "original": original, "dispatch": dispatch}
    return projection, lifetime, expected


class SavedSigningQualificationTests(unittest.TestCase):
    def accepted(self, case, values):
        projection, lifetime, expected = values
        return subject.validate_saved_signing_case(case, projection, lifetime, **expected)

    def rejected(self, case, values):
        with self.assertRaises(ValueError):
            self.accepted(case, values)

    def test_three_exact_case_predicates_accept_without_creating_native_evidence(self):
        self.assertEqual(subject.SAVED_SIGNING_CASES, ("android-saved-signing", "android-saved-signing-wrong-fingerprint",
                                                     "android-saved-signing-cancel"))
        for case in subject.SAVED_SIGNING_CASES:
            with self.subTest(case=case):
                values = data(case)
                before = copy.deepcopy(values)
                self.assertIsNone(self.accepted(case, values))
                self.assertEqual(values, before)

    def test_case_prefix_counts_do_not_credit_an_unsigned_or_successor_command(self):
        for case in subject.SAVED_SIGNING_CASES:
            for count in (0, 2, 4):
                with self.subTest(case=case, count=count):
                    values = data(case); values[1]["commands"] = count
                    self.rejected(case, values)
            values = data(case); values[0]["context"]["signing"] = None
            self.rejected(case, values)
        values = data(subject.SAVED_SIGNING_CASES[0])
        self.rejected("android-build", values)  # Historical unsigned selector is not saved3.

    def test_original_joins_and_core_closures_cannot_be_replaced_by_a_success_label(self):
        case = subject.SAVED_SIGNING_CASES[0]
        for name in ("complete", "contained", "commandDispatched", *wire._CLOSE_FIELDS):
            with self.subTest(core=name):
                values = data(case); values[1][name] = False
                self.rejected(case, values)
        for name in ("inspectionJoined", "acquisitionJoined", "childWaitedSuccess", "ioJoined", "coreLifetimeSettled",
                     "runtimeLedgerSettled", "runtimeSettlementJoined", "driverJoined", "managerJoined", "observerJoined",
                     "watchdogJoined", "retiredBeforeCutoff"):
            with self.subTest(native=name):
                values = data(case); values[2]["original"][name] = False
                self.rejected(case, values)
        for name in ("activeRetained", "resourceUnknown", "noChild"):
            values = data(case); values[2]["original"][name] = True
            self.rejected(case, values)

    def test_real_saved_values_certificate_and_session_assignment_must_correspond(self):
        case = subject.SAVED_SIGNING_CASES[0]
        for change in ("config", "version", "selection", "certificate", "zero-certificate", "missing-firebase", "stale-revision"):
            with self.subTest(change=change):
                values = data(case); p, _, expected = values
                if change == "config": expected["saved_config"]["sha256"] = "9" * 64
                elif change == "version": expected["saved_version"]["build"] = 8
                elif change == "selection": expected["selection"]["applicationId"] = "org.example.other"
                elif change == "certificate": expected["certificate_sha256"] = "9" * 64
                elif change == "zero-certificate": expected["certificate_sha256"] = "0" * 64
                elif change == "missing-firebase": p["context"]["signing"]["assignments"].pop()
                else: p["context"]["signing"]["assignments"][1]["contextRevision"] += 1
                self.rejected(case, values)

    def test_cancellation_requires_original_dispatch_before_cancel_and_no_late_exit(self):
        case = subject.SAVED_SIGNING_CASES[2]
        for change in ("not-observed", "wrong-id", "wrong-generation", "early-stage", "late-request", "zero-exit", "failed-exit",
                       "not-dispatched", "unrestored", "result", "inspectors", "work-retained"):
            with self.subTest(change=change):
                values = data(case); p, _, expected = values
                event = expected["dispatch"]
                if change == "not-observed": event["observed"] = False
                elif change == "wrong-id": event["operationId"] = "9" * 32
                elif change == "wrong-generation": event["ownerGeneration"] = "9" * 32
                elif change == "early-stage": event["stage"] = "capturing"
                elif change == "late-request": event["cancelAfter"] = False
                elif change in ("zero-exit", "failed-exit"):
                    p["activity"]["signing"]["signingCommand"] = {"outcome": "exited", "exitCode": 0 if change == "zero-exit" else 1}
                elif change == "not-dispatched": p["activity"]["signing"]["signingCommand"]["outcome"] = "not-dispatched"
                elif change == "unrestored": p["activity"]["signing"]["materialization"] = "unknown"
                elif change == "result": p["result"] = data(subject.SAVED_SIGNING_CASES[0])[0]["result"]
                elif change == "inspectors":
                    p["activity"]["findings"] = [{"ordinal": 0, "check": "signature", "status": "PASS"}]
                    p["activity"]["summary"].update(total=1, shown=1)
                    p["activity"]["summary"]["counts"]["PASS"] = 1
                else: p["disposition"]["work"] = "retained-work"
                self.rejected(case, values)

    def test_wrong_fingerprint_is_a_real_failed_validation_not_refusal_or_unsigned_fallback(self):
        case = subject.SAVED_SIGNING_CASES[1]
        for change in ("same-certificate", "refused", "keytool-nonzero", "validation-passed", "gradle", "materialized", "no-invalid"):
            with self.subTest(change=change):
                values = data(case); p, _, expected = values; signing = p["activity"]["signing"]
                if change == "same-certificate": expected["certificate_sha256"] = "9" * 64
                elif change == "refused": p["outcome"] = "refused"
                elif change == "keytool-nonzero": signing["validationCommand"]["exitCode"] = 1
                elif change == "validation-passed": signing["validationPassed"] = True
                elif change == "gradle": p["activity"]["command"] = {"outcome": "exited", "exitCode": 0}
                elif change == "materialized": signing["materialization"] = "restored"
                else:
                    p["activity"]["findings"][0]["status"] = "PASS"
                    p["activity"]["summary"]["counts"].update(INVALID=0, PASS=1)
                self.rejected(case, values)

    def test_success_requires_actual_native_manifest_signature_leaf_and_same_artifact_observation(self):
        case = subject.SAVED_SIGNING_CASES[0]
        for change in ("manifest", "signature", "signer", "toolkit", "result-config", "result-activity", "no-artifact", "unknown-abi", "release-authority"):
            with self.subTest(change=change):
                values = data(case); p = values[0]; result = p["result"]
                if change in ("manifest", "signature", "signer", "toolkit"):
                    key = {"manifest": "nativeManifest", "signature": "signature", "signer": "signer", "toolkit": "toolkitSigning"}[change]
                    result["assurances"][key] = "not-checked"
                elif change == "result-config": result["usedConfig"]["sha256"] = "9" * 64
                elif change == "result-activity": result["selection"]["applicationId"] = "org.example.other"
                elif change == "no-artifact": result["artifacts"] = []
                elif change == "unknown-abi": result["artifacts"][0]["unknownAbi"] = True
                else: result["assurances"]["releaseReadiness"] = "ready"
                self.rejected(case, values)

    def test_extra_private_fields_bool_counts_and_wrong_original_do_not_form_receipt_evidence(self):
        case = subject.SAVED_SIGNING_CASES[0]
        for change in ("extra-projection", "extra-dispatch", "bool-count", "bool-join", "id", "generation", "domain"):
            with self.subTest(change=change):
                values = data(case); p, life, expected = values
                if change == "extra-projection": p["stdout"] = "INERT_PRIVATE_TEXT"
                elif change == "extra-dispatch": expected["dispatch"]["pid"] = 123
                elif change == "bool-count": life["commands"] = True
                elif change == "bool-join": expected["original"]["driverJoined"] = 1
                elif change == "id": expected["original"]["id"] = "9" * 32
                elif change == "generation": expected["original"]["generation"] = "9" * 32
                else: expected["original"]["domain"] = "offline"
                self.rejected(case, values)
