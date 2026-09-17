"""Pure compiler-helper contracts; never run its main, phases, tools or fixtures.

All subprocess calls in these tests are inert mocks. Source inspection checks
the fixed caller inventory rather than executing hosted admission on the VPS.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
HELPER = SOURCE / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_ci_foundation_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


NATIVE_CASE_NAMES = (
    "core-capabilities", "core-catalog", "core-zip-catalog", "core-valid-draft",
    "core-invalid-draft", "core-service-error", "core-snapshot", "malformed",
    "truncated", "extra_frames", "wrong_id", "nonzero_exit", "pipe_pressure",
    "stdout_limit", "stderr_limit", "delay_exit", "busy-abandon", "operation-timeout",
    "shutdown-active", "controlled-startup", "controlled-io-join",
    "controlled-management-returns", "controlled-management-late",
)


def native_report(platform: str = "linux") -> dict:
    """Inert consumer data, never evidence of a hosted/native invocation."""
    # The old 21 retain their existing case-name/passed consumer predicates.
    cases = [{"case": name, "passed": True} for name in NATIVE_CASE_NAMES[:-2]]
    for late, name, notes in zip((False, True), NATIVE_CASE_NAMES[-2:], (
        ("nativeSettledBeforeManagementReturns", "driverReturnHeldBeforeReply", "watchdogReturnHeldBeforeReply"),
        ("nativeSettledBeforeWatchdogReturn", "originalCleanupEndpointUnchanged", "retainedWhileUnknown",
         "newQueryRefused", "lateJoinPreservedFailure"),
    ), strict=True):
        native = {**dict.fromkeys(("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
            "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined",
            "driver_joined", "watchdog_joined"), True), "stdout_bytes": 4096, "stderr_bytes": 0}
        cases.append({"case": name, "passed": True, "failureCode": None, "elapsedMs": 2000 if late else 100,
            "evidenceKind": "scheduling-control-not-os-fault", "notes": dict.fromkeys(notes, True),
            "results": [{"return": "error", "code": "cleanup_unknown"}] if late else [{"return": "ok"}],
            "owners": [{"id": "query-1", "terminal": True, "unknownLatched": late, "permitRetained": False, "native": native}],
            "registeredOwners": 0, "disabled": late})
    return {"schemaVersion": 1, "scope": "passive-hosted-v2", "status": "passed", "allOwnersSettled": True,
            "failureCode": None, "cases": cases,
            "bindings": {"sourceSha": "1" * 40, "target": helper.TARGETS[platform], "coreZipSha256": "2" * 64}}


def validate_native(report: object, platform: str = "linux") -> dict:
    return helper.validate_native_receipt(report, source_sha="1" * 40, platform=platform, core_zip_hash="2" * 64)


def owner_report() -> dict:
    cases = []
    for name, effect, journal, reason, requests, responses in (
        ("create", "committed", "clean", "none", 3, 3),
        ("no-op", "unchanged", "not_created", "none", 3, 3),
        ("discard-editing", "not_started", "not_created", "discarded", 1, 2),
    ):
        cases.append({"name": name, "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": "none"},
                      "nativeReason": reason, "nativeFinality": "settled", "requestFrames": requests, "responseFrames": responses,
                      "stdoutBytes": 4096, "stderrBytes": 0, "forceAttempted": False,
                      **dict.fromkeys(helper.CONFIG_OWNER_FINALITY, True)})
    return {"schemaVersion": 1, "scope": "configuration-owner-hosted-v1", "status": "passed", "allOwnersSettled": True,
            "failureCode": None, "notVerified": list(helper.CONFIG_OWNER_NOT_VERIFIED), "cases": cases,
            "bindings": {"sourceSha": "1" * 40, "host": "linux", "target": helper.TARGETS["linux"],
                         "runtimeMode": "trusted-development-only", "pythonSha256": "2" * 64,
                         "sourceHashes": dict.fromkeys(helper.CONFIG_OWNER_SOURCES, "3" * 64),
                         "payloadHashes": dict.fromkeys(("draft", "createConfig", "createIgnore", "noOpConfig", "noOpIgnore", "unrelated"), "4" * 64)}}


def validate_owner(report: dict) -> dict:
    return helper.validate_config_owner_receipt(report, source_sha="1" * 40, platform="linux",
        source_hashes=dict.fromkeys(helper.CONFIG_OWNER_SOURCES, "3" * 64), python_hash="2" * 64)


def loss_report(kind: str) -> dict:
    positive = owner_report()
    case = {"name": kind, "nativePhase": "unknown", "nativeFinality": "unknown", "registryDisabled": True,
            "editPermitClosed": True, "nativeCanExit": False, "originalResourcesSettled": True,
            "failedTask": kind.removesuffix("-loss"), "failedJoinKind": "panic", "failedTaskHandleRetained": True,
            "requestFrames": 1, "responseFrames": 2, "stdoutBytes": 4096, "stderrBytes": 0, "forceAttempted": False,
            **dict.fromkeys(helper.CONFIG_OWNER_FINALITY, True)}
    case["driverJoined" if kind == "driver-loss" else "watchdogJoined"] = False
    return {"schemaVersion": 1, "scope": "configuration-owner-management-loss-hosted-v1", "status": "passed",
            "failureCode": None, "bindings": positive["bindings"], "case": case, "notVerified": positive["notVerified"]}


def validate_loss(report: dict, kind: str) -> dict:
    return helper.validate_config_loss_receipt(report, kind, source_sha="1" * 40, platform="linux",
        source_hashes=dict.fromkeys(helper.CONFIG_OWNER_SOURCES, "3" * 64), python_hash="2" * 64)


def delta_report(kind: str) -> dict:
    positive = owner_report()
    report = {key: positive[key] for key in ("schemaVersion", "status", "failureCode", "bindings", "notVerified")}
    if kind == "stop":
        report.update(scope="configuration-owner-stop-hosted-v1", allOwnersSettled=True, cases=[])
        for name, reason, applying, evidence, prefix in (
            ("discard-reviewing", "discarded", False, "actual-config-child", 0),
            ("partial-apply-eof", "cancelled", True, "fixed-prefix-scheduling-control", 1),
        ):
            report["cases"].append({"name": name, "evidenceKind": evidence, "nativePhase": "final", "nativeFinality": "settled",
                "nativeReason": reason, "applySubmitted": applying,
                "outcome": {"effect": "not_started", "journal": "not_created", "resources": "settled", "reason": "cancelled"},
                "terminalSeq": 1, "requestFrames": 2, "responseFrames": 3, "stdoutBytes": 4096, "stderrBytes": 0,
                "forceAttempted": False, "preparedCorrelation": True, "prefixBytes": prefix, "applySuffixStarted": False,
                **dict.fromkeys(helper.CONFIG_OWNER_FINALITY, True)})
        return report
    terminal = kind == "terminal-deadline"
    case = {"name": kind, "evidenceKind": "scheduling-control-not-os-fault", "nativePhase": "unknown", "nativeFinality": "unknown",
            "nativeReason": "active_timeout" if terminal else "discarded", "applySubmitted": terminal,
            "outcome": {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"} if terminal else None,
            "terminalSeq": 2 if terminal else None, "requestFrames": 3 if terminal else 0, "responseFrames": 3 if terminal else 0,
            "stdoutBytes": 4096 if terminal else 0, "stderrBytes": 0, "forceAttempted": False,
            "registryDisabled": True, "editPermitClosed": True, "editAvailability": "shutdown" if terminal else "cleanup_unknown",
            "nativeCanExit": True, "originalResourcesSettled": True, "lateSettled": True, "retainedBeforeRelease": True,
            "cleanupStartUnchanged": True, "cleanupElapsedMs": 10000, "scheduledActiveDeadline": terminal, "inspectionJoined": True,
            "acquisitionNotAdmitted": not terminal, "pipeAcquisition": "available" if terminal else "absent",
            "controlEntered": True, "controlReleased": True, "shutdownObserved": terminal,
            **{field: terminal or field in {"ioJoined", "driverJoined", "watchdogJoined", "managerJoined"}
               for field in helper.CONFIG_OWNER_FINALITY}}
    return {**report, "scope": "configuration-owner-clock-retention-hosted-v1", "case": case}


def validate_delta(report: dict, kind: str) -> dict:
    return helper.validate_config_delta_receipt(report, kind, source_sha="1" * 40, platform="linux",
        source_hashes=dict.fromkeys(helper.CONFIG_OWNER_SOURCES, "3" * 64), python_hash="2" * 64)


def transaction_eof_report() -> dict:
    report = owner_report()
    report["scope"] = "configuration-transaction-eof-hosted-v1"
    report["bindings"]["sourceHashes"] = dict.fromkeys(helper.CONFIG_TRANSACTION_EOF_SOURCES, "3" * 64)
    report["bindings"]["payloadHashes"].update(dict.fromkeys(("eofDraft", "eofConfig", "eofInitialIgnore", "eofIgnore"), "4" * 64))
    report["cases"] = []
    for committed in (False, True):
        name = "postcommit-eof" if committed else "precommit-eof"
        boundary = "after-durable-COMMITTED" if committed else "before-COMMITTED"
        checkpoint = "descriptor-close" if committed else "publisher-entry"
        terminal = "COMMITTED" if committed else "ROLLED_BACK"
        records = (f"MRK_CONFIG_EOF_V1 {name} boundary={boundary}\n"
            f"MRK_CONFIG_EOF_V1 {name} eof=1 nonempty=0 readErrors=0 checkpoint={checkpoint} "
            f"applied=1 committed={int(committed)} rolledBack={int(not committed)} terminal={terminal} "
            "durable=1 recovery=1 clean=1 settled=1 cancelled=1\n")
        report["cases"].append({"name": name, "evidenceKind": "real-stdin-eof-at-controlled-transaction-boundary",
            "bootstrapMode": "instrumented-genuine-engine", "nativePhase": "final", "nativeFinality": "settled",
            "nativeReason": "cancelled", "applySubmitted": True, "lateSettled": False, "ownerDisabled": False,
            "outcome": {"effect": "committed" if committed else "rolled_back", "journal": "clean", "resources": "settled", "reason": "cancelled"},
            "terminalSeq": 2, "preparedCorrelation": True, "closeBeforeActiveDeadline": True, "controlRecords": 2,
            "boundary": boundary, "actualStdinEof": True, "eofReadCount": 1, "nonemptyReadCount": 0, "readErrorCount": 0,
            "originalCheckpoint": checkpoint, "committedPublication": committed, "rolledBackPublication": not committed,
            "terminalDurable": True, "fixedRecovery": True, "journalClean": True, "originalsPreserved": not committed,
            "payloadsInstalled": committed, "modesPreserved": True, "unrelatedPreserved": True, "journalAbsent": True,
            "fixtureFilesSettled": True, "requestFrames": 3, "responseFrames": 3, "stdoutBytes": 4096,
            "stderrBytes": len(records.encode("ascii")), "forceAttempted": False,
            **dict.fromkeys(helper.CONFIG_OWNER_FINALITY, True)})
    return report


def validate_transaction_eof(report: dict) -> dict:
    return helper.validate_config_transaction_eof_receipt(report, source_sha="1" * 40, platform="linux",
        source_hashes=dict.fromkeys(helper.CONFIG_TRANSACTION_EOF_SOURCES, "3" * 64), python_hash="2" * 64)


class FixedCompilerHelperTests(unittest.TestCase):
    def test_passive_management_requires_v2_complete_roster_and_existing_bindings(self):
        self.assertEqual(helper.NATIVE_CASES, NATIVE_CASE_NAMES)
        for platform in ("linux", "macos", "windows"):
            report = native_report(platform)
            with self.subTest(platform=platform):
                self.assertIs(validate_native(report, platform), report)
        report = native_report()
        for invalid in (None, [], "passed"):
            with self.subTest(invalid=invalid), self.assertRaises(helper.CheckFailure):
                validate_native(invalid)
        for changed in ({"scope": "passive-hosted-v1"}, {"scope": "production-enablement"}, {"schemaVersion": True},
                        {"status": "failed"}, {"allOwnersSettled": False}, {"allOwnersSettled": 1}, {"bindings": []}):
            with self.subTest(top=changed), self.assertRaises(helper.CheckFailure):
                validate_native({**report, **changed})
        cases = report["cases"]
        for inventory in (cases[:-2], cases[:-1], cases[1:], [*cases[:-2], cases[-1]], list(reversed(cases)),
                          [*cases[:-1], cases[-2]], [*cases, cases[-1]], [*cases[:-2], cases[-1], cases[-2]], [None] * 23):
            with self.subTest(inventory=inventory), self.assertRaises(helper.CheckFailure):
                validate_native({**report, "cases": inventory})
        for index in range(len(cases)):
            for value in (False, 1, None):
                failed = deepcopy(report)
                failed["cases"][index]["passed"] = value
                with self.subTest(case=index, passed=value), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
        for field, value in (("sourceSha", "0" * 40), ("target", helper.TARGETS["windows"]), ("coreZipSha256", "0" * 64)):
            failed = deepcopy(report)
            failed["bindings"][field] = value
            with self.subTest(binding=field), self.assertRaises(helper.CheckFailure):
                validate_native(failed)
            del failed["bindings"][field]
            with self.subTest(missing_binding=field), self.assertRaises(helper.CheckFailure):
                validate_native(failed)

    def test_passive_management_checkpoint_notes_are_exact_typed_and_case_specific(self):
        report = native_report()
        for index in (-2, -1):
            notes = report["cases"][index]["notes"]
            for field in notes:
                for value in (False, 1, "true", None):
                    failed = deepcopy(report)
                    failed["cases"][index]["notes"][field] = value
                    with self.subTest(case=index, field=field, value=value), self.assertRaises(helper.CheckFailure):
                        validate_native(failed)
                failed = deepcopy(report)
                del failed["cases"][index]["notes"][field]
                with self.subTest(case=index, missing=field), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            other_notes = report["cases"][-1 if index == -2 else -2]["notes"]
            for changed in ({}, None, [], {**notes, "unrecognizedFact": True}, other_notes):
                failed = deepcopy(report)
                failed["cases"][index]["notes"] = changed
                with self.subTest(case=index, notes=changed), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)

    def test_passive_management_results_and_retirement_are_not_interchangeable(self):
        report = native_report()
        for index in (-2, -1):
            case = report["cases"][index]
            late = index == -1
            other_results = report["cases"][-1 if index == -2 else -2]["results"]
            mutations = [{"results": []}, {"results": {}}, {"results": other_results},
                {"results": [*case["results"], {"return": "ok"}]}, {"results": [{"return": "error"}]},
                {"results": [{"return": "error", "code": "shutting_down"}]},
                {"results": [{**case["results"][0], "extra": True}]},
                {"disabled": not late}, {"disabled": int(late)}, {"disabled": None},
                {"registeredOwners": 1}, {"registeredOwners": False}, {"registeredOwners": 0.0},
                {"elapsedMs": True}, {"elapsedMs": 2000.0}, {"elapsedMs": -1},
                {"failureCode": "not_completed"}, {"evidenceKind": "actual-passive-child"},
                {"evidenceKind": "genuine-os-fault"}, {"extra": True}]
            if late:
                mutations.append({"elapsedMs": 1999})  # The real existing two-second allowance, not a note.
            for changed in mutations:
                failed = deepcopy(report)
                failed["cases"][index].update(changed)
                with self.subTest(case=index, changed=changed), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            for field in case:
                failed = deepcopy(report)
                del failed["cases"][index][field]
                with self.subTest(case=index, missing=field), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)

    def test_passive_management_requires_one_original_with_sticky_late_failure(self):
        report = native_report()
        for index in (-2, -1):
            owner = report["cases"][index]["owners"][0]
            late = index == -1
            for owners in ([], [owner, owner], {}, None, [None]):
                failed = deepcopy(report)
                failed["cases"][index]["owners"] = owners
                with self.subTest(case=index, owners=owners), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            for changed in ({"id": "query-2"}, {"id": None}, {"terminal": False}, {"terminal": 1},
                            {"permitRetained": True}, {"permitRetained": 0},
                            {"unknownLatched": not late}, {"unknownLatched": int(late)}, {"unknownLatched": None}, {"extra": True}):
                failed = deepcopy(report)
                failed["cases"][index]["owners"][0].update(changed)
                with self.subTest(case=index, owner=changed), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            for field in owner:
                failed = deepcopy(report)
                del failed["cases"][index]["owners"][0][field]
                with self.subTest(case=index, missing=field), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)

    def test_passive_management_native_and_management_returns_are_all_required(self):
        report = native_report()
        for index in (-2, -1):
            native = report["cases"][index]["owners"][0]["native"]
            for field, original in native.items():
                for value in (False, 1, None) if type(original) is bool else ():
                    failed = deepcopy(report)
                    failed["cases"][index]["owners"][0]["native"][field] = value
                    with self.subTest(case=index, field=field, value=value), self.assertRaises(helper.CheckFailure):
                        validate_native(failed)
                failed = deepcopy(report)
                del failed["cases"][index]["owners"][0]["native"][field]
                with self.subTest(case=index, missing=field), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            for changed in ({"stdout_bytes": 0}, {"stdout_bytes": 4 * 1024 * 1024 + 1}, {"stdout_bytes": True},
                            {"stdout_bytes": 4096.0}, {"stderr_bytes": -1}, {"stderr_bytes": 64 * 1024 + 1},
                            {"stderr_bytes": False}, {"stderr_bytes": 0.0}, {"extra": True}):
                failed = deepcopy(report)
                failed["cases"][index]["owners"][0]["native"].update(changed)
                with self.subTest(case=index, native=changed), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
            for invalid in (None, [], {}):
                failed = deepcopy(report)
                failed["cases"][index]["owners"][0]["native"] = invalid
                with self.subTest(case=index, native=invalid), self.assertRaises(helper.CheckFailure):
                    validate_native(failed)
        for case in report["cases"][-2:]:
            case["owners"][0]["native"].update(stdout_bytes=4 * 1024 * 1024, stderr_bytes=64 * 1024)
        self.assertIs(validate_native(report), report)  # Preserve the original passive reader bounds.

    def test_passive_management_keeps_existing_native_invocation(self):
        report = native_report()
        with patch.object(helper, "run", side_effect=AssertionError("pure validation called a tool")), \
             patch.object(helper, "hash_file", side_effect=AssertionError("pure validation read a file")):
            self.assertIs(validate_native(report), report)
        self.assertEqual(helper.NATIVE_TEST, "supervisor::hosted_tests::passive_hosted_contract")
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "run" and any(keyword.arg == "check" and isinstance(keyword.value, ast.Constant)
                     and keyword.value.value == "passive-native-contract" for keyword in node.keywords)]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(next(keyword.value.value for keyword in call.keywords if keyword.arg == "timeout"), 300)
        constants = [item.value for item in call.args[0].elts if isinstance(item, ast.Constant)]
        self.assertEqual(constants, ["test", "--lib", "--features", "development-runtime", "--", "--exact", "--ignored", "--test-threads=1"])
        self.assertTrue(any(isinstance(item, ast.Name) and item.id == "NATIVE_TEST" for item in call.args[0].elts))
        wrapper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "native_receipt")
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "validate_native_receipt" for node in ast.walk(wrapper)))

    def test_transaction_eof_requires_original_eof_settlement_and_distinct_commit_outcomes(self):
        report = transaction_eof_report()
        self.assertIs(validate_transaction_eof(report), report)
        for index, case in enumerate(report["cases"]):
            mutations = [{field: not value} for field, value in case.items() if type(value) is bool]
            mutations += [{field: True} for field, value in case.items() if type(value) is int]
            mutations += [{"stderrBytes": 0}, {"stdoutBytes": 0}, {"eofReadCount": 0}, {"nonemptyReadCount": 1},
                {"readErrorCount": 1}, {"controlRecords": 1}, {"requestFrames": 2}, {"responseFrames": 2},
                {"boundary": "uncontrolled"}, {"originalCheckpoint": "injected-cancellation"},
                {"bootstrapMode": "fake-result"}, {"evidenceKind": "genuine-os-fault"},
                {"nativeReason": "none"}, {"nativePhase": "unknown"}, {"nativeFinality": "unknown"},
                {"outcome": {**case["outcome"], "reason": "none"}},
                {"outcome": report["cases"][1 - index]["outcome"]}, {"unrecognizedFact": True}]
            for changed in mutations:
                failed = deepcopy(report)
                failed["cases"][index].update(changed)
                with self.subTest(case=index, change=changed), self.assertRaises(helper.CheckFailure):
                    validate_transaction_eof(failed)

    def test_transaction_eof_is_bound_to_the_extra_shim_and_complete_payload_inventory(self):
        report = transaction_eof_report()
        for changed in ({"scope": "production-save-enablement"}, {"allOwnersSettled": False}, {"schemaVersion": True},
                        {"failureCode": "not_completed"}, {"notVerified": []}, {"status": "failed"},
                        {"cases": report["cases"][:1]}, {"cases": list(reversed(report["cases"]))}, {"extra": True}):
            with self.subTest(top=changed), self.assertRaises(helper.CheckFailure):
                validate_transaction_eof({**report, **changed})
        for field, value in (("sourceSha", "0" * 40), ("pythonSha256", "0" * 64), ("sourceHashes", {}),
                             ("runtimeMode", "production"), ("target", helper.TARGETS["windows"]), ("payloadHashes", {})):
            failed = deepcopy(report)
            failed["bindings"][field] = value
            with self.subTest(binding=field), self.assertRaises(helper.CheckFailure):
                validate_transaction_eof(failed)
        for group, key in (("sourceHashes", "transactionEofShim"), ("payloadHashes", "eofDraft"),
                           ("payloadHashes", "eofConfig"), ("payloadHashes", "eofInitialIgnore"), ("payloadHashes", "eofIgnore")):
            failed = deepcopy(report)
            del failed["bindings"][group][key]
            with self.subTest(group=group, key=key), self.assertRaises(helper.CheckFailure):
                validate_transaction_eof(failed)
        with self.assertRaises(helper.CheckFailure):
            validate_owner(report)  # New evidence cannot masquerade as an older healthy-save receipt.

    def test_transaction_eof_is_one_bounded_phase_before_last_retained_fault(self):
        source = HELPER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "run" and any(keyword.arg == "check" and isinstance(keyword.value, ast.Constant)
                     and keyword.value.value == "config-transaction-eof-native-contract" for keyword in node.keywords)]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(next(keyword.value.value for keyword in call.keywords if keyword.arg == "timeout"), 90)
        constants = [item.value for item in call.args[0].elts if isinstance(item, ast.Constant)]
        self.assertEqual(constants, ["test", "--lib", "--features", "development-runtime", "--", "--exact", "--ignored", "--test-threads=1"])
        self.assertTrue(any(isinstance(item, ast.Name) and item.id == "CONFIG_TRANSACTION_EOF_TEST" for item in call.args[0].elts))
        self.assertLess(source.index('elif name == "config-owner-delta"'), source.index('elif name == "config-transaction-eof"'))
        self.assertLess(source.index('elif name == "config-transaction-eof"'), source.index('elif name == "config-core"'))
        for section in (source.split('elif name == "config-core":', 1)[1].split('    else:', 1)[0],
                        source.split('require(name == "clean"', 1)[1]):
            self.assertIn("config_transaction_eof_receipt(context)", section)
        workflow = (SOURCE / ".github/workflows/desktop-foundation.yml").read_text(encoding="utf-8")
        self.assertLess(workflow.index("ci_foundation.py config-owner-delta"), workflow.index("ci_foundation.py config-transaction-eof"))
        self.assertLess(workflow.index("ci_foundation.py config-transaction-eof"), workflow.index("ci_foundation.py config-core"))
        self.assertIn("/config-transaction-eof-checks.json", workflow)
        self.assertIn("/config-transaction-eof/receipt.json", workflow)

    def test_prepared_eof_and_partial_apply_cannot_claim_accepted_apply(self):
        report = delta_report("stop")
        self.assertIs(validate_delta(report, "stop"), report)
        for index in (0, 1):
            for changed in [{field: False} for field in helper.CONFIG_OWNER_FINALITY] + [
                {"requestFrames": 3}, {"responseFrames": 2}, {"terminalSeq": True}, {"prefixBytes": True},
                {"preparedCorrelation": False}, {"applySuffixStarted": True}, {"forceAttempted": True},
                {"applySubmitted": index == 0}, {"nativePhase": "unknown"}, {"nativeFinality": "unknown"},
                {"stdoutBytes": 0}, {"stderrBytes": 1}, {"evidenceKind": "genuine-os-short-write"},
                {"outcome": {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"}},
            ]:
                failed = deepcopy(report)
                failed["cases"][index].update(changed)
                with self.subTest(case=index, changed=changed), self.assertRaises(helper.CheckFailure):
                    validate_delta(failed, "stop")

    def test_clock_receipts_keep_unknown_and_actual_late_original_settlement(self):
        for kind in ("terminal-deadline", "startup-stop"):
            report = delta_report(kind)
            self.assertIs(validate_delta(report, kind), report)
            truth_fields = ("registryDisabled", "editPermitClosed", "nativeCanExit", "originalResourcesSettled", "lateSettled",
                            "retainedBeforeRelease", "cleanupStartUnchanged", "inspectionJoined", "controlEntered", "controlReleased")
            for changed in [{field: False} for field in truth_fields] + [
                {"nativePhase": "final"}, {"nativeFinality": "settled"}, {"nativeReason": "none"},
                {"editAvailability": "available"}, {"forceAttempted": True}, {"cleanupElapsedMs": 9999},
                {"cleanupElapsedMs": 60001}, {"cleanupElapsedMs": True}, {"cleanupElapsedMs": 10000.0},
                {"stderrBytes": 1}, {"responseFrames": True}, {"evidenceKind": "genuine-os-fault"},
            ]:
                failed = deepcopy(report)
                failed["case"].update(changed)
                with self.subTest(kind=kind, changed=changed), self.assertRaises(helper.CheckFailure):
                    validate_delta(failed, kind)
            for field in (*helper.CONFIG_OWNER_FINALITY, "scheduledActiveDeadline", "acquisitionNotAdmitted", "shutdownObserved"):
                failed = deepcopy(report)
                failed["case"][field] = not report["case"][field]
                with self.subTest(kind=kind, field=field), self.assertRaises(helper.CheckFailure):
                    validate_delta(failed, kind)

    def test_startup_absence_and_late_committed_result_are_not_interchangeable(self):
        for kind, changes in (
            ("startup-stop", ({"outcome": {}}, {"terminalSeq": 0}, {"requestFrames": 1}, {"stdoutBytes": 1}, {"pipeAcquisition": "available"})),
            ("terminal-deadline", ({"outcome": None}, {"terminalSeq": None}, {"terminalSeq": True}, {"stdoutBytes": 0},
                                   {"pipeAcquisition": "absent"}, {"outcome": {"effect": "unknown", "journal": "clean", "resources": "settled", "reason": "none"}})),
        ):
            for changed in changes:
                failed = delta_report(kind)
                failed["case"].update(changed)
                with self.subTest(kind=kind, changed=changed), self.assertRaises(helper.CheckFailure):
                    validate_delta(failed, kind)

    def test_lifecycle_receipts_are_closed_source_bound_and_not_product_qualification(self):
        for kind in ("stop", "terminal-deadline", "startup-stop"):
            report = delta_report(kind)
            for changed in ({"schemaVersion": True}, {"status": "failed"}, {"failureCode": "not_completed"},
                            {"scope": "production-save-enablement"}, {"notVerified": []}, {"extra": True}):
                with self.subTest(kind=kind, top=changed), self.assertRaises(helper.CheckFailure):
                    validate_delta({**report, **changed}, kind)
            for field, value in (("sourceSha", "0" * 40), ("pythonSha256", "0" * 64), ("sourceHashes", {}),
                                 ("target", helper.TARGETS["windows"]), ("runtimeMode", "production")):
                failed = deepcopy(report)
                failed["bindings"][field] = value
                with self.subTest(kind=kind, binding=field), self.assertRaises(helper.CheckFailure):
                    validate_delta(failed, kind)
            if kind == "stop":
                for cases in (report["cases"][:1], list(reversed(report["cases"])), None):
                    with self.assertRaises(helper.CheckFailure):
                        validate_delta({**report, "cases": cases}, kind)
                with self.assertRaises(helper.CheckFailure):
                    validate_delta({**report, "allOwnersSettled": False}, kind)
            else:
                # A negative control cannot add a blanket finality claim, even
                # if the claimed value is false; it has a different contract.
                for value in (True, False):
                    with self.assertRaises(helper.CheckFailure):
                        validate_delta({**report, "allOwnersSettled": value}, kind)

    def test_task_loss_requires_native_settlement_without_normal_management_success(self):
        for kind in ("driver-loss", "watchdog-loss"):
            report = loss_report(kind)
            self.assertIs(validate_loss(report, kind), report)
            failed_join = "driverJoined" if kind == "driver-loss" else "watchdogJoined"
            for changes in [{field: False} for field in helper.CONFIG_OWNER_FINALITY if field != failed_join] + [
                {failed_join: True}, {"failedJoinKind": "cancelled"}, {"failedTaskHandleRetained": False},
                {"originalResourcesSettled": False}, {"registryDisabled": False}, {"editPermitClosed": False},
                {"nativeCanExit": True}, {"nativePhase": "final"}, {"nativeFinality": "settled"},
                {"requestFrames": 2}, {"responseFrames": 1}, {"stdoutBytes": 0}, {"stderrBytes": 1},
                {"forceAttempted": True}, {"managerJoined": 1}, {"unknownReceipt": True},
            ]:
                failed = deepcopy(report)
                failed["case"].update(changes)
                with self.subTest(kind=kind, changed=changes), self.assertRaises(helper.CheckFailure):
                    validate_loss(failed, kind)
            for changes in ({"allOwnersSettled": True}, {"allOwnersSettled": False}, {"failureCode": "not_completed"},
                            {"case": None}, {"status": "failed"}, {"notVerified": []}, {"schemaVersion": True}):
                with self.subTest(kind=kind, top=changes), self.assertRaises(helper.CheckFailure):
                    validate_loss({**report, **changes}, kind)
            failed = deepcopy(report)
            failed["bindings"]["sourceSha"] = "0" * 40
            with self.assertRaises(helper.CheckFailure):
                validate_loss(failed, kind)

    def test_config_owner_original_facts_cannot_be_replaced_by_summary_success(self):
        report = owner_report()
        self.assertIs(validate_owner(report), report)
        for changes in [{field: False} for field in helper.CONFIG_OWNER_FINALITY] + [
            {"requestFrames": 4}, {"responseFrames": 4}, {"forceAttempted": True}, {"nativeFinality": "unknown"},
            {"stderrBytes": 1}, {"stdoutBytes": 0}, {"stdoutBytes": True}, {"stdoutBytes": 12 * 1024 * 1024 + 1},
            {"unexpectedReceipt": True},
        ]:
            failed = deepcopy(report)
            failed["cases"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(helper.CheckFailure):
                validate_owner(failed)
        for changed in ({"effect": "unknown"}, {"journal": "recovery_required"}, {"resources": "unknown"},
                        {"reason": "cancelled"}, {"reason": {"raw": "not accepted"}}):
            failed = deepcopy(report)
            failed["cases"][0]["outcome"].update(changed)
            with self.subTest(outcome=changed), self.assertRaises(helper.CheckFailure):
                validate_owner(failed)
        report["cases"][2]["outcome"]["reason"] = "cancelled"
        self.assertIs(validate_owner(report), report)  # Settled explicit discard, not Saved.

    def test_config_owner_receipt_is_complete_source_bound_and_narrowly_scoped(self):
        original = owner_report()
        for changes in ({"status": "failed"}, {"allOwnersSettled": False}, {"allOwnersSettled": 1},
                        {"schemaVersion": True}, {"failureCode": "not_completed"}, {"cases": original["cases"][:-1]},
                        {"notVerified": []}, {"scope": "production-save-enablement"}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(helper.CheckFailure):
                validate_owner({**original, **changes})
        for changes in ({"sourceSha": "0" * 40}, {"pythonSha256": "0" * 64}, {"sourceHashes": {}},
                        {"host": "macos"}, {"target": helper.TARGETS["windows"]}, {"runtimeMode": "production"},
                        {"payloadHashes": {}}):
            failed = deepcopy(original)
            failed["bindings"].update(changes)
            with self.subTest(bindings=changes), self.assertRaises(helper.CheckFailure):
                validate_owner(failed)
        failed = deepcopy(original)
        failed["cases"][0], failed["cases"][1] = failed["cases"][1], failed["cases"][0]
        with self.assertRaises(helper.CheckFailure):
            validate_owner(failed)

    def test_native_config_reports_do_not_launder_retained_uncertainty(self):
        for partition in helper.CONFIG_PARTITIONS:
            report = {"suite": "desktop-config-native", "partition": partition, "status": "passed", "reason": "none",
                      "completed": list(helper.CONFIG_CASES[partition]), "failedAt": None,
                      "retained": partition != "ordinary", "uncertaintyLatched": partition == "committed-close",
                      "injection": helper.CONFIG_INJECTIONS[partition]}
            self.assertIs(helper.validate_config_receipt(report, partition), report)
            for changed in ({"retained": not report["retained"]}, {"uncertaintyLatched": not report["uncertaintyLatched"]},
                            {"status": "failed"}, {"completed": report["completed"][:-1]}, {"allOwnersSettled": True},
                            {"injection": "genuine-os-close-failure"}):
                with self.subTest(partition=partition, changed=changed), self.assertRaises(helper.CheckFailure):
                    helper.validate_config_receipt({**report, **changed}, partition)

    def test_fixed_command_shape_capture_and_metadata_output_are_preserved(self):
        argv = ["/never-executed/tool", "private-argument-canary"]
        environment = {"PRIVATE_CANARY": "not-a-log-value"}
        completed = subprocess.CompletedProcess(argv, 0, "1.98.0\n")
        with patch.object(helper.subprocess, "run", return_value=completed) as called, redirect_stdout(io.StringIO()) as logs:
            result = helper.run(argv, check="rust-version-target", cwd=Path("/unused"),
                                env=environment, timeout=15, capture=True)
            self.assertEqual(result, "1.98.0")
            called.assert_called_once_with(argv, cwd=Path("/unused"), env=environment,
                                           check=True, timeout=15, text=True, stdout=subprocess.PIPE)
            self.assertEqual(logs.getvalue(), "Fixed check: rust-version-target\n")
        with patch.object(helper.subprocess, "run", return_value=completed) as called, redirect_stdout(io.StringIO()):
            destination = io.StringIO()
            self.assertEqual(helper.run(argv, check="locked-platform-metadata", cwd=Path("/unused"),
                                         env={}, timeout=600, output=destination), "")
            self.assertIs(called.call_args.kwargs["stdout"], destination)
            self.assertTrue(called.call_args.kwargs["check"])
            self.assertEqual(called.call_args.kwargs["timeout"], 600)

    def test_failure_diagnostics_never_include_command_paths_or_captured_values(self):
        private = "PRIVATE-CANARY-NOT-FOR-OUTPUT"
        failures = (
            (subprocess.CalledProcessError(1, [private], output=private, stderr=private),
             "Fixed check source-clean exited 1"),
            (subprocess.TimeoutExpired([private], 15, output=private, stderr=private),
             "Fixed check source-clean exceeded its deadline"),
            (OSError(13, private, private), "Fixed check source-clean could not start"),
        )
        for error, expected in failures:
            with self.subTest(kind=type(error).__name__), patch.object(helper.subprocess, "run", side_effect=error), redirect_stdout(io.StringIO()) as logs:
                with self.assertRaises(helper.CheckFailure) as caught:
                    helper.run([private], check="source-clean", cwd=Path("/unused"),
                               env={"PRIVATE": private}, timeout=15)
                self.assertEqual(str(caught.exception), expected)
                self.assertNotIn(private, logs.getvalue() + str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)

    def test_unlisted_labels_conflicting_output_and_capture_overflow_refuse(self):
        with patch.object(helper.subprocess, "run") as called, redirect_stdout(io.StringIO()):
            with self.assertRaises(helper.CheckFailure):
                helper.run(["unused"], check="unlisted", cwd=Path("/unused"), env={}, timeout=15)
            with self.assertRaises(helper.CheckFailure):
                helper.run(["unused"], check="source-head", cwd=Path("/unused"), env={}, timeout=15,
                           capture=True, output=io.StringIO())
            called.assert_not_called()
        with patch.object(helper.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "x" * (1024 * 1024 + 1))), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(helper.CheckFailure, "metadata exceeded"):
                helper.run(["unused"], check="source-head", cwd=Path("/unused"), env={}, timeout=15, capture=True)

    def test_fixed_callers_and_private_toolchain_install_do_not_bypass_wrapper(self):
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        raw_calls = [node for node in calls if isinstance(node.func, ast.Attribute)
                     and isinstance(node.func.value, ast.Name)
                     and node.func.value.id == "subprocess" and node.func.attr == "run"]
        wrapper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        self.assertEqual(len(raw_calls), 1)
        self.assertIn(raw_calls[0], list(ast.walk(wrapper)))
        tool_calls = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == "run"]
        labels = []
        for call in tool_calls:
            label = next(keyword.value for keyword in call.keywords if keyword.arg == "check")
            self.assertIsInstance(label, ast.Constant)
            self.assertIn(label.value, helper.TOOL_CHECKS)
            labels.append(label.value)
        self.assertEqual(set(labels), helper.TOOL_CHECKS)
        install = next(call for call in tool_calls if any(keyword.arg == "check"
                       and isinstance(keyword.value, ast.Constant)
                       and keyword.value.value == "rust-toolchain-install" for keyword in call.keywords))
        self.assertIsInstance(install.args[0], ast.List)
        constants = [item.value for item in install.args[0].elts if isinstance(item, ast.Constant)]
        self.assertEqual(constants, ["toolchain", "install", "--profile", "minimal", "--no-self-update"])
        self.assertTrue(any(isinstance(item, ast.Name) and item.id == "RUST" for item in install.args[0].elts))


def workflow_environment() -> dict:
    return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": helper.WORKFLOW_NATIVE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.WORKFLOW_NATIVE_WORKFLOW}@{helper.WORKFLOW_NATIVE_REF}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


def workflow_host_report() -> dict:
    return {"kernelRelease": "fixed-synthetic-kernel", "machine": "x86_64", "nonRoot": True,
            "filesystem": {"device": "23", "blockSize": 4096, "fragmentSize": 4096, "nameMax": 255, "flags": 0}}


def workflow_context() -> dict:
    return {**helper.workflow_native_binding(workflow_environment()), "executionScope": helper.WORKFLOW_NATIVE_SCOPE,
            "platform": "linux", "sourceTree": "3" * 40, "workflowSha256": "4" * 64,
            "root": "/synthetic/workflow-task", "source": "/synthetic/source", "python": "/selected/python",
            "observedHost": workflow_host_report(),
            "workflowInputs": {"sourceFiles": [{"path": path, "size": 1, "sha256": "5" * 64}
                                               for path in helper.WORKFLOW_NATIVE_SOURCES],
                               "coreFiles": [{"path": "mobile_release/__init__.py", "size": 1, "sha256": "6" * 64}],
                               "coreZipSha256": "7" * 64, "pythonSha256": "2" * 64}}


def workflow_phase_report(name: str) -> dict:
    context = workflow_context()
    return {"schemaVersion": 1, "scope": helper.WORKFLOW_NATIVE_EVIDENCE_SCOPE, "phase": name, "status": "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                            "workflowRef", "workflowSha256", "runId", "attempt", "workflowInputs")},
            "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "python": helper.PYTHON,
            "features": ["development-runtime"], "testTarget": "lib",
            "checks": [{"check": check, "exitCode": 0} for check in helper.WORKFLOW_NATIVE_CHECKS[name]],
            "notVerified": list(helper.WORKFLOW_NOT_VERIFIED)}


def workflow_core_report(partition: str) -> dict:
    rows = helper.WORKFLOW_CORE_ROWS[partition]
    return deepcopy({"schemaVersion": 1, "suite": "desktop-workflow-native", "domain": "github_workflows",
        "partition": partition, "status": "passed", "reason": "none", "failedAt": None,
        "retained": True, "uncertaintyLatched": partition != "committed-fsync",
        "injection": helper.WORKFLOW_CORE_INJECTIONS[partition], "host": workflow_host_report(),
        "bindings": {"sourceSha": "1" * 40, "sourceKind": "source", "sourceHashes": dict.fromkeys(helper.WORKFLOW_CORE_SOURCES, "3" * 64),
                     "pythonSha256": "2" * 64, **helper.WORKFLOW_PAYLOAD_BINDINGS},
        "completed": [row[0] for row in rows],
        "cases": [{"case": name, "outcome": {"effect": effect, "journal": journal, "resources": resources, "reason": reason},
                   "owner": {"closed": True, "handlerRestored": True, "fatal": fatal}, "observed": observed}
                  for name, effect, journal, resources, reason, fatal, observed in rows]})


def validate_workflow_core(value: object, partition: str) -> dict:
    return helper.validate_workflow_core_receipt(value, partition, source_sha="1" * 40,
        source_hashes=dict.fromkeys(helper.WORKFLOW_CORE_SOURCES, "3" * 64), python_hash="2" * 64, host=workflow_host_report())


# Inert receipt expectations transcribed from independent Rust contract DATA
# da0dc551ec6ce88993282f8d364b7481eb7c3ddedfdfe0eca6de024922d27809.
# They are not produced by, or accepted as, a native invocation.
WORKFLOW_NATIVE_SOURCE_KEYS = (
    'fixture', 'owner', 'editProtocol', 'runtime', 'protocol',
    'errors', 'library', 'build', 'cargoManifest', 'cargoLock',
    'bootstrap', 'passiveBootstrap', 'corePackage', 'engine', 'control',
    'coreProtocol', 'configEdit', 'configPayloads', 'config', 'transaction',
    'rootCustody', 'cancellation', 'buildInputs', 'coreErrors', 'preview',
    'nativeFixture', 'workflowProtocol', 'bridge', 'documentBinding', 'documentLifetime',
    'assetSource', 'assetCommands', 'supervisor', 'editCommands', 'githubCommands',
    'workflowEdit', 'workflowPayloads', 'githubSetup', 'githubResource', 'canonicalPreflight',
    'canonicalCandidate', 'canonicalExternalTesting', 'canonicalProductionSubmit',
)
WORKFLOW_CASE_COMMON = {'originalWait': True, 'stdoutEof': True, 'stderrEof': True, 'stdinClosed': True, 'stdoutClosed': True, 'stderrClosed': True, 'startupJoined': True, 'ioJoined': True, 'driverJoined': True, 'watchdogJoined': True, 'managerJoined': True, 'forceAttempted': False, 'registeredByOriginalProbe': True, 'sourceProbesSettled': True}
WORKFLOW_NATIVE_FIXED_BINDINGS = {
    'domain': 'github_workflows',
    'host': 'linux',
    'target': 'x86_64-unknown-linux-gnu',
    'runtimeMode': 'trusted-development-only',
    'templateResourceSha256': '4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c',
    'toolingRepository': 'Example/mobile-release-kit',
    'toolingSha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'inheritedFileMaskObserved': True,
    'requestedCreateMode': 420,
    'observedCreateMode': 384,
    'newDirectoryMode': 493,
    'documentEvidence': 'controlled-original-lifetime-not-gui-callbacks',
    'ref': 'refs/heads/verify/desktop-github-workflow-apply-native',
    "payloadHashes": {
        'draft': '7c19854e3652c3f3ed698c02fa6078e3e8f62f73682517617bac86cb0038acc7',
        'workflows': {'preflight': '50845641f06763aab532900d1b3b186a5d684d465a4d63fab05f53c99f9685de', 'candidate': '8fb540be24c263c97f7dbf95df524a8b11633e5fa7b1dc92e77cd648ad16e32f', 'external-testing': '97fa27d95cc7b2d75be0c3a0860af1d350edb6a52741ed87c0a5b13eca8386f1', 'production-submit': '85865a4df661ef7c7b708b55598a70d56fd84957ce07c9c60f15bcf10a5554b8'},
        'protectedConfig': 'd0eb25f7006a26234235a3a4e7ed7588f36f3ce7fc95f1e707b0d57c8d4b83d0',
        'protectedIgnore': 'd4247a03ac6b6122d0402ff195f354112aca945da5d8e9ce362d19701dbcafe6',
        'unrelated': '0e4722e0ca13cfc08d5e8bd61c73d37c9880610e1723a8eb1c2363e92e2eebef',
        'umaskProbe': '9c32669444fb9694299448392c40adef003059b9987eb57efcfc685cd4c00a56',
    },
}

WORKFLOW_OWNER_CASE_DATA = (
    {'name': 'create-fresh', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'committed', 'journal': 'clean', 'resources': 'settled', 'reason': 'none'},
     "observations": {'created': 4, 'preserved': 0, 'directoriesCreated': ['.github', '.github/workflows'], 'canonicalPayloads': True, 'templateIdentity': True, 'completePreparedBytes': True, 'capturePrepareUnchanged': True, 'protectedPreserved': True, 'existingIdentityPreserved': True, 'createModesMasked': True, 'directoryModesExact': True, 'duplicateApplyObservation': True, 'oppositeDomainRefused': True, 'sharedStatusRevision': True}},
    {'name': 'create-under-github', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'committed', 'journal': 'clean', 'resources': 'settled', 'reason': 'none'},
     "observations": {'created': 4, 'preserved': 0, 'directoriesCreated': ['.github/workflows'], 'canonicalPayloads': True, 'templateIdentity': True, 'completePreparedBytes': True, 'capturePrepareUnchanged': True, 'protectedPreserved': True, 'existingIdentityPreserved': True, 'createModesMasked': True, 'directoryModesExact': True, 'duplicateApplyObservation': False, 'oppositeDomainRefused': False, 'sharedStatusRevision': True}},
    {'name': 'mixed-create-preserve', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'committed', 'journal': 'clean', 'resources': 'settled', 'reason': 'none'},
     "observations": {'created': 2, 'preserved': 2, 'directoriesCreated': [], 'canonicalPayloads': True, 'templateIdentity': True, 'completePreparedBytes': True, 'capturePrepareUnchanged': True, 'protectedPreserved': True, 'existingIdentityPreserved': True, 'createModesMasked': True, 'directoryModesExact': True, 'duplicateApplyObservation': False, 'oppositeDomainRefused': False, 'sharedStatusRevision': True}},
    {'name': 'preserve-all', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'unchanged', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'created': 0, 'preserved': 4, 'directoriesCreated': [], 'canonicalPayloads': True, 'templateIdentity': True, 'completePreparedBytes': True, 'capturePrepareUnchanged': True, 'protectedPreserved': True, 'existingIdentityPreserved': True, 'createModesMasked': True, 'directoryModesExact': True, 'duplicateApplyObservation': False, 'oppositeDomainRefused': False, 'sharedStatusRevision': True}},
    {'name': 'different-refusal', 'domain': 'github_workflows', 'requestFrames': 2, 'responseFrames': 2, 'terminalSeq': 1, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'noPlanToken': True, 'oneDifferingNewline': True, 'noPreparedFrame': True, 'wholeBundleRefused': True, 'treeUnchanged': True}},
    {'name': 'root-replaced-before-open', 'domain': 'github_workflows', 'requestFrames': 1, 'responseFrames': 1, 'terminalSeq': 0, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'none', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'stale_revision'},
     "observations": {'registeredIdentityRetained': True, 'replacementRejectedBeforeCheckout': True, 'replacementTreeUnchanged': True}},
    {'name': 'registration-before-prepare', 'domain': 'github_workflows', 'requestFrames': 1, 'responseFrames': 2, 'terminalSeq': 0, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'caller_lost', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'newRegistrationPublishedUnderDocumentLock': True, 'originalRegistrationRetained': True, 'staleCommandNotSent': True, 'treeUnchanged': True}},
    {'name': 'registration-before-apply', 'domain': 'github_workflows', 'requestFrames': 2, 'responseFrames': 3, 'terminalSeq': 1, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'caller_lost', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'newRegistrationPublishedUnderDocumentLock': True, 'originalRegistrationRetained': True, 'staleCommandNotSent': True, 'treeUnchanged': True}},
    {'name': 'config-blocks-workflow', 'domain': 'configuration', 'requestFrames': 1, 'responseFrames': 2, 'terminalSeq': 0, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'discarded', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'oppositeDomainRefused': True, 'sharedStatusRevision': True, 'sharedLastTerminalReplaced': True, 'configurationFilesUnchanged': True, 'workflowPermitStillSeparate': True}},
    {'name': 'document-loss', 'domain': 'github_workflows', 'requestFrames': 2, 'responseFrames': 3, 'terminalSeq': 1, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'window_lost', 'applySubmitted': False, 'lateSettled': False, 'stderrBytes': 0,
     "outcome": {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled', 'reason': 'none'},
     "observations": {'controlledOriginalDocumentLoss': True, 'originalStopRequested': True, 'replacementDocumentRefused': True, 'preparedCorrelationRetained': True, 'treeUnchanged': True, 'guiCallbacksNotClaimed': True}},
)

WORKFLOW_EOF_CASE_DATA = (
    {'name': 'precommit-eof', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'cancelled', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 258,
     "outcome": {'effect': 'rolled_back', 'journal': 'clean', 'resources': 'settled', 'reason': 'cancelled'},
     "observations": {'evidenceKind': 'real-stdin-eof-at-controlled-transaction-boundary', 'bootstrapMode': 'instrumented-genuine-engine', 'boundary': 'before-COMMITTED', 'originalCheckpoint': 'publisher-entry', 'closeBeforeActiveDeadline': True, 'controlRecords': 2, 'actualStdinEof': True, 'eofReadCount': 1, 'nonemptyReadCount': 0, 'readErrorCount': 0, 'preparedCorrelation': True, 'committedPublication': False, 'rolledBackPublication': True, 'terminalDurable': True, 'fixedRecovery': True, 'journalClean': True, 'journalAbsent': True, 'originalTreeRestored': True, 'canonicalPayloadsRemain': False, 'protectedPreserved': True, 'unrelatedIntroducedBeforeEof': False, 'introducedOriginalPreserved': False, 'recoveryEvidenceRetained': False, 'sharedBlockedProject': False, 'bothDomainsDisabled': False, 'noFurtherAdmission': False, 'fixtureFilesSettled': True}},
    {'name': 'postcommit-eof', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'final', 'nativeFinality': 'settled', 'nativeReason': 'cancelled', 'applySubmitted': True, 'lateSettled': False, 'stderrBytes': 266,
     "outcome": {'effect': 'committed', 'journal': 'clean', 'resources': 'settled', 'reason': 'cancelled'},
     "observations": {'evidenceKind': 'real-stdin-eof-at-controlled-transaction-boundary', 'bootstrapMode': 'instrumented-genuine-engine', 'boundary': 'after-durable-COMMITTED', 'originalCheckpoint': 'descriptor-close', 'closeBeforeActiveDeadline': True, 'controlRecords': 2, 'actualStdinEof': True, 'eofReadCount': 1, 'nonemptyReadCount': 0, 'readErrorCount': 0, 'preparedCorrelation': True, 'committedPublication': True, 'rolledBackPublication': False, 'terminalDurable': True, 'fixedRecovery': True, 'journalClean': True, 'journalAbsent': True, 'originalTreeRestored': False, 'canonicalPayloadsRemain': True, 'protectedPreserved': True, 'unrelatedIntroducedBeforeEof': False, 'introducedOriginalPreserved': False, 'recoveryEvidenceRetained': False, 'sharedBlockedProject': False, 'bothDomainsDisabled': False, 'noFurtherAdmission': False, 'fixtureFilesSettled': True}},
    {'name': 'precommit-conflict-eof', 'domain': 'github_workflows', 'requestFrames': 3, 'responseFrames': 3, 'terminalSeq': 2, 'nativePhase': 'unknown', 'nativeFinality': 'unknown', 'nativeReason': 'cancelled', 'applySubmitted': True, 'lateSettled': True, 'stderrBytes': 272,
     "outcome": {'effect': 'unknown', 'journal': 'recovery_required', 'resources': 'settled', 'reason': 'cancelled'},
     "observations": {'evidenceKind': 'real-stdin-eof-at-controlled-transaction-boundary', 'bootstrapMode': 'instrumented-genuine-engine', 'boundary': 'before-COMMITTED', 'originalCheckpoint': 'publisher-entry', 'closeBeforeActiveDeadline': True, 'controlRecords': 2, 'actualStdinEof': True, 'eofReadCount': 1, 'nonemptyReadCount': 0, 'readErrorCount': 0, 'preparedCorrelation': True, 'committedPublication': False, 'rolledBackPublication': False, 'terminalDurable': False, 'fixedRecovery': True, 'journalClean': False, 'journalAbsent': False, 'originalTreeRestored': False, 'canonicalPayloadsRemain': True, 'protectedPreserved': True, 'unrelatedIntroducedBeforeEof': True, 'introducedOriginalPreserved': True, 'recoveryEvidenceRetained': True, 'sharedBlockedProject': True, 'bothDomainsDisabled': True, 'noFurtherAdmission': True, 'fixtureFilesSettled': True}},
)

def workflow_owner_report(mode: str = "source", *, eof: bool = False) -> dict:
    rows = WORKFLOW_EOF_CASE_DATA if eof else WORKFLOW_OWNER_CASE_DATA if mode == "source" else WORKFLOW_OWNER_CASE_DATA[:1]
    keys = (*WORKFLOW_NATIVE_SOURCE_KEYS, "transactionEofShim") if eof else WORKFLOW_NATIVE_SOURCE_KEYS
    return deepcopy({"schemaVersion": 1, "domain": "github_workflows", "status": "passed", "failureCode": None,
        "scope": "github-workflow-transaction-eof-hosted-v1" if eof else "github-workflow-owner-hosted-v1",
        "allOwnersSettled": not eof, "originalResourcesSettled": True, "ownerDisabled": eof, "retainedEffectUnknown": eof,
        "notVerified": list(helper.WORKFLOW_NOT_VERIFIED),
        "cases": [{**WORKFLOW_CASE_COMMON, "stdoutBytes": 4096, **row} for row in rows],
        "bindings": {**WORKFLOW_NATIVE_FIXED_BINDINGS, "sourceSha": "1" * 40, "sourceTree": "3" * 40,
            "workflowSha256": "4" * 64, "runId": "123", "attempt": "2", "pythonSha256": "2" * 64,
            "coreZipSha256": "7" * 64,
            "coreInventorySha256": "b78b4a875a0341d629a8aaa0148a9816f9cbc24cd55f14168a2b54a8a1cea4c0",
            "sourceHashes": dict.fromkeys(keys, "3" * 64), "runtimeInput": mode}})


def validate_workflow_owner(value: object, mode: str = "source", *, eof: bool = False) -> dict:
    if eof:
        return helper.validate_workflow_transaction_eof_receipt(value, context=workflow_context(),
            source_hashes=dict.fromkeys((*WORKFLOW_NATIVE_SOURCE_KEYS, "transactionEofShim"), "3" * 64))
    return helper.validate_workflow_owner_receipt(value, mode, context=workflow_context(),
        source_hashes=dict.fromkeys(WORKFLOW_NATIVE_SOURCE_KEYS, "3" * 64))


class WorkflowNativeHelperTests(unittest.TestCase):
    """Explicit inert selectors; data consumers/source checks, never fixtures."""

    def test_owner_source_matrix_and_single_zip_case_require_original_mode_and_case_inventory(self):
        for mode in ("source", "zip"):
            report = workflow_owner_report(mode)
            with patch.object(helper, "run", side_effect=AssertionError("no subprocess")), \
                    patch.object(helper, "hash_file", side_effect=AssertionError("no file read")):
                self.assertIs(validate_workflow_owner(report, mode), report)
            self.assertEqual(len(report["cases"]), 10 if mode == "source" else 1)
            for changed in ({"schemaVersion": True}, {"domain": "configuration"}, {"status": "failed"},
                            {"allOwnersSettled": False}, {"originalResourcesSettled": False}, {"ownerDisabled": True},
                            {"retainedEffectUnknown": True}, {"failureCode": "not_completed"}, {"notVerified": []},
                            {"cases": []}, {"cases": report["cases"] * 2}, {"extra": True}):
                with self.subTest(mode=mode, change=changed), self.assertRaises(helper.CheckFailure):
                    validate_workflow_owner({**report, **changed}, mode)
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_owner(report, "zip" if mode == "source" else "source")
        report = workflow_owner_report()
        self.assertEqual(tuple(case["name"] for case in report["cases"]), (
            "create-fresh", "create-under-github", "mixed-create-preserve", "preserve-all", "different-refusal",
            "root-replaced-before-open", "registration-before-prepare", "registration-before-apply", "config-blocks-workflow", "document-loss"))
        for altered in (list(reversed(report["cases"])), report["cases"][:-1]):
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_owner({**report, "cases": altered})
        for index in (6, 7, 8, 9):
            report["cases"][index]["outcome"]["reason"] = "cancelled"
        self.assertIs(validate_workflow_owner(report), report)  # Only the four closed EOF/discard races allow both reasons.
        for value in (None, [], True, "passed"):
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_owner(value)

    def test_owner_bindings_require_every_original_source_runtime_payload_workflow_and_run_field(self):
        for eof in (False, True):
            report = workflow_owner_report(eof=eof)
            self.assertEqual(len(report["bindings"]), 24)
            self.assertEqual(len(report["bindings"]["sourceHashes"]), 44 if eof else 43)
            for key in report["bindings"]:
                changed = deepcopy(report)
                del changed["bindings"][key]
                with self.subTest(eof=eof, missing=key), self.assertRaises(helper.CheckFailure):
                    validate_workflow_owner(changed, eof=eof)
            for key, value in (("sourceSha", "2" * 40), ("sourceTree", "2" * 40), ("workflowSha256", "0" * 64),
                               ("runId", "124"), ("attempt", "3"), ("ref", "refs/heads/main"), ("domain", "configuration"),
                               ("host", "macos"), ("target", helper.TARGETS["windows"]), ("runtimeMode", "production"),
                               ("runtimeInput", "zip"), ("pythonSha256", "0" * 64), ("coreZipSha256", "0" * 64),
                               ("coreInventorySha256", "0" * 64), ("sourceHashes", {}), ("payloadHashes", {}),
                               ("requestedCreateMode", True), ("observedCreateMode", 420), ("newDirectoryMode", 493.0),
                               ("inheritedFileMaskObserved", 1), ("documentEvidence", "genuine-gui-callbacks"), ("extra", False)):
                changed = deepcopy(report)
                changed["bindings"][key] = value
                with self.subTest(eof=eof, key=key), self.assertRaises(helper.CheckFailure):
                    validate_workflow_owner(changed, eof=eof)
            for group in ("sourceHashes", "payloadHashes"):
                for key in report["bindings"][group]:
                    changed = deepcopy(report)
                    del changed["bindings"][group][key]
                    with self.subTest(eof=eof, group=group, key=key), self.assertRaises(helper.CheckFailure):
                        validate_workflow_owner(changed, eof=eof)

    def test_owner_original_returns_correlations_frames_and_observations_are_strict(self):
        for eof in (False, True):
            report = workflow_owner_report(eof=eof)
            for index, case in enumerate(report["cases"]):
                self.assertEqual(len(case), 28)
                for key, original in case.items():
                    values = (not original, int(original)) if type(original) is bool else (True, float(original)) if type(original) is int else ()
                    for value in values:
                        changed = deepcopy(report)
                        changed["cases"][index][key] = value
                        with self.subTest(eof=eof, case=case["name"], key=key, value=value), self.assertRaises(helper.CheckFailure):
                            validate_workflow_owner(changed, eof=eof)
                for key, original in case["observations"].items():
                    values = (not original, int(original)) if type(original) is bool else (True, float(original), original + 1) if type(original) is int else (None,)
                    for value in values:
                        changed = deepcopy(report)
                        changed["cases"][index]["observations"][key] = value
                        with self.subTest(eof=eof, case=case["name"], observation=key, value=value), self.assertRaises(helper.CheckFailure):
                            validate_workflow_owner(changed, eof=eof)
                for key, value in (("stdoutBytes", 0), ("stdoutBytes", 12 * 1024 * 1024 + 1),
                                   ("requestFrames", case["requestFrames"] + 1), ("responseFrames", case["responseFrames"] + 1),
                                   ("terminalSeq", case["terminalSeq"] + 1), ("nativeReason", "uncontrolled"),
                                   ("domain", "configuration" if case["domain"] == "github_workflows" else "github_workflows"),
                                   ("extra", True), ("observations", {}),
                                   ("outcome", {**case["outcome"], "resources": "unknown"}),
                                   ("outcome", {**case["outcome"], "reason": "filesystem_error"})):
                    changed = deepcopy(report)
                    changed["cases"][index][key] = value
                    with self.subTest(eof=eof, case=case["name"], key=key), self.assertRaises(helper.CheckFailure):
                        validate_workflow_owner(changed, eof=eof)

    def test_eof_last_conflict_is_native_unknown_with_actual_original_resources_not_normal_settlement(self):
        report = workflow_owner_report(eof=True)
        self.assertIs(validate_workflow_owner(report, eof=True), report)
        self.assertEqual([case["stderrBytes"] for case in report["cases"]], [258, 266, 272])
        self.assertEqual([case["outcome"]["effect"] for case in report["cases"]], ["rolled_back", "committed", "unknown"])
        self.assertIs(report["allOwnersSettled"], False)
        self.assertIs(report["originalResourcesSettled"], True)
        for changed in ({"allOwnersSettled": True}, {"originalResourcesSettled": False}, {"ownerDisabled": False},
                        {"retainedEffectUnknown": False}, {"cases": report["cases"][:2]},
                        {"cases": list(reversed(report["cases"]))}, {"scope": "github-workflow-owner-hosted-v1"}):
            with self.subTest(change=changed), self.assertRaises(helper.CheckFailure):
                validate_workflow_owner({**report, **changed}, eof=True)
        last = report["cases"][-1]
        self.assertEqual((last["nativePhase"], last["nativeFinality"], last["lateSettled"]), ("unknown", "unknown", True))
        self.assertEqual(last["outcome"], {"effect": "unknown", "journal": "recovery_required", "resources": "settled", "reason": "cancelled"})
        for key, value in (("nativePhase", "final"), ("nativeFinality", "settled"), ("lateSettled", False), ("stderrBytes", 258),
                           ("outcome", {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"})):
            changed = deepcopy(report)
            changed["cases"][-1][key] = value
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_owner(changed, eof=True)
        with self.assertRaises(helper.CheckFailure):
            validate_workflow_owner(report)  # Expected negative EOF cannot substitute for a healthy owner proof.

    def test_native_receipt_reader_enforces_its_smaller_bound_before_any_open(self):
        with patch.object(helper, "ordinary"), patch.object(Path, "stat") as details, \
                patch.object(Path, "open", side_effect=AssertionError("oversized data must not be opened")):
            details.return_value.st_size = 65537
            with self.assertRaises(helper.CheckFailure):
                helper.workflow_json(Path("/never-opened/receipt.json"), maximum=65536)
        source = HELPER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for name in ("workflow_owner_receipt", "workflow_transaction_eof_receipt"):
            wrapper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
            calls = [node for node in ast.walk(wrapper) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "workflow_json"]
            self.assertEqual(len(calls), 1)
            self.assertIn("maximum=64 * 1024", ast.get_source_segment(source, calls[0]))

    def test_native_scope_is_separate_and_refuses_other_phases_before_context_or_tools(self):
        self.assertNotIn(helper.WORKFLOW_NATIVE_SCOPE, helper.COMPILE_PROFILES)
        self.assertEqual(set(helper.COMPILE_PROFILES), {helper.COMPILE_SCOPE, helper.GTK_COMPILE_SCOPE})
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for name in ("native", "config-owner", "config-task-loss", "config-owner-delta", "config-transaction-eof", "config-core", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", helper.WORKFLOW_NATIVE_SCOPE)
            for scope in (*helper.COMPILE_PROFILES, helper.BOUNDARY_SCOPE):
                for name in ("workflow-owner", "workflow-transaction-eof", "workflow-core"):
                    with self.subTest(scope=scope, phase=name), self.assertRaises(helper.CheckFailure):
                        helper.phase(name, "linux", scope)
            for platform in ("macos", "windows", "unexpected"):
                for name in helper.WORKFLOW_NATIVE_PHASES:
                    with self.subTest(platform=platform, phase=name), self.assertRaises(helper.CheckFailure):
                        helper.phase(name, platform, helper.WORKFLOW_NATIVE_SCOPE)
                with self.assertRaises(helper.CheckFailure):
                    helper.prepare(platform, helper.WORKFLOW_NATIVE_SCOPE)
        for name in helper.WORKFLOW_NATIVE_PHASES:
            helper.admit_phase(helper.WORKFLOW_NATIVE_SCOPE, name)

    def test_binding_requires_fixed_workflow_ref_source_attempt_and_exact_dispatch(self):
        environment = workflow_environment()
        expected = helper.workflow_native_binding(environment)
        self.assertEqual(expected["workflowPath"], ".github/workflows/desktop-github-workflow-apply-native.yml")
        for key, value in (("GITHUB_SHA", "bad"), ("GITHUB_WORKFLOW_SHA", "2" * 40), ("GITHUB_REF", helper.COMPILE_REF),
                           ("GITHUB_WORKFLOW_REF", "other/workflow"), ("GITHUB_REPOSITORY", "other/project"),
                           ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                helper.workflow_native_binding({**environment, key: value})
        with self.assertRaises(helper.CheckFailure):
            helper.workflow_native_binding({**environment, "GITHUB_SHA": "0" * 40, "GITHUB_WORKFLOW_SHA": "0" * 40})
        dispatch = {**environment, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        for sha in (None, "2" * 40, "main"):
            with self.subTest(expected_sha=sha), self.assertRaises(helper.CheckFailure):
                helper.workflow_native_binding({**dispatch, "MRK_EXPECTED_SHA": sha})
        self.assertEqual(helper.workflow_native_binding({**dispatch, "MRK_EXPECTED_SHA": "1" * 40}), expected)
        for scope in helper.COMPILE_PROFILES:
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding(environment, scope)

    def test_observed_host_is_typed_nonroot_linux_data_not_filesystem_qualification(self):
        host = workflow_host_report()
        helper.validate_workflow_host(host)
        for changes in ({"nonRoot": False}, {"nonRoot": 1}, {"machine": "aarch64"}, {"kernelRelease": ""},
                        {"kernelRelease": "private\nline"}, {"kernelRelease": "x" * 257}, {"extra": True}):
            with self.subTest(change=changes), self.assertRaises(helper.CheckFailure):
                helper.validate_workflow_host({**host, **changes})
        for key, value in (("device", 23), ("device", "023"), ("device", "-1"), ("device", str(2**64)),
                           ("blockSize", True), ("fragmentSize", 4096.0), ("nameMax", 0), ("flags", False), ("flags", -1)):
            with self.subTest(key=key, value=value), self.assertRaises(helper.CheckFailure):
                helper.validate_workflow_host({**host, "filesystem": {**host["filesystem"], key: value}})

    def test_phase_receipts_are_closed_typed_source_bound_and_not_compiler_proof(self):
        context = workflow_context()
        for name in helper.WORKFLOW_NATIVE_CHECKS:
            report = workflow_phase_report(name)
            self.assertIs(helper.validate_workflow_phase_receipt(report, context, name), report)
            for key, value in (("schemaVersion", True), ("sourceSha", "2" * 40), ("sourceTree", "2" * 40),
                               ("platform", "windows"), ("workflowPath", helper.COMPILE_WORKFLOW), ("workflowSha256", "6" * 64),
                               ("workflowSha", "2" * 40), ("workflowRef", "other/ref"), ("runId", "124"), ("attempt", "1"),
                               ("status", "failed"), ("features", ["desktop-shell", "development-runtime"]),
                               ("testTarget", "session-gtk-qualification"), ("notVerified", []),
                               ("checks", report["checks"][:-1]), ("node", helper.NODE), ("extra", False)):
                with self.subTest(phase=name, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_workflow_phase_receipt({**report, key: value}, context, name)
            for value in (False, 1, 0.0, None):
                changed = deepcopy(report)
                changed["checks"][0]["exitCode"] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_workflow_phase_receipt(changed, context, name)
            changed = deepcopy(report)
            changed["workflowInputs"]["sourceFiles"][0]["size"] = True
            with self.assertRaises(helper.CheckFailure):
                helper.validate_workflow_phase_receipt(changed, context, name)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(report, context, "compile")
            for scope in (*helper.COMPILE_PROFILES, helper.BOUNDARY_SCOPE):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_workflow_phase_receipt(report, {**context, "executionScope": scope}, name)

    def test_receipt_bytes_refuse_duplicate_nonfinite_truncated_extra_and_oversized_data(self):
        report = workflow_core_report("ordinary")
        raw = json.dumps(report, separators=(",", ":")).encode()
        self.assertEqual(helper.parse_workflow_receipt(raw), report)
        for malformed in (raw.replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1'),
                          raw.replace(b'"scopesClosed":2', b'"scopesClosed":0,"scopesClosed":2'),
                          raw[:-1], raw + b'{}', b'{"bad":NaN}', b'{"bad":Infinity}', b'\xff', b'', b' ' * (128 * 1024 + 1)):
            with self.subTest(size=len(malformed)), self.assertRaises(helper.CheckFailure):
                helper.parse_workflow_receipt(malformed)

    def test_core_roster_and_terminal_controls_keep_orthogonal_unknown_facts(self):
        names = (
            "capture-prepare-discard", "existing-differs", "oversized", "unreadable", "symlink-leaf", "symlink-ancestor",
            "hardlink", "aliased-leaf", "nonregular-fifo", "registered-root-replaced", "stale-leaf-bytes-before-prepare",
            "stale-leaf-inode-before-apply", "stale-ancestor-mode-before-prepare", "absent-ancestor-before-prepare",
            "absent-leaf-before-apply", "stale-root-before-apply", "pending-init", "pending-build", "contention-init",
            "contention-build", "review-unlocked", "partial-install-rollback", "incomplete-preparing", "wrong-roster-controls",
            "unowned-staging-slot", "rollback-pending-replaced", "cleanup-committed-unused-missing",
            "cleanup-rolled-back-unused-missing", "commit-pending-replaced",
        )
        self.assertEqual(tuple(row[0] for row in helper.WORKFLOW_CORE_ROWS["ordinary"]), names)
        self.assertEqual(tuple(len(helper.WORKFLOW_CORE_ROWS[name]) for name in helper.WORKFLOW_PARTITIONS), (29, 1, 1))
        with patch.object(helper, "run", side_effect=AssertionError("no subprocess")), \
                patch.object(helper, "hash_file", side_effect=AssertionError("no file read")):
            for partition in helper.WORKFLOW_PARTITIONS:
                report = workflow_core_report(partition)
                self.assertIs(validate_workflow_core(report, partition), report)
                self.assertTrue(report["retained"])
        ordinary = workflow_core_report("ordinary")
        self.assertEqual(ordinary["cases"][-1]["outcome"], {"effect": "unknown", "journal": "recovery_required",
                                                              "resources": "settled", "reason": "filesystem_error"})
        self.assertTrue(ordinary["uncertaintyLatched"])
        fsync = workflow_core_report("committed-fsync")
        self.assertEqual(fsync["cases"][0]["outcome"], {"effect": "committed", "journal": "recovery_required",
                                                        "resources": "settled", "reason": "filesystem_error"})
        self.assertFalse(fsync["uncertaintyLatched"])
        close = workflow_core_report("committed-close")
        self.assertEqual(close["cases"][0]["outcome"], {"effect": "committed", "journal": "clean", "resources": "unknown", "reason": "cancelled"})
        self.assertTrue(close["cases"][0]["owner"]["fatal"])
        self.assertEqual(close["cases"][0]["observed"]["afterUnknownProbes"], 0)

    def test_core_receipts_refuse_incomplete_reordered_cross_domain_or_laundered_outcomes(self):
        for partition in helper.WORKFLOW_PARTITIONS:
            report = workflow_core_report(partition)
            changes = ({"schemaVersion": True}, {"suite": "desktop-config-native"}, {"domain": "configuration"},
                       {"status": "failed"}, {"reason": "other"}, {"failedAt": report["completed"][-1]}, {"retained": False},
                       {"uncertaintyLatched": not report["uncertaintyLatched"]}, {"injection": "genuine-os-fault"},
                       {"completed": report["completed"][:-1]}, {"cases": report["cases"][:-1]}, {"allOwnersSettled": True})
            for changed in changes:
                with self.subTest(partition=partition, change=changed), self.assertRaises(helper.CheckFailure):
                    validate_workflow_core({**report, **changed}, partition)
            changed = deepcopy(report)
            changed["cases"][-1]["outcome"].update(resources="settled", reason="none", effect="committed", journal="clean")
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_core(changed, partition)
        report = workflow_core_report("ordinary")
        for cases in (list(reversed(report["cases"])), report["cases"] + [report["cases"][-1]]):
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_core({**report, "cases": cases}, "ordinary")
        for value in (None, [], True, "passed"):
            with self.assertRaises(helper.CheckFailure):
                validate_workflow_core(value, "ordinary")

    def test_each_core_observed_fact_and_owner_return_is_exact_and_strictly_typed(self):
        for partition in helper.WORKFLOW_PARTITIONS:
            report = workflow_core_report(partition)
            for index, case in enumerate(report["cases"]):
                for group in ("owner", "observed"):
                    for key, original in case[group].items():
                        values = (not original, int(original)) if type(original) is bool else (True, float(original), original + 1) if type(original) is int else (None,)
                        for value in values:
                            changed = deepcopy(report)
                            changed["cases"][index][group][key] = value
                            with self.subTest(partition=partition, case=case["case"], group=group, key=key, value=value), self.assertRaises(helper.CheckFailure):
                                validate_workflow_core(changed, partition)
                changed = deepcopy(report)
                changed["cases"][index]["observed"]["unobservedSummary"] = True
                with self.assertRaises(helper.CheckFailure):
                    validate_workflow_core(changed, partition)

    def test_core_bindings_require_exact_source_payload_template_and_host_inputs(self):
        report = workflow_core_report("ordinary")
        for key, value in (("sourceSha", "0" * 40), ("sourceKind", "zip"), ("sourceHashes", {}), ("pythonSha256", "0" * 64),
                           ("draftSha256", "0" * 64), ("toolingRepository", "other/repository"), ("toolingSha", "main"),
                           ("templateSet", {}), ("payloadHashes", {}), ("extra", True)):
            changed = deepcopy(report)
            changed["bindings"][key] = value
            with self.subTest(binding=key), self.assertRaises(helper.CheckFailure):
                validate_workflow_core(changed, "ordinary")
        for group in ("sourceHashes", "payloadHashes", "templateSet"):
            for key in report["bindings"][group]:
                changed = deepcopy(report)
                del changed["bindings"][group][key]
                with self.subTest(group=group, key=key), self.assertRaises(helper.CheckFailure):
                    validate_workflow_core(changed, "ordinary")
        changed = deepcopy(report)
        changed["host"]["filesystem"]["device"] = "24"
        with self.assertRaises(helper.CheckFailure):
            validate_workflow_core(changed, "ordinary")

    def test_source_closure_is_narrow_complete_and_keeps_config_map_unchanged(self):
        self.assertEqual(len(helper.CONFIG_OWNER_SOURCES), 26)
        self.assertEqual(len(helper.WORKFLOW_OWNER_SOURCES), 43)
        self.assertEqual(len(helper.WORKFLOW_TRANSACTION_EOF_SOURCES), 44)
        self.assertEqual(len(helper.WORKFLOW_CORE_SOURCES), 14)
        self.assertEqual(helper.WORKFLOW_TRANSACTION_EOF_SOURCES["transactionEofShim"], "tests/native_desktop_config_eof.py")
        for path in (helper.WORKFLOW_NATIVE_WORKFLOW, "desktop/tools/ci_foundation.py", "desktop/src-tauri/src/document_lifetime.rs",
                     "desktop/src-tauri/src/asset_source.rs", "desktop/src-tauri/src/github_workflow_edit_protocol.rs",
                     "desktop/native/linux-mount-observation/src/lib.rs", "tests/native_desktop_config.py",
                     "src/mobile_release/api/data/github-setup-v1.json", "templates/workflows/mobile-production-submit.yml"):
            self.assertIn(path, helper.WORKFLOW_NATIVE_SOURCES)
        for path in ("desktop/package-lock.json", "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/tests/session_gtk_qualification.rs"):
            self.assertNotIn(path, helper.WORKFLOW_NATIVE_SOURCES)
        self.assertEqual(helper.WORKFLOW_NATIVE_SOURCES, tuple(sorted(set(helper.WORKFLOW_NATIVE_SOURCES))))
        self.assertEqual(helper.WORKFLOW_PAYLOAD_BINDINGS["templateSet"]["resourceSha256"], "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c")

    def test_native_metadata_binds_original_source_zip_workflow_and_run_without_paths(self):
        context = workflow_context()
        metadata = helper.workflow_core_metadata(context)
        self.assertEqual(metadata, {"sourceSha": "1" * 40, "sourceTree": "3" * 40, "workflowSha256": "4" * 64,
            "runId": "123", "attempt": "2", "ref": "refs/heads/verify/desktop-github-workflow-apply-native",
            "coreFiles": context["workflowInputs"]["coreFiles"], "coreZipSha256": "7" * 64})
        self.assertNotIn("root", metadata)
        self.assertNotIn("source", metadata)
        self.assertNotIn("python", metadata)

    def test_successor_requires_prior_phase_and_original_resource_receipts_without_replay(self):
        context = workflow_context()
        observed = []
        def data(path):
            if path.name.endswith("-started.json"):
                return {"scope": helper.WORKFLOW_NATIVE_SCOPE, "phase": path.name.removesuffix("-started.json"),
                        "sourceSha": "1" * 40, "runId": "123", "attempt": "2"}
            return workflow_phase_report(path.name.removesuffix("-checks.json"))
        with patch.object(helper, "workflow_json", side_effect=data), patch.object(Path, "exists", return_value=False), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(helper, "workflow_owner_receipt", side_effect=lambda _, mode: observed.append(mode)), \
                patch.object(helper, "workflow_transaction_eof_receipt", side_effect=lambda _: observed.append("eof")), \
                patch.object(helper, "workflow_core_receipt", side_effect=AssertionError("core has not run")), \
                patch.object(helper, "run", side_effect=AssertionError("no subprocess")):
            helper.workflow_predecessors(context, "workflow-core")
        self.assertEqual(observed, ["source", "zip", "eof"])
        def bad_data(path):
            value = data(path)
            if path.name == "compile-checks.json":
                value["sourceSha"] = "2" * 40
            return value
        with patch.object(helper, "workflow_json", side_effect=bad_data), \
                patch.object(helper, "workflow_owner_receipt", side_effect=AssertionError("prior compiler binding failed")):
            with self.assertRaises(helper.CheckFailure):
                helper.workflow_predecessors(context, "workflow-core")
        with patch.object(helper, "workflow_json", side_effect=data), \
                patch.object(helper, "workflow_owner_receipt", side_effect=helper.CheckFailure("unsettled source owner")), \
                patch.object(helper, "workflow_transaction_eof_receipt", side_effect=AssertionError("cannot advance past unsettled owner")):
            with self.assertRaises(helper.CheckFailure):
                helper.workflow_predecessors(context, "workflow-core")
        with patch.object(Path, "exists", return_value=True), patch.object(helper, "write_json") as emit:
            with self.assertRaises(helper.CheckFailure):
                helper.workflow_phase_start(context, "acquire")
        emit.assert_not_called()

    def test_fixed_headless_commands_have_one_source_matrix_one_zip_case_and_closed_bounds(self):
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        phase = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "phase_workflow_native")
        calls = [node for node in ast.walk(phase) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run"]
        by_label = {next(keyword.value.value for keyword in call.keywords if keyword.arg == "check"): call for call in calls}
        bounds = {"rust-toolchain-install": 600, "workflow-locked-headless-metadata": 600, "headless-test-compile-only": 600,
                  "workflow-owner-source-native-contract": 180, "workflow-owner-zip-native-contract": 60,
                  "workflow-transaction-eof-native-contract": 90, "workflow-core-ordinary": 90,
                  "workflow-core-committed-fsync": 45, "workflow-core-committed-close": 45}
        self.assertEqual(set(by_label), set(bounds))
        self.assertEqual(len(calls), len(bounds))
        for label, timeout in bounds.items():
            self.assertEqual(next(keyword.value.value for keyword in by_label[label].keywords if keyword.arg == "timeout"), timeout)
        for label in ("workflow-owner-source-native-contract", "workflow-owner-zip-native-contract", "workflow-transaction-eof-native-contract"):
            constants = [node.value for node in by_label[label].args[0].elts if isinstance(node, ast.Constant)]
            self.assertEqual(constants, ["test", "--lib", "--features", "development-runtime", "--", "--exact", "--ignored", "--test-threads=1"])
        constants = [node.value for node in by_label["headless-test-compile-only"].args[0].elts if isinstance(node, ast.Constant)]
        self.assertEqual(constants, ["test", "--lib", "--no-run", "--features", "development-runtime"])
        source = ast.get_source_segment(HELPER.read_text(encoding="utf-8"), phase)
        for forbidden in ("npm", "node-version", "vite", "desktop-shell", "CONFIG_OWNER_TEST", "NATIVE_TEST", "MRK_DESKTOP_CONFIG_NATIVE", "MRK_DESKTOP_EDIT_HOSTED_CHECKS"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"--locked", "--offline", "--jobs", "1", "--no-default-features"', source)
        self.assertIn('"--domain", "github_workflows", "--case"', source)

    def test_close_control_is_last_native_call_and_cleanup_has_no_subprocess_or_deletion(self):
        source = HELPER.read_text(encoding="utf-8")
        core = source.split('elif name == "workflow-core":', 1)[1].split('    else:', 1)[0]
        self.assertLess(core.index('check="workflow-core-ordinary"'), core.index('check="workflow-core-committed-fsync"'))
        self.assertLess(core.index('check="workflow-core-committed-fsync"'), core.index('check="workflow-core-committed-close"'))
        tail = core.split('check="workflow-core-committed-close"', 1)[1]
        self.assertNotIn("run(", tail)
        self.assertNotIn("source_unchanged(", tail)
        self.assertIn('workflow_core_receipt(context, "committed-close")', tail)
        self.assertIn("workflow_inputs_unchanged(context)", tail)
        context = workflow_context()
        with patch.object(helper, "workflow_predecessors") as previous, patch.object(helper, "workflow_inputs_unchanged") as inputs, \
                patch.object(helper, "write_json") as emit, patch.object(helper, "run", side_effect=AssertionError("no subprocess")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tools")), \
                patch.object(helper.shutil, "rmtree", side_effect=AssertionError("no deletion")), redirect_stdout(io.StringIO()):
            helper.clean_workflow_native(context)  # Every side effect is inertly mocked.
        previous.assert_called_once_with(context, "clean")
        inputs.assert_called_once_with(context)
        receipt = emit.call_args.args[1]
        self.assertEqual(receipt["status"], "retained")
        for key in ("deleted", "laterNativeWork", "projectProbes"):
            self.assertIs(receipt[key], False)
        self.assertIs(receipt["vmDisposalRequired"], True)

    def test_workflow_is_one_pinned_readonly_linux_job_with_allowlisted_receipts_only(self):
        workflow = (SOURCE / helper.WORKFLOW_NATIVE_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("runs-on:"), 1)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        for action in ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                       "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
                       "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"):
            self.assertIn(action, workflow)
        for forbidden in ("strategy:", "matrix", "setup-node", "apt-get", "sudo", "continue-on-error", "pull_request", "secrets.", "node_modules", "core.zip", "context.json", "*.json"):
            self.assertNotIn(forbidden, workflow)
        positions = [workflow.index(f"ci_foundation.py {phase}'") for phase in helper.WORKFLOW_NATIVE_PHASES]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(workflow.count("ci_foundation.py "), len(helper.WORKFLOW_NATIVE_PHASES))
        allowlist = [line.strip().split("${{ steps.prepare.outputs.root }}/", 1)[1]
                     for line in workflow.splitlines() if line.strip().startswith("${{ steps.prepare.outputs.root }}/")]
        self.assertEqual(allowlist, ["public-bindings.json", "acquire-checks.json", "compile-checks.json", "workflow-owner-checks.json",
            "workflow-owner-source/receipt.json", "workflow-owner-zip/receipt.json", "workflow-transaction-eof-checks.json",
            "workflow-transaction-eof/receipt.json", "workflow-core-checks.json", "workflow-ordinary.json",
            "workflow-committed-fsync.json", "workflow-committed-close.json", "retention-checks.json"])


if __name__ == "__main__":
    unittest.main()
