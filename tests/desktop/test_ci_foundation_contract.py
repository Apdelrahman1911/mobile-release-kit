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
import hashlib
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
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


def windows_test_checks(name: str) -> dict:
    """Synthetic consumer data only; these values are never native evidence."""
    yes = lambda fields: dict.fromkeys(fields.split(), True)
    if name in {"ordinary-source", "ordinary-zip"}:
        return {**yes("genuineCore configExact androidExact iosExact versionNotDisclosed"), "unicodeOpens": 1,
                "spelling": "verbatim" if name.endswith("zip") else "ordinary"}
    if name in {"reparse-root", "reparse-ancestor"}:
        return {"junctionTag": 0xA0000003, "unsafeControlMatched": True, "rootRefused": True, "reparseRestored": 1}
    if name in {"short-alias", "case-alias"}:
        return {**yes("aliasObserved spellingDiffers sameObject"), "aliasAcquired": 1, "aliasReadBytes": 0}
    if name in {"unc", "device", "ads"}:
        return {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True}
    if name in {"root-reparse-race", "config-reparse-race", "walk-reparse-race"}:
        return {**yes("parentIdSame mutationSucceeded originalRelativeEntry entryBeforeDeadline unsafeControlMatched "
                      "sharingWriteDenied sharingDeleteDenied reparseRestored"), "mutationAccess": 256, "mutationTag": 0xA0000003,
                "outsideAcquired": 0, "outsideReadBytes": 0, "preparatoryDeletes": int(name.startswith("walk"))}
    if name in {"disappear", "config-disappear"}:
        return yes("entryObserved actualMissingReturn changedIssue missingNotTrusted")
    return {
        "closed-gate": {},
        "link-children": {"fileSymlinkTag": 0xA000000C, "directorySymlinkTag": 0xA000000C, "junctionTag": 0xA0000003,
                          "hardlinkCount": 2, "hardlinkIdMatch": True, "excludedReparses": 3, "hardlinkReadBytes": 0, "restoredLinks": 4},
        "case-collision": {"enabledFlags": 1, "distinctIds": True, "collisionFiles": 2, "collisionDirectoryBatches": 0, "caseRestored": True},
        "subst-drive": {**yes("aliasInitiallyAbsent localNonSystemToken subtreeMappingObserved mappingRemoved"), "rootOpens": 0},
        "case-mode-race": {**yes("parentIdSame originalRelativeEntry entryBeforeDeadline missingNotTrusted caseRestored"),
                           "mutationAccess": 256, "enabledFlags": 1},
        "acl-type": {**yes("fileAccessDenied directoryAccessDenied accessibleSiblingRead configDirectoryRefused initialAbsenceRestored"),
                     "denialPoliciesConfirmed": 2, "createdObjectsRemoved": 2},
        "read-eof-size": {**yes("emptyEof invalidUtf8Refused shortFinalRead multichunkEof exactLimitEof"),
                          "oversizeReadBytes": 0, "largestRequest": 65536, "largestReturn": 65536},
        "entry-limit": {"returnedRecords": 10000, "chargedEntries": 10000, "overBudgetChildOpens": 0, "entryLimitIssue": True},
        "candidate-limit": {"chargedCandidates": 128, "refusedExtraCandidate": True, "sourceFileLimitIssue": True},
        "aggregate-limit": {"chargedBytes": 8388608, "extraByteRead": 0, "capNotEof": True, "byteLimitIssue": True},
        "depth-path-limit": {"deepestAdmitted": 12, "depth13Opens": 0, "oversizedPathOpens": 0, **yes("depthIssue pathIssue siblingRead")},
        "replace": {**yes("entryObserved originalIdDiffers changedIssue"), "replacementReadBytes": 0},
        "ending-metadata-case": yes("genuineFileEof writeMetadataChanged fileChangeVeto genuineDirectoryEof caseFlagsChanged "
                                    "directoryCaseVeto attributesRestored"),
        "drive-map-change": {**yes("aliasInitiallyAbsent localNonSystemToken initialVolumeMapping endingSubtreeMapping changedIssue mappingRemoved"),
                             "laterProjectOpens": 0},
        "oplock-release": yes("grantPending originalReaderEntered breakSignalled completionKnown blockedBeforeRelease holderCloseReturned "
                              "observerJoined eventCloseReturned originalReaderReturned"),
        "oplock-withhold": {**yes("grantPending originalReaderEntered breakSignalled completionKnown originalProcessStopped"),
                            "readerReturnedBeforeStop": False, "holderReleasedBeforeStop": False},
        "pending-failstop": {"originalParentHeld": True, "realFsctlEntry": True, "afterCallMarker": False, "originalExitCode": 70},
    }[name]


def windows_report() -> dict:
    """Never serialized to disk, run as a fixture, or reported as native success."""
    sdk = {"version": "10.0.26100.0", "headers": [{"path": path, "size": 1, "sha256": "2" * 64}
                                                  for path in helper.WINDOWS_SDK_HEADERS]}
    bindings = {"sourceSha": "1" * 40, "sourceTree": "2" * 40, "target": "x86_64-pc-windows-msvc",
                "pythonVersion": "3.14.7", "rustVersion": "1.98.0", "runId": "123", "attempt": "1", "job": "windows-snapshot",
                "image": "synthetic-not-a-run", "architecture": "X64", "coreZipSha256": "3" * 64, "coreInventorySha256": "4" * 64,
                "sources": [{"path": path, "sha256": "5" * 64, "size": 1} for path in helper.WINDOWS_SNAPSHOT_SOURCES],
                "pythonSha256": "6" * 64, "compiledTestSha256": "7" * 64, "compileInvocationSha256": "8" * 64, "sdk": sdk}
    report = {"schemaVersion": 1, "scope": "windows-static-snapshot-native-v1", "status": "passed", "failureCode": None,
              "bindings": bindings, "groups": [], "allOwnersSettled": True, "allFixtureResourcesSettled": True,
              "allFixturesRestored": True, "cleanupDisposition": "proven-settled", "notVerified": list(helper.WINDOWS_SNAPSHOT_NOT_VERIFIED)}
    errors = {"closed-gate": "platform_unavailable", "reparse-root": "unsafe_path", "reparse-ancestor": "unsafe_path",
              "root-reparse-race": "unsafe_path", "short-alias": "unsafe_path", "case-alias": "unsafe_path",
              "subst-drive": "snapshot_unavailable", "unc": "unsafe_path", "device": "unsafe_path", "ads": "unsafe_path",
              "oplock-withhold": "query_timeout", "pending-failstop": "engine_failed"}
    required = {"entry-limit": ["snapshot.entry-limit"], "candidate-limit": ["snapshot.file-limit"],
                "aggregate-limit": ["snapshot.byte-limit"], "depth-path-limit": ["snapshot.depth-limit", "snapshot.path-limit"],
                "read-eof-size": ["snapshot.encoding", "snapshot.file-size"]}
    unavailable = {"config-reparse-race", "case-mode-race", "acl-type", "config-disappear", "drive-map-change"}
    for group_id, names in helper.WINDOWS_SNAPSHOT_GROUPS:
        group = {"id": group_id, "controls": []}
        report["groups"].append(group)
        for name in names:
            abnormal, uninstrumented = name in {"oplock-withhold", "pending-failstop"}, name == "closed-gate"
            positive = name in {"ordinary-source", "ordinary-zip", "oplock-release"}
            error = errors.get(name)
            result = {"return": "error" if error else "ok", "code": error, "configState": None if error else
                      "unavailable" if name in unavailable else "format-valid", "partial": None if error else not positive,
                      "scan": None if error else {"entries": 10, "sourceFiles": 3, "sourceBytes": 100, "excludedEntries": 0},
                      "issueCodes": [] if error or positive else required.get(name, ["snapshot.changed"]),
                      "dtoSha256": None if error else "a" * 64}
            original = {"id": "query-1", **dict.fromkeys(helper.WINDOWS_ORIGINAL_FLAGS, True), "waitExitCode": 70 if name == "pending-failstop"
                        else 1 if abnormal else 0, "exitSuccess": not abnormal, "stdoutBytes": 0 if abnormal else 1000, "stderrBytes": 0,
                        "unknownLatched": False, "disabled": False, "errorCode": error}
            reader = {"state": "uninstrumented" if uninstrumented else "prefix" if abnormal else "complete",
                      "calls": [] if uninstrumented else [{"api": api, "entered": 0, "returned": 0, "completed": 0, "errors": 0}
                                                          for api in helper.WINDOWS_READER_APIS],
                      **dict.fromkeys(helper.WINDOWS_READER_COUNTERS, None if uninstrumented else 0),
                      "eventSha256": None if uninstrumented else "b" * 64,
                      "closeDisposition": "uninstrumented" if uninstrumented else "not-observed-after-abnormal-exit" if abnormal else "returned-once"}
            if not uninstrumented and name not in {"unc", "device", "ads"}:
                # Internally possible counter data, not a measured native run.
                completed = {"GetCurrentProcess": 1, "IsWow64Process2": 1, "QueryDosDeviceW": 1}
                if name != "subst-drive":
                    completed.update(NtCreateFile=2, GetHandleInformation=2, GetFileType=1,
                                     GetFileInformationByHandleEx=6, GetVolumeInformationByHandleW=1,
                                     GetFinalPathNameByHandleW=1, ReadFile=2, CloseHandle=0 if abnormal else 2)
                    reader.update(acquired=2, closeAttempts=0 if abnormal else 2, closeSucceeded=0 if abnormal else 2,
                                  live=2 if abnormal else 0, maxLive=2, maxBufferBytes=65536,
                                  rootOpens=1, relativeOpens=1, metadataChecks=1, identitiesMatched=1,
                                  readCalls=2, readBytes=1, readEof=1, directoryCalls=2, directoryRecords=1, directoryEof=1)
                for call in reader["calls"]:
                    count = completed.get(call["api"], 0)
                    call.update(entered=count, returned=count, completed=count,
                                errors=1 if call["api"] == "GetFileInformationByHandleEx" and name != "subst-drive" else 0)
                    if abnormal and call["api"] == ("NtCreateFile" if name == "oplock-withhold" else "DeviceIoControl"):
                        call["entered"] += 1
                if name == "oplock-withhold":
                    reader["relativeOpens"] += 1
                reader["eventCount"] = sum(call["completed"] for call in reader["calls"]) + reader["acquired"]
            fixture = {"state": "uninstrumented" if uninstrumented else "prefix" if abnormal else "complete",
                       **dict.fromkeys(helper.WINDOWS_FIXTURE_COUNTERS, None if uninstrumented else 0),
                       "pending": "completed" if name in {"oplock-release", "oplock-withhold"} else "retained" if abnormal else "none",
                       "thread": "joined" if name == "oplock-release" else "not-observed" if name == "oplock-withhold" else "none",
                       "event": "retained" if abnormal else "closed" if name == "oplock-release" else "none",
                       "restored": None if abnormal or uninstrumented else True,
                       "resourcesSettledBy": "uninstrumented" if uninstrumented else "original-process" if abnormal else "returned-closes",
                       "data": None if uninstrumented else {"entries": 6, "bytes": 100, "maxDepth": 3, "manifestSha256": "c" * 64,
                            "after": {"entries": 6, "bytes": 100, "maxDepth": 3, "inventorySha256": "c" * 64}},
                       "profile": None if uninstrumented else {"pointerBytes": 8, "processMachine": 0, "nativeMachine": 34404,
                           "filesystem": "NTFS", "pythonSha256": bindings["pythonSha256"], "ctypesSha256": "d" * 64,
                           "dlls": [{"name": dll, "sha256": "e" * 64, "size": 1} for dll in ("kernel32.dll", "ntdll.dll", "advapi32.dll")],
                           "layoutSha256": "f" * 64, "sdkSha256": hashlib.sha256(helper.canonical_json(sdk)).hexdigest()},
                       "checks": windows_test_checks(name)}
            if not uninstrumented:
                fixture.update(acquired=2, closeAttempts=0 if abnormal else 2, closeSucceeded=0 if abnormal else 2,
                               live=2 if abnormal else 0, maxLive=2, maxArenaBytes=128)
            charged = {"entry-limit": ("entries", "chargedEntries"), "candidate-limit": ("sourceFiles", "chargedCandidates"),
                       "aggregate-limit": ("sourceBytes", "chargedBytes")}.get(name)
            if charged:
                result["scan"][charged[0]] = fixture["checks"][charged[1]]
                fixture["data"].update(entries=10003 if name == "entry-limit" else 300,
                                       bytes=8388708 if name == "aggregate-limit" else 1000)
                fixture["data"]["after"].update(entries=fixture["data"]["entries"], bytes=fixture["data"]["bytes"])
            evidence = {"closed-gate": "uninstrumented-public-refusal", "oplock-withhold": "original-process-oplock-stop",
                        "pending-failstop": "instrumented-pending-classifier-exit"}.get(name, "native-static-reader")
            group["controls"].append({"id": name, "coreMode": "zip" if name == "ordinary-zip" else "source",
                "bootstrapMode": "ordinary" if uninstrumented else "windows-snapshot", "evidenceKind": evidence, "result": result,
                "reader": reader, "fixture": fixture, "original": original, "elapsedMs": 10, "failureCode": None})
    return report


class WindowsConsumerTests(unittest.TestCase):
    def test_created_denial_receipt_requires_policy_removal_and_original_absence(self):
        name = "acl-type"
        checks = windows_test_checks(name)
        original_predicates = {"fileAccessDenied", "directoryAccessDenied", "accessibleSiblingRead", "configDirectoryRefused"}
        added = {"denialPoliciesConfirmed", "createdObjectsRemoved", "initialAbsenceRestored"}
        self.assertEqual(set(checks), original_predicates | added)
        helper.validate_windows_checks(name, checks)
        old = {key: checks[key] for key in original_predicates}
        old["daclRestored"] = 2
        for fields in (old, {**checks, "daclRestored": 2}, {key: value for key, value in checks.items() if key not in added}):
            with self.subTest(fields=tuple(fields)), self.assertRaises(helper.CheckFailure):
                helper.validate_windows_checks(name, fields)
        for field in added:
            invalid = (False, 1, "true", None) if field == "initialAbsenceRestored" else (True, 1, 3, 2.0, "2", None)
            for value in invalid:
                with self.subTest(field=field, value=value), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_checks(name, {**checks, field: value})
        report = windows_report()
        report["groups"][3]["controls"][0]["fixture"]["checks"] = old
        with self.assertRaises(helper.CheckFailure):
            helper.validate_windows_snapshot_receipt(report, bindings=report["bindings"])

    def test_closed_receipt_requires_complete_ordered_native_scope_and_exact_bindings(self):
        report = windows_report()
        validate = lambda value: helper.validate_windows_snapshot_receipt(value, bindings=report["bindings"])
        with patch.object(helper, "run", side_effect=AssertionError("pure consumer called a tool")), \
             patch.object(helper, "hash_file", side_effect=AssertionError("pure consumer read a native input")):
            self.assertIs(validate(report), report)
        self.assertEqual(tuple(len(group["controls"]) for group in report["groups"]), (3, 10, 4, 6, 5, 3))
        self.assertEqual(sum(len(group["controls"]) for group in report["groups"]), 31)
        for change in ({"schemaVersion": True}, {"status": "failed"}, {"status": "failed-retained"}, {"failureCode": "timeout"},
                       {"scope": "passive-hosted-v2"}, {"allOwnersSettled": 1}, {"allFixtureResourcesSettled": False},
                       {"allFixturesRestored": False}, {"cleanupDisposition": "retain"}, {"notVerified": []}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(helper.CheckFailure):
                validate({**report, **change})
        for inventory in (report["groups"][:-1], report["groups"][::-1], [*report["groups"], report["groups"][-1]]):
            with self.subTest(groups=len(inventory)), self.assertRaises(helper.CheckFailure):
                validate({**report, "groups": inventory})
        for group_index, group in enumerate(report["groups"]):
            for change in (group["controls"][:-1], group["controls"][::-1], [*group["controls"], group["controls"][-1]]):
                bad = deepcopy(report); bad["groups"][group_index]["controls"] = change
                with self.subTest(group=group["id"]), self.assertRaises(helper.CheckFailure): validate(bad)
        for field in report["bindings"]:
            bad = deepcopy(report); bad["bindings"].pop(field)
            with self.subTest(binding=field), self.assertRaises(helper.CheckFailure): validate(bad)

    def test_each_native_predicate_rejects_mutation_extra_fields_and_bool_count_aliases(self):
        for group in windows_report()["groups"]:
            for control in group["controls"]:
                name, checks = control["id"], control["fixture"]["checks"]
                helper.validate_windows_checks(name, checks)
                with self.subTest(name=name, extra=True), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_checks(name, {**checks, "passed": True})
                for field, value in checks.items():
                    changed = not value if type(value) is bool else True if type(value) is int else "unrelated"
                    with self.subTest(name=name, field=field), self.assertRaises(helper.CheckFailure):
                        helper.validate_windows_checks(name, {**checks, field: changed})
        for name in ("root-reparse-race", "config-reparse-race", "walk-reparse-race"):
            for change in ({"mutationAccess": 0x40000000}, {"outsideAcquired": 1}, {"outsideReadBytes": 1}):
                with self.subTest(name=name, change=change), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_checks(name, {**windows_test_checks(name), **change})

    def test_original_returns_unknown_and_inprocess_cleanup_cannot_be_fabricated(self):
        report = windows_report()
        for group in report["groups"]:
            for control in group["controls"]:
                name, original = control["id"], control["original"]
                for field in helper.WINDOWS_ORIGINAL_FLAGS:
                    for value in (False, 1):
                        with self.subTest(name=name, field=field, value=value), self.assertRaises(helper.CheckFailure):
                            helper.validate_windows_original(name, {**original, field: value}, control["result"]["code"])
                for change in ({"unknownLatched": True}, {"disabled": True}, {"waitExitCode": True}, {"errorCode": "wrong"}):
                    with self.subTest(name=name, change=change), self.assertRaises(helper.CheckFailure):
                        helper.validate_windows_original(name, {**original, **change}, control["result"]["code"])
        for control in report["groups"][-1]["controls"][1:]:
            for change in ({"resourcesSettledBy": "returned-closes"}, {"restored": True}, {"event": "closed"}, {"thread": "joined"},
                           {"acquired": 0, "live": 0, "maxLive": 0, "maxArenaBytes": 0}, {"live": 1}, {"maxArenaBytes": 35},
                           {"closeFailed": 1}):
                with self.subTest(name=control["id"], change=change), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_fixture(control["id"], {**control["fixture"], **change}, report["bindings"])
            for after in (None, {}, {"entries": 12001, "bytes": 1, "maxDepth": 1, "inventorySha256": "c" * 64},
                          {"entries": 3, "bytes": 33554433, "maxDepth": 1, "inventorySha256": "c" * 64},
                          {"entries": 2, "bytes": 1, "maxDepth": 1, "inventorySha256": "c" * 64}):
                changed = deepcopy(control["fixture"]); changed["data"]["after"] = after
                with self.subTest(name=control["id"], payload_after=after), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_fixture(control["id"], changed, report["bindings"])
            changed = deepcopy(control["fixture"]); changed["data"]["entries"] = 2
            with self.assertRaises(helper.CheckFailure):
                helper.validate_windows_fixture(control["id"], changed, report["bindings"])
            for change in ({"live": 0}, {"relativeOpens": 0}, {"identitiesMatched": 0}, {"closeFailed": 1}):
                with self.subTest(name=control["id"], reader_prefix=change), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_reader(control["id"], {**control["reader"], **change})
            changed = deepcopy(control["reader"])
            pending_api = "NtCreateFile" if control["id"] == "oplock-withhold" else "DeviceIoControl"
            for call in changed["calls"]:
                if call["api"] == pending_api:
                    call["returned"] = call["completed"] = call["entered"]
            with self.subTest(name=control["id"], unmatched_entry=False), self.assertRaises(helper.CheckFailure):
                helper.validate_windows_reader(control["id"], changed)
        ordinary = report["groups"][0]["controls"][0]
        for change in ({"closeFailed": 1}, {"live": 1}, {"outsideReads": 1}, {"outsideAcquired": 1},
                       {"maxBufferBytes": 65537}, {"readBytes": 8388609}, {"closeDisposition": "not-observed-after-abnormal-exit"},
                       {"acquired": 0, "closeAttempts": 0, "closeSucceeded": 0, "maxLive": 0}, {"readCalls": 0},
                       {"directoryCalls": 0}, {"metadataChecks": 0}, {"eventCount": 0}):
            with self.subTest(reader=change), self.assertRaises(helper.CheckFailure):
                helper.validate_windows_reader("ordinary-source", {**ordinary["reader"], **change})
        for api in ("NtCreateFile", "CloseHandle", "ReadFile", "GetFileInformationByHandleEx"):
            changed = deepcopy(ordinary["reader"])
            for call in changed["calls"]:
                if call["api"] == api:
                    call.update(entered=0, returned=0, completed=0, errors=0)
            with self.subTest(missing_api=api), self.assertRaises(helper.CheckFailure):
                helper.validate_windows_reader("ordinary-source", changed)
        uninstrumented = report["groups"][0]["controls"][2]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_windows_reader("closed-gate", {**uninstrumented["reader"], "acquired": 0})

    def test_outcomes_and_actual_issue_codes_are_case_specific(self):
        for group in windows_report()["groups"]:
            for control in group["controls"]:
                name, result = control["id"], control["result"]
                with self.subTest(name=name), self.assertRaises(helper.CheckFailure):
                    helper.validate_windows_result(name, {**result, "code": "unrelated_transport_failure"})
                if result["partial"] is True:
                    with self.subTest(name=name, partial=False), self.assertRaises(helper.CheckFailure):
                        helper.validate_windows_result(name, {**result, "partial": False})
                if name in {"entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit", "read-eof-size"}:
                    with self.subTest(name=name, wrong_issue=True), self.assertRaises(helper.CheckFailure):
                        helper.validate_windows_result(name, {**result, "issueCodes": ["snapshot.changed"]})
        for name, field in (("entry-limit", "entries"), ("candidate-limit", "sourceFiles"), ("aggregate-limit", "sourceBytes")):
            report = windows_report()
            control = next(control for group in report["groups"] for control in group["controls"] if control["id"] == name)
            control["result"]["scan"][field] -= 1
            with self.subTest(name=name, contradictory_charge=True), self.assertRaises(helper.CheckFailure):
                helper.validate_windows_snapshot_receipt(report, bindings=report["bindings"])

    def test_json_duplicate_truncation_overflow_depth_and_nonfinite_inputs_refuse(self):
        self.assertEqual(helper.bounded_json(b'{"fixed":1}\n', 32), {"fixed": 1})
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'{}{}', b'\xff',
                    b'{' + b' ' * 40, b'[' * 18 + b'0' + b']' * 18):
            with self.subTest(raw=raw), self.assertRaises(helper.CheckFailure): helper.bounded_json(raw, 40)

    def test_push_dispatch_scopes_are_disjoint_and_sha_bound_without_host_execution(self):
        env = {"MRK_DESKTOP_HOSTED_CHECKS": "windows-snapshot-v1", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
               "GITHUB_SHA": "1" * 40, "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/verify/desktop-windows-snapshot"}
        with patch.dict(helper.os.environ, env, clear=True): self.assertEqual(helper.admitted_scope("windows"), "windows-snapshot-v1")
        for change in ({"GITHUB_REF": "refs/heads/feature/desktop-application"}, {"GITHUB_EVENT_NAME": "pull_request"},
                       {"RUNNER_ARCH": "ARM64"}, {"GITHUB_SHA": "latest"}, {"MRK_DESKTOP_HOSTED_CHECKS": "passive-v1"}):
            with self.subTest(change=change), patch.dict(helper.os.environ, {**env, **change}, clear=True), self.assertRaises(helper.CheckFailure):
                helper.admitted_scope("windows")
        manual = {**env, "GITHUB_EVENT_NAME": "workflow_dispatch", "MRK_DESKTOP_DISPATCH_SCOPE": "windows-snapshot",
                  "MRK_DESKTOP_EXPECTED_SHA": "1" * 40}
        with patch.dict(helper.os.environ, manual, clear=True): self.assertEqual(helper.admitted_scope("windows"), "windows-snapshot-v1")
        for change in ({"MRK_DESKTOP_EXPECTED_SHA": "2" * 40}, {"MRK_DESKTOP_DISPATCH_SCOPE": "foundation"}):
            with patch.dict(helper.os.environ, {**manual, **change}, clear=True), self.assertRaises(helper.CheckFailure):
                helper.admitted_scope("windows")
        with patch.dict(helper.os.environ, env, clear=True), self.assertRaises(helper.CheckFailure): helper.admitted_scope("linux")
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "run" and any(keyword.arg == "check" and isinstance(keyword.value, ast.Constant)
                     and keyword.value.value == "windows-snapshot-native-contract" for keyword in node.keywords)]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(next(keyword.value.value for keyword in call.keywords if keyword.arg == "timeout"), 300)
        self.assertEqual([item.value for item in call.args[0].elts if isinstance(item, ast.Constant)],
                         ["test", "--lib", "--features", "development-runtime", "--", "--exact", "--ignored", "--test-threads=1"])
        self.assertEqual(helper.WINDOWS_SNAPSHOT_PHASES, {"prepare", "acquire", "compile", "windows-snapshot", "clean"})

    def test_original_cargo_output_selects_one_libtest_without_binary_scan_or_execution(self):
        anchor = Path(Path.cwd().anchor)
        target = anchor / "not-created" / "target"
        artifact = {"reason": "compiler-artifact", "executable": str(target / "a.exe"),
                    "target": {"name": "mobile_release_desktop", "kind": ["lib"]}, "profile": {"test": True},
                    "features": ["development-runtime"]}
        done = {"reason": "build-finished", "success": True}
        encode = lambda values: b"\n".join(json.dumps(value).encode() for value in values)
        with patch.object(helper, "run", side_effect=AssertionError("parser executed a tool")), \
             patch.object(helper, "hash_file", side_effect=AssertionError("parser read an executable")):
            self.assertEqual(helper.compiled_windows_test(encode([artifact, done]), target_root=target), target / "a.exe")
            for values in ([done], [artifact], [artifact, artifact, done], [artifact, {**done, "success": False}],
                           [{**artifact, "features": ["desktop-shell", "development-runtime"]}, done],
                           [{**artifact, "executable": str(anchor / "outside" / "a.exe")}, done],
                           [{**artifact, "target": {"name": "other", "kind": ["bin"]}}, done]):
                with self.subTest(values=values), self.assertRaises(helper.CheckFailure):
                    helper.compiled_windows_test(encode(values), target_root=target)
            for path in (str(target / ".." / "outside.exe"), str(target) + "/./a.exe", str(target / "a.exe:alternate.exe"),
                         str(target / "a.exe") + "\0", "relative.exe", {}, 1, True):
                with self.subTest(path=path), self.assertRaises(helper.CheckFailure):
                    helper.compiled_windows_test(encode([{**artifact, "executable": path}, done]), target_root=target)
        normal = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0)
        redirected = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
        # Mocked metadata only: the check never creates a link/directory/file.
        for observations in ([redirected], [normal, redirected]):
            with patch.object(helper.Path, "lstat", side_effect=observations), patch.object(helper, "ordinary") as leaf:
                with self.assertRaises(helper.CheckFailure):
                    helper.ordinary_windows_executable(str(target / "debug" / "a.exe"), target_root=target)
                leaf.assert_not_called()
        with patch.object(helper.Path, "lstat", side_effect=[normal, normal]), patch.object(helper, "ordinary") as leaf:
            self.assertEqual(helper.ordinary_windows_executable(str(target / "debug" / "a.exe"), target_root=target),
                             target / "debug" / "a.exe")
            leaf.assert_called_once_with(target / "debug" / "a.exe")


class WindowsCleanupMetadataTests(unittest.TestCase):
    """Actual cleanup control flow with fake capabilities; no real file removal."""

    def fixture(self, *, inventory_change=None, recheck_change=None, prerequisite=False,
                hardlinks=False, member_change=None, duplicate=False, after_unlink_change=None, failure=None,
                reparses=False, reparse_alias=False, leaf_change=None, raw_change=None,
                after_unlink_leaf_change=None, missing_raw_tag=False, reparse_member_change=None):
        events = []
        root, first, nested, second = "/inert", "/inert/first", "/inert/nested", "/inert/nested/second"
        singleton = "/inert/singleton"
        file_link, directory_link = "/inert/file-link", "/inert/directory-link"
        junction, link_alias = "/inert/nested/junction", "/inert/nested/file-link-alias"
        def metadata(inode, *, directory=False):
            return {"st_mode": (stat.S_IFDIR if directory else stat.S_IFREG) | 0o700,
                    "st_file_attributes": 0x10 if directory else 0, "st_reparse_tag": 0,
                    "st_nlink": 1, "st_dev": 7, "st_ino": inode,
                    "st_size": 4, "st_mtime_ns": 100, "st_ctime_ns": 200}
        values = {root: metadata(10, directory=True), first: metadata(11),
                  nested: metadata(12, directory=True), second: metadata(13)}
        children = {root: (first, nested), nested: (second,)}
        if hardlinks:
            values[first]["st_nlink"] = 2
            values[second] = dict(values[first])
            values[singleton] = metadata(14)
            # Keep the unrelated group BETWEEN the two cross-directory aliases.
            children[root] = (first, singleton, nested)
        values[second].update(member_change or {})
        targets = {}
        if reparses:
            values[file_link] = {**metadata(21), "st_mode": stat.S_IFLNK | 0o700,
                                 "st_file_attributes": 0x400, "st_reparse_tag": 0xA000000C}
            values[directory_link] = {**metadata(22), "st_mode": stat.S_IFLNK | 0o700,
                                      "st_file_attributes": 0x410, "st_reparse_tag": 0xA000000C}
            values[junction] = {**metadata(23, directory=True), "st_file_attributes": 0x410,
                                "st_reparse_tag": 0xA0000003}
            values[file_link].update(leaf_change or {})
            children[root] = (first, file_link, *((singleton,) if hardlinks else ()), directory_link, nested)
            children[nested] = (second, junction)
            targets = {file_link: "/outside/private-target", directory_link: "/missing/private-target",
                       junction: "/outside/private-directory"}
            if reparse_alias:
                values[file_link]["st_nlink"] = 2
                values[link_alias] = dict(values[file_link])
                values[link_alias].update(reparse_member_change or {})
                children[nested] += (link_alias,)
                targets[link_alias] = targets[file_link]
        if duplicate:
            children[nested] += (second,)
        reads = {}

        def fail(*operation):
            if failure == operation:
                raise OSError("private-cleanup-error /inert/private-name")

        class FakePath:
            facts = values
            observations = []
            cached_observations = []
            successful_unlinks = []
            removed_directories = []
            output = io.StringIO()
            link_targets = targets
            target_state = {"/outside/private-target": b"unchanged target canary",
                            "/outside/private-directory": (b"unchanged child canary",),
                            "/missing/private-target": None}
            expected_target_state = dict(target_state)
            def __init__(self, value):
                self_test.assertIn(value, values, "cleanup requested an unprovided path capability")
                self.value = value
                self.parts = tuple(value.split("/"))
            def __str__(self):
                return self.value
            def __getattr__(self, name):
                raise AssertionError("cleanup requested an unprovided path operation")
            def lstat(self):
                events.append(("lstat", self.value))
                self_test.assertNotIn(self.value, self.successful_unlinks)
                reads[self.value] = reads.get(self.value, 0) + 1
                fail("lstat", self.value, reads[self.value])
                result = dict(values[self.value])
                if self.value == first:
                    result.update((inventory_change if reads[self.value] == 1 else recheck_change) or {})
                self.observations.append((self.value, reads[self.value], dict(result)))
                return SimpleNamespace(**result)
            def unlink(self):
                events.append(("unlink", self.value))
                self_test.assertNotIn(self.value, children, "cleanup unlinked an ordinary directory")
                self_test.assertNotIn(self.value, self.successful_unlinks)
                fail("unlink", self.value)
                original = values[self.value]
                identity = (original["st_dev"], original["st_ino"])
                for value, facts in values.items():
                    if value not in children and (facts["st_dev"], facts["st_ino"]) == identity:
                        facts["st_nlink"] -= 1
                        facts["st_ctime_ns"] += 1
                values[self.value.rpartition("/")[0]]["st_mtime_ns"] += 1
                self.successful_unlinks.append(self.value)
                if self.value == first:
                    values[second].update(after_unlink_change or {})
                    if reparses:
                        values[file_link].update(after_unlink_leaf_change or {})
            def rmdir(self):
                events.append(("rmdir", self.value))
                self_test.assertIn(self.value, children, "cleanup treated a reparse leaf as an ordinary directory")
                fail("rmdir", self.value)
                self.removed_directories.append(self.value)

        class Entry:
            def __init__(self, path):
                self.path = path
                self.raw = dict(values[path])
                if type(self.raw["st_mode"]) is int and stat.S_ISREG(self.raw["st_mode"]):
                    # Cached permission bits need not match full path metadata.
                    self.raw["st_mode"] &= ~0o111
                if path == file_link:
                    self.raw.update(raw_change or {})
                    if missing_raw_tag:
                        self.raw.pop("st_reparse_tag", None)
            def stat(self, *, follow_symlinks):
                events.append(("cached-stat", self.path))
                self_test.assertIs(follow_symlinks, False)
                fail("cached-stat", self.path)
                result = {**self.raw, "st_dev": 0, "st_ino": 0, "st_nlink": 0}
                FakePath.cached_observations.append((self.path, dict(result)))
                return SimpleNamespace(**result)

        class Enumeration:
            def __init__(self, path):
                self.path = path
            def __enter__(self):
                events.append(("scan", self.path.value))
                self_test.assertIn(self.path.value, children, "cleanup enumerated a reparse leaf or target")
                fail("scan-open", self.path.value)
                def entries():
                    for value in children[self.path.value]:
                        yield Entry(value)
                    fail("scan-next", self.path.value)
                return entries()
            def __exit__(self, *args):
                events.append(("scan-close", self.path.value))
                fail("scan-close", self.path.value)

        def receipt(context):
            self.assertEqual(context, {"root": root})
            events.append(("receipt", root))
            if prerequisite:
                raise helper.CheckFailure("inert unsettled prerequisite")
        self_test = self
        return events, FakePath, Enumeration, receipt

    def invoke(self, fixture):
        events, paths, enumeration, receipt = fixture
        with patch.object(helper, "Path", paths), patch.object(helper.os, "scandir", enumeration), \
                patch.object(helper, "windows_snapshot_receipt", side_effect=receipt), \
                patch.object(helper, "run", side_effect=AssertionError("cleanup must not select a tool")), \
                redirect_stdout(paths.output):
            helper.clean_windows_outputs({"root": "/inert"})

    def assert_initial_raw_screens(self, fixture):
        events, paths = fixture[:2]
        first_mutation = next((index for index, item in enumerate(events) if item[0] in ("unlink", "rmdir")), len(events))
        screened, observed = set(), set()
        for index, (kind, path) in enumerate(events):
            if kind == "cached-stat":
                self.assertNotIn(path, screened)
                screened.add(path)
                self.assertLess(index, first_mutation)
            elif kind == "lstat" and path not in observed:
                observed.add(path)
                if path != "/inert":
                    self.assertEqual(events[index - 1], ("cached-stat", path))
        for _, facts in paths.cached_observations:
            self.assertEqual((facts["st_dev"], facts["st_ino"], facts["st_nlink"]), (0, 0, 0))

    def test_windows_cleanup_uses_full_no_follow_metadata_and_complete_inventory(self):
        fixture = self.fixture()
        events = fixture[0]
        self.invoke(fixture)
        self.assert_initial_raw_screens(fixture)
        first_unlink = events.index(("unlink", "/inert/first"))
        self.assertLess(events.index(("scan-close", "/inert/nested")), first_unlink)
        self.assertEqual([item for item in events if item[0] in ("unlink", "rmdir")],
                         [("unlink", "/inert/first"), ("unlink", "/inert/nested/second"),
                          ("rmdir", "/inert/nested"), ("rmdir", "/inert")])
        for index, (kind, path) in enumerate(events):
            if kind in ("unlink", "rmdir"):
                self.assertEqual(events[index - 1], ("lstat", path))
        self.assertEqual(events[0], ("receipt", "/inert"))

    def test_windows_cleanup_preserves_admission_and_before_unlink_refusals(self):
        fixture = self.fixture(prerequisite=True)
        with self.assertRaises(helper.CheckFailure):
            self.invoke(fixture)
        self.assertEqual(fixture[0], [("receipt", "/inert")])
        refused = ({"st_file_attributes": 0x400}, {"st_mode": stat.S_IFLNK | 0o700},
                   {"st_mode": stat.S_IFIFO | 0o600}, {"st_nlink": 2}, {"st_nlink": 0})
        for changed in refused:
            with self.subTest(stage="inventory", changed=changed):
                fixture = self.fixture(inventory_change=changed)
                with self.assertRaises(helper.CheckFailure):
                    self.invoke(fixture)
                self.assertFalse(any(kind in ("unlink", "rmdir") for kind, _ in fixture[0]))
        for changed in (*refused, {"st_dev": 8}, {"st_ino": 99}, {"st_size": 5}, {"st_mtime_ns": 101}):
            with self.subTest(stage="before-unlink", changed=changed):
                fixture = self.fixture(recheck_change=changed)
                with self.assertRaises(helper.CheckFailure):
                    self.invoke(fixture)
                self.assertIn(("scan-close", "/inert/nested"), fixture[0])
                self.assertFalse(any(kind in ("unlink", "rmdir") for kind, _ in fixture[0]))

    def test_windows_cleanup_closes_interleaved_original_hardlink_groups(self):
        fixture = self.fixture(hardlinks=True)
        events, paths = fixture[:2]
        self.invoke(fixture)
        removals = [("unlink", "/inert/first"), ("unlink", "/inert/singleton"),
                    ("unlink", "/inert/nested/second"), ("rmdir", "/inert/nested"), ("rmdir", "/inert")]
        self.assertEqual([item for item in events if item[0] in ("unlink", "rmdir")], removals)
        self.assertEqual(paths.successful_unlinks, [path for kind, path in removals if kind == "unlink"])
        self.assertEqual(paths.removed_directories, ["/inert/nested", "/inert"])
        first_unlink = events.index(removals[0])
        self.assertEqual(events[0], ("receipt", "/inert"))
        self.assert_initial_raw_screens(fixture)
        self.assertEqual([item for item in events[:first_unlink] if item[0] == "scan-close"],
                         [("scan-close", "/inert"), ("scan-close", "/inert/nested")])
        self.assertFalse(any(kind.startswith("scan") for kind, _ in events[first_unlink:]))
        rechecks = [(path, facts["st_nlink"], facts["st_ctime_ns"])
                    for path, ordinal, facts in paths.observations if ordinal == 2 and stat.S_ISREG(facts["st_mode"])]
        self.assertEqual(rechecks, [("/inert/first", 2, 200), ("/inert/singleton", 1, 200),
                                    ("/inert/nested/second", 1, 201)])
        self.assertTrue(all(facts["st_nlink"] == 0 for facts in paths.facts.values() if stat.S_ISREG(facts["st_mode"])))
        for index, (kind, path) in enumerate(events):
            if kind in ("unlink", "rmdir"):
                self.assertEqual(events[index - 1], ("lstat", path))

    def test_windows_cleanup_refuses_unclosed_or_unusable_whole_inventory(self):
        unclosed = "Windows task cleanup hardlink group is not closed inside the original root"
        disagree = "Windows task cleanup hardlink metadata disagrees"
        unusable = "Windows task cleanup inventory has an unusable file identity"
        bad_links = "Windows task cleanup inventory has an invalid link count"
        cases = [
            ({"inventory_change": {"st_nlink": 3}, "member_change": {"st_nlink": 3}}, unclosed),
            ({"duplicate": True}, "Windows task cleanup inventory repeated a path"),
            ({"member_change": {"st_nlink": 3}}, disagree),
            ({"member_change": {"st_size": 5}}, disagree),
            ({"member_change": {"st_mtime_ns": 101}}, disagree),
            ({"inventory_change": {"st_ino": 0}, "member_change": {"st_ino": 0}}, unusable),
            ({"member_change": {"st_ino": None}}, unusable),
            ({"member_change": {"st_ino": True}}, unusable),
            ({"member_change": {"st_dev": -1}}, unusable),
            ({"inventory_change": {"st_nlink": True}}, bad_links),
            ({"inventory_change": {"st_nlink": 2.0}}, bad_links),
            ({"inventory_change": {"st_nlink": 500001}}, bad_links),
            ({"failure": ("lstat", "/inert", 1)}, "Windows cleanup inventory directory metadata failed"),
            ({"failure": ("lstat", "/inert/nested/second", 1)}, "Windows cleanup inventory entry metadata failed"),
        ]
        cases.extend(({"failure": (stage, "/inert/nested")}, "Windows cleanup inventory enumeration failed")
                     for stage in ("scan-open", "scan-next", "scan-close"))
        for options, diagnostic in cases:
            with self.subTest(options=options):
                fixture = self.fixture(hardlinks=True, **options)
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertNotIn("/inert", str(caught.exception))
                self.assertNotIn("private-cleanup-error", str(caught.exception))
                if "failure" in options:
                    self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(fixture[0][0], ("receipt", "/inert"))
                self.assertFalse(any(kind in ("unlink", "rmdir") for kind, _ in fixture[0]))
                self.assert_initial_raw_screens(fixture)
                self.assertEqual(fixture[1].successful_unlinks, [])
                self.assertEqual(fixture[1].removed_directories, [])

    def test_windows_cleanup_stops_on_late_alias_change_without_rollback(self):
        for changed in ({"st_nlink": 2}, {"st_nlink": 0}, {"st_dev": 8}, {"st_ino": 99},
                        {"st_size": 5}, {"st_mtime_ns": 101}):
            with self.subTest(changed=changed):
                fixture = self.fixture(hardlinks=True, after_unlink_change=changed)
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                diagnostic = ("Windows task cleanup remaining link count changed" if "st_nlink" in changed
                              else "Windows task cleanup file identity changed")
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertEqual(fixture[1].successful_unlinks, ["/inert/first", "/inert/singleton"])
                self.assertEqual([item for item in fixture[0] if item[0] in ("unlink", "rmdir")],
                                 [("unlink", "/inert/first"), ("unlink", "/inert/singleton")])
                self.assertEqual(fixture[0][-1], ("lstat", "/inert/nested/second"))
                self.assertEqual(fixture[1].removed_directories, [])
                self.assertNotIn("/inert", str(caught.exception))

    def test_windows_cleanup_stops_on_original_io_failure_without_retry(self):
        all_files = ["/inert/first", "/inert/singleton", "/inert/nested/second"]
        unlink_failure = "Windows task cleanup original unlink failed; remaining outputs retained"
        cases = (
            (("unlink", "/inert/first"), [], unlink_failure),
            (("unlink", "/inert/nested/second"), all_files[:2], unlink_failure),
            (("lstat", "/inert/nested/second", 2), all_files[:2], "Windows cleanup before-unlink metadata failed"),
            (("lstat", "/inert/nested", 3), all_files, "Windows cleanup final directory metadata failed"),
            (("rmdir", "/inert/nested"), all_files,
             "Windows task cleanup original directory removal failed; remaining outputs retained"),
        )
        for failure, successful, diagnostic in cases:
            with self.subTest(failure=failure):
                fixture = self.fixture(hardlinks=True, failure=failure)
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertNotIn("/inert", str(caught.exception))
                self.assertNotIn("private-cleanup-error", str(caught.exception))
                self.assertEqual(fixture[1].successful_unlinks, successful)
                self.assertEqual(fixture[1].removed_directories, [])
                self.assertEqual(fixture[0][-1], failure[:2])
                attempts = [item for item in fixture[0] if item[0] in ("unlink", "rmdir")]
                expected = [("unlink", path) for path in successful]
                if failure[0] in ("unlink", "rmdir"):
                    expected.append(failure)
                self.assertEqual(attempts, expected)
                # A failed original unlink never performs the fake success update.
                if failure[0] == "unlink":
                    self.assertEqual(fixture[1].facts[failure[1]]["st_nlink"], 2 if not successful else 1)

    def test_windows_cleanup_removes_all_known_reparse_leaf_kinds_without_target_traversal(self):
        for aliases in (False, True):
            with self.subTest(known_leaf_aliases=aliases):
                fixture = self.fixture(hardlinks=True, reparses=True, reparse_alias=aliases)
                events, paths = fixture[:2]
                self.invoke(fixture)
                leaves = ["/inert/first", "/inert/file-link", "/inert/singleton", "/inert/directory-link",
                          "/inert/nested/second", "/inert/nested/junction"]
                expected_counts = [("/inert/first", 2, 200), ("/inert/file-link", 2 if aliases else 1, 200),
                                   ("/inert/singleton", 1, 200), ("/inert/directory-link", 1, 200),
                                   ("/inert/nested/second", 1, 201), ("/inert/nested/junction", 1, 200)]
                if aliases:
                    leaves.append("/inert/nested/file-link-alias")
                    expected_counts.append(("/inert/nested/file-link-alias", 1, 201))
                removals = [("unlink", path) for path in leaves] + [("rmdir", "/inert/nested"), ("rmdir", "/inert")]
                self.assertEqual([item for item in events if item[0] in ("unlink", "rmdir")], removals)
                self.assertEqual(paths.successful_unlinks, leaves)
                self.assertEqual(paths.removed_directories, ["/inert/nested", "/inert"])
                self.assert_initial_raw_screens(fixture)
                first_unlink = events.index(removals[0])
                self.assertEqual(events[0], ("receipt", "/inert"))
                self.assertEqual([item for item in events[:first_unlink] if item[0] == "scan-close"],
                                 [("scan-close", "/inert"), ("scan-close", "/inert/nested")])
                self.assertFalse(any(kind.startswith("scan") or kind == "cached-stat" for kind, _ in events[first_unlink:]))
                for index, (kind, path) in enumerate(events):
                    if kind in ("unlink", "rmdir"):
                        self.assertEqual(events[index - 1], ("lstat", path))
                    if path in paths.link_targets:
                        self.assertNotIn(kind, ("scan", "rmdir"))
                self.assertEqual([(path, facts["st_nlink"], facts["st_ctime_ns"])
                                  for path, ordinal, facts in paths.observations if ordinal == 2 and path in leaves],
                                 expected_counts)
                self.assertTrue(all(paths.facts[path]["st_nlink"] == 0 for path in leaves))
                self.assertEqual(paths.target_state, paths.expected_target_state)
                self.assertIsNone(paths.target_state[paths.link_targets["/inert/directory-link"]])
                self.assertTrue(all(path not in paths.target_state for _, path in events))
                self.assertEqual(paths.output.getvalue(),
                                 "Removed only the fully settled Windows job's inventoried compiler/dependency and synthetic fixture outputs.\n")

    def test_windows_cleanup_refuses_unknown_or_inconsistent_reparse_inventory(self):
        unknown = "Windows task cleanup encountered an unsupported reparse tag"
        incoherent = "Windows task cleanup encountered incoherent reparse metadata"
        bad_type = "Windows task cleanup encountered incoherent type metadata"
        cases = (
            ({"raw_change": {"st_reparse_tag": 0xA0000042, "st_mode": stat.S_IFREG | 0o600}}, unknown, True),
            ({"raw_change": {"st_reparse_tag": 0x80000013, "st_mode": stat.S_IFREG | 0o600}}, unknown, True),
            ({"missing_raw_tag": True}, unknown, True),
            ({"raw_change": {"st_reparse_tag": 0}}, unknown, True),
            ({"raw_change": {"st_reparse_tag": True}}, unknown, True),
            ({"raw_change": {"st_reparse_tag": 0xA0000003, "st_mode": stat.S_IFREG | 0o600}}, incoherent, True),
            ({"raw_change": {"st_file_attributes": 0x410, "st_mode": stat.S_IFDIR | 0o700}}, incoherent, True),
            ({"raw_change": {"st_file_attributes": 0}}, bad_type, True),
            ({"raw_change": {"st_file_attributes": None}}, bad_type, True),
            ({"raw_change": {"st_file_attributes": 0, "st_mode": stat.S_IFREG | 0o600}},
             "Windows task cleanup inventory entry classification changed", False),
            ({"leaf_change": {"st_ino": 0}}, "Windows task cleanup inventory has an unusable file identity", False),
            ({"leaf_change": {"st_nlink": 2}},
             "Windows task cleanup hardlink group is not closed inside the original root", False),
            ({"leaf_change": {"st_ino": 11}}, "Windows task cleanup hardlink metadata disagrees", False),
            ({"reparse_alias": True, "reparse_member_change": {"st_file_attributes": 0x420}},
             "Windows task cleanup hardlink metadata disagrees", False),
        )
        for options, diagnostic, raw_refusal in cases:
            with self.subTest(options=options):
                # Raw unknown tags must stop before even this fake full-stat trap.
                fixture = self.fixture(reparses=True, failure=("lstat", "/inert/file-link", 1) if raw_refusal else None,
                                       **options)
                events, paths = fixture[:2]
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertNotIn("/inert", str(caught.exception))
                self.assertNotIn("private", str(caught.exception))
                self.assertFalse(any(kind in ("unlink", "rmdir") for kind, _ in events))
                self.assertEqual(paths.successful_unlinks, [])
                self.assertEqual(paths.removed_directories, [])
                self.assertEqual(paths.output.getvalue(), "")
                self.assert_initial_raw_screens(fixture)
                if raw_refusal:
                    self.assertNotIn(("lstat", "/inert/file-link"), events)
                self.assertEqual(paths.target_state, paths.expected_target_state)

    def test_windows_cleanup_stops_on_changed_original_reparse_leaf(self):
        changed_binding = "Windows task cleanup reparse leaf binding changed"
        changed_links = "Windows task cleanup remaining link count changed"
        cases = (
            ({"st_ino": 99}, changed_binding), ({"st_dev": 8}, changed_binding),
            ({"st_mode": stat.S_IFDIR | 0o700, "st_file_attributes": 0x410, "st_reparse_tag": 0xA0000003}, changed_binding),
            ({"st_file_attributes": 0x410}, changed_binding), ({"st_file_attributes": 0x420}, changed_binding),
            ({"st_mode": stat.S_IFREG | 0o700, "st_file_attributes": 0}, changed_binding),
            ({"st_size": 5}, changed_binding), ({"st_mtime_ns": 101}, changed_binding),
            ({"st_nlink": 2}, changed_links), ({"st_nlink": 0}, changed_links),
        )
        for changed, diagnostic in cases:
            with self.subTest(changed=changed):
                fixture = self.fixture(reparses=True, after_unlink_leaf_change=changed)
                events, paths = fixture[:2]
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertEqual(paths.successful_unlinks, ["/inert/first"])
                self.assertEqual([item for item in events if item[0] in ("unlink", "rmdir")], [("unlink", "/inert/first")])
                self.assertEqual(events[-1], ("lstat", "/inert/file-link"))
                self.assertEqual(paths.removed_directories, [])
                self.assertEqual(paths.output.getvalue(), "")
                self.assert_initial_raw_screens(fixture)
                self.assertNotIn("/inert", str(caught.exception))
                self.assertEqual(paths.target_state, paths.expected_target_state)

    def test_windows_cleanup_stops_on_reparse_metadata_or_unlink_failure(self):
        leaves = ["/inert/first", "/inert/file-link", "/inert/singleton", "/inert/directory-link",
                  "/inert/nested/second", "/inert/nested/junction", "/inert/nested/file-link-alias"]
        inventory_error = "Windows cleanup inventory entry metadata failed"
        unlink_error = "Windows task cleanup original unlink failed; remaining outputs retained"
        cases = (
            (("cached-stat", "/inert/file-link"), [], inventory_error),
            (("lstat", "/inert/file-link", 1), [], inventory_error),
            (("lstat", "/inert/file-link", 2), leaves[:1], "Windows cleanup before-unlink metadata failed"),
            (("unlink", "/inert/file-link"), leaves[:1], unlink_error),
            (("unlink", "/inert/nested/junction"), leaves[:5], unlink_error),
        )
        for failure, successful, diagnostic in cases:
            with self.subTest(failure=failure):
                fixture = self.fixture(hardlinks=True, reparses=True, reparse_alias=True, failure=failure)
                events, paths = fixture[:2]
                originals = {path: (paths.facts[path]["st_dev"], paths.facts[path]["st_ino"], paths.facts[path]["st_nlink"])
                             for path in leaves}
                with self.assertRaises(helper.CheckFailure) as caught:
                    self.invoke(fixture)
                self.assertEqual(str(caught.exception), diagnostic)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertNotIn("/inert", str(caught.exception))
                self.assertNotIn("private-cleanup-error", str(caught.exception))
                self.assertEqual(paths.successful_unlinks, successful)
                self.assertEqual(paths.removed_directories, [])
                self.assertEqual(paths.output.getvalue(), "")
                expected_attempts = [("unlink", path) for path in successful]
                if failure[0] == "unlink":
                    expected_attempts.append(failure)
                self.assertEqual([item for item in events if item[0] in ("unlink", "rmdir")], expected_attempts)
                self.assertEqual(events.count(failure[:2]), failure[2] if failure[0] == "lstat" else 1)
                if successful:
                    self.assertEqual(events[-1], failure[:2])
                else:
                    self.assertEqual(events[-1], ("scan-close", "/inert"))
                for path, (device, inode, links) in originals.items():
                    removed = sum(originals[other][:2] == (device, inode) for other in successful)
                    self.assertEqual(paths.facts[path]["st_nlink"], links - removed)
                    self.assertEqual(paths.facts[path]["st_ctime_ns"], 200 + removed)
                self.assert_initial_raw_screens(fixture)
                self.assertEqual(paths.target_state, paths.expected_target_state)


if __name__ == "__main__":
    unittest.main()
