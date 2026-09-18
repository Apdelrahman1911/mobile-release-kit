"""Inert compiler-helper contracts; never run main, real tools or native fixtures.

Phase/cleanup capabilities and all subprocess calls are inert mocks. Source inspection checks
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
        outer = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "github_tls_run_outer")
        self.assertEqual(len(raw_calls), 2)
        ordinary_calls = [call for call in raw_calls if call in list(ast.walk(wrapper))]
        outer_calls = [call for call in raw_calls if call in list(ast.walk(outer))]
        self.assertEqual((len(ordinary_calls), len(outer_calls)), (1, 1))
        # The one additional closed launcher must retain its own actual wait;
        # it is not a generic check label or an inner-receipt assertion.
        launch = outer_calls[0]
        self.assertIsInstance(launch.args[0], ast.Call)
        self.assertIsInstance(launch.args[0].func, ast.Name)
        self.assertEqual(launch.args[0].func.id, "github_tls_launch_argv")
        outer_keywords = {keyword.arg: keyword.value for keyword in launch.keywords}
        self.assertIs(outer_keywords["check"].value, False)
        self.assertEqual(outer_keywords["timeout"].value, 300)
        self.assertEqual(outer_keywords["preexec_fn"].id, "github_tls_outer_limits")
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
            for name in ("native", "config-owner", "config-task-loss", "config-owner-delta", "config-transaction-eof", "config-core", "windows-snapshot", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", helper.WORKFLOW_NATIVE_SCOPE)
            for scope in (*helper.COMPILE_PROFILES, helper.BOUNDARY_SCOPE, helper.WINDOWS_SNAPSHOT_SCOPE):
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


def github_readonly_binding_data() -> dict:
    return {
        "sourceSha": "1" * 40, "host": "linux", "target": "x86_64-unknown-linux-gnu",
        "runtimeMode": "trusted-development-only", "coreZipSha256": "2" * 64,
        "engineSha256": "3" * 64, "bootstrapSha256": "4" * 64, "cargoLockSha256": "5" * 64,
        "fixtureSha256": "6" * 64, "githubBootstrapSha256": "7" * 64,
        "githubFixtureSha256": "8" * 64, "packageSha256": "9" * 64,
        "pythonSha256": "a" * 64, "pythonBytes": 123456,
    }


def github_readonly_report_data() -> dict:
    """Independently authored, inert frozen-producer DATA; no execution claim."""
    late_notes = ("retainedWhileUnknown", "newPassiveAndGitHubAdmissionRefused",
                  "originalCleanupEndpointUnchanged", "lateJoinPreservedFailure",
                  "terminalReceiptAndSettledAtImmutable")
    # name, original first error, absorbing Unknown, additional literal notes.
    rows = (
        ("g1-correct", None, False, ("typedGitHubMailbox", "terminalReceiptAndSettledAtImmutable")),
        ("g1-passive-envelope", "protocol_error", False, ()),
        ("g1-wrong-id", "protocol_error", False, ()),
        ("g1-wrong-protocol", "protocol_error", False, ()),
        ("g1-truncated", "protocol_error", False, ()),
        ("g1-extra-frames", "protocol_error", False, ()),
        ("g1-nonzero-exit", "engine_failed", False, ("validOutputDidNotSalvageFailedExit",)),
        ("g1-delay-exit", None, False, ("mailboxPendingAfterBothEofs",)),
        ("g1-stdout-limit", "output_limit", False, ()),
        ("g1-stderr-limit", "output_limit", False, ()),
        ("g1-stalled-input", "query_timeout", False, ("originalOperationDeadlineObserved",
            "originalCleanupEndpointUnchanged", "unreadInputIsNotBlockedWriterEvidence")),
        ("g1-mixed-abandon", None, False, ("sharedTwoSlotLimit", "originalRetainedAfterTicketDrop",
            "droppedTicketOriginalReturnedTypedSuccess")),
        ("g1-controlled-inspection", "shutting_down", True, (*late_notes,
            "noChildBeforeHeldStartupReturn", "noLateChildAfterCleanupExpiry")),
        ("g1-controlled-acquisition", "shutting_down", True, (*late_notes,
            "noChildBeforeHeldStartupReturn", "noLateChildAfterCleanupExpiry")),
        ("g1-controlled-io-join", "shutting_down", True, (*late_notes,
            "nativeExitAndEofBeforeStdoutJoin", "lateOriginalStdoutJoined")),
        ("g1-controlled-management", None, False, ("nativeSettledBeforeManagementReturns",
            "driverReturnHeldBeforeMailbox", "watchdogReturnHeldBeforeMailbox", "terminalReceiptAndSettledAtImmutable")),
        ("g1-controlled-management-late", "shutting_down", True, (*late_notes, "nativeSettledBeforeWatchdogReturn")),
        ("g1-document-connect-refresh", None, False, ("ordinaryAndUnrelatedRefusedBeforeDecode",
            "statusStartsNoRead", "refreshPinsAndOriginalExpiryPreserved")),
        ("g1-document-disconnect-held", "cancelled", False, ("wrongSessionUnchanged", "pendingMaterialRetained",
            "originalCleanupEndpointUnchanged", "lateReceiptCannotRestoreSession")),
        ("g1-document-registry-change", None, False, ("registryRecheckedBeforePositiveReceipt",)),
        ("g1-document-loss", "cancelled", False, ("actualLossPathRetiredSynchronously",
            "newAdmissionRefusedAfterLoss", "lateReceiptCannotRestoreSession")),
        ("g1-document-unknown-late", "cancelled", True, ("pendingMaterialRetained",
            "originalCleanupEndpointUnchanged", "lateSettlementPreservedUnknown", "originalSettledAtImmutable")),
        ("g1-document-terminal-unknown", "shutting_down", True, ("terminalOperationUsesReservedUnknownIdentity",
            "settledDocumentDoesNotReplaceOwnerFinality")),
    )
    cases = []
    for name, error, sticky, extra_notes in rows:
        document = name.startswith("g1-document-")
        startup = name in {"g1-controlled-inspection", "g1-controlled-acquisition"}
        notes = {"originalRetentionSettled": True, **dict.fromkeys(extra_notes, True)}
        if document:
            notes.update(documentEvidence="controlled-original-lifetime-not-gui-callbacks",
                         sourceBooksSettled=2 if name == "g1-document-registry-change" else 1,
                         documentMaterialSettled=True)
        ids = [("github-read-1", "github-readonly")]
        if name == "g1-mixed-abandon":
            ids.append(("query-2", "passive"))
        if name in {"g1-document-connect-refresh", "g1-document-terminal-unknown"}:
            ids.append(("github-read-2", "github-readonly"))
        owners = []
        for index, (identity, profile) in enumerate(ids):
            earlier_healthy = name == "g1-document-terminal-unknown" and index == 0
            unknown = sticky and not earlier_healthy
            first_error = None if earlier_healthy else error
            if profile == "passive":
                terminal = None
            elif unknown:
                terminal = {"return": "error", "code": "cleanup_unknown", "wasUnknown": True}
            elif first_error:
                terminal = {"return": "error", "code": first_error, "wasUnknown": False}
            else:
                terminal = {"return": "github-facts", "wasUnknown": False}
            stdout = 0 if startup or name in {"g1-stalled-input", "g1-stderr-limit", "g1-document-loss"} else 256
            native = {
                "inspection_joined": True, "acquisition_joined": name != "g1-controlled-inspection",
                "spawned": not startup, "waited": not startup,
                "exit_success": None if startup else name not in {"g1-nonzero-exit", "g1-stalled-input", "g1-document-loss"},
                "writer_joined": not startup, "writer_complete": not startup,
                "stdout_eof": not startup, "stderr_eof": not startup,
                "stdout_joined": not startup, "stderr_joined": not startup,
                "stdout_bytes": 65536 if name == "g1-stdout-limit" else stdout,
                "stderr_bytes": 65536 if name == "g1-stderr-limit" else 0,
                "driver_joined": True, "watchdog_joined": True,
            }
            owners.append({"id": identity, "terminal": True, "unknownLatched": unknown, "permitRetained": False,
                           "profile": profile, "observerJoined": True, "native": native,
                           "firstError": first_error, "receipt": terminal})
        if document:
            results = []
        elif name == "g1-mixed-abandon":
            results = [{"return": "error", "code": "busy"},
                       {"return": "ticket-dropped", "ownerRetained": True}, {"return": "ok"}]
        else:
            results = [deepcopy(owners[0]["receipt"])]
            if sticky:
                results.insert(0, {"return": "retained-unknown"})
        cases.append({"case": name, "passed": True, "failureCode": None,
                      "elapsedMs": 10000 if name == "g1-stalled-input" else 2000 if sticky else 80,
                      "evidenceKind": "controlled-document-original-owner" if document else
                          "scheduling-control-not-os-fault" if name.startswith("g1-controlled-") else "actual-private-frame-child",
                      "results": results, "notes": notes, "owners": owners, "registeredOwners": 0, "disabled": sticky})
    return {"schemaVersion": 1, "scope": "github-readonly-hosted-v1", "status": "passed", "allOwnersSettled": True,
            "failureCode": None, "bindings": github_readonly_binding_data(), "cases": cases,
            "notVerified": ["live-transport", "authenticated-remote-facts", "native-gui", "webview-callbacks-or-crash-hook",
                            "production-runtime-custody", "production-github-enablement", "native-stuck-wait-close",
                            "macos-windows-github", "credentials", "stores", "mobile-builds", "installers"]}


def validate_github_readonly_data(value: object) -> dict:
    return helper.validate_github_readonly_receipt(value, bindings=github_readonly_binding_data())


class GitHubReadonlyReceiptContractTests(unittest.TestCase):
    def test_github_readonly_supplied_data_not_execution_evidence(self):
        report = github_readonly_report_data()
        self.assertEqual(23, len(report["cases"]))
        self.assertEqual(14, len(report["bindings"]))
        self.assertEqual(tuple(row["case"] for row in report["cases"]), helper.GITHUB_READONLY_CASES)
        self.assertEqual(tuple(report["notVerified"]), helper.GITHUB_READONLY_NOT_VERIFIED)
        self.assertIs(report, validate_github_readonly_data(report))
        raw = json.dumps(report, separators=(",", ":")).encode("utf-8")
        self.assertEqual(report, helper.parse_github_readonly_receipt(raw, bindings=github_readonly_binding_data()))

    def test_github_readonly_closed_header_roster_and_independent_bindings(self):
        report = github_readonly_report_data()
        changes = [{"schemaVersion": True}, {"scope": "passive-hosted-v2"}, {"status": "running"},
                   {"status": "failed-retained"}, {"allOwnersSettled": 1}, {"allOwnersSettled": False},
                   {"failureCode": "custody_unresolved"}, {"extra": True}, {"cases": report["cases"][:-1]},
                   {"cases": report["cases"] + report["cases"][:1]}, {"cases": list(reversed(report["cases"]))},
                   {"cases": [report["cases"][0]] * 23}, {"cases": tuple(report["cases"])},
                   {"notVerified": report["notVerified"][:-1]}, {"notVerified": report["notVerified"] + ["extra"]},
                   {"notVerified": list(reversed(report["notVerified"]))}]
        for change in changes:
            bad = deepcopy(report); bad.update(change)
            with self.subTest(change=tuple(change)), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for field in report:
            bad = deepcopy(report); del bad[field]
            with self.subTest(missing=field), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for field, original in report["bindings"].items():
            bad = deepcopy(report)
            bad["bindings"][field] = original + 1 if type(original) is int else "b" * len(original)
            with self.subTest(binding=field), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
            del bad["bindings"][field]
            with self.subTest(missing_binding=field), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for change in ({"sourceSha": "0" * 40}, {"sourceSha": "A" * 40}, {"sourceSha": "1" * 64},
                       {"host": "macos"}, {"target": "aarch64-apple-darwin"}, {"runtimeMode": "production"},
                       {"pythonSha256": "A" * 64}, {"pythonBytes": True}, {"pythonBytes": 0},
                       {"pythonBytes": 512 * 1024 * 1024 + 1}, {"pythonBytes": 1.0}, {"extra": "field"}):
            expected = github_readonly_binding_data(); expected.update(change)
            bad = deepcopy(report); bad["bindings"] = deepcopy(expected)
            # Even equal received/expected data cannot qualify another platform,
            # an invalid SHA, Boolean size, or additional binding contract.
            with self.subTest(invalid_expected=tuple(change)), self.assertRaises(helper.CheckFailure):
                helper.validate_github_readonly_receipt(bad, bindings=expected)
        expected = github_readonly_binding_data(); del expected["pythonBytes"]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_github_readonly_receipt(report, bindings=expected)

    def test_github_readonly_raw_byte_structure_and_scalar_bounds(self):
        raw = json.dumps(github_readonly_report_data(), separators=(",", ":")).encode("utf-8")
        invalid = [b"", b"\xff", b"null", b"[]", raw[:-1], raw + b"{}",
                   raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1', 1),
                   raw.replace(b'"terminal":true', b'"terminal":true,"terminal":true', 1),
                   raw.replace(b'"elapsedMs":80', b'"elapsedMs":NaN', 1),
                   raw.replace(b'"elapsedMs":80', b'"elapsedMs":Infinity', 1),
                   raw.replace(b'"elapsedMs":80', b'"elapsedMs":1.0', 1),
                   b"[" * 17 + b"0" + b"]" * 17,
                   b"[" + b"0," * 50000 + b"0]", b" " * (128 * 1024 + 1)]
        for index, data in enumerate(invalid):
            with self.subTest(raw_case=index), self.assertRaises(helper.CheckFailure):
                helper.parse_github_readonly_receipt(data, bindings=github_readonly_binding_data())
        for data in (raw.decode("utf-8"), bytearray(raw), None, {}):
            with self.subTest(raw_type=type(data).__name__), self.assertRaises(helper.CheckFailure):
                helper.parse_github_readonly_receipt(data, bindings=github_readonly_binding_data())
        at_limit = raw + b" " * (128 * 1024 - len(raw))
        self.assertEqual(github_readonly_report_data(), helper.parse_github_readonly_receipt(
            at_limit, bindings=github_readonly_binding_data()))
        with self.assertRaises(helper.CheckFailure):
            helper.parse_github_readonly_receipt(at_limit + b" ", bindings=github_readonly_binding_data())

    def test_github_readonly_original_finality_cannot_be_replaced_by_notes(self):
        report = github_readonly_report_data()
        for index, row in enumerate(report["cases"]):
            for owner_index, owner in enumerate(row["owners"]):
                for field in ("terminal", "observerJoined", "permitRetained"):
                    bad = deepcopy(report)
                    bad["cases"][index]["owners"][owner_index][field] = not owner[field]
                    with self.subTest(case=row["case"], owner=owner_index, field=field), self.assertRaises(helper.CheckFailure):
                        validate_github_readonly_data(bad)
        for field in ("inspection_joined", "acquisition_joined", "spawned", "waited", "writer_joined",
                      "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined", "driver_joined", "watchdog_joined"):
            for change in (False, 1):
                bad = deepcopy(report); bad["cases"][0]["owners"][0]["native"][field] = change
                with self.subTest(native=field, change=change), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
        for change in ({"registeredOwners": 1}, {"registeredOwners": False}, {"passed": 1}, {"disabled": 0},
                       {"failureCode": "not_settled"}, {"owners": []}, {"extra": True},
                       {"evidenceKind": "scheduling-control-not-os-fault"}, {"elapsedMs": True}, {"elapsedMs": -1}):
            bad = deepcopy(report); bad["cases"][0].update(change)
            with self.subTest(case_change=tuple(change)), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for field in report["cases"][0]["owners"][0]:
            bad = deepcopy(report); del bad["cases"][0]["owners"][0][field]
            with self.subTest(missing_owner_field=field), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for change in ({"observer_joined": True}, {"driver_joined": None}):
            bad = deepcopy(report); bad["cases"][0]["owners"][0]["native"].update(change)
            with self.subTest(native_shape=tuple(change)), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)

    def test_github_readonly_original_errors_and_typed_failure_are_not_salvaged(self):
        report = github_readonly_report_data()
        for index, row in enumerate(report["cases"]):
            if not row["owners"][0]["firstError"]:
                continue
            for change in ("positive", "first-error", "receipt-extra", "untyped"):
                bad = deepcopy(report); owner = bad["cases"][index]["owners"][0]
                if change == "positive":
                    owner["receipt"] = {"return": "github-facts", "wasUnknown": False}
                    if bad["cases"][index]["results"]:
                        bad["cases"][index]["results"][-1] = deepcopy(owner["receipt"])
                elif change == "first-error":
                    owner["firstError"] = None
                elif change == "receipt-extra":
                    owner["receipt"]["extra"] = True
                else:
                    owner["receipt"] = {"return": "ok"}
                with self.subTest(case=row["case"], change=change), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
        for name in ("g1-nonzero-exit", "g1-stalled-input", "g1-document-loss"):
            bad = deepcopy(report)
            next(row for row in bad["cases"] if row["case"] == name)["owners"][0]["native"]["exit_success"] = True
            with self.subTest(exit_cannot_be_positive=name), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for mutation in ("failed-native", "wrong-identity", "wrong-profile", "passive-envelope"):
            bad = deepcopy(report); owner = bad["cases"][0]["owners"][0]
            if mutation == "failed-native": owner["native"]["exit_success"] = False
            elif mutation == "wrong-identity": owner["id"] = "query-1"
            elif mutation == "wrong-profile": owner["profile"] = "passive"
            else: owner["receipt"] = {"return": "ok"}
            with self.subTest(healthy=mutation), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)

    def test_github_readonly_profile_specific_output_accounting(self):
        report = github_readonly_report_data()
        bounded = deepcopy(report); bounded["cases"][0]["owners"][0]["native"]["stdout_bytes"] = 65536
        validate_github_readonly_data(bounded)
        for field, changes in (("stdout_bytes", (0, -1, True, 1.0, 65537)), ("stderr_bytes", (-1, False, 0.0, 1))):
            for change in changes:
                bad = deepcopy(report); bad["cases"][0]["owners"][0]["native"][field] = change
                with self.subTest(github_output=field, change=change), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
        mixed_index = next(index for index, row in enumerate(report["cases"]) if row["case"] == "g1-mixed-abandon")
        bounded = deepcopy(report); bounded["cases"][mixed_index]["owners"][1]["native"]["stdout_bytes"] = 4 * 1024 * 1024
        validate_github_readonly_data(bounded)
        for change in (4 * 1024 * 1024 + 1, False):
            bad = deepcopy(bounded); bad["cases"][mixed_index]["owners"][1]["native"]["stdout_bytes"] = change
            with self.subTest(passive_output=change), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for change in ({"id": "github-read-2"}, {"profile": "github-readonly"}, {"receipt": {"return": "ok"}}):
            bad = deepcopy(report); bad["cases"][mixed_index]["owners"][1].update(change)
            with self.subTest(passive_contract=tuple(change)), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for name in ("g1-stdout-limit", "g1-stderr-limit"):
            for success in (False, True):
                permitted = deepcopy(report)
                next(row for row in permitted["cases"] if row["case"] == name)["owners"][0]["native"]["exit_success"] = success
                validate_github_readonly_data(permitted)
        stderr_index = next(index for index, row in enumerate(report["cases"]) if row["case"] == "g1-stderr-limit")
        for change in (0, -1, True, 65537):
            bad = deepcopy(report); bad["cases"][stderr_index]["owners"][0]["native"]["stderr_bytes"] = change
            with self.subTest(stderr_limit=change), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)

    def test_github_readonly_sticky_unknown_original_error_and_clock(self):
        report = github_readonly_report_data()
        for index, row in enumerate(report["cases"]):
            if not row["disabled"]:
                continue
            owner_index = 1 if row["case"] == "g1-document-terminal-unknown" else 0
            for change in ("disabled", "unknown", "was-unknown", "first-error", "short-clock", "missing-retained"):
                if change == "missing-retained" and not row["results"]:
                    continue
                bad = deepcopy(report); case = bad["cases"][index]; owner = case["owners"][owner_index]
                if change == "disabled": case["disabled"] = False
                elif change == "unknown": owner["unknownLatched"] = False
                elif change == "was-unknown": owner["receipt"]["wasUnknown"] = False
                elif change == "first-error": owner["firstError"] = "cleanup_unknown"
                elif change == "short-clock": case["elapsedMs"] = 1999
                else: case["results"] = case["results"][1:]
                with self.subTest(case=row["case"], change=change), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
        for elapsed in (9999, 10000.0, True):
            bad = deepcopy(report)
            next(row for row in bad["cases"] if row["case"] == "g1-stalled-input")["elapsedMs"] = elapsed
            with self.subTest(original_deadline=elapsed), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        bad = deepcopy(report)
        terminal = next(row for row in bad["cases"] if row["case"] == "g1-document-terminal-unknown")
        terminal["owners"][0].update(unknownLatched=True, firstError="shutting_down",
                                    receipt={"return": "error", "code": "cleanup_unknown", "wasUnknown": True})
        with self.assertRaises(helper.CheckFailure): validate_github_readonly_data(bad)
        bad = deepcopy(report)
        terminal = next(row for row in bad["cases"] if row["case"] == "g1-document-terminal-unknown")
        terminal["owners"].reverse()
        with self.assertRaises(helper.CheckFailure): validate_github_readonly_data(bad)

    def test_github_readonly_document_and_lifecycle_notes_are_closed(self):
        report = github_readonly_report_data()
        for index, row in enumerate(report["cases"]):
            for field in row["notes"]:
                bad = deepcopy(report); del bad["cases"][index]["notes"][field]
                with self.subTest(case=row["case"], missing_note=field), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
            bad = deepcopy(report); bad["cases"][index]["notes"]["releaseFileFailure"] = True
            with self.subTest(case=row["case"], release_failure=True), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
            if not row["case"].startswith("g1-document-"):
                continue
            for change in ({"documentEvidence": "native-gui"}, {"sourceBooksSettled": 0}, {"sourceBooksSettled": True},
                           {"sourceBooksSettled": 3}, {"documentMaterialSettled": False}, {"documentMaterialSettled": 1}):
                bad = deepcopy(report); bad["cases"][index]["notes"].update(change)
                with self.subTest(case=row["case"], document_note=change), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
            bad = deepcopy(report); bad["cases"][index]["results"] = [deepcopy(row["owners"][0]["receipt"])]
            with self.subTest(case=row["case"], substituted_results=True), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        bad = deepcopy(report)
        next(row for row in bad["cases"] if row["case"] == "g1-document-registry-change")["notes"]["sourceBooksSettled"] = 1
        with self.assertRaises(helper.CheckFailure): validate_github_readonly_data(bad)
        bad = deepcopy(report)
        next(row for row in bad["cases"] if row["case"] == "g1-document-connect-refresh")["owners"].pop()
        with self.assertRaises(helper.CheckFailure): validate_github_readonly_data(bad)

    def test_github_readonly_startup_without_child_and_unread_input_are_distinct(self):
        report = github_readonly_report_data()
        for name in ("g1-controlled-inspection", "g1-controlled-acquisition"):
            index = next(index for index, row in enumerate(report["cases"]) if row["case"] == name)
            observed = report["cases"][index]["owners"][0]["native"]
            for field in ("acquisition_joined", "spawned", "waited", "writer_joined", "writer_complete",
                          "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined"):
                bad = deepcopy(report); bad["cases"][index]["owners"][0]["native"][field] = not observed[field]
                with self.subTest(startup=name, field=field), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
            for change in ({"exit_success": True}, {"stdout_bytes": 1}, {"stderr_bytes": 1}):
                bad = deepcopy(report); bad["cases"][index]["owners"][0]["native"].update(change)
                with self.subTest(startup=name, unexpected=tuple(change)), self.assertRaises(helper.CheckFailure):
                    validate_github_readonly_data(bad)
        stalled_index = next(index for index, row in enumerate(report["cases"]) if row["case"] == "g1-stalled-input")
        for complete in (False, True):
            permitted = deepcopy(report)
            permitted["cases"][stalled_index]["owners"][0]["native"]["writer_complete"] = complete
            validate_github_readonly_data(permitted)
        for change in ({"writer_complete": 1}, {"writer_joined": False}, {"stdout_bytes": 1}):
            bad = deepcopy(report); bad["cases"][stalled_index]["owners"][0]["native"].update(change)
            with self.subTest(unread_input=tuple(change)), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)
        for field in ("unreadInputIsNotBlockedWriterEvidence", "originalCleanupEndpointUnchanged"):
            bad = deepcopy(report); bad["cases"][stalled_index]["notes"][field] = False
            with self.subTest(unread_evidence=field), self.assertRaises(helper.CheckFailure):
                validate_github_readonly_data(bad)


class GitHubReadonlyWorkflowContractTests(unittest.TestCase):
    def test_fixed_native_workflow_is_single_job_exact_source_and_redacted(self):
        # Bounded SOURCE only. No hosted admission, dispatch or YAML execution.
        import re
        path = SOURCE / ".github/workflows/desktop-github-connection-native.yml"
        with path.open("rb") as stream:
            raw = stream.read(16384 + 1)
        self.assertLessEqual(len(raw), 16384)
        workflow = raw.decode("utf-8")
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9-]*):$", workflow.split("\njobs:\n", 1)[1], re.MULTILINE),
                         ["github-readonly-native"])
        self.assertEqual(workflow.count("runs-on: ubuntu-24.04"), 1)
        self.assertNotIn("matrix:", workflow)
        self.assertEqual(workflow.count("permissions:"), 1)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertNotIn("${{ secrets.", workflow)
        self.assertEqual(re.findall(r"uses: ([^\s]+)", workflow), [
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ])
        for guard in ('"$RUNNER_ENVIRONMENT" == github-hosted', '"$EUID" -ne 0',
                      '"$GITHUB_REF" == refs/heads/verify/desktop-github-connection-native',
                      '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"', '"$MRK_EXPECTED_SHA" == "$GITHUB_SHA"',
                      '"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-github-connection-native.yml@$GITHUB_REF"',
                      "persist-credentials: false", "MRK_DESKTOP_HOSTED_CHECKS: github-readonly-native-v1"):
            self.assertIn(guard, workflow)
        self.assertEqual(re.findall(r"ci_foundation\.py ([a-z-]+)'", workflow),
                         ["prepare", "acquire", "compile", "github-owner", "clean"])
        self.assertEqual(len(re.findall(r"^        run:", workflow, re.MULTILINE)), 6)
        self.assertIn("if: success()", workflow)
        self.assertIn("if: always() && steps.prepare.outcome == 'success'", workflow)
        paths = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            "${{ steps.prepare.outputs.root }}/" + name for name in (
                "public-bindings.json", "acquire-checks.json", "compile-checks.json",
                "github-owner-checks.json", "github-owner/receipt.json", "clean-checks.json")])


class WindowsCompositionRoutingTests(unittest.TestCase):
    """Composed entry points with finite inert capabilities, never hosted work."""

    def test_windows_admission_and_main_routing_preserve_closed_profiles(self):
        platforms = {"linux", "macos", "windows"}
        profiles = {
            helper.BOUNDARY_SCOPE: (set(helper.BOUNDARY_PHASES), platforms),
            helper.COMPILE_SCOPE: (set(helper.COMPILE_PHASES), platforms),
            helper.GTK_COMPILE_SCOPE: (set(helper.COMPILE_PHASES), {"linux"}),
            helper.WORKFLOW_NATIVE_SCOPE: (set(helper.WORKFLOW_NATIVE_PHASES), {"linux"}),
            helper.GITHUB_READONLY_SCOPE: (set(helper.GITHUB_READONLY_PHASES), {"linux"}),
            helper.GITHUB_TLS_SCOPE: (set(helper.GITHUB_TLS_PHASES), {"linux"}),
            helper.WINDOWS_SNAPSHOT_SCOPE: ({"prepare", "acquire", "compile", "windows-snapshot", "clean"}, {"windows"}),
        }
        self.assertEqual(helper.FOUNDATION_SCOPE, helper.BOUNDARY_SCOPE)
        self.assertEqual(set(helper.COMPILE_PROFILES), {helper.COMPILE_SCOPE, helper.GTK_COMPILE_SCOPE})
        self.assertEqual(helper.WINDOWS_SNAPSHOT_PHASES, profiles[helper.WINDOWS_SNAPSHOT_SCOPE][0])
        phases = {"unexpected", ""}.union(*(names for names, _ in profiles.values()))

        def forbidden(*args, **kwargs):
            raise AssertionError("admission must refuse before any capability")

        with patch.multiple(helper, Path=forbidden, load_context=forbidden, tools=forbidden, run=forbidden,
                            admitted_host=forbidden, admitted_scope=forbidden, clean_environment=forbidden,
                            compile_profile=forbidden, compile_workflow_binding=forbidden,
                            workflow_native_binding=forbidden, source_unchanged=forbidden,
                            no_cargo_configuration=forbidden, write_json=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden), \
                patch.object(helper.shutil, "which", side_effect=forbidden), \
                patch.object(helper.tempfile, "mkdtemp", side_effect=forbidden), \
                patch.object(helper.zipfile, "ZipFile", side_effect=forbidden):
            for scope, (allowed_phases, allowed_platforms) in profiles.items():
                for name in sorted(phases):
                    with self.subTest(scope=scope, phase=name):
                        if name in allowed_phases:
                            helper.admit_phase(scope, name)
                        else:
                            with self.assertRaises(helper.CheckFailure):
                                helper.admit_phase(scope, name)
                            for platform in sorted(allowed_platforms):
                                with self.assertRaises(helper.CheckFailure):
                                    helper.phase(name, platform, scope)
                for platform in sorted(platforms | {"unknown", ""}):
                    with self.subTest(scope=scope, platform=platform):
                        if platform in allowed_platforms:
                            helper.admit_platform(scope, platform)
                        else:
                            with self.assertRaises(helper.CheckFailure):
                                helper.admit_platform(scope, platform)
                            with self.assertRaises(helper.CheckFailure):
                                helper.prepare(platform, scope)
                            for name in sorted(allowed_phases):
                                with self.assertRaises(helper.CheckFailure):
                                    helper.phase(name, platform, scope)
            for scope in ("", "unknown", "windows-snapshot-v1-extra"):
                for name in sorted(phases):
                    with self.subTest(scope=scope, phase=name), self.assertRaises(helper.CheckFailure):
                        helper.admit_phase(scope, name)
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase(name, "windows", scope)
                with self.assertRaises(helper.CheckFailure):
                    helper.prepare("windows", scope)

        # Fixed bounded SOURCE reads only: main and real hosted admission are never called.
        with HELPER.open("rb") as stream:
            raw = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(raw), 512 * 1024)
        source = raw.decode("utf-8")
        main = source.split("def main() -> int:\n", 1)[1].split('\n\nif __name__ == "__main__":', 1)[0]
        self.assertIn('"workflow-core", "windows-snapshot", "github-owner", "github-tls"))', main)
        self.assertIn('scope = os.environ.get("MRK_DESKTOP_HOSTED_CHECKS", "")', main)
        self.assertLess(main.index("admit_phase(scope, args.phase)"), main.index("platform = admitted_host()"))
        self.assertLess(main.index("platform = admitted_host()"), main.index("prepare(platform, scope)"))
        self.assertIn('prepare(platform, scope) if args.phase == "prepare" else phase(args.phase, platform, scope)', main)
        self.assertNotIn("--scope", main)
        self.assertIn("def prepare(platform: str, scope: str = BOUNDARY_SCOPE) -> None:", source)
        self.assertIn("def phase(name: str, platform: str, scope: str = BOUNDARY_SCOPE) -> None:", source)
        host = source.split("def admitted_host() -> str:\n", 1)[1].split("\n\ndef admitted_scope(", 1)[0]
        self.assertEqual(host.count("admitted_scope(platform)"), 1)
        self.assertIn('if os.environ["MRK_DESKTOP_HOSTED_CHECKS"] == WINDOWS_SNAPSHOT_SCOPE:\n        admitted_scope(platform)', host)
        self.assertIn('if os.environ["MRK_DESKTOP_HOSTED_CHECKS"] in {WORKFLOW_NATIVE_SCOPE, GITHUB_READONLY_SCOPE, GITHUB_TLS_SCOPE}:', host)
        self.assertIn('os.environ.get("ImageOS") == "ubuntu24" and os.uname().machine == "x86_64"', host)
        self.assertIn('os.geteuid() != 0', host)

    def test_windows_context_requires_both_scopes_and_original_event_binding(self):
        root = "/inert/temp/mrk-desktop-foundation-composition"
        temp = "/inert/temp"
        context_path = root + "/context.json"
        original_environment = {
            "MRK_DESKTOP_HOSTED_CHECKS": helper.WINDOWS_SNAPSHOT_SCOPE,
            "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "RUNNER_TEMP": temp,
            "MRK_DESKTOP_CI_ROOT": root, "GITHUB_SHA": "1" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/verify/desktop-windows-snapshot",
        }
        original_context = {
            "root": root, "source": "/inert/source", "platform": "windows", "python": "/inert/python",
            "executionScope": helper.WINDOWS_SNAPSHOT_SCOPE, "scope": helper.WINDOWS_SNAPSHOT_SCOPE,
            "event": "push", "ref": original_environment["GITHUB_REF"], "sourceSha": "1" * 40,
            "sourceTree": "3" * 40, "runId": "123", "attempt": "2", "sdkRoot": "/inert/sdk",
        }
        environment = dict(original_environment)
        record = dict(original_context)
        events = []
        test = self

        class ContextPath:
            def __init__(self, value):
                self.value = str(value)
                test.assertIn(self.value, {root, temp, context_path})
                events.append(("path", self.value))

            def __str__(self):
                return self.value

            def __eq__(self, other):
                return isinstance(other, ContextPath) and self.value == other.value

            def __truediv__(self, name):
                test.assertEqual((self.value, name), (root, "context.json"))
                return ContextPath(context_path)

            @property
            def name(self):
                test.assertEqual(self.value, root)
                return "mrk-desktop-foundation-composition"

            @property
            def parent(self):
                test.assertEqual(self.value, root)
                return ContextPath(temp)

            def is_absolute(self):
                test.assertEqual(self.value, root)
                return True

            def is_symlink(self):
                test.assertEqual(self.value, root)
                return False

            def resolve(self, *, strict):
                test.assertEqual((self.value, strict), (temp, True))
                return self

            def read_text(self, *, encoding):
                test.assertEqual((self.value, encoding), (context_path, "utf-8"))
                test.assertIn(("ordinary", context_path), events)
                events.append(("read", self.value))
                return json.dumps(record)

        def ordinary(path):
            self.assertEqual(str(path), context_path)
            events.append(("ordinary", str(path)))

        def forbidden(*args, **kwargs):
            raise AssertionError("no real context, SDK, workflow or tool capability")

        with patch.object(helper.os, "environ", environment), \
                patch.multiple(helper, Path=ContextPath, ordinary=ordinary, hash_file=forbidden, run=forbidden,
                               tools=forbidden, windows_sdk_root=forbidden, windows_inputs=forbidden,
                               workflow_json=forbidden, compile_workflow_binding=forbidden,
                               workflow_native_binding=forbidden, gtk_compile_binding=forbidden,
                               workflow_inputs_unchanged=forbidden, write_json=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            self.assertEqual(helper.load_context("windows", helper.WINDOWS_SNAPSHOT_SCOPE), original_context)
            self.assertEqual([event for event in events if event[0] in {"ordinary", "read"}],
                             [("ordinary", context_path), ("read", context_path)])
            mutations = {
                "executionScope": helper.BOUNDARY_SCOPE, "scope": helper.COMPILE_SCOPE,
                "event": "workflow_dispatch", "ref": "refs/heads/main", "sourceSha": "2" * 40,
                "runId": "124", "attempt": "3", "root": root + "-other", "platform": "linux",
            }
            for key, value in mutations.items():
                for missing in (False, True):
                    record = dict(original_context)
                    if missing:
                        del record[key]
                    else:
                        record[key] = value
                    events.clear()
                    with self.subTest(binding=key, missing=missing), self.assertRaises((helper.CheckFailure, KeyError)):
                        helper.load_context("windows", helper.WINDOWS_SNAPSHOT_SCOPE)
                    self.assertEqual(events[-1], ("read", context_path))
            record = dict(original_context)
            for key, value in (("GITHUB_SHA", "2" * 40), ("GITHUB_RUN_ID", "124"), ("GITHUB_RUN_ATTEMPT", "3"),
                               ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/main"),
                               ("MRK_DESKTOP_HOSTED_CHECKS", helper.COMPILE_SCOPE),
                               ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "ARM64")):
                for missing in (False, True):
                    environment.clear()
                    environment.update(original_environment)
                    if missing:
                        del environment[key]
                    else:
                        environment[key] = value
                    with self.subTest(environment=key, missing=missing), self.assertRaises((helper.CheckFailure, KeyError)):
                        helper.load_context("windows", helper.WINDOWS_SNAPSHOT_SCOPE)
            environment.clear()
            environment.update(original_environment)
            environment.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_DESKTOP_DISPATCH_SCOPE="windows-snapshot",
                               MRK_DESKTOP_EXPECTED_SHA=original_environment["GITHUB_SHA"])
            record = {**original_context, "event": "workflow_dispatch"}
            self.assertEqual(helper.load_context("windows", helper.WINDOWS_SNAPSHOT_SCOPE), record)
            self.assertEqual(record["sdkRoot"], "/inert/sdk")  # Persisted, not revalidated by load_context.
            record = dict(original_context)
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("windows", helper.WINDOWS_SNAPSHOT_SCOPE)

        with HELPER.open("rb") as stream:
            raw = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(raw), 512 * 1024)
        source = raw.decode("utf-8")
        prepare = source.split("def prepare(platform: str, scope: str = BOUNDARY_SCOPE) -> None:\n", 1)[1].split("\n\ndef load_context(", 1)[0]
        self.assertTrue(prepare.startswith('    admit_phase(scope, "prepare")\n    admit_platform(scope, platform)\n'))
        self.assertLess(prepare.index('require(admitted_scope(platform) == scope'), prepare.index('source = Path('))
        self.assertIn('directories = GITHUB_TLS_DIRECTORIES if native_tls else GITHUB_READONLY_DIRECTORIES if native_github else WORKFLOW_NATIVE_DIRECTORIES if native_workflow else (\n'
                      '        "home", "cargo", "rustup", "tmp", "target", "windows-snapshot", "appdata", "localappdata") if windows else (', prepare)
        self.assertIn('empty_files = ("gitconfig-empty",) if native_workflow or native_github or native_tls or windows else ("npmrc-user", "npmrc-global", "gitconfig-empty")', prepare)
        self.assertIn('"executionScope": scope,', prepare)
        self.assertIn('if windows:\n        context.update(scope=scope, event=os.environ["GITHUB_EVENT_NAME"], ref=os.environ["GITHUB_REF"])', prepare)
        self.assertEqual(prepare.count('write_json(root / "context.json", context)'), 2)
        self.assertIn('if not windows:\n        write_json(root / "context.json", context)', prepare)
        self.assertIn('if windows:\n        windows_prepare_bindings(context, public)\n        write_json(root / "context.json", context)', prepare)
        self.assertEqual(prepare.count("windows_prepare_bindings(context, public)"), 1)
        self.assertLess(prepare.index("source_unchanged(context)"), prepare.index("if not windows:"))
        self.assertLess(prepare.index("if not windows:"), prepare.index("public = workflow_public_bindings(context)"))
        self.assertLess(prepare.index("public.update(binding)"), prepare.index("windows_prepare_bindings(context, public)"))
        self.assertLess(prepare.index("windows_prepare_bindings(context, public)"), prepare.index('write_json(root / "public-bindings.json", public)'))
        self.assertIn('WINDOWS_SNAPSHOT_PUBLIC_SCOPE if windows else "passive-development-foundation-only"', prepare)
        self.assertIn('validate_gtk_core_inventory(inventory)', prepare)
        bindings = source.split("def windows_prepare_bindings(", 1)[1].split("\n\ndef windows_executable_path(", 1)[0]
        self.assertIn('context["sdkRoot"] = str(sdk)', bindings)
        inputs = source.split("def windows_inputs(", 1)[1].split("\n\ndef windows_snapshot_receipt(", 1)[0]
        self.assertIn('require(str(sdk_root) == context["sdkRoot"]', inputs)

    def test_windows_phase_routes_stay_headless_and_fail_closed(self):
        root, source = "/inert/mrk-desktop-foundation-composition", "/inert/source"
        cargo = "/inert/cargo"
        context = {"root": root, "source": source, "sourceSha": "1" * 40, "platform": "windows",
                   "executionScope": helper.WINDOWS_SNAPSHOT_SCOPE, "scope": helper.WINDOWS_SNAPSHOT_SCOPE,
                   "python": "/inert/python", "rustup": "/inert/rustup"}
        compiled = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "path": root + "/target/original.exe",
                    "sha256": "3" * 64, "size": 144, "invocationSha256": "4" * 64}
        common = ["--locked", "--offline", "--jobs", "1", "--no-default-features", "--target", helper.TARGETS["windows"],
                  "--manifest-path", source + "/desktop/src-tauri/Cargo.toml", "--target-dir", root + "/target"]
        base_environment = {"INERT_ENVIRONMENT": "1", "GITHUB_SHA": context["sourceSha"]}
        native_environment = {
            **base_environment, "MRK_DESKTOP_DEV_PYTHON": context["python"], "MRK_DESKTOP_DEV_CORE": source + "/src",
            "MRK_DESKTOP_TEST_ROOT": root + "/windows-snapshot", "MRK_DESKTOP_TEST_CORE_ZIP": root + "/core.zip",
            "MRK_DESKTOP_HOSTED_CHECKS": helper.WINDOWS_SNAPSHOT_SCOPE, "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
        }
        commands = {
            "acquire": [([context["rustup"], "toolchain", "install", helper.RUST, "--profile", "minimal", "--no-self-update"],
                         "rust-toolchain-install", 600, None),
                        ([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features", "--features",
                          "development-runtime", "--filter-platform", helper.TARGETS["windows"],
                          "--manifest-path", source + "/desktop/src-tauri/Cargo.toml"], "locked-platform-metadata", 600, "metadata.json")],
            "compile": [([cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime", "--message-format=json"],
                         "headless-test-compile-only", 600, "windows-compile-messages.jsonl")],
            "windows-snapshot": [([cargo, "test", *common, "--lib", "--features", "development-runtime", helper.WINDOWS_SNAPSHOT_TEST,
                                  "--", "--exact", "--ignored", "--test-threads=1"], "windows-snapshot-native-contract", 300, None)],
            "clean": [],
        }
        prefix = ["load_context", "clean_environment", "source_unchanged", "no_cargo_configuration"]
        orders = {
            "acquire": prefix + ["run:rust-toolchain-install", "tools", "open:metadata.json", "run:locked-platform-metadata",
                                 "close:metadata.json", "source_unchanged", "phase_receipt"],
            "compile": prefix + ["tools", "open:windows-compile-messages.jsonl", "run:headless-test-compile-only",
                                 "close:windows-compile-messages.jsonl", "windows_compile_record", "source_unchanged", "phase_receipt"],
            "windows-snapshot": prefix + ["tools", "windows_inputs", "run:windows-snapshot-native-contract",
                                          "source_unchanged", "windows_snapshot_receipt", "phase_receipt"],
            # Route-level tool selection is retained; only the real cleanup consumer is subprocess-free.
            "clean": prefix + ["tools", "clean_windows_outputs"],
        }
        phase_checks = {
            "acquire": ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"],
            "compile": ["rust-version-target", "headless-test-compile-only"],
            "windows-snapshot": ["rust-version-target", helper.WINDOWS_SNAPSHOT_TEST,
                                 "windows-snapshot-original-resource-receipt-acceptance"],
        }
        test = self

        def invoke(name, failure=None):
            events, calls, receipts, cleaned = [], [], [], []
            counts, writers = {}, {}
            environment = {"INERT_ENVIRONMENT": "1"}

            def step(label):
                counts[label] = counts.get(label, 0) + 1
                event = (label, counts[label])
                events.append(event)
                if event == failure:
                    raise helper.CheckFailure("inert predecessor failed")

            class Writer:
                def __init__(self, leaf):
                    self.leaf, self.data, self.closed = leaf, "", False

                def __enter__(self):
                    return self

                def write(self, data):
                    test.assertFalse(self.closed)
                    test.assertIs(type(data), str)
                    self.data += data
                    return len(data)

                def __exit__(self, *error):
                    self.closed = True
                    step("close:" + self.leaf)
                    return False

            class RoutePath:
                def __init__(self, value):
                    self.value = str(value)
                    test.assertIn(self.value, {
                        root, source, "/inert", "/", root + "/target", root + "/metadata.json",
                        root + "/windows-compile-messages.jsonl", source + "/desktop/src-tauri/Cargo.toml",
                        root + "/windows-snapshot", root + "/core.zip", source + "/src",
                    })

                def __str__(self):
                    return self.value

                def __truediv__(self, relative):
                    return RoutePath(self.value + "/" + relative)

                @property
                def parents(self):
                    test.assertEqual(self.value, root)
                    return (RoutePath("/inert"), RoutePath("/"))

                def open(self, mode, *, encoding, newline=None):
                    leaf = self.value.removeprefix(root + "/")
                    test.assertIn(leaf, {"metadata.json", "windows-compile-messages.jsonl"})
                    test.assertEqual((mode, encoding, newline), ("x", "utf-8", "\n" if leaf.endswith(".jsonl") else None))
                    test.assertNotIn(leaf, writers)
                    step("open:" + leaf)
                    writers[leaf] = Writer(leaf)
                    return writers[leaf]

            def load_context(platform, scope):
                self.assertEqual((platform, scope), ("windows", helper.WINDOWS_SNAPSHOT_SCOPE))
                step("load_context")
                return context

            def clean_environment(path):
                self.assertEqual(str(path), root)
                step("clean_environment")
                return environment

            def source_unchanged(value):
                self.assertIs(value, context)
                self.assertEqual(environment["GITHUB_SHA"], context["sourceSha"])
                step("source_unchanged")

            def no_cargo_configuration(paths):
                self.assertEqual(tuple(map(str, paths)), (root, "/inert", "/"))
                step("no_cargo_configuration")

            def tools(value, env):
                self.assertIs(value, context)
                self.assertIs(env, environment)
                self.assertEqual(env, base_environment)
                step("tools")
                return cargo, "/inert/rustc"

            def run(argv, *, check, cwd, env, timeout, output=None):
                self.assertIs(env, environment)
                self.assertEqual(str(cwd), root)
                self.assertIn(check, {command[1] for command in commands[name]})
                step("run:" + check)
                calls.append((list(argv), check, timeout, output.leaf if output is not None else None, dict(env)))
                if output is not None:
                    self.assertIs(output, writers[output.leaf])
                    output.write("inert-original-" + check + "\n")
                return ""

            def windows_compile_record(value, argv, messages):
                self.assertIs(value, context)
                self.assertEqual(argv, commands["compile"][0][0])
                self.assertEqual(str(messages), root + "/windows-compile-messages.jsonl")
                self.assertTrue(writers["windows-compile-messages.jsonl"].closed)
                self.assertEqual(writers["windows-compile-messages.jsonl"].data, "inert-original-headless-test-compile-only\n")
                step("windows_compile_record")
                return compiled

            def windows_inputs(value, *, create):
                self.assertIs(value, context)
                self.assertIs(create, True)
                step("windows_inputs")
                return {}

            def windows_snapshot_receipt(value):
                self.assertIs(value, context)
                step("windows_snapshot_receipt")
                return {"status": "passed"}  # Inert DATA, never native evidence.

            def clean_windows_outputs(value):
                self.assertIs(value, context)
                step("clean_windows_outputs")
                cleaned.append(True)

            def phase_receipt(value, phase, checks, **kwargs):
                self.assertIs(value, context)
                self.assertEqual(phase, name)
                if phase == "compile":
                    self.assertIs(kwargs.get("compiled"), compiled)
                step("phase_receipt")
                receipts.append((phase, list(checks), deepcopy(kwargs)))

            def forbidden(*args, **kwargs):
                raise AssertionError("no real IO, process, deletion, Node, GTK, Apply or configuration capability")

            with patch.object(helper.os, "environ", {}), \
                    patch.multiple(helper, Path=RoutePath, load_context=load_context, clean_environment=clean_environment,
                                   source_unchanged=source_unchanged, no_cargo_configuration=no_cargo_configuration,
                                   tools=tools, run=run, windows_compile_record=windows_compile_record,
                                   windows_inputs=windows_inputs, windows_snapshot_receipt=windows_snapshot_receipt,
                                   clean_windows_outputs=clean_windows_outputs, phase_receipt=phase_receipt,
                                   compile_gtk=forbidden, gtk_compile_binding=forbidden, clean_compile=forbidden,
                                   phase_workflow_native=forbidden, native_receipt=forbidden, config_receipt=forbidden,
                                   config_owner_receipt=forbidden, config_loss_receipt=forbidden,
                                   config_delta_receipt=forbidden, config_transaction_eof_receipt=forbidden,
                                   hash_file=forbidden, ordinary=forbidden, write_json=forbidden,
                                   windows_sdk_root=forbidden, read_bounded_json=forbidden), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), \
                    patch.object(helper.shutil, "which", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), \
                    patch.object(helper.os, "scandir", side_effect=forbidden):
                if failure is None:
                    helper.phase(name, "windows", helper.WINDOWS_SNAPSHOT_SCOPE)
                else:
                    with self.assertRaises(helper.CheckFailure) as caught:
                        helper.phase(name, "windows", helper.WINDOWS_SNAPSHOT_SCOPE)
                    self.assertEqual(str(caught.exception), "inert predecessor failed")
                    self.assertIn(failure, events)
                    self.assertEqual(receipts, [])
                    self.assertEqual(cleaned, [])
            return events, calls, receipts, cleaned

        for name, order in orders.items():
            counts = {}
            expected_order = []
            for label in order:
                counts[label] = counts.get(label, 0) + 1
                expected_order.append((label, counts[label]))
            with self.subTest(phase=name):
                events, calls, receipts, cleaned = invoke(name)
                self.assertEqual(events, expected_order)
                self.assertEqual(calls, [(*command, native_environment if name == "windows-snapshot" else base_environment)
                                         for command in commands[name]])
                self.assertEqual(cleaned, [True] if name == "clean" else [])
                kwargs = {"scope": helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE}
                if name == "compile":
                    kwargs["compiled"] = compiled
                self.assertEqual(receipts, [] if name == "clean" else [(name, phase_checks[name], kwargs)])
            for predecessor in expected_order:
                if predecessor[0] != "phase_receipt":
                    with self.subTest(phase=name, failure=predecessor):
                        invoke(name, predecessor)

    def test_compiled_receipt_is_windows_only_and_preserves_existing_profiles(self):
        context = {"root": "/inert/receipts", "sourceSha": "1" * 40, "platform": "windows",
                   "executionScope": helper.WINDOWS_SNAPSHOT_SCOPE, "scope": helper.WINDOWS_SNAPSHOT_SCOPE}
        compiled = {"schemaVersion": 1, "sourceSha": "1" * 40, "path": "/inert/target/original.exe",
                    "sha256": "3" * 64, "size": 144, "invocationSha256": "4" * 64}
        checks = ["rust-version-target", "headless-test-compile-only"]
        written = []

        def collect(path, value):
            written.append((str(path), deepcopy(value)))

        def forbidden(*args, **kwargs):
            raise AssertionError("receipts use in-memory data, never filesystem or tools")

        with patch.object(helper, "write_json", side_effect=collect), \
                patch.multiple(helper, run=forbidden, hash_file=forbidden, ordinary=forbidden,
                               windows_compile_record=forbidden, windows_inputs=forbidden, windows_sdk_root=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            helper.phase_receipt(context, "compile", checks, scope=helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, compiled=compiled)
            self.assertEqual(written, [("/inert/receipts/compile-checks.json", {
                "schemaVersion": 1, "scope": helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, "phase": "compile", "status": "passed",
                "sourceSha": "1" * 40, "platform": "windows", "rust": {"release": helper.RUST, "target": helper.TARGETS["windows"]},
                "node": None, "checks": [{"check": check, "exitCode": 0} for check in checks],
                "compiledTest": {"sha256": compiled["sha256"], "size": compiled["size"], "invocationSha256": compiled["invocationSha256"]},
            })])
            invalid = []
            for key in ("executionScope", "scope"):
                for scope in (helper.BOUNDARY_SCOPE, helper.COMPILE_SCOPE, helper.GTK_COMPILE_SCOPE,
                              helper.WORKFLOW_NATIVE_SCOPE, "unknown", None):
                    invalid.append(({**context, key: scope}, "compile", helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, None))
                missing = dict(context)
                del missing[key]
                invalid.append((missing, "compile", helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, None))
            for phase in ("acquire", "windows-snapshot", "clean", "unexpected"):
                invalid.append((context, phase, helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, None))
            for scope in ("passive-development-foundation-only", helper.COMPILE_EVIDENCE_SCOPE, helper.GTK_COMPILE_EVIDENCE_SCOPE,
                          helper.WORKFLOW_NATIVE_EVIDENCE_SCOPE, "unknown"):
                invalid.append((context, "compile", scope, None))
            for node in (helper.NODE, "", False):
                invalid.append((context, "compile", helper.WINDOWS_SNAPSHOT_PUBLIC_SCOPE, node))
            for changed, phase, scope, node in invalid:
                written.clear()
                with self.subTest(context=changed, phase=phase, scope=scope, node=node), self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(changed, phase, checks, scope=scope, node=node, compiled=compiled)
                self.assertEqual(written, [])

            # Existing branches still construct and validate their original closed shapes.
            written.clear()
            foundation = {"root": "/inert/receipts", "sourceSha": "1" * 40, "platform": "linux",
                          "executionScope": helper.BOUNDARY_SCOPE}
            foundation_checks = list(helper.COMPILE_CHECKS["compile"])
            helper.phase_receipt(foundation, "compile", foundation_checks, node=helper.NODE)
            self.assertEqual(written[-1], ("/inert/receipts/compile-checks.json", {
                "schemaVersion": 1, "scope": "passive-development-foundation-only", "phase": "compile", "status": "passed",
                "sourceSha": "1" * 40, "platform": "linux", "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]},
                "node": helper.NODE, "checks": [{"check": check, "exitCode": 0} for check in foundation_checks],
            }))
            for scope in (helper.COMPILE_SCOPE, helper.GTK_COMPILE_SCOPE):
                profile = helper.COMPILE_PROFILES[scope]
                environment = {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
                               "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": profile["ref"],
                               "GITHUB_WORKFLOW_REF": f"fictional/project/{profile['workflow']}@{profile['ref']}",
                               "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}
                bound = {**helper.compile_workflow_binding(environment, scope), "root": "/inert/receipts",
                         "executionScope": scope, "platform": "linux", "workflowSha256": "2" * 64}
                if scope == helper.GTK_COMPILE_SCOPE:
                    bound.update(sourceTree="3" * 40, sg1={
                        "features": list(helper.GTK_COMPILE_FEATURES), "testTarget": "session-gtk-qualification", "execution": "no-run",
                        "sources": [{"path": path, "size": 1, "sha256": "4" * 64} for path in helper.GTK_COMPILE_SOURCES],
                    })
                for phase in ("acquire", "compile"):
                    expected = {
                        "schemaVersion": 1, "scope": profile["evidence"], "phase": phase, "status": "passed",
                        **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
                        "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "node": helper.NODE,
                        "checks": [{"check": check, "exitCode": 0} for check in profile["checks"][phase]],
                    }
                    if scope == helper.GTK_COMPILE_SCOPE:
                        expected.update(sourceTree=bound["sourceTree"], sg1=bound["sg1"])
                    helper.phase_receipt(bound, phase, list(profile["checks"][phase]), node=helper.NODE)
                    self.assertEqual(written[-1], (f"/inert/receipts/{phase}-checks.json", expected))
            workflow = workflow_context()
            helper.phase_receipt(workflow, "compile", list(helper.WORKFLOW_NATIVE_CHECKS["compile"]))
            self.assertEqual(written[-1], (workflow["root"] + "/compile-checks.json", workflow_phase_report("compile")))
            self.assertEqual(len(written), 6)
            for _, value in written:
                self.assertNotIn("compiledTest", value)


# SOURCE-only fragment for tests/desktop/test_ci_foundation_contract.py.
# Insert before its existing unittest.main guard; reuse its one helper loader,
# unittest/patch/deepcopy/json/hashlib/io/stat/SimpleNamespace/redirect_stdout globals. Do not
# import or execute this fragment as a second standalone verification runner.
# All paths, streams, metadata and tool/receipt capabilities below are inert.
from pathlib import PurePosixPath


class GitHubReadonlyCIIntegrationTests(unittest.TestCase):
    """G1 routing/authority DATA, never hosted admission or native evidence."""

    SCOPE = "github-readonly-native-v1"
    EVIDENCE = "desktop-github-readonly-native-only-v1"
    PHASES = ("prepare", "acquire", "compile", "github-owner", "clean")
    CHECKS = {
        "acquire": ("rust-toolchain-install", "rust-version-target", "github-locked-headless-metadata"),
        "compile": ("rust-version-target", "github-headless-test-compile-only", "github-compiled-artifact"),
        "github-owner": ("github-original-artifact", "github-owner-native-contract", "github-owner-receipt"),
    }

    @staticmethod
    def forbidden(*args, **kwargs):
        raise AssertionError("G1 inert contract requested an unprovided IO/tool capability")

    @staticmethod
    def environment():
        workflow = ".github/workflows/desktop-github-connection-native.yml"
        ref = "refs/heads/verify/desktop-github-connection-native"
        return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
                "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": ref,
                "GITHUB_WORKFLOW_REF": f"fictional/project/{workflow}@{ref}",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}

    @classmethod
    def context(cls):
        environment = cls.environment()
        return {"executionScope": cls.SCOPE, "platform": "linux", "root": "/inert/g1/job",
                "source": "/inert/g1/source", "python": "/inert/g1/python", "rustup": "/inert/g1/rustup",
                "sourceSha": "1" * 40, "sourceTree": "3" * 40, "workflowSha": "1" * 40,
                "workflowPath": ".github/workflows/desktop-github-connection-native.yml",
                "workflowRef": environment["GITHUB_WORKFLOW_REF"], "workflowSha256": "4" * 64,
                "runId": "123", "attempt": "2",
                "githubInputs": {"sourceFiles": [{"path": "desktop/src-tauri/src/lib.rs", "size": 1, "sha256": "5" * 64}],
                                 "coreFiles": [{"path": "mobile_release/__init__.py", "size": 1, "sha256": "6" * 64}],
                                 "coreZipSha256": "7" * 64, "pythonSha256": "8" * 64, "pythonBytes": 16}}

    @staticmethod
    def artifact():
        return {"path": "/inert/g1/job/target/x86_64-unknown-linux-gnu/debug/deps/mobile_release_desktop-0123456789abcdef",
                "size": 144, "sha256": "a" * 64, "invocationSha256": "b" * 64, "messagesSha256": "c" * 64}

    @classmethod
    def claim(cls, context, name):
        return {"scope": cls.SCOPE, "phase": name,
                **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")}}

    @classmethod
    def phase_report(cls, context, name):
        inputs = json.dumps(context["githubInputs"], sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("utf-8")
        value = {"schemaVersion": 1, "scope": cls.EVIDENCE, "phase": name, "status": "passed",
                 **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                                "workflowRef", "workflowSha256", "runId", "attempt")},
                 "inputSha256": hashlib.sha256(inputs).hexdigest(),
                 "rust": {"release": helper.RUST, "target": "x86_64-unknown-linux-gnu"},
                 "checks": [{"check": check, "exitCode": 0} for check in cls.CHECKS[name]]}
        if name in {"compile", "github-owner"}:
            compiled = cls.artifact()
            value["compiledTest"] = {key: compiled[key] for key in ("size", "sha256", "invocationSha256", "messagesSha256")}
        return value

    def test_binding_and_scope_refusal_before_capabilities(self):
        environment, forbidden = self.environment(), self.forbidden
        expected = {"workflowPath": ".github/workflows/desktop-github-connection-native.yml",
                    "workflowSha": "1" * 40, "workflowRef": environment["GITHUB_WORKFLOW_REF"],
                    "sourceSha": "1" * 40, "runId": "123", "attempt": "2"}
        with patch.multiple(helper, Path=forbidden, run=forbidden, hash_file=forbidden,
                            read_bounded_json=forbidden, load_context=forbidden, tools=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            self.assertEqual(helper.github_readonly_binding(environment), expected)
            for key, value in (("GITHUB_SHA", "bad"), ("GITHUB_WORKFLOW_SHA", "2" * 40),
                               ("GITHUB_REF", helper.WORKFLOW_NATIVE_REF), ("GITHUB_REF", "refs/heads/main"),
                               ("GITHUB_WORKFLOW_REF", "fictional/project/other.yml@main"),
                               ("GITHUB_REPOSITORY", "another/project"), ("GITHUB_RUN_ID", "0"),
                               ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
                with self.subTest(key=key, value=value), self.assertRaises(helper.CheckFailure):
                    helper.github_readonly_binding({**environment, key: value})
            with self.assertRaises(helper.CheckFailure):
                helper.github_readonly_binding({**environment, "GITHUB_SHA": "0" * 40, "GITHUB_WORKFLOW_SHA": "0" * 40})
            dispatch = {**environment, "GITHUB_EVENT_NAME": "workflow_dispatch"}
            for expected_sha in (None, "2" * 40, "main"):
                with self.subTest(expected_sha=expected_sha), self.assertRaises(helper.CheckFailure):
                    helper.github_readonly_binding({**dispatch, "MRK_EXPECTED_SHA": expected_sha})
            self.assertEqual(helper.github_readonly_binding({**dispatch, "MRK_EXPECTED_SHA": "1" * 40}), expected)
            # Each binding function retains its own fixed lane; no relabelling.
            with self.assertRaises(helper.CheckFailure):
                helper.github_readonly_binding(workflow_environment())
            with self.assertRaises(helper.CheckFailure):
                helper.workflow_native_binding(environment)
            for scope in helper.COMPILE_PROFILES:
                with self.subTest(scope=scope), self.assertRaises(helper.CheckFailure):
                    helper.compile_workflow_binding(environment, scope)
        self._assert_scope_refusal_before_capabilities()

    def _assert_scope_refusal_before_capabilities(self):
        self.assertEqual(helper.GITHUB_READONLY_SCOPE, self.SCOPE)
        self.assertEqual(helper.GITHUB_READONLY_PHASES, self.PHASES)
        self.assertEqual(helper.GITHUB_READONLY_CHECKS, self.CHECKS)
        self.assertNotIn(self.SCOPE, helper.COMPILE_PROFILES)
        forbidden = self.forbidden
        with patch.multiple(helper, Path=forbidden, load_context=forbidden, run=forbidden, tools=forbidden,
                            clean_environment=forbidden, phase_workflow_native=forbidden,
                            phase_github_readonly=forbidden, write_json=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            for name in self.PHASES:
                helper.admit_phase(self.SCOPE, name)
            helper.admit_platform(self.SCOPE, "linux")
            for name in ("native", "workflow-owner", "workflow-core", "config-owner", "windows-snapshot", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", self.SCOPE)
            for scope in (helper.BOUNDARY_SCOPE, helper.WORKFLOW_NATIVE_SCOPE, helper.WINDOWS_SNAPSHOT_SCOPE,
                          *helper.COMPILE_PROFILES):
                with self.subTest(scope=scope), self.assertRaises(helper.CheckFailure):
                    helper.phase("github-owner", "linux", scope)
            for platform in ("macos", "windows", "unexpected"):
                with self.subTest(platform=platform), self.assertRaises(helper.CheckFailure):
                    helper.phase("github-owner", platform, self.SCOPE)
                with self.subTest(prepare_platform=platform), self.assertRaises(helper.CheckFailure):
                    helper.prepare(platform, self.SCOPE)

    def test_cargo_selector_and_exact_posix_path_mutations(self):
        source, target = PurePosixPath("/inert/g1/source"), PurePosixPath("/inert/g1/job/target")
        artifact = {"reason": "compiler-artifact", "executable": self.artifact()["path"],
                    "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
                    "target": {"kind": ["lib"], "name": "mobile_release_desktop",
                               "src_path": str(source / "desktop/src-tauri/src/lib.rs")},
                    "profile": {"test": True, "debug_assertions": True},
                    "features": ["development-runtime"], "fresh": False}
        done = {"reason": "build-finished", "success": True}
        encode = lambda rows: b"\n".join(json.dumps(row, separators=(",", ":")).encode("utf-8") for row in rows) + b"\n"
        rejected = [[done], [artifact], [artifact, artifact, done], [artifact, done, done],
                    [artifact, {**done, "success": False}], [artifact, {**done, "success": 1}],
                    [artifact, done, {"reason": "compiler-message"}]]
        for key, value in (("manifest_path", str(source / "other/Cargo.toml")), ("fresh", True), ("fresh", 0),
                           ("features", ["desktop-shell", "development-runtime"]), ("features", [])):
            rejected.append([{**artifact, key: value}, done])
        for key, value in (("kind", ["bin"]), ("name", "another_target"),
                           ("src_path", str(source / "desktop/src-tauri/src/other.rs"))):
            rejected.append([{**artifact, "target": {**artifact["target"], key: value}}, done])
        for key, value in (("test", False), ("test", 1), ("debug_assertions", False), ("debug_assertions", 1)):
            rejected.append([{**artifact, "profile": {**artifact["profile"], key: value}}, done])
        forbidden = self.forbidden
        with patch.multiple(helper, Path=PurePosixPath, run=forbidden, hash_file=forbidden,
                            ordinary=forbidden, read_bounded_json=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            dependency = {"reason": "compiler-artifact", "executable": None}
            self.assertEqual(helper.github_compiled_test(encode([dependency, artifact, done]), source=source, target_root=target),
                             PurePosixPath(self.artifact()["path"]))
            for index, rows in enumerate(rejected):
                with self.subTest(mutation=index), self.assertRaises(helper.CheckFailure):
                    helper.github_compiled_test(encode(rows), source=source, target_root=target)
            invalid_bytes = (b"", bytearray(encode([artifact, done])), b"{}\n", b"not-json\n",
                             b'{"reason":"build-finished","success":true,"success":true}\n',
                             b"x" * (16 * 1024 * 1024 + 1))
            for index, raw in enumerate(invalid_bytes):
                with self.subTest(framing=index), self.assertRaises(helper.CheckFailure):
                    helper.github_compiled_test(raw, source=source, target_root=target)
        self._assert_exact_posix_path_mutations()

    def _assert_exact_posix_path_mutations(self):
        target, path = PurePosixPath("/inert/g1/job/target"), self.artifact()["path"]
        invalid = ("relative", str(target / "outside" / PurePosixPath(path).name),
                   path.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"),
                   path.replace("/debug/deps/", "/release/deps/"), path.replace("/debug/", "/debug/./"),
                   path.replace("/debug/", "/debug//"), path.replace("/debug/", "/debug/../"),
                   path + ".exe", path + "\0", path.replace("0123456789abcdef", "0123456789ABCDEF"),
                   path.replace("mobile_release_desktop-", "other-"), "x" * 16385, {}, 1, True)
        forbidden = self.forbidden
        with patch.multiple(helper, Path=PurePosixPath, run=forbidden, hash_file=forbidden,
                            ordinary=forbidden, read_bounded_json=forbidden):
            self.assertEqual(helper.github_executable_path(path, target_root=target), PurePosixPath(path))
            for index, value in enumerate(invalid):
                with self.subTest(path_mutation=index), self.assertRaises(helper.CheckFailure):
                    helper.github_executable_path(value, target_root=target)
            with self.assertRaises(helper.CheckFailure):
                helper.github_executable_path(path, target_root=PurePosixPath("relative/target"))

    def test_predecessors_bind_claims_receipts_one_use_and_native_finality(self):
        context, test, forbidden = self.context(), self, self.forbidden

        def invoke(name, *, changed=None, present=(), links=(), missing_native=False, entry="predecessors"):
            events, data = [], {}
            for phase in self.CHECKS:
                data[f"{phase}-started.json"] = self.claim(context, phase)
                data[f"{phase}-checks.json"] = self.phase_report(context, phase)
            if changed:
                filename, key, value = changed
                data[filename][key] = value

            class ProbePath(PurePosixPath):
                def exists(self):
                    return self.name in present

                def is_symlink(self):
                    return self.name in links

            def read(path, limit):
                test.assertEqual(path.parent, PurePosixPath(context["root"]))
                test.assertEqual(limit, 4096 if path.name.endswith("-started.json") else 16384)
                events.append(("read", path.name))
                return deepcopy(data[path.name])

            def native(value):
                test.assertIs(value, context)
                events.append(("native", "original-receipt"))
                if missing_native:
                    raise helper.CheckFailure("inert original native receipt missing")
                return {"status": "passed"}  # Supplied DATA, never a native claim.

            with patch.multiple(helper, Path=ProbePath, read_bounded_json=read, github_owner_receipt=native,
                                github_inputs_unchanged=forbidden, github_source_unchanged=forbidden,
                                run=forbidden, tools=forbidden, hash_file=forbidden), \
                    patch.object(helper, "github_original_artifact", return_value=self.artifact()), \
                    patch.object(helper, "write_json") as write, \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), \
                    patch.object(helper.os, "scandir", side_effect=forbidden):
                call = (lambda: helper.clean_github_readonly(context)) if entry == "clean" else (
                    (lambda: helper.phase_github_readonly(name, context)) if entry == "phase"
                    else (lambda: helper.github_predecessors(context, name)))
                if changed or present or links or missing_native:
                    with self.assertRaises(helper.CheckFailure):
                        call()
                else:
                    call()
                write.assert_not_called()
            return events

        for name in ("acquire", "compile", "github-owner", "clean"):
            with self.subTest(successor=name):
                events = invoke(name)
                previous = list(self.CHECKS) if name == "clean" else list(self.CHECKS)[:list(self.CHECKS).index(name)]
                expected = [("read", f"{phase}-{suffix}.json") for phase in previous for suffix in ("started", "checks")]
                if name == "clean":
                    expected.append(("native", "original-receipt"))
                self.assertEqual(events, expected)
        compiled_projection = {key: self.artifact()[key] for key in ("size", "sha256", "invocationSha256", "messagesSha256")}
        for change in (("compile-started.json", "scope", helper.WORKFLOW_NATIVE_SCOPE),
                       ("compile-started.json", "attempt", "3"),
                       ("compile-started.json", "sourceSha", "2" * 40),
                       ("compile-started.json", "runId", "124"),
                       ("compile-checks.json", "sourceTree", "9" * 40),
                       ("compile-checks.json", "status", "failed"),
                       ("github-owner-checks.json", "compiledTest", {**compiled_projection, "sha256": "d" * 64})):
            with self.subTest(predecessor_change=change[:2]):
                events = invoke("clean", changed=change)
                self.assertNotIn(("native", "original-receipt"), events)
        for name in ("github-owner-started.json", "github-owner-checks.json", "clean-checks.json"):
            with self.subTest(existing_claim=name):
                invoke("github-owner", present=(name,), entry="phase")
        invoke("github-owner", links=("clean-started.json",), entry="phase")
        for name in ("clean-started.json", "clean-checks.json"):
            with self.subTest(repeated_clean=name):
                invoke("clean", present=(name,), entry="clean")
        events = invoke("clean", missing_native=True, entry="clean")
        self.assertEqual(events[-1], ("native", "original-receipt"))
        # Above, even a positive compiler/outer-owner phase receipt cannot reach
        # input IO, a clean claim, deletion or tools without original finality.

    def test_g1_phase_routes_use_original_artifact_and_fail_closed(self):
        context, test, forbidden = self.context(), self, self.forbidden
        root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
        cargo, rustc = "/inert/g1/selected/cargo", "/inert/g1/selected/rustc"
        base_environment = {"PATH": "/inert/no-executables", "HOME": str(root / "home")}
        original = {**self.artifact(), "path": self.artifact()["path"].replace("0123456789abcdef", "fedcba9876543210")}
        pairs = {"acquire": ("cargo-metadata.json", "acquire.stderr"),
                 "compile": ("github-compile-messages.jsonl", "compile.stderr"),
                 "github-owner": ("github-owner.stdout", "github-owner.stderr")}
        manifest = str(source / "desktop/src-tauri/Cargo.toml")
        expected_runs = {
            "acquire": [
                ("rust-toolchain-install", [context["rustup"], "toolchain", "install", helper.RUST,
                                             "--profile", "minimal", "--no-self-update"], 600),
                ("github-locked-headless-metadata", [cargo, "metadata", "--locked", "--format-version", "1",
                    "--no-default-features", "--features", "development-runtime", "--filter-platform",
                    "x86_64-unknown-linux-gnu", "--manifest-path", manifest], 600)],
            "compile": [("github-headless-test-compile-only", [cargo, "test", "--locked", "--offline", "--jobs", "1",
                "--no-default-features", "--features", "development-runtime", "--target", "x86_64-unknown-linux-gnu",
                "--manifest-path", manifest, "--target-dir", str(root / "target"), "--lib", "--no-run",
                "--message-format=json"], 600)],
            "github-owner": [("github-owner-native-contract", [original["path"],
                "supervisor::hosted_tests::github_readonly_hosted_contract", "--exact", "--ignored", "--test-threads=1"], 180)],
        }

        def exercise(name, *, missing_native=False):
            events, streams, writes, calls = [], {}, {}, []
            pair = pairs[name]
            expected_environment = {**base_environment, "GITHUB_SHA": context["sourceSha"]}
            if name == "github-owner":
                expected_environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"],
                    MRK_DESKTOP_DEV_CORE=str(source / "src"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                    MRK_DESKTOP_TEST_ROOT=str(root / "github-owner"), MRK_DESKTOP_HOSTED_CHECKS="github-readonly-v1",
                    GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", RUNNER_ARCH="X64")

            class Writer(io.StringIO):
                def __init__(self, filename):
                    super().__init__()
                    self.filename = filename

                def __exit__(self, exc_type, exc_value, traceback):
                    self.close()
                    events.append(("close", self.filename))
                    return False

            class StreamPath(PurePosixPath):
                def open(self, mode="r", *, encoding=None, newline=None):
                    test.assertEqual(self.parent, root)
                    test.assertIn(self.name, pair)
                    test.assertNotIn(self.name, streams)
                    test.assertEqual((mode, encoding), ("x", "utf-8"))
                    test.assertEqual(newline, "\n" if self.name == "github-compile-messages.jsonl" else None)
                    events.append(("open", self.name))
                    streams[self.name] = Writer(self.name)
                    return streams[self.name]

            def load(platform, scope):
                test.assertEqual((platform, scope), ("linux", test.SCOPE))
                events.append(("load", name))
                return context

            def predecessors(value, phase):
                test.assertIs(value, context)
                test.assertEqual(phase, name)
                events.append(("predecessors", name))

            def emit(path, value):
                test.assertEqual(path.parent, root)
                test.assertIn(path.name, (f"{name}-started.json", f"{name}-checks.json"))
                test.assertNotIn(path.name, writes)
                expected = test.claim(context, name) if path.name.endswith("-started.json") else test.phase_report(context, name)
                test.assertEqual(value, expected)
                writes[path.name] = deepcopy(value)
                events.append(("write", path.name))

            def source_check(value):
                test.assertIs(value, context)
                events.append(("source", "unchanged"))

            def configuration(paths):
                test.assertEqual(paths, (root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents))
                events.append(("no-config", "fixed"))

            def environment(path):
                test.assertEqual(path, root)
                events.append(("environment", "private"))
                return dict(base_environment)

            def selected_tools(value, env):
                test.assertIs(value, context)
                test.assertIn(name, ("acquire", "compile"))
                test.assertEqual(env, expected_environment)
                events.append(("tools", "fixed"))
                return cargo, rustc

            def execute(argv, *, check, cwd, env, timeout, output=None, diagnostics=None):
                test.assertLess(len(calls), len(expected_runs[name]))
                test.assertEqual((check, argv, timeout), expected_runs[name][len(calls)])
                test.assertEqual(cwd, root)
                test.assertEqual(env, expected_environment)
                calls.append(check)
                events.append(("run", check))
                if check == "rust-toolchain-install":
                    test.assertIsNone(output)
                    test.assertIsNone(diagnostics)
                else:
                    test.assertEqual(set(streams), set(pair))
                    test.assertIs(output, streams[pair[0]])
                    test.assertIs(diagnostics, streams[pair[1]])
                    test.assertFalse(output.closed)
                    test.assertFalse(diagnostics.closed)
                    output.write("supplied inert output DATA\n")
                    diagnostics.write("supplied inert diagnostic DATA\n")
                return ""  # An inert successful outer return, never a native result.

            def compile_record(value, argv, messages):
                test.assertIs(value, context)
                test.assertEqual(name, "compile")
                test.assertEqual(argv, expected_runs["compile"][0][1])
                test.assertEqual(messages, root / "github-compile-messages.jsonl")
                test.assertTrue(all(stream.closed for stream in streams.values()))
                events.append(("compile-record", "original"))
                return dict(original)  # Artifact IO is a supplied capability here.

            def original_artifact(value):
                test.assertIs(value, context)
                events.append(("artifact", "original"))
                return dict(original)

            def native(value):
                test.assertIs(value, context)
                test.assertEqual(name, "github-owner")
                test.assertEqual(calls, ["github-owner-native-contract"])
                test.assertEqual(set(streams), set(pair))
                test.assertTrue(all(stream.closed for stream in streams.values()))
                events.append(("native", "original-receipt"))
                if missing_native:
                    raise helper.CheckFailure("inert original native receipt refused")
                return {"status": "passed"}  # Supplied DATA, not executed evidence.

            with patch.multiple(helper, Path=StreamPath, load_context=load, github_predecessors=predecessors,
                                github_source_unchanged=source_check, no_cargo_configuration=configuration,
                                clean_environment=environment, tools=selected_tools, run=execute,
                                github_compile_record=compile_record, github_original_artifact=original_artifact,
                                github_owner_receipt=native, write_json=emit, read_bounded_json=forbidden,
                                github_inputs_unchanged=forbidden, source_unchanged=forbidden, hash_file=forbidden,
                                ordinary=forbidden, phase_workflow_native=forbidden, clean_compile=forbidden,
                                clean_github_readonly=forbidden, compile_profile=forbidden), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), \
                    patch.object(helper.subprocess, "Popen", side_effect=forbidden), \
                    patch.object(helper.shutil, "which", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), \
                    patch.object(helper.os, "scandir", side_effect=forbidden):
                if missing_native:
                    with test.assertRaises(helper.CheckFailure):
                        helper.phase(name, "linux", test.SCOPE)
                else:
                    helper.phase(name, "linux", test.SCOPE)

            expected_events = [("load", name), ("predecessors", name), ("write", f"{name}-started.json"),
                               ("source", "unchanged"), ("no-config", "fixed"), ("environment", "private")]
            if name == "acquire":
                expected_events.append(("run", "rust-toolchain-install"))
            if name in ("acquire", "compile"):
                expected_events.append(("tools", "fixed"))
            expected_events.extend((("open", pair[0]), ("open", pair[1]), ("run", expected_runs[name][-1][0]),
                                    ("close", pair[1]), ("close", pair[0])))
            if name == "compile":
                expected_events.append(("compile-record", "original"))
            elif name == "github-owner":
                expected_events.append(("native", "original-receipt"))
                test.assertLess(events.index(("artifact", "original")), events.index(("open", pair[0])))
            if not missing_native:
                expected_events.extend((("source", "unchanged"), ("write", f"{name}-checks.json")))
            test.assertEqual([event for event in events if event[0] != "artifact"], expected_events)
            test.assertEqual(calls, [check for check, _, _ in expected_runs[name]])
            test.assertTrue(all(stream.closed for stream in streams.values()))
            test.assertEqual(set(writes), {f"{name}-started.json"} if missing_native else
                             {f"{name}-started.json", f"{name}-checks.json"})
            if name == "acquire":
                test.assertNotIn(("artifact", "original"), events)

        for name in ("acquire", "compile", "github-owner"):
            with self.subTest(phase=name):
                exercise(name)
        exercise("github-owner", missing_native=True)
        self.assertEqual(context, self.context())

        # Exercise the real shared wrapper separately, still with a wholly
        # inert subprocess endpoint. Only the three G1 roles may route stderr
        # into a supplied private writer; the old defaults remain unchanged.
        argv = ["/inert/nonexistent-tool"]
        with io.StringIO() as output, io.StringIO() as diagnostics, io.StringIO() as notices, \
                redirect_stdout(notices), patch.object(helper, "Path", new=forbidden), \
                patch.object(helper.subprocess, "run", return_value=SimpleNamespace(stdout="inert captured DATA\n")) as process, \
                patch.object(helper.subprocess, "Popen", side_effect=forbidden):
            for role in ("github-locked-headless-metadata", "github-headless-test-compile-only", "github-owner-native-contract"):
                with self.subTest(private_diagnostics=role):
                    self.assertEqual(helper.run(argv, check=role, cwd=root, env=base_environment, timeout=1,
                                                output=output, diagnostics=diagnostics), "")
                    process.assert_called_once_with(argv, cwd=root, env=base_environment, check=True, timeout=1,
                                                    text=True, stdout=output, stderr=diagnostics)
                    process.reset_mock()
            self.assertEqual(helper.run(argv, check="headless-test-compile-only", cwd=root, env=base_environment,
                                        timeout=1, output=output), "")
            process.assert_called_once_with(argv, cwd=root, env=base_environment, check=True, timeout=1,
                                            text=True, stdout=output, stderr=None)
            process.reset_mock()
            self.assertEqual(helper.run(argv, check="source-head", cwd=root, env=base_environment,
                                        timeout=1, capture=True), "inert captured DATA")
            process.assert_called_once_with(argv, cwd=root, env=base_environment, check=True, timeout=1,
                                            text=True, stdout=helper.subprocess.PIPE, stderr=None)
            process.reset_mock()
            for keywords in ({"check": "locked-platform-metadata", "output": output, "diagnostics": diagnostics},
                             {"check": "github-owner-native-contract", "diagnostics": diagnostics},
                             {"check": "github-owner-native-contract", "capture": True, "output": output, "diagnostics": diagnostics},
                             {"check": "unknown-role", "output": output, "diagnostics": diagnostics}):
                with self.subTest(refused_diagnostics=keywords["check"]), self.assertRaises(helper.CheckFailure):
                    helper.run(argv, cwd=root, env=base_environment, timeout=1, **keywords)
            process.assert_not_called()

    def test_cleanup_uses_finite_no_follow_plan_and_retains_unknown_names(self):
        context, test, forbidden = self.context(), self, self.forbidden
        root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
        native, outside = root / "github-owner", PurePosixPath("/inert/g1/outside")
        work_names = ("home", "cargo", "rustup", "tmp", "target")
        private_names = ("core.zip", "gitconfig-empty", "cargo-metadata.json", "acquire.stderr",
                         "github-compile-messages.jsonl", "compile.stderr", "github-compiled-test.json",
                         "github-owner.stdout", "github-owner.stderr")
        evidence_names = ("context.json", "public-bindings.json",
                          *(f"{name}-{suffix}.json" for name in self.CHECKS for suffix in ("started", "checks")))
        case_names = (
            "g1-correct", "g1-passive-envelope", "g1-wrong-id", "g1-wrong-protocol",
            "g1-truncated", "g1-extra-frames", "g1-nonzero-exit", "g1-delay-exit",
            "g1-stdout-limit", "g1-stderr-limit", "g1-stalled-input", "g1-mixed-abandon",
            "g1-controlled-inspection", "g1-controlled-acquisition", "g1-controlled-io-join",
            "g1-controlled-management", "g1-controlled-management-late",
            "g1-document-connect-refresh", "g1-document-disconnect-held", "g1-document-registry-change",
            "g1-document-loss", "g1-document-unknown-late", "g1-document-terminal-unknown",
        )
        self.assertEqual(helper.GITHUB_READONLY_DIRECTORIES, (*work_names, "github-owner"))
        self.assertEqual(helper.GITHUB_READONLY_CASES, case_names)

        def exercise(mutation):
            nodes, observations, writes = {}, {}, {}
            events, scans, unlinked, removed_directories, hardlink_removals = [], [], [], [], []
            serial = 100

            def children(path):
                return sorted(child for child in nodes if child.parent == path)

            def changed_parent(path, directory_delta=0):
                parent = nodes.get(path.parent)
                if parent is not None:
                    test.assertEqual(parent["kind"], "directory")
                    parent["info"]["st_mtime_ns"] += 1
                    parent["info"]["st_ctime_ns"] += 1
                    parent["info"]["st_nlink"] += directory_delta

            def add(path, kind="regular", *, data=b"inert payload DATA", target=None, inode=None, nlink=1):
                nonlocal serial
                path = PurePosixPath(path)
                test.assertNotIn(path, nodes)
                serial += 1
                modes = {"directory": stat.S_IFDIR | 0o700, "regular": stat.S_IFREG | 0o600, "link": stat.S_IFLNK | 0o777}
                size = 4096 if kind == "directory" else (len(str(target).encode("utf-8")) if kind == "link" else len(data))
                nodes[path] = {"kind": kind, "data": data, "target": target,
                    "info": {"st_dev": 7, "st_ino": serial if inode is None else inode, "st_mode": modes[kind],
                             "st_uid": 1000, "st_gid": 1000, "st_size": size,
                             "st_nlink": 2 if kind == "directory" else nlink, "st_mtime_ns": 1000, "st_ctime_ns": 2000}}
                changed_parent(path, int(kind == "directory"))

            add(root, "directory")
            add(native, "directory")
            add(source, "directory")
            add(source / "source-canary.bin", data=b"source must never be opened or removed")
            add(outside, "directory")
            add(outside / "file-canary.bin", data=b"external file target must remain")
            add(outside / "tree", "directory")
            add(outside / "tree/inside.bin", data=b"external directory target must remain")
            planned_directories = {root / name for name in work_names} | {native / name for name in case_names}
            planned_directories.add(root / "target/nested")
            planned_leaves = {root / name for name in private_names}
            for directory in sorted(planned_directories, key=lambda path: (len(path.parts), str(path))):
                add(directory, "directory")
                add(directory / "payload.bin")
                planned_leaves.add(directory / "payload.bin")
            for name in private_names:
                add(root / name, data=("inert private " + name).encode("ascii"))
            for name in evidence_names:
                add(root / name, data=("inert original evidence " + name).encode("ascii"))
            add(native / "receipt.json", data=b"inert original native receipt DATA")
            link_targets = {root / "tmp/external-file-link": outside / "file-canary.bin",
                            root / "tmp/external-directory-link": outside / "tree"}
            for path, target in link_targets.items():
                add(path, "link", target=target)
                planned_leaves.add(path)
            aliases = (root / "cargo/original-hardlink", root / "target/original-hardlink")
            add(aliases[0], data=b"inert original hardlink DATA", nlink=2)
            add(aliases[1], data=b"inert original hardlink DATA", inode=nodes[aliases[0]]["info"]["st_ino"], nlink=2)
            planned_leaves.update(aliases)
            if mutation == "unexpected-entry":
                add(root / "unexpected.txt", data=b"unknown top-level DATA")
            initial = deepcopy(nodes)
            protected = {path for path in initial if path != root and root not in path.parents}
            protected.update(root / name for name in evidence_names)
            protected.add(native / "receipt.json")
            inventoried_bytes = sum(initial[path]["info"]["st_size"] for path in planned_leaves)
            expected_receipt = {
                "schemaVersion": 1, "scope": test.EVIDENCE, "phase": "clean", "status": "passed",
                **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha",
                                               "workflowRef", "workflowSha256", "runId", "attempt")},
                "allOriginalOwnersSettled": True, "documentMaterialSettled": True, "observerJoinsComplete": True,
                "removedFiles": len(planned_leaves), "removedDirectories": len(planned_directories),
                "inventoriedBytes": inventoried_bytes,
                "retained": ["redacted-evidence", "private-original-context"], "productionQualified": False,
            }

            def node_at(path):
                path = PurePosixPath(path)
                test.assertTrue(path == root or root in path.parents, "no observation may follow a link outside the private job")
                test.assertIn(path, nodes)
                return nodes[path]

            class FakePath(PurePosixPath):
                # No following metadata, reads, discovery or native IO exists.
                open = stat = is_dir = is_file = read_bytes = read_text = readlink = resolve = glob = rglob = forbidden

                def iterdir(self):
                    path = PurePosixPath(self)
                    test.assertIn(path, (root, native))
                    test.assertEqual(node_at(path)["kind"], "directory")
                    events.append(("iterdir", path))
                    return iter(FakePath(child) for child in children(path))

                def lstat(self):
                    path = PurePosixPath(self)
                    node = node_at(path)
                    observations[path] = observations.get(path, 0) + 1
                    if mutation == "changed-leaf" and path == root / "github-owner.stderr" and observations[path] == 2:
                        node["info"]["st_mtime_ns"] += 1
                    events.append(("lstat", path))
                    return SimpleNamespace(**node["info"])  # Snapshot, not a mutable alias.

                def unlink(self):
                    path = PurePosixPath(self)
                    node = node_at(path)
                    test.assertIn(path, planned_leaves)
                    test.assertIn(node["kind"], ("regular", "link"))
                    test.assertEqual(set(scans), planned_directories)
                    test.assertTrue(planned_leaves <= set(observations))
                    test.assertNotIn(path, unlinked)
                    if path in aliases:
                        hardlink_removals.append((node["info"]["st_nlink"], node["info"]["st_ctime_ns"]))
                    events.append(("unlink", path))
                    unlinked.append(path)
                    device, inode = node["info"]["st_dev"], node["info"]["st_ino"]
                    del nodes[path]
                    changed_parent(path)
                    for survivor in nodes.values():
                        info = survivor["info"]
                        if (info["st_dev"], info["st_ino"]) == (device, inode):
                            info["st_nlink"] -= 1
                            info["st_ctime_ns"] += 1
                    if mutation == "late-entry" and len(unlinked) == 1:
                        add(root / "home/late.txt", data=b"unknown name created after the whole inventory")
                        events.append(("late-entry", root / "home/late.txt"))

                def rmdir(self):
                    path = PurePosixPath(self)
                    test.assertIn(path, planned_directories)
                    test.assertEqual(node_at(path)["kind"], "directory")
                    events.append(("rmdir", path))
                    if children(path):
                        raise OSError("inert directory is not empty; retain new content")
                    del nodes[path]
                    removed_directories.append(path)
                    changed_parent(path, -1)

            class Scan:
                def __init__(self, entries):
                    self.entries = entries

                def __enter__(self):
                    return iter(self.entries)

                def __exit__(self, exc_type, exc_value, traceback):
                    return False

            def scandir(path):
                path = PurePosixPath(path)
                test.assertFalse(unlinked, "inventory must finish before any deletion; no rescan or sweep")
                test.assertIn(path, planned_directories)
                test.assertEqual(node_at(path)["kind"], "directory")
                scans.append(path)
                events.append(("scandir", path))
                return Scan(tuple(SimpleNamespace(name=child.name) for child in children(path)))

            def load(platform, scope):
                test.assertEqual((platform, scope), ("linux", test.SCOPE))
                events.append(("load", "clean"))
                return context

            def predecessors(value, name):
                test.assertIs(value, context)
                test.assertEqual(name, "clean")
                events.append(("predecessors", "clean"))

            def inputs(value):
                test.assertIs(value, context)
                events.append(("inputs", "original"))

            def emit(path, value):
                path = PurePosixPath(path)
                test.assertIn(path, (root / "clean-started.json", root / "clean-checks.json"))
                expected = test.claim(context, "clean") if path.name == "clean-started.json" else expected_receipt
                test.assertEqual(value, expected)
                test.assertNotIn(path.name, writes)
                writes[path.name] = deepcopy(value)
                events.append(("write", path.name))
                add(path, data=b"supplied inert JSON DATA")

            printed = io.StringIO()
            # Original native refusal is exercised by the actual predecessor
            # function in the preceding leaf. Here only that admission and the
            # input observation are supplied; the whole cleanup algorithm runs.
            with redirect_stdout(printed), \
                    patch.multiple(helper, Path=FakePath, load_context=load, github_predecessors=predecessors,
                                   github_inputs_unchanged=inputs, write_json=emit, run=forbidden, tools=forbidden,
                                   github_source_unchanged=forbidden, source_unchanged=forbidden, clean_environment=forbidden,
                                   no_cargo_configuration=forbidden, read_bounded_json=forbidden, hash_file=forbidden,
                                   ordinary=forbidden, phase_workflow_native=forbidden, clean_compile=forbidden), \
                    patch.object(helper.os, "scandir", side_effect=scandir), \
                    patch.object(helper.os, "geteuid", return_value=1000, create=True), \
                    patch.object(helper.os, "unlink", side_effect=forbidden), \
                    patch.object(helper.os, "rmdir", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), \
                    patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if mutation in ("unexpected-entry", "changed-leaf"):
                    with test.assertRaises(helper.CheckFailure):
                        helper.phase("clean", "linux", test.SCOPE)
                elif mutation == "late-entry":
                    with test.assertRaises(OSError):
                        helper.phase("clean", "linux", test.SCOPE)
                else:
                    helper.phase("clean", "linux", test.SCOPE)

            test.assertEqual(events[:4], [("load", "clean"), ("predecessors", "clean"),
                                          ("inputs", "original"), ("write", "clean-started.json")])
            for path in protected:
                test.assertEqual(nodes[path], initial[path])
            test.assertIn(root, nodes)
            test.assertIn(native, nodes)
            test.assertTrue(set(unlinked) <= planned_leaves)
            test.assertTrue(set(removed_directories) <= planned_directories)
            if mutation == "none":
                test.assertCountEqual(scans, planned_directories)
                test.assertCountEqual(unlinked, planned_leaves)
                test.assertCountEqual(removed_directories, planned_directories)
                test.assertEqual(set(nodes), (set(initial) - planned_leaves - planned_directories)
                                 | {root / "clean-started.json", root / "clean-checks.json"})
                test.assertEqual({path.name for path in children(root)},
                                 {"github-owner", *evidence_names, "clean-started.json", "clean-checks.json"})
                test.assertEqual(children(native), [native / "receipt.json"])
                test.assertEqual([links for links, _ in hardlink_removals], [2, 1])
                test.assertGreater(hardlink_removals[1][1], hardlink_removals[0][1])
                test.assertGreater(nodes[root]["info"]["st_mtime_ns"], initial[root]["info"]["st_mtime_ns"])
                test.assertEqual(writes, {"clean-started.json": test.claim(context, "clean"), "clean-checks.json": expected_receipt})
                test.assertEqual(printed.getvalue(),
                    "Removed only positively settled G1 compiler and fixture outputs; original evidence retained.\n")
            else:
                test.assertEqual(set(writes), {"clean-started.json"})
                test.assertNotIn(root / "clean-checks.json", nodes)
                test.assertEqual(printed.getvalue(), "")
                if mutation in ("unexpected-entry", "changed-leaf"):
                    test.assertEqual(unlinked, [])
                    test.assertEqual(removed_directories, [])
                    test.assertEqual(set(nodes), set(initial) | {root / "clean-started.json"})
                    if mutation == "unexpected-entry":
                        test.assertEqual(scans, [])
                        test.assertEqual(nodes[root / "unexpected.txt"], initial[root / "unexpected.txt"])
                    else:
                        test.assertCountEqual(scans, planned_directories)
                        test.assertEqual(observations[root / "github-owner.stderr"], 2)
                else:
                    test.assertTrue(unlinked)
                    test.assertCountEqual(scans, planned_directories)
                    test.assertIn(root / "home/late.txt", nodes)
                    test.assertIn(root / "home", nodes)
                    test.assertNotIn(root / "home/late.txt", unlinked)
                    test.assertEqual(events[-1], ("rmdir", root / "home"))

        for mutation in ("none", "unexpected-entry", "changed-leaf", "late-entry"):
            with self.subTest(cleanup=mutation):
                exercise(mutation)


# Independent supplied TLS DATA. These builders are not native execution,
# certificate verification, a runtime probe or evidence that a peer ever ran.
TLS_CASE_ROWS = (
    ("T1-source", 4, "none", "source", "root-ca.pem", False, 4),
    ("T1-zip", 5, "none", "zip", "root-ca.pem", False, 5),
    ("T2-root", 1, "tls-failed", "source", "other-root-ca.pem", True, 0),
    ("T2-name", 1, "tls-failed", "source", "root-ca.pem", True, 0),
    ("T2-expired", 1, "tls-failed", "source", "root-ca.pem", True, 0),
    ("T3-clean", 4, "none", "source", "root-ca.pem", False, 4),
    ("T3-ragged", 1, "tls-failed", "source", "root-ca.pem", False, 0),
    ("T3-length", 1, "response-invalid", "source", "root-ca.pem", False, 1),
    ("T3-chunk", 1, "response-invalid", "source", "root-ca.pem", False, 1),
)
TLS_NOT_VERIFIED = [
    "T4-destination-ambient-environment", "T5-real-network-deadlines", "T6-streaming-controls",
    "CA-file-native-faults", "real-github-authentication", "production-runtime-custody",
    "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement",
]


def github_tls_binding_data() -> dict:
    return {"sourceSha": "1" * 40, "sourceTree": "3" * 40, "workflowSha256": "4" * 64,
            "runId": "123", "attempt": "2", "tlsInputsSha256": "9" * 64,
            "artifactSha256": "a" * 64, "artifactBytes": 144, "coreZipSha256": "7" * 64,
            "pythonSha256": "8" * 64,
            "namespace": {"parentNetns": "net:[100]", "parentMntns": "mnt:[200]", "uid": 1000, "gid": 1000}}


def github_tls_report_data() -> dict:
    cases = []
    for name, connections, reason, mode, trust, refused, notify in TLS_CASE_ROWS:
        native = {**dict.fromkeys(("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
            "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined",
            "driver_joined", "watchdog_joined"), True), "stdout_bytes": 1024, "stderr_bytes": 0}
        terminal = {"schemaVersion": 1, "scope": "github-tls-peer-v1", "case": name, "state": "finished",
            "status": "passed", "code": None, "connections": connections, "handshakes": 0 if refused else connections,
            "requests": 0 if refused else connections, "decryptedBytes": 0 if refused else connections * 128,
            "authBytes": 0 if refused else connections * len(b"Bearer INERT_NOT_A_CREDENTIAL"), "closeNotify": notify,
            "tlsRefused": refused, "wireReadBytes": [1024] * connections, "wireWriteBytes": [2048] * connections,
            "replyBytes": [0 if refused else 512] * connections, "allSocketsClosed": True}
        peer = {**dict.fromkeys(("acquisitionJoined", "spawned", "waited", "exitSuccess", "stdoutJoined", "stderrJoined",
                    "stdoutEof", "stderrEof", "ready", "settled", "withinEndpoint", "protocolChecked"), True),
                "exitCode": 0, "stopAttempted": False, "stdoutOverflow": False, "stderrOverflow": False,
                "stdoutBytes": 1024, "stderrBytes": 0, "terminal": terminal}
        cases.append({"case": name, "passed": True, "failureCode": None, "elapsedMs": 100,
            "coreMode": mode, "trustFixture": trust,
            "product": {"settled": True, "projectionChecked": True, "reason": reason, "registeredOwners": 0,
                "disabled": False, "owners": [{"id": "github-read-1", "profile": "github-readonly", "terminal": True,
                    "unknownLatched": False, "permitRetained": False, "observerJoined": True,
                    "firstError": None, "native": native}]}, "peer": peer})
    bindings = github_tls_binding_data()
    bindings["namespace"].update(netns="net:[101]", mntns="mnt:[201]")
    return {"schemaVersion": 1, "scope": "github-readonly-tls-hosted-v1", "status": "passed", "allOwnersSettled": True,
            "allPeersSettled": True, "failureCode": None, "bindings": bindings, "cases": cases,
            "outerWait": "external-original-observer-required", "notVerified": list(TLS_NOT_VERIFIED)}


class GitHubTLSReceiptContractTests(unittest.TestCase):
    def reject_at(self, path, replacement):
        report = github_tls_report_data()
        target = report
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        with self.subTest(path=path, value=replacement), self.assertRaises(helper.CheckFailure):
            helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data())

    def test_tls_supplied_nine_case_data_is_not_execution_or_outer_finality(self):
        report = github_tls_report_data()
        self.assertEqual(tuple(row[0] for row in TLS_CASE_ROWS), helper.GITHUB_TLS_CASES)
        self.assertEqual(TLS_NOT_VERIFIED, list(helper.GITHUB_TLS_NOT_VERIFIED))
        self.assertIs(report, helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data()))
        raw = json.dumps(report, separators=(",", ":")).encode("utf-8")
        self.assertEqual(report, helper.parse_github_tls_receipt(raw, bindings=github_tls_binding_data()))
        self.assertNotIn("outer", report)
        for foreign in (github_readonly_report_data(), native_report(), {**report, "outerWait": True}):
            with self.subTest(foreign_scope=foreign.get("scope")), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(foreign, bindings=github_tls_binding_data())
        with self.assertRaises(helper.CheckFailure):
            validate_github_readonly_data(report)

    def test_tls_closed_headers_inputs_and_distinct_original_namespaces(self):
        report = github_tls_report_data()
        for key, value in (("schemaVersion", True), ("scope", "github-readonly-native-v1"), ("status", "failed-retained"),
                ("allOwnersSettled", False), ("allPeersSettled", 1), ("failureCode", "tls_custody_unresolved"),
                ("outerWait", "passed"), ("extra", True), ("cases", report["cases"][:-1]),
                ("cases", report["cases"] + report["cases"][:1]), ("cases", list(reversed(report["cases"]))),
                ("cases", [report["cases"][0]] * 9), ("notVerified", TLS_NOT_VERIFIED[:-1])):
            self.reject_at((key,), value)
        for key in report:
            bad = deepcopy(report); del bad[key]
            with self.subTest(missing=key), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(bad, bindings=github_tls_binding_data())
        for key in github_tls_binding_data().keys() - {"namespace"}:
            value = 145 if key == "artifactBytes" else "5" if key in {"runId", "attempt"} else "f" * len(report["bindings"][key])
            self.reject_at(("bindings", key), value)
        for key, value in (("netns", "net:[100]"), ("mntns", "mnt:[200]"), ("netns", "mnt:[101]"),
                ("parentNetns", "net:[999]"), ("parentMntns", "mnt:[999]"), ("uid", 0), ("gid", True),
                ("uid", 1001), ("netns", "net:[0]"), ("netns", "net:[001]"), ("extra", True)):
            self.reject_at(("bindings", "namespace", key), value)
        expected = github_tls_binding_data()
        for key, value in (("sourceSha", "0" * 40), ("sourceTree", "A" * 40), ("runId", 123), ("attempt", "0"),
                ("artifactBytes", True), ("artifactBytes", 512 * 1024 * 1024 + 1), ("workflowSha256", "bad")):
            with self.subTest(expected_binding=key), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(report, bindings={**expected, key: value})

    def test_tls_every_original_product_and_peer_join_is_required(self):
        report = github_tls_report_data()
        # Generic schema/join predicates are shared: mutate one representative,
        # not a nine-case Cartesian replay of the same structural validator.
        for index, case in enumerate(report["cases"][:1]):
            for key in ("settled", "projectionChecked"):
                for value in (False, 1, None):
                    self.reject_at(("cases", index, "product", key), value)
            for key, value in (("registeredOwners", 1), ("registeredOwners", False), ("disabled", True),
                    ("owners", []), ("owners", case["product"]["owners"] * 2), ("extra", True)):
                self.reject_at(("cases", index, "product", key), value)
            owner = case["product"]["owners"][0]
            for key, value in (("id", "github-read-2"), ("profile", "passive"), ("terminal", False),
                    ("unknownLatched", True), ("permitRetained", True), ("observerJoined", False),
                    ("firstError", "engine_failed"), ("extra", True)):
                self.reject_at(("cases", index, "product", "owners", 0, key), value)
            for key, value in owner["native"].items():
                for bad in ((False, 1, None) if type(value) is bool else (-1, True, 65537) if key == "stdout_bytes" else (1, False)):
                    self.reject_at(("cases", index, "product", "owners", 0, "native", key), bad)
            for key, value in case["peer"].items():
                if type(value) is bool:
                    for bad in (not value, int(value), None):
                        self.reject_at(("cases", index, "peer", key), bad)
            for key, value in (("exitCode", 1), ("exitCode", None), ("exitCode", False), ("stdoutBytes", 0),
                    ("stdoutBytes", 8193), ("stdoutBytes", True), ("stderrBytes", 1), ("extra", True)):
                self.reject_at(("cases", index, "peer", key), value)
            self.reject_at(("cases", index, "product", "owners", 0, "native", "extra"), True)
        for index in range(1, len(report["cases"])):
            self.reject_at(("cases", index, "product", "owners", 0, "native", "exit_success"), False)
            self.reject_at(("cases", index, "peer", "waited"), False)

    def test_tls_auth_refusal_eof_framing_and_typed_projection_are_case_specific(self):
        for key, value in (("case", "g1-correct"), ("passed", False), ("passed", 1), ("failureCode", "tls_failed"),
                          ("elapsedMs", -1), ("elapsedMs", True), ("elapsedMs", 300001), ("extra", True)):
            self.reject_at(("cases", 0, key), value)
        for key, value in (("schemaVersion", True), ("scope", "github-readonly-tls-hosted-v1"), ("case", "T4"),
                ("state", "ready"), ("status", "failed"), ("code", "peer_failed"), ("allSocketsClosed", False), ("extra", True)):
            self.reject_at(("cases", 0, "peer", "terminal", key), value)
        for index, (name, connections, reason, mode, trust, refused, notify) in enumerate(TLS_CASE_ROWS):
            for key, value in (("coreMode", "zip" if mode == "source" else "source"),
                    ("trustFixture", "root-ca.pem" if trust == "other-root-ca.pem" else "other-root-ca.pem")):
                self.reject_at(("cases", index, key), value)
            self.reject_at(("cases", index, "product", "reason"), "none" if reason != "none" else "tls-failed")
            for key, value in (("connections", connections + 1),
                    ("handshakes", 1 if refused else 0), ("requests", 1 if refused else 0), ("tlsRefused", not refused),
                    ("authBytes", 1 if refused else 0), ("decryptedBytes", 1 if refused else connections * 8192 + 1),
                    ("closeNotify", 1 if notify == 0 else 0)):
                self.reject_at(("cases", index, "peer", "terminal", key), value)
            if index in (0, 2):  # One successful and one pre-HTTP-refusal vector shape.
                for key, limit in (("wireReadBytes", 131072), ("wireWriteBytes", 131072), ("replyBytes", 65536)):
                    for vector in ([], [1] * (connections + 1), [True] * connections, [-1] * connections,
                            [limit + 1] * connections, [1 if refused and key == "replyBytes" else 0] * connections):
                        self.reject_at(("cases", index, "peer", "terminal", key), vector)

    def test_tls_raw_receipt_duplicate_scalar_depth_size_and_encoding_bounds(self):
        raw = json.dumps(github_tls_report_data(), separators=(",", ":")).encode("utf-8")
        invalid = (b"", bytearray(raw), raw.decode("utf-8"), raw[:-1], raw + b"{}", b"\xff", b"x" * 131073,
                   raw.replace(b'"passed":true', b'"passed":true,"passed":true', 1),
                   raw.replace(b'"elapsedMs":100', b'"elapsedMs":1.0', 1),
                   raw.replace(b'"elapsedMs":100', b'"elapsedMs":NaN', 1),
                   b'{"nested":' + b'[' * 17 + b'0' + b']' * 17 + b'}')
        for index, value in enumerate(invalid):
            with self.subTest(raw=index), self.assertRaises(helper.CheckFailure):
                helper.parse_github_tls_receipt(value, bindings=github_tls_binding_data())


class GitHubTLSCIIntegrationTests(unittest.TestCase):
    """Actual CI control algorithms over supplied, finite inert capabilities."""

    SCOPE = "github-readonly-tls-native-v1"
    EVIDENCE = "desktop-github-readonly-tls-native-only-v1"
    WORKFLOW = ".github/workflows/desktop-github-connection-tls.yml"
    REF = "refs/heads/verify/desktop-github-connection-tls"
    PHASES = ("prepare", "acquire", "compile", "github-tls", "clean")
    CHECKS = {
        "acquire": ("rust-toolchain-install", "rust-version-target", "github-tls-locked-headless-metadata"),
        "compile": ("rust-version-target", "github-tls-headless-test-compile-only", "github-tls-compiled-artifact"),
        "github-tls": ("github-tls-original-artifact", "github-tls-original-outer-wait", "github-tls-receipt"),
    }
    CERTIFICATES = ("root-ca.pem", "other-root-ca.pem", "api-valid.pem", "wrong-san.pem", "api-expired.pem", "server-key.pem")
    TOOLS = {**{name: "/usr/bin/" + name for name in (
        "sudo", "unshare", "env", "bash", "mount", "setpriv", "readlink", "findmnt", "stat", "sha256sum", "ip")},
        "sysctl": "/usr/sbin/sysctl"}
    CONFIG = {"hosts": b"127.0.0.1 api.github.com localhost\n::1 localhost\n",
        "resolv.conf": b"# Synthetic namespace: DNS is disabled by hosts: files.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
        "nsswitch.conf": b"passwd: files\ngroup: files\nhosts: files\n"}

    @staticmethod
    def forbidden(*args, **kwargs):
        raise AssertionError("TLS inert contract requested an unprovided IO/tool/runtime capability")

    @staticmethod
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")

    @classmethod
    def environment(cls):
        return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
                "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": cls.REF,
                "GITHUB_WORKFLOW_REF": f"fictional/project/{cls.WORKFLOW}@{cls.REF}",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}

    @classmethod
    def context(cls):
        context = {"executionScope": cls.SCOPE, "platform": "linux", "root": "/inert/tls/mrk-desktop-foundation-github-tls-123-2",
            "source": "/inert/tls/source", "python": "/inert/tls/python/bin/python3.14",
            "git": "/inert/tls/git", "rustup": "/inert/tls/rustup", "sourceSha": "1" * 40, "sourceTree": "3" * 40,
            "workflowSha": "1" * 40, "workflowPath": cls.WORKFLOW, "workflowRef": cls.environment()["GITHUB_WORKFLOW_REF"],
            "workflowSha256": "4" * 64, "runId": "123", "attempt": "2", "tlsInputsSha256": "9" * 64,
            "originalDirectories": {"inert": "original identities supplied separately"},
            "observedHost": {"kernelRelease": "inert-6.8", "machine": "x86_64", "nonRoot": True,
                "filesystem": {"device": "7", "blockSize": 4096, "fragmentSize": 4096, "nameMax": 255, "flags": 0}}}
        context["tlsInputs"] = cls.input_summary(context, cls.manifest(context))
        return context

    @classmethod
    def manifest(cls, context):
        source, root = PurePosixPath(context["source"]), PurePosixPath(context["root"])
        fixtures = source / "desktop/src-tauri/tests/fixtures"
        library = PurePosixPath(context["python"]).parent.parent / "lib/python3.14"
        roles = {"python": context["python"], "bootstrap": str(source / "desktop/github_connection_bootstrap.py"),
            "coreZip": str(root / "core.zip"), "peer": str(fixtures / "github_tls_peer.py"),
            "namespace": str(fixtures / "github_tls_namespace.sh"),
            **{name: str(fixtures / "github_tls" / name) for name in cls.CERTIFICATES},
            **{name: str(root / "github-tls-namespace" / name) for name in cls.CONFIG},
            **{"tool:" + name: path for name, path in cls.TOOLS.items()},
            "ssl": str(library / "ssl.py"), "socket": str(library / "socket.py"),
            "_ssl": str(library / "lib-dynload/_ssl.cpython-314-x86_64-linux-gnu.so"),
            "_socket": str(library / "lib-dynload/_socket.cpython-314-x86_64-linux-gnu.so"),
            "libssl": "/inert/tls/lib/libssl.so.3", "libcrypto": "/inert/tls/lib/libcrypto.so.3",
            "loader": "/inert/tls/lib/ld-linux-x86-64.so.2"}
        names = {*roles.values(), *(str(source / name) for name in helper.GITHUB_TLS_SOURCES),
                 *(str(source / "src" / name) for name in helper.GTK_CORE_PATHS)}
        hashes = {roles["python"]: "8" * 64, roles["coreZip"]: "7" * 64, str(source / cls.WORKFLOW): "4" * 64}
        files = [{"path": name, "size": 16 if name == roles["python"] else 32, "sha256": hashes.get(name, "5" * 64)}
                 for name in sorted(names)]
        return {"schemaVersion": 1, "scope": cls.SCOPE,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
            "sourceRoot": str(source), "jobRoot": str(root), "python": context["python"],
            "coreSource": str(source / "src"), "coreZip": str(root / "core.zip"), "uid": 1000, "gid": 1000,
            "parentNetns": "net:[100]", "parentMntns": "mnt:[200]",
            "ssl": {"opensslVersion": "OpenSSL 3.0.0 inert supplied DATA", "ignoreUnexpectedEof": 128}, "roles": roles, "files": files}

    @classmethod
    def input_summary(cls, context, manifest):
        source = PurePosixPath(context["source"])
        by_path = {row["path"]: row for row in manifest["files"]}
        def row(path, name):
            return {"path": name, "size": by_path[str(path)]["size"], "sha256": by_path[str(path)]["sha256"]}
        return {"sourceFiles": [row(source / name, name) for name in helper.GITHUB_TLS_SOURCES],
            "coreFiles": [row(source / "src" / name, name) for name in helper.GTK_CORE_PATHS],
            "coreZipSha256": by_path[manifest["coreZip"]]["sha256"], "pythonSha256": by_path[manifest["python"]]["sha256"],
            "pythonBytes": by_path[manifest["python"]]["size"], "closureFiles": len(by_path),
            "closureBytes": sum(item["size"] for item in by_path.values()),
            "closureSha256": hashlib.sha256(cls.encoded(manifest["files"])).hexdigest(), "ssl": manifest["ssl"],
            "roles": {name: {key: by_path[path][key] for key in ("size", "sha256")} for name, path in manifest["roles"].items()}}

    @classmethod
    def artifact(cls):
        return {"schemaVersion": 1, "scope": cls.SCOPE, "sourceSha": "1" * 40, "sourceTree": "3" * 40,
            "tlsInputsSha256": "9" * 64,
            "path": "/inert/tls/mrk-desktop-foundation-github-tls-123-2/target/x86_64-unknown-linux-gnu/debug/deps/mobile_release_desktop-0123456789abcdef",
            "size": 144, "sha256": "a" * 64, "invocationSha256": "b" * 64, "messagesSha256": "c" * 64,
            "identity": {"device": "7", "inode": "88", "mode": stat.S_IFREG | 0o700, "uid": 1000, "gid": 1000,
                         "size": 144, "mtimeNs": 1000000}}

    @classmethod
    def compiled_public(cls):
        value = cls.artifact()
        return {**{key: value[key] for key in ("size", "sha256", "invocationSha256", "messagesSha256")},
                "identitySha256": hashlib.sha256(cls.encoded(value["identity"])).hexdigest()}

    @classmethod
    def outer(cls, context):
        return {"schemaVersion": 1, "scope": "github-readonly-tls-original-outer-v1",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256")},
            "artifactSha256": "a" * 64, "artifactBytes": 144,
            "artifactIdentitySha256": hashlib.sha256(cls.encoded(cls.artifact()["identity"])).hexdigest(),
            "status": "passed", "waitObserved": True, "exitCode": 0, "timedOut": False,
            "elapsedMs": 125, "stdoutBytes": 256, "stderrBytes": 0}

    @classmethod
    def claim(cls, context, name):
        return {"scope": cls.SCOPE, "phase": name,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256")}}

    @classmethod
    def phase_report(cls, context, name):
        value = {"schemaVersion": 1, "scope": cls.EVIDENCE, "phase": name, "status": "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "tlsInputsSha256")},
            "inputSha256": hashlib.sha256(cls.encoded(context["tlsInputs"])).hexdigest(),
            "rust": {"release": helper.RUST, "target": "x86_64-unknown-linux-gnu"},
            "checks": [{"check": check, "exitCode": 0} for check in cls.CHECKS[name]]}
        if name in ("compile", "github-tls"):
            value["compiledTest"] = cls.compiled_public()
        if name == "github-tls":
            value.update(nativeReceiptSha256="d" * 64, outer=cls.outer(context))
        return value

    def test_tls_fixed_scope_binding_refuses_owner23_and_other_lanes_before_io(self):
        environment, forbidden = self.environment(), self.forbidden
        self.assertEqual((helper.GITHUB_TLS_SCOPE, helper.GITHUB_TLS_EVIDENCE_SCOPE, helper.GITHUB_TLS_WORKFLOW,
                          helper.GITHUB_TLS_REF, helper.GITHUB_TLS_PHASES, helper.GITHUB_TLS_CHECKS),
                         (self.SCOPE, self.EVIDENCE, self.WORKFLOW, self.REF, self.PHASES, self.CHECKS))
        expected = {"workflowPath": self.WORKFLOW, "workflowSha": "1" * 40, "workflowRef": environment["GITHUB_WORKFLOW_REF"],
                    "sourceSha": "1" * 40, "runId": "123", "attempt": "2"}
        with patch.multiple(helper, Path=forbidden, load_context=forbidden, tools=forbidden, run=forbidden,
                read_bounded_json=forbidden, hash_file=forbidden, write_json=forbidden, clean_environment=forbidden,
                phase_github_readonly=forbidden, phase_workflow_native=forbidden, phase_github_tls=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden):
            self.assertEqual(helper.github_tls_binding(environment), expected)
            for key, value in (("GITHUB_REF", helper.GITHUB_READONLY_REF), ("GITHUB_REF", "refs/heads/main"),
                    ("GITHUB_SHA", "0" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40), ("GITHUB_REPOSITORY", "another/project"),
                    ("GITHUB_WORKFLOW_REF", "fictional/project/other.yml@main"), ("GITHUB_RUN_ID", "0"),
                    ("GITHUB_RUN_ATTEMPT", "02"), ("GITHUB_EVENT_NAME", "pull_request")):
                with self.subTest(binding=key), self.assertRaises(helper.CheckFailure):
                    helper.github_tls_binding({**environment, key: value})
            dispatch = {**environment, "GITHUB_EVENT_NAME": "workflow_dispatch"}
            for sha in (None, "main", "2" * 40):
                with self.subTest(dispatch=sha), self.assertRaises(helper.CheckFailure):
                    helper.github_tls_binding({**dispatch, "MRK_EXPECTED_SHA": sha})
            self.assertEqual(helper.github_tls_binding({**dispatch, "MRK_EXPECTED_SHA": "1" * 40}), expected)
            for binding in (helper.github_readonly_binding, helper.workflow_native_binding, helper.compile_workflow_binding):
                with self.subTest(foreign_binding=binding.__name__), self.assertRaises(helper.CheckFailure):
                    binding(environment)
            with self.assertRaises(helper.CheckFailure):
                helper.github_tls_binding(GitHubReadonlyCIIntegrationTests.environment())
            for name in self.PHASES:
                helper.admit_phase(self.SCOPE, name)
            for name in ("native", "github-owner", "workflow-owner", "workflow-core", "windows-snapshot", "config-owner", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", self.SCOPE)
            for scope in (helper.GITHUB_READONLY_SCOPE, helper.BOUNDARY_SCOPE, helper.WORKFLOW_NATIVE_SCOPE,
                          helper.WINDOWS_SNAPSHOT_SCOPE, *helper.COMPILE_PROFILES):
                with self.subTest(scope=scope), self.assertRaises(helper.CheckFailure):
                    helper.phase("github-tls", "linux", scope)
            for platform in ("windows", "macos", "other"):
                with self.subTest(platform=platform), self.assertRaises(helper.CheckFailure):
                    helper.prepare(platform, self.SCOPE)
                with self.subTest(native_platform=platform), self.assertRaises(helper.CheckFailure):
                    helper.phase("github-tls", platform, self.SCOPE)

    def test_tls_manifest_roles_source_ca_ssl_and_file_bounds_are_closed_data(self):
        context, forbidden = self.context(), self.forbidden
        manifest = self.manifest(context)
        self.assertEqual(helper.GITHUB_TLS_CERTIFICATES, self.CERTIFICATES)
        self.assertEqual(helper.GITHUB_TLS_TOOLS, self.TOOLS)
        self.assertEqual(helper.GITHUB_TLS_CONFIG, self.CONFIG)
        self.assertEqual(set(helper.GITHUB_TLS_SOURCES) - set(helper.GITHUB_READONLY_SOURCES), {
            self.WORKFLOW, "desktop/src-tauri/tests/fixtures/github_tls_peer.py",
            "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh",
            *("desktop/src-tauri/tests/fixtures/github_tls/" + name for name in self.CERTIFICATES)})
        mutations = []
        for key, value in (("scope", helper.GITHUB_READONLY_SCOPE), ("schemaVersion", True), ("uid", 0), ("gid", True),
                ("gid", 2**32), ("parentNetns", "net:[0]"), ("parentMntns", "net:[200]"), ("python", "/another/python"),
                ("coreSource", "/another/source"), ("workflowSha256", "f" * 64), ("tlsInputsSha256", "9" * 64)):
            mutations.append({**deepcopy(manifest), key: value})
        for key, value in (("ignoreUnexpectedEof", 0), ("ignoreUnexpectedEof", True), ("ignoreUnexpectedEof", 2**64),
                ("opensslVersion", "unknown"), ("opensslVersion", "OpenSSL \nprivate"), ("extra", True)):
            bad = deepcopy(manifest); bad["ssl"][key] = value; mutations.append(bad)
        for role in manifest["roles"]:
            bad = deepcopy(manifest); del bad["roles"][role]; mutations.append(bad)
            bad = deepcopy(manifest); bad["roles"][role] = manifest["roles"]["bootstrap"]; mutations.append(bad)
            if role == "bootstrap":
                mutations.pop()  # A genuine unchanged value is not a refusal test.
        for key, value in (("size", True), ("size", -1), ("size", 64 * 1024 * 1024 + 1), ("sha256", "A" * 64),
                ("path", "relative/input.py"), ("path", "/inert//input.py"), ("path", "/inert/../input.py"),
                ("path", "/inert/./input.py"), ("path", "/inert/input\0.py"), ("path", "/inert/input\\file.py"), ("extra", True)):
            bad = deepcopy(manifest); bad["files"][0][key] = value; mutations.append(bad)
        for files in (manifest["files"][:-1], manifest["files"] + manifest["files"][:1], list(reversed(manifest["files"])),
                      [{**row, "size": 64 * 1024 * 1024} for row in manifest["files"]]):
            mutations.append({**deepcopy(manifest), "files": files})
        for name in (*self.CERTIFICATES, "python", "coreZip"):
            bad = deepcopy(manifest)
            next(row for row in bad["files"] if row["path"] == manifest["roles"][name])["size"] = 0
            mutations.append(bad)
        with patch.multiple(helper, Path=PurePosixPath, github_tls_runtime=forbidden, github_tls_file=forbidden,
                ordinary=forbidden, hash_file=forbidden, read_bounded_json=forbidden, run=forbidden, tools=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            self.assertIs(manifest, helper.validate_github_tls_manifest(manifest, context=context))
            self.assertEqual(helper.github_tls_input_summary(context, manifest), context["tlsInputs"])
            for index, value in enumerate(mutations):
                with self.subTest(manifest_mutation=index), self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_manifest(value, context=context)

    def test_tls_frozen_import_roster_and_bytes_recheck_without_ssl_or_tools(self):
        context, forbidden, test = self.context(), self.forbidden, self
        manifest = self.manifest(context)
        library = PurePosixPath(manifest["roles"]["ssl"]).parent
        expected = {PurePosixPath(row["path"]) for row in manifest["files"] if library in PurePosixPath(row["path"]).parents}
        rows = {row["path"]: row for row in manifest["files"]}

        def exercise(mutation):
            events = []
            def record(path):
                events.append(("file", str(path)))
                value = dict(rows[str(path)])
                if mutation == "bytes" and str(path) == manifest["roles"]["server-key.pem"]:
                    value["sha256"] = "f" * 64
                return value
            def roster(path):
                test.assertEqual(path, library)
                events.append(("roster", str(path)))
                return expected | {library / "__pycache__/ssl.cpython-314.pyc"} if mutation == "added-cache" else set(expected)
            with patch.multiple(helper, Path=PurePosixPath, github_tls_runtime=forbidden, github_tls_file=record,
                    github_tls_stdlib_files=roster, run=forbidden, tools=forbidden, ordinary=forbidden,
                    source_unchanged=forbidden, write_json=forbidden), \
                    patch.object(helper, "github_tls_directories", return_value=context["originalDirectories"]), \
                    patch.object(helper, "hash_file", return_value="f" * 64 if mutation == "anchor" else "9" * 64), \
                    patch.object(helper, "read_bounded_json", return_value=deepcopy(manifest)), \
                    patch.object(helper, "github_tls_namespaces", return_value={"parentNetns": "net:[999]" if mutation == "namespace" else "net:[100]", "parentMntns": "mnt:[200]"}), \
                    patch.object(helper.os, "geteuid", return_value=1000, create=True), \
                    patch.object(helper.os, "getegid", return_value=1000, create=True), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if mutation:
                    with test.assertRaises(helper.CheckFailure):
                        helper.github_tls_inputs_unchanged(context)
                else:
                    helper.github_tls_inputs_unchanged(context)
            if mutation in ("anchor", "namespace"):
                test.assertEqual(events, [])
            elif mutation == "added-cache":
                test.assertEqual(events, [("roster", str(library))])
            else:
                test.assertEqual(events, [("roster", str(library)), *(("file", row["path"]) for row in manifest["files"])])

        for mutation in (None, "anchor", "namespace", "added-cache", "bytes"):
            with self.subTest(freeze=mutation):
                exercise(mutation)

        class RosterPath(PurePosixPath):
            def resolve(self, *, strict=False):
                test.assertTrue(strict)
                return self
            def is_dir(self):
                return self == library
            def is_symlink(self):
                return False
        walk = [(str(library), ["lib-dynload", "__pycache__", "site-packages"], ["ssl.py", "socket.py", "README"]),
                (str(library / "lib-dynload"), [], ["_ssl.cpython-314-x86_64-linux-gnu.so", "_socket.cpython-314-x86_64-linux-gnu.so"]),
                (str(library / "__pycache__"), [], ["ssl.cpython-314.pyc", "ssl.cpython-314.opt-1.pyc", "ssl.cpython-314.opt-2.pyc"])]
        with patch.multiple(helper, Path=RosterPath, run=forbidden, tools=forbidden, github_tls_runtime=forbidden), \
                patch.object(helper.os, "walk", return_value=iter(walk)) as walking, \
                patch.object(helper.os.path, "lexists", return_value=False), \
                patch.object(helper.subprocess, "run", side_effect=forbidden):
            self.assertEqual(helper.github_tls_stdlib_files(RosterPath(library)), expected | {library / "__pycache__/ssl.cpython-314.pyc"})
            walking.assert_called_once_with(RosterPath(library), followlinks=False)
            self.assertNotIn("site-packages", walk[0][1])
        for too_many in ([(str(library), [], ["README"] * 8193)], [(str(library / ("deep/" * 17)), [], ["ssl.py"])]):
            with patch.object(helper, "Path", RosterPath), patch.object(helper.os.path, "lexists", return_value=False), \
                    patch.object(helper.os, "walk", return_value=iter(too_many)), self.assertRaises(helper.CheckFailure):
                helper.github_tls_stdlib_files(RosterPath(library))

    def test_tls_compile_record_and_launch_bind_original_artifact_and_input_anchor(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
        cargo_row = {"reason": "compiler-artifact", "executable": compiled["path"],
            "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
            "target": {"kind": ["lib"], "name": "mobile_release_desktop", "src_path": str(source / "desktop/src-tauri/src/lib.rs")},
            "profile": {"test": True, "debug_assertions": True}, "features": ["development-runtime"], "fresh": False}
        raw = self.encoded(cargo_row) + b"\n" + self.encoded({"reason": "build-finished", "success": True}) + b"\n"
        argv = ["/inert/tls/cargo", "test", "--lib", "--no-run", "--message-format=json"]
        writes, observations = {}, []
        class MessagePath(PurePosixPath):
            def stat(self):
                test.assertEqual(self, root / "github-tls-compile-messages.jsonl")
                return SimpleNamespace(st_size=len(raw))
            def open(self, mode):
                test.assertEqual((self, mode), (root / "github-tls-compile-messages.jsonl", "rb"))
                return io.BytesIO(raw)
        def identity(path, job):
            test.assertEqual((path, job), (PurePosixPath(compiled["path"]), root))
            observations.append("original-artifact")
            return {key: deepcopy(compiled[key]) for key in ("identity", "size", "sha256")}
        def emit(path, value):
            test.assertEqual(path, root / "github-tls-compiled-test.json")
            test.assertFalse(writes)
            writes.update(value)
        with patch.multiple(helper, Path=MessagePath, github_artifact_identity=identity, write_json=emit,
                ordinary=lambda path: observations.append("ordinary-message"), run=forbidden, tools=forbidden,
                hash_file=forbidden, read_bounded_json=forbidden), patch.object(helper.subprocess, "run", side_effect=forbidden):
            result = helper.github_tls_compile_record(context, argv, MessagePath(root / "github-tls-compile-messages.jsonl"))
        expected = {**compiled, "messagesSha256": hashlib.sha256(raw).hexdigest(), "invocationSha256": hashlib.sha256(self.encoded(argv)).hexdigest()}
        self.assertEqual(result, expected)
        self.assertEqual(writes, expected)
        self.assertEqual(observations, ["ordinary-message", "original-artifact"])

        for mutation in (None, ("scope", helper.GITHUB_READONLY_SCOPE), ("sourceTree", "f" * 40),
                ("tlsInputsSha256", "f" * 64), ("schemaVersion", True), ("size", 145), ("sha256", "e" * 64),
                ("path", compiled["path"].replace("debug/deps", "release/deps")), ("identity", {**compiled["identity"], "inode": "89"})):
            value = deepcopy(expected)
            if mutation:
                value[mutation[0]] = mutation[1]
            with self.subTest(original=mutation), patch.multiple(helper, Path=PurePosixPath, github_artifact_identity=identity,
                    run=forbidden, tools=forbidden, hash_file=forbidden, ordinary=forbidden), \
                    patch.object(helper, "read_bounded_json", return_value=value):
                if mutation:
                    with self.assertRaises(helper.CheckFailure):
                        helper.github_tls_original_artifact(context)
                else:
                    self.assertEqual(helper.github_tls_original_artifact(context), expected)
        manifest = self.manifest(context)
        with patch.object(helper, "Path", PurePosixPath):
            self.assertEqual(helper.github_tls_expected_bindings(context, compiled, manifest), github_tls_binding_data())
            launch = helper.github_tls_launch_argv(context, compiled, manifest)
        self.assertEqual(launch, ["/usr/bin/sudo", "-n", "--", "/usr/bin/unshare", "--mount", "--net", "--",
            "/usr/bin/env", "-i", "LANG=C", "LC_ALL=C", "/usr/bin/bash", "--noprofile", "--norc",
            str(source / "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh"),
            context["source"], context["root"], compiled["path"], context["python"], "1000", "1000", "net:[100]", "mnt:[200]",
            "9" * 64, "a" * 64, "144", "1" * 40])
        self.assertEqual(len(launch[15:]), 12)
        self.assertNotIn("--pid", launch)
        self.assertNotIn(helper.GITHUB_READONLY_TEST, launch)

    def test_tls_original_outer_wait_not_inner_assertion_controls_success(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root = PurePosixPath(context["root"])
        manifest, expected = self.manifest(context), self.outer(context)
        base_environment = {"PATH": "/inert/no-executables", "HOME": str(root / "home")}
        original_validate = helper.validate_github_tls_outer
        diagnostic_faults = {"diagnostic-pipe": BrokenPipeError, "diagnostic-shape": ValueError}
        for outcome in (0, 7, "timeout", "oserror", "subprocess-error", *diagnostic_faults, "existing"):
            events, streams, written, diagnostics, failures = [], {}, {}, [], []
            class Writer(io.StringIO):
                def __init__(self, name):
                    super().__init__(); self.name = name
                def __exit__(self, *args):
                    self.close(); events.append(("close", self.name)); return False
            class OuterPath(PurePosixPath):
                def open(self, mode, *, encoding=None):
                    test.assertEqual((mode, encoding), ("x", "utf-8"))
                    test.assertEqual(self.parent, root)
                    test.assertIn(self.name, ("github-tls.stdout", "github-tls.stderr"))
                    test.assertNotIn(self.name, streams)
                    streams[self.name] = Writer(self.name)
                    events.append(("open", self.name))
                    return streams[self.name]
                def stat(self):
                    test.assertTrue(all(stream.closed for stream in streams.values()))
                    test.assertIn(self.name, streams)
                    return SimpleNamespace(st_size=256 if self.name.endswith("stdout") else 0)
            def read(path, limit):
                test.assertEqual((path, limit), (root / "github-tls-inputs.json", 1024 * 1024))
                return deepcopy(manifest)
            def process(argv, **kwargs):
                events.append(("run", "original-outer"))
                test.assertEqual(argv, helper.github_tls_launch_argv(context, compiled, manifest))
                test.assertEqual(set(kwargs), {"cwd", "env", "stdin", "stdout", "stderr", "check", "timeout", "preexec_fn"})
                test.assertEqual((kwargs["cwd"], kwargs["env"], kwargs["stdin"], kwargs["check"], kwargs["timeout"]),
                                 (root, base_environment, subprocess.DEVNULL, False, 300))
                test.assertIs(kwargs["preexec_fn"], helper.github_tls_outer_limits)
                test.assertIs(kwargs["stdout"], streams["github-tls.stdout"])
                test.assertIs(kwargs["stderr"], streams["github-tls.stderr"])
                test.assertFalse(any(stream.closed for stream in streams.values()))
                if outcome == "timeout":
                    raise subprocess.TimeoutExpired("private-inert-command", 300)
                if outcome == "oserror":
                    raise OSError("private-inert-error")
                if outcome == "subprocess-error":
                    raise subprocess.SubprocessError("private-inert-preexec")
                return subprocess.CompletedProcess(argv, 7 if outcome in diagnostic_faults else outcome)
            def emit(path, value):
                test.assertEqual(path, root / "github-tls-outer.json")
                test.assertTrue(all(stream.closed for stream in streams.values()))
                test.assertFalse(written)
                written.update(deepcopy(value))
                events.append(("write", "original-outer"))
            def diagnose(actual_context, actual_compiled, original, launch_error):
                test.assertEqual((actual_context, actual_compiled), (context, compiled))
                test.assertEqual(original, written)  # Only after exclusive original record.
                diagnostics.append((deepcopy(original), launch_error))
                if outcome in diagnostic_faults:
                    raise diagnostic_faults[outcome]("private-inert-diagnostics")
            def validate(value, **kwargs):
                try:
                    return original_validate(value, **kwargs)
                except helper.CheckFailure as original_failure:
                    failures.append(original_failure)
                    raise
            with self.subTest(outer=outcome), patch.multiple(helper, Path=OuterPath, read_bounded_json=read,
                    write_json=emit, run=forbidden, tools=forbidden, github_tls_result=forbidden,
                    github_tls_runtime=forbidden, hash_file=forbidden, github_tls_failure_diagnostics=diagnose,
                    validate_github_tls_outer=validate), \
                    patch.object(helper, "clean_environment", return_value=base_environment), \
                    patch.object(helper.time, "monotonic", side_effect=[10.0, 10.125]), \
                    patch.object(helper.os.path, "lexists", return_value=outcome == "existing"), \
                    patch.object(helper.subprocess, "run", side_effect=process), \
                    patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if outcome == 0:
                    self.assertEqual(helper.github_tls_run_outer(context, compiled), expected)
                else:
                    with self.assertRaises(helper.CheckFailure) as caught:
                        helper.github_tls_run_outer(context, compiled)
                    self.assertNotIn("private-inert", str(caught.exception))
                    if outcome != "existing":
                        self.assertEqual(len(failures), 1)
                        self.assertIs(caught.exception, failures[0])
            if outcome == "existing":
                self.assertEqual(events, [])
                self.assertEqual(written, {})
                self.assertEqual(diagnostics, [])
                continue
            self.assertEqual(events, [("open", "github-tls.stdout"), ("open", "github-tls.stderr"),
                ("run", "original-outer"), ("close", "github-tls.stderr"), ("close", "github-tls.stdout"), ("write", "original-outer")])
            if outcome == 0:
                self.assertEqual(written, expected)
                self.assertEqual(diagnostics, [])
            elif outcome == 7 or outcome in diagnostic_faults:
                self.assertEqual(written, {**expected, "status": "failed", "exitCode": 7})
            else:
                self.assertEqual(written, {**expected, "status": "unknown", "waitObserved": False,
                    "exitCode": None, "timedOut": outcome == "timeout", "stdoutBytes": None, "stderrBytes": None})
            if outcome != 0:
                self.assertEqual(diagnostics, [(written,
                    "none" if outcome == 7 or outcome in diagnostic_faults else outcome)])
        for key, value in (("waitObserved", 1), ("status", "unknown"), ("exitCode", False), ("timedOut", True),
                ("elapsedMs", 300001), ("stdoutBytes", 1048577), ("artifactIdentitySha256", "f" * 64),
                ("tlsInputsSha256", "f" * 64), ("outerWait", "passed")):
            with self.subTest(forged_outer=key), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_outer({**expected, key: value}, context=context, compiled=compiled)
        limits = []
        resource = SimpleNamespace(RLIMIT_CORE="core", RLIMIT_FSIZE="file", RLIMIT_NOFILE="fds", RLIMIT_AS="address-space",
                                   setrlimit=lambda key, value: limits.append((key, value)))
        # This fake module is the only capability provided to the limiter; no
        # real rlimit is changed in the test process, child, or shared host.
        with patch.dict(helper.sys.modules, {"resource": resource}):
            helper.github_tls_outer_limits()
        self.assertEqual(limits, [("core", (0, 0)), ("file", (1048576, 1048576)),
                                 ("fds", (128, 128)), ("address-space", (1073741824, 1073741824))])

    def test_tls_namespace_diagnostics_accept_only_complete_literal_frames(self):
        expected = {"stage": "host-resolver", "code": "file-owner"}
        frame = b"github-tls-namespace: host-resolver/file-owner\n"
        self.assertEqual(helper.github_tls_namespace_refusal(frame), expected)
        for raw in (None, "github-tls-namespace: host-resolver/file-owner\n", b"", frame[:-1],
                b"private-path\n" + frame, frame + b"private-token", frame * 2,
                frame.replace(b"host-resolver", b"private-identity"), frame.replace(b"file-owner", b"unknown"),
                frame.replace(b"/", b"\xff"), frame + b"\0", b"x" * 65537):
            with self.subTest(kind=type(raw).__name__, size=len(raw) if raw is not None else None):
                self.assertIsNone(helper.github_tls_namespace_refusal(raw))

    def test_tls_diagnostic_snapshot_requires_bounded_unchanged_original_regular_output(self):
        test, frame = self, b"github-tls-namespace: host-resolver/file-owner\n"
        for fault in (None, "link", "symlink", "oversize", "opened-replacement", "read-change", "path-change",
                      "short", "overflow", "unavailable", "close"):
            info = dict(st_dev=7, st_ino=9, st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=1000,
                        st_gid=1000, st_size=len(frame), st_mtime_ns=10, st_ctime_ns=11)
            if fault == "link": info["st_nlink"] = 2
            if fault == "symlink": info["st_mode"] = stat.S_IFLNK | 0o777
            if fault == "oversize": info["st_size"] = 65537
            events, lstat_calls, fstat_calls = [], [], []
            class Stream(io.BytesIO):
                def fileno(self): return 777  # Supplied identity, never an actual descriptor operation.
                def read(self, size):
                    test.assertEqual(size, 65537)
                    events.append("read")
                    return super().read(size)
                def __exit__(self, *args):
                    super().__exit__(*args)
                    events.append("close")
                    if fault == "close": raise OSError("private-close-detail")
            class OutputPath(PurePosixPath):
                def lstat(self):
                    lstat_calls.append(None)
                    if fault == "unavailable": raise OSError("private-path")
                    return SimpleNamespace(**{**info, **({"st_ino": 99} if fault == "path-change" and len(lstat_calls) > 1 else {})})
                def open(self, mode):
                    test.assertEqual(mode, "rb")
                    events.append("open")
                    body = frame[:-1] if fault == "short" else frame + b"x" if fault == "overflow" else frame
                    return Stream(body)
            def fstat(descriptor):
                test.assertEqual(descriptor, 777)
                fstat_calls.append(None)
                changed = fault == "opened-replacement" or fault == "read-change" and len(fstat_calls) > 1
                return SimpleNamespace(**{**info, **({"st_ino": 99} if changed else {})})
            with self.subTest(fault=fault), patch.object(helper.os, "fstat", side_effect=fstat):
                self.assertEqual(helper.github_tls_stderr_snapshot(OutputPath("/inert/original-stderr")),
                                 frame if fault is None else None)
            if "open" in events: self.assertIn("close", events)
            if fault in {"link", "symlink", "oversize", "unavailable"}: self.assertEqual(events, [])

    def test_tls_failed_diagnostics_are_redacted_non_authorizing_projections(self):
        context, compiled, test = self.context(), self.artifact(), self
        outer = {**self.outer(context), "status": "failed", "exitCode": 71, "stderrBytes": 53}
        # A private field in an observation must not be copied into public output.
        outer["private"] = "private-token-and-path"
        for raw, write_fails in ((b"github-tls-namespace: host-resolver/file-owner\n", False),
                                 (b"private-token-and-path", False), (b"", True)):
            writes, output = [], io.StringIO()
            def emit(path, value):
                test.assertEqual(path, PurePosixPath(context["root"]) / "github-tls-checks.json")
                writes.append(deepcopy(value))
                if write_fails: raise OSError("private-token-and-path")
            with patch.multiple(helper, write_json=emit, github_tls_stderr_snapshot=lambda path: raw), redirect_stdout(output):
                helper.github_tls_failure_diagnostics(context, compiled, outer, "none")
            self.assertEqual(len(writes), 1)
            value = writes[0]
            self.assertEqual(set(value), {"schemaVersion", "scope", "phase", "status", "sourceSha", "sourceTree",
                "workflowSha256", "runId", "attempt", "tlsInputsSha256", "compiledTest", "launchError",
                "namespaceRefusal", "outerObservation"})
            self.assertEqual((value["scope"], value["phase"], value["status"], value["launchError"]),
                             (self.EVIDENCE, "github-tls", "failed", "none"))
            self.assertEqual(value["outerObservation"], {key: outer[key] for key in (
                "status", "waitObserved", "exitCode", "timedOut", "elapsedMs", "stdoutBytes", "stderrBytes")})
            self.assertEqual(value["namespaceRefusal"], {"stage": "host-resolver", "code": "file-owner"} if raw.startswith(b"github-tls-") else None)
            self.assertNotIn("private", output.getvalue())
            self.assertNotIn(context["root"], output.getvalue())
            self.assertNotIn(compiled["path"], output.getvalue())
            lines = output.getvalue().splitlines()
            self.assertEqual(json.loads(lines[-1].removeprefix("TLS failed-only diagnostic: ")), value)
            self.assertEqual(len(lines), 2 if write_fails else 1)
            with patch.object(helper, "github_tls_phase_value", return_value={"status": "passed"}):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_phase_receipt(value, context, "github-tls")
            with self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_outer(value, context=context, compiled=compiled)
        for launch_error in ("timeout", "oserror", "subprocess-error"):
            unknown = {**outer, "status": "unknown", "waitObserved": False, "exitCode": None,
                       "timedOut": launch_error == "timeout", "stdoutBytes": None, "stderrBytes": None}
            writes, output = [], io.StringIO()
            with patch.multiple(helper, github_tls_stderr_snapshot=self.forbidden,
                    write_json=lambda path, value: writes.append(value)), redirect_stdout(output):
                helper.github_tls_failure_diagnostics(context, compiled, unknown, launch_error)
            self.assertEqual((writes[0]["status"], writes[0]["namespaceRefusal"], writes[0]["launchError"]),
                             ("failed", None, launch_error))
            self.assertFalse(writes[0]["outerObservation"]["waitObserved"])
            self.assertIsNone(writes[0]["outerObservation"]["exitCode"])

    def test_tls_predecessors_require_own_claims_inner_and_outer_before_cleanup(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root = PurePosixPath(context["root"])

        def exercise(name, *, mutation=None, present=(), clean=False):
            data, events = {}, []
            for prior in test.CHECKS:
                data[f"{prior}-started.json"] = test.claim(context, prior)
                data[f"{prior}-checks.json"] = test.phase_report(context, prior)
            data["github-tls-inputs.json"] = test.manifest(context)
            data["github-tls/receipt.json"] = github_tls_report_data()
            data["github-tls-outer.json"] = test.outer(context)
            if mutation:
                path, keys, value = mutation
                row = data[path]
                for key in keys[:-1]:
                    row = row[key]
                row[keys[-1]] = value
            def read(path, limit):
                name = path.relative_to(root).as_posix()
                expected_limit = 4096 if name.endswith("-started.json") else 128 * 1024 if name == "github-tls/receipt.json" else 1024 * 1024 if name == "github-tls-inputs.json" else 16384 if name == "github-tls-outer.json" else 32768
                test.assertEqual(limit, expected_limit)
                events.append(("read", name))
                return deepcopy(data[name])
            def digest(path):
                test.assertEqual(path, root / "github-tls/receipt.json")
                events.append(("hash", "native"))
                return "d" * 64
            with patch.multiple(helper, Path=PurePosixPath, read_bounded_json=read, hash_file=digest,
                    run=forbidden, tools=forbidden, github_tls_inputs_unchanged=forbidden, github_tls_source_unchanged=forbidden,
                    ordinary=forbidden, write_json=forbidden, clean_environment=forbidden), \
                    patch.object(helper, "github_tls_original_artifact", return_value=compiled), \
                    patch.object(helper.os.path, "lexists", side_effect=lambda path: path.relative_to(root).as_posix() in present), \
                    patch.object(helper.os, "scandir", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                call = (lambda: helper.clean_github_tls(context)) if clean else (lambda: helper.github_tls_predecessors(context, name))
                if mutation or present:
                    with test.assertRaises(helper.CheckFailure):
                        call()
                else:
                    call()
            return events

        for name in ("acquire", "compile", "github-tls", "clean"):
            events = exercise(name)
            previous = list(self.CHECKS) if name == "clean" else list(self.CHECKS)[:list(self.CHECKS).index(name)]
            expected = [("read", f"{prior}-{suffix}.json") for prior in previous for suffix in ("started", "checks")]
            if name == "clean":
                expected.extend([("read", "github-tls-inputs.json"), ("read", "github-tls/receipt.json"),
                                 ("read", "github-tls-outer.json"), ("hash", "native")])
            self.assertEqual(events, expected)
        mutations = (
            ("acquire-started.json", ("scope",), helper.GITHUB_READONLY_SCOPE),
            ("compile-started.json", ("attempt",), "3"), ("compile-started.json", ("tlsInputsSha256",), "f" * 64),
            ("compile-checks.json", ("compiledTest", "identitySha256"), "f" * 64),
            ("github-tls-checks.json", ("nativeReceiptSha256",), "f" * 64),
            ("github-tls/receipt.json", ("scope",), "github-readonly-hosted-v1"),
            ("github-tls/receipt.json", ("allPeersSettled",), False),
            ("github-tls/receipt.json", ("cases", 0, "product", "owners", 0, "unknownLatched"), True),
            ("github-tls/receipt.json", ("cases", 0, "peer", "stdoutJoined"), False),
            ("github-tls-outer.json", ("waitObserved",), False),
            ("github-tls-outer.json", ("artifactSha256",), "f" * 64),
            ("github-tls-outer.json", ("exitCode",), 1),
        )
        for mutation in mutations:
            with self.subTest(predecessor=mutation[:2]):
                # Real clean must refuse in real predecessor validation, before
                # its input observer, clean claim, inventory or first deletion.
                exercise("clean", mutation=mutation, clean=True)
        for name in ("github-tls-started.json", "github-tls-checks.json", "github-tls-outer.json",
                     "github-tls/receipt.json", "clean-started.json", "clean-checks.json"):
            with self.subTest(spent=name):
                exercise("github-tls", present=(name,))
        for name in ("clean-started.json", "clean-checks.json"):
            with self.subTest(spent_clean=name):
                exercise("clean", present=(name,), clean=True)

    def test_tls_phase_routes_compile_once_and_stop_on_original_outer_or_inner_failure(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
        cargo, rustc = "/inert/tls/selected/cargo", "/inert/tls/selected/rustc"
        environment = {"HOME": str(root / "home"), "PATH": "/inert/no-executables"}
        admitted_environment = {**environment, "GITHUB_SHA": "1" * 40, "MRK_GITHUB_TLS_INPUTS_SHA256": "9" * 64}
        manifest = str(source / "desktop/src-tauri/Cargo.toml")
        commands = {
            "acquire": [("rust-toolchain-install", [context["rustup"], "toolchain", "install", helper.RUST,
                "--profile", "minimal", "--no-self-update"]),
                ("github-tls-locked-headless-metadata", [cargo, "metadata", "--locked", "--format-version", "1",
                    "--no-default-features", "--features", "development-runtime", "--filter-platform",
                    "x86_64-unknown-linux-gnu", "--manifest-path", manifest])],
            "compile": [("github-tls-headless-test-compile-only", [cargo, "test", "--locked", "--offline", "--jobs", "1",
                "--no-default-features", "--features", "development-runtime", "--target", "x86_64-unknown-linux-gnu",
                "--manifest-path", manifest, "--target-dir", str(root / "target"), "--lib", "--no-run", "--message-format=json"])],
            "github-tls": [],
        }
        for name, failure in (("acquire", None), ("compile", None), ("github-tls", None),
                              ("compile", "compile"), ("github-tls", "outer"), ("github-tls", "inner")):
            events, streams, writes, calls = [], {}, {}, []
            pair = {"acquire": ("cargo-metadata.json", "acquire.stderr"),
                    "compile": ("github-tls-compile-messages.jsonl", "compile.stderr"), "github-tls": ()}[name]
            class StreamPath(PurePosixPath):
                def open(self, mode, *, encoding=None, newline=None):
                    test.assertEqual((self.parent, mode, encoding), (root, "x", "utf-8"))
                    test.assertIn(self.name, pair)
                    test.assertNotIn(self.name, streams)
                    test.assertEqual(newline, "\n" if self.name.endswith("jsonl") else None)
                    streams[self.name] = io.StringIO()
                    return streams[self.name]
            def load(platform, scope):
                test.assertEqual((platform, scope), ("linux", test.SCOPE))
                events.append("load")
                return context
            def predecessors(value, phase):
                test.assertIs(value, context); test.assertEqual(phase, name); events.append("predecessors")
            def unchanged(value):
                test.assertIs(value, context); events.append("source")
            def configuration(paths):
                test.assertEqual(paths, (root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents))
                events.append("configuration")
            def selected(value, env):
                test.assertIs(value, context); test.assertEqual(env, admitted_environment)
                test.assertIn(name, ("acquire", "compile")); events.append("tools")
                return cargo, rustc
            def execute(argv, *, check, cwd, env, timeout, output=None, diagnostics=None):
                test.assertLess(len(calls), len(commands[name]))
                test.assertEqual((check, argv), commands[name][len(calls)])
                test.assertEqual((cwd, env, timeout), (root, admitted_environment, 600))
                calls.append((check, argv)); events.append("run")
                if check != "rust-toolchain-install":
                    test.assertIs(output, streams[pair[0]]); test.assertIs(diagnostics, streams[pair[1]])
                    test.assertFalse(output.closed or diagnostics.closed)
                else:
                    test.assertIsNone(output); test.assertIsNone(diagnostics)
                if failure == "compile":
                    raise helper.CheckFailure("inert compiler refusal")
                return ""
            def record(value, argv, messages):
                test.assertIs(value, context); test.assertEqual(name, "compile")
                test.assertEqual(argv, commands["compile"][0][1]); test.assertEqual(messages, root / "github-tls-compile-messages.jsonl")
                test.assertTrue(all(stream.closed for stream in streams.values())); events.append("compile-record")
                return compiled
            def outer(value, artifact):
                test.assertIs(value, context); test.assertIs(artifact, compiled); test.assertEqual(name, "github-tls")
                events.append("outer")
                if failure == "outer":
                    raise helper.CheckFailure("inert original outer refusal")
                return test.outer(context)
            def result(value):
                test.assertIs(value, context); test.assertEqual(name, "github-tls"); test.assertIn("outer", events)
                events.append("inner")
                if failure == "inner":
                    raise helper.CheckFailure("inert original peer/client refusal")
                return {"nativeReceiptSha256": "d" * 64, "outer": test.outer(context)}
            def emit(path, value):
                test.assertEqual(path.parent, root); test.assertNotIn(path.name, writes)
                expected = test.claim(context, name) if path.name == f"{name}-started.json" else test.phase_report(context, name)
                test.assertEqual(value, expected); writes[path.name] = deepcopy(value)
                events.append("claim" if path.name.endswith("-started.json") else "receipt")
            with self.subTest(phase=name, failure=failure), patch.multiple(helper, Path=StreamPath, load_context=load,
                    github_tls_predecessors=predecessors, github_tls_source_unchanged=unchanged, no_cargo_configuration=configuration,
                    tools=selected, run=execute, github_tls_compile_record=record, github_tls_run_outer=outer,
                    github_tls_result=result, write_json=emit, source_unchanged=forbidden, read_bounded_json=forbidden,
                    github_tls_runtime=forbidden, github_tls_inputs_unchanged=forbidden, ordinary=forbidden, hash_file=forbidden,
                    phase_github_readonly=forbidden, phase_workflow_native=forbidden, clean_compile=forbidden), \
                    patch.object(helper, "github_tls_original_artifact", return_value=compiled), \
                    patch.object(helper, "clean_environment", side_effect=lambda path: dict(environment)), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden), \
                    patch.object(helper.os, "scandir", side_effect=forbidden), patch.object(helper.shutil, "rmtree", side_effect=forbidden):
                if failure:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase(name, "linux", self.SCOPE)
                else:
                    helper.phase(name, "linux", self.SCOPE)
            self.assertEqual(events[:5], ["load", "predecessors", "claim", "source", "configuration"])
            self.assertEqual(calls, commands[name])
            self.assertTrue(all(stream.closed for stream in streams.values()))
            self.assertEqual(set(writes), {f"{name}-started.json"} if failure else {f"{name}-started.json", f"{name}-checks.json"})
            self.assertEqual(events.count("source"), 1 if failure else 2)
            if name == "github-tls":
                self.assertEqual(events.count("outer"), 1)
                self.assertEqual(events.count("tools"), 0)
                if failure == "outer":
                    self.assertNotIn("inner", events)
                else:
                    self.assertLess(events.index("outer"), events.index("inner"))
                if not failure:
                    self.assertLess(events.index("inner"), len(events) - 1)
            elif name == "compile":
                self.assertEqual(events.count("compile-record"), 0 if failure else 1)

        # Keep the shared wrapper's diagnostic extension exact, not a generic
        # github-tls-* capability. No native launch passes through this wrapper.
        with io.StringIO() as output, io.StringIO() as diagnostics, io.StringIO() as notices, redirect_stdout(notices), \
                patch.object(helper.subprocess, "run", return_value=SimpleNamespace(stdout="inert")) as process, \
                patch.object(helper.subprocess, "Popen", side_effect=forbidden):
            for role in ("github-tls-locked-headless-metadata", "github-tls-headless-test-compile-only"):
                helper.run(["/inert/no-tool"], check=role, cwd=root, env=environment, timeout=1, output=output, diagnostics=diagnostics)
                process.assert_called_once_with(["/inert/no-tool"], cwd=root, env=environment, check=True, timeout=1,
                                                text=True, stdout=output, stderr=diagnostics)
                process.reset_mock()
            for role in ("github-tls-native", "github-tls-any-command", "locked-platform-metadata"):
                with self.assertRaises(helper.CheckFailure):
                    helper.run(["/inert/no-tool"], check=role, cwd=root, env=environment, timeout=1, output=output, diagnostics=diagnostics)
            process.assert_not_called()

    def test_tls_context_keeps_exact_lane_root_source_python_and_public_binding(self):
        original, test, forbidden = self.context(), self, self.forbidden
        root = PurePosixPath(original["root"])
        public = {"schemaVersion": 1, "scope": self.EVIDENCE,
            **{key: original[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha", "workflowRef",
                "workflowSha256", "runId", "attempt", "tlsInputsSha256", "tlsInputs")},
            "python": "3.14.7", "rust": {"release": helper.RUST, "target": "x86_64-unknown-linux-gnu"},
            "features": ["development-runtime"], "testTarget": "lib", "host": original["observedHost"], "notVerified": TLS_NOT_VERIFIED}
        class ContextPath(PurePosixPath):
            def resolve(self, *, strict=False):
                test.assertTrue(strict); return self
            def is_symlink(self):
                return False
        for change in (None, ("executionScope", helper.GITHUB_READONLY_SCOPE), ("source", "/inert/other-source"),
                ("python", "/inert/other-python"), ("workflowPath", helper.GITHUB_READONLY_WORKFLOW),
                ("sourceTree", True), ("attempt", "3"), ("workflowSha256", "f" * 64), ("public", "foreign")):
            context, supplied_public, events = deepcopy(original), deepcopy(public), []
            if change:
                if change[0] == "public":
                    supplied_public["scope"] = helper.GITHUB_READONLY_EVIDENCE_SCOPE
                else:
                    context[change[0]] = change[1]
            def read(path, limit):
                test.assertEqual(limit, 256 * 1024); test.assertEqual(path.parent, root)
                events.append(path.name)
                return deepcopy(context if path.name == "context.json" else supplied_public)
            def inputs(value):
                test.assertEqual(value, context); events.append("inputs")
            with self.subTest(context_change=change), patch.multiple(helper, Path=ContextPath, read_bounded_json=read,
                    github_tls_inputs_unchanged=inputs, ordinary=lambda path: None, github_inputs_unchanged=forbidden,
                    run=forbidden, tools=forbidden, write_json=forbidden, github_tls_runtime=forbidden), \
                    patch.object(helper, "hash_file", return_value="4" * 64), \
                    patch.object(helper.sys, "executable", original["python"]), \
                    patch.dict(helper.os.environ, {**self.environment(), "MRK_DESKTOP_CI_ROOT": str(root),
                        "RUNNER_TEMP": str(root.parent), "GITHUB_WORKSPACE": original["source"]}, clear=True), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden):
                if change:
                    with self.assertRaises(helper.CheckFailure):
                        helper.load_context("linux", self.SCOPE)
                else:
                    self.assertEqual(helper.load_context("linux", self.SCOPE), original)
            self.assertEqual(events, ["context.json", "inputs", "public-bindings.json"] if change is None or change[0] == "public" else ["context.json"])

    def test_tls_cleanup_finite_no_follow_plan_keeps_evidence_and_unknown_content(self):
        context, test, forbidden = self.context(), self, self.forbidden
        root = PurePosixPath(context["root"])
        native, outside = root / "github-tls", PurePosixPath("/inert/tls/outside")
        work = ("home", "cargo", "rustup", "tmp", "target", "github-tls-namespace")
        private = ("core.zip", "gitconfig-empty", "cargo-metadata.json", "acquire.stderr", "github-tls-compile-messages.jsonl",
                   "compile.stderr", "github-tls-compiled-test.json", "github-tls.stdout", "github-tls.stderr")
        evidence = ("context.json", "public-bindings.json", "github-tls-inputs.json", "github-tls-outer.json",
                    *(f"{phase}-{suffix}.json" for phase in self.CHECKS for suffix in ("started", "checks")))
        self.assertEqual(set(helper.GITHUB_TLS_DIRECTORIES), {*work, "github-tls"})

        for mutation in (None, "finality", "unexpected", "changed-leaf", "late-entry"):
            nodes, counts, writes = {}, {}, {}
            events, scans, unlinked, removed = [], [], [], []
            def add(path, kind="file", *, size=32, inode=None, links=1):
                path = PurePosixPath(path)
                test.assertNotIn(path, nodes)
                mode = {"file": stat.S_IFREG | 0o400, "directory": stat.S_IFDIR | 0o700, "link": stat.S_IFLNK | 0o777}[kind]
                nodes[path] = {"st_dev": 7, "st_ino": len(nodes) + 100 if inode is None else inode,
                    "st_mode": mode, "st_uid": 1000, "st_gid": 1000, "st_size": 4096 if kind == "directory" else size,
                    "st_nlink": 2 if kind == "directory" else links, "st_mtime_ns": 1000, "st_ctime_ns": 2000}
            def children(path):
                return sorted(child for child in nodes if child.parent == path)
            add(root, "directory"); add(native, "directory")
            add(outside, "directory"); add(outside / "protected.pem")
            add(PurePosixPath(context["source"]), "directory")
            add(PurePosixPath(context["source"]) / "protected.py")
            directories = {root / name for name in work}
            for name, *_ in TLS_CASE_ROWS:
                directories.update((native / name, native / name / "control", native / name / "runtime"))
            for path in sorted(directories, key=lambda path: (len(path.parts), str(path))):
                add(path, "directory")
            leaves = {root / name for name in private}
            for name, *_ in TLS_CASE_ROWS:
                # These are actual settled producer names, including the
                # reusable Case::settle release record (not an empty control).
                leaves.update((native / name / "control/release-github-read-1.json",
                    native / name / "runtime/github_connection_bootstrap.py", native / name / "runtime/github-ca.pem"))
            leaves.update(root / "github-tls-namespace" / name for name in self.CONFIG)
            for path in sorted(leaves):
                add(path)
            for name in evidence:
                add(root / name)
            add(native / "receipt.json")
            link = root / "tmp/external-link"
            add(link, "link"); leaves.add(link)
            aliases = (root / "cargo/original-hardlink", root / "target/original-hardlink")
            add(aliases[0], inode=9999, links=2); add(aliases[1], inode=9999, links=2); leaves.update(aliases)
            if mutation == "unexpected":
                add(root / "unexpected.pem")
            initial = deepcopy(nodes)
            protected = {root / name for name in evidence} | {native / "receipt.json"}
            protected.update(path for path in nodes if path != root and root not in path.parents)
            total = sum(nodes[path]["st_size"] for path in leaves)
            expected_receipt = {"schemaVersion": 1, "scope": self.EVIDENCE, "phase": "clean", "status": "passed",
                **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
                "allOriginalOwnersSettled": True, "allOriginalPeersSettled": True, "observerJoinsComplete": True,
                "originalOuterWaitObserved": True, "tlsInputsSha256": "9" * 64, "compiledTest": self.compiled_public(),
                "nativeReceiptSha256": "d" * 64, "outer": self.outer(context), "removedFiles": len(leaves),
                "removedDirectories": len(directories), "inventoriedBytes": total,
                "retained": ["redacted-evidence", "private-original-context", "private-tls-input-manifest", "private-original-outer-receipt"],
                "productionQualified": False}
            class FakePath(PurePosixPath):
                # No following read/metadata or recursive convenience deletion
                # is available. The symbolic link's external target is opaque.
                open = stat = resolve = read_bytes = read_text = is_dir = is_file = readlink = glob = rglob = forbidden
                def lstat(self):
                    path = PurePosixPath(self)
                    test.assertTrue(path == root or root in path.parents)
                    test.assertIn(path, nodes)
                    counts[path] = counts.get(path, 0) + 1
                    if mutation == "changed-leaf" and path == root / "github-tls.stderr" and counts[path] == 2:
                        nodes[path]["st_mtime_ns"] += 1
                    return SimpleNamespace(**nodes[path])
                def iterdir(self):
                    path = PurePosixPath(self); test.assertIn(path, (root, native))
                    return iter(FakePath(child) for child in children(path))
                def unlink(self):
                    path = PurePosixPath(self)
                    test.assertIn(path, leaves); test.assertNotIn(path, unlinked)
                    test.assertEqual(set(scans), directories); test.assertTrue(leaves <= counts.keys())
                    info = nodes.pop(path); unlinked.append(path); events.append(("unlink", path))
                    for other in nodes.values():
                        if (other["st_dev"], other["st_ino"]) == (info["st_dev"], info["st_ino"]):
                            other["st_nlink"] -= 1; other["st_ctime_ns"] += 1
                    if mutation == "late-entry" and len(unlinked) == 1:
                        add(root / "home/late.pem")
                def rmdir(self):
                    path = PurePosixPath(self); test.assertIn(path, directories)
                    events.append(("rmdir", path))
                    if children(path):
                        raise OSError("inert new entry retained")
                    del nodes[path]; removed.append(path)
            class Scan:
                def __init__(self, entries):
                    self.entries = entries
                def __enter__(self):
                    return iter(self.entries)
                def __exit__(self, *args):
                    return False
            def scan(path):
                path = PurePosixPath(path)
                test.assertIn(path, directories); test.assertFalse(unlinked)
                scans.append(path)
                return Scan([SimpleNamespace(name=child.name) for child in children(path)])
            def result(value):
                test.assertIs(value, context); events.append(("finality", "original"))
                if mutation == "finality":
                    raise helper.CheckFailure("inert finality missing")
                return {"nativeReceiptSha256": "d" * 64, "outer": test.outer(context)}
            def emit(path, value):
                path = PurePosixPath(path)
                test.assertIn(path.name, ("clean-started.json", "clean-checks.json"))
                test.assertNotIn(path.name, writes)
                test.assertEqual(value, test.claim(context, "clean") if path.name == "clean-started.json" else expected_receipt)
                writes[path.name] = deepcopy(value); add(path); events.append(("write", path.name))
            notice = io.StringIO()
            with self.subTest(cleanup=mutation), redirect_stdout(notice), patch.multiple(helper, Path=FakePath,
                    github_tls_predecessors=lambda value, name: events.append(("predecessors", name)),
                    github_tls_inputs_unchanged=lambda value: events.append(("inputs", "original")),
                    github_tls_result=result, write_json=emit, run=forbidden, tools=forbidden,
                    github_tls_source_unchanged=forbidden, source_unchanged=forbidden, clean_environment=forbidden,
                    read_bounded_json=forbidden, hash_file=forbidden, ordinary=forbidden), \
                    patch.object(helper, "github_tls_original_artifact", return_value=self.artifact()), \
                    patch.object(helper.os, "scandir", side_effect=scan), patch.object(helper.os, "geteuid", return_value=1000, create=True), \
                    patch.object(helper.os, "unlink", side_effect=forbidden), patch.object(helper.os, "rmdir", side_effect=forbidden), \
                    patch.object(helper.shutil, "rmtree", side_effect=forbidden), patch.object(helper.subprocess, "run", side_effect=forbidden), \
                    patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if mutation == "late-entry":
                    with self.assertRaises(OSError):
                        helper.clean_github_tls(context)
                elif mutation:
                    with self.assertRaises(helper.CheckFailure):
                        helper.clean_github_tls(context)
                else:
                    helper.clean_github_tls(context)
            self.assertEqual(events[:3], [("predecessors", "clean"), ("inputs", "original"), ("finality", "original")])
            for path in protected:
                self.assertEqual(nodes[path], initial[path])
            self.assertTrue(set(unlinked) <= leaves); self.assertTrue(set(removed) <= directories)
            if mutation is None:
                self.assertCountEqual(unlinked, leaves); self.assertCountEqual(removed, directories)
                self.assertEqual(writes, {"clean-started.json": self.claim(context, "clean"), "clean-checks.json": expected_receipt})
                self.assertEqual(set(nodes), (set(initial) - leaves - directories) | {root / "clean-started.json", root / "clean-checks.json"})
                self.assertEqual(children(native), [native / "receipt.json"])
                self.assertEqual(notice.getvalue(), "Removed only positively settled TLS compiler and fixture outputs; original evidence retained.\n")
            else:
                self.assertNotIn("clean-checks.json", writes); self.assertEqual(notice.getvalue(), "")
                self.assertEqual(set(writes), set() if mutation == "finality" else {"clean-started.json"})
                if mutation != "late-entry":
                    self.assertEqual(unlinked, []); self.assertEqual(removed, [])
                else:
                    self.assertIn(root / "home/late.pem", nodes); self.assertNotIn(root / "home/late.pem", unlinked)
                    self.assertIn(root / "home", nodes)


class GitHubTLSWorkflowContractTests(unittest.TestCase):
    def test_tls_workflow_has_own_fixed_chain_and_only_six_redacted_artifacts(self):
        # One bounded SOURCE read. No YAML loader, workflow dispatch or shell.
        import re
        path = SOURCE / ".github/workflows/desktop-github-connection-tls.yml"
        with path.open("rb") as stream:
            raw = stream.read(16384 + 1)
        self.assertLessEqual(len(raw), 16384)
        workflow = raw.decode("utf-8")
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9-]*):$", workflow.split("\njobs:\n", 1)[1], re.MULTILINE), ["github-readonly-tls-native"])
        self.assertEqual(re.findall(r"ci_foundation\.py ([a-z-]+)'", workflow), ["prepare", "acquire", "compile", "github-tls", "clean"])
        self.assertEqual(len(re.findall(r"^        run:", workflow, re.MULTILINE)), 6)
        self.assertEqual(workflow.count("runs-on: ubuntu-24.04"), 1)
        self.assertEqual(workflow.count("permissions:"), 1)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertNotIn("matrix:", workflow); self.assertNotIn("${{ secrets.", workflow)
        self.assertNotIn("github-owner", workflow); self.assertNotIn("refs/heads/verify/desktop-github-connection-native", workflow)
        for guard in ('"$RUNNER_ENVIRONMENT" == github-hosted', '"$RUNNER_OS" == Linux', '"$RUNNER_ARCH" == X64',
                '"$ImageOS" == ubuntu24', '"$EUID" -ne 0', '"$GITHUB_REF" == refs/heads/verify/desktop-github-connection-tls',
                '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"', '"$MRK_EXPECTED_SHA" == "$GITHUB_SHA"',
                '"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-github-connection-tls.yml@$GITHUB_REF"',
                "persist-credentials: false", "cancel-in-progress: false", "timeout-minutes: 45", "python-version: '3.14.7'",
                "MRK_DESKTOP_HOSTED_CHECKS: github-readonly-tls-native-v1", "if: success()",
                "if: always() && steps.prepare.outcome == 'success'"):
            self.assertIn(guard, workflow)
        self.assertEqual(workflow.count('"$MRK_PYTHON" -I -S -B desktop/tools/ci_foundation.py'), 5)
        self.assertEqual(re.findall(r"uses: ([^\s]+)", workflow), [
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"])
        paths = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], ["${{ steps.prepare.outputs.root }}/" + name for name in (
            "public-bindings.json", "acquire-checks.json", "compile-checks.json", "github-tls-checks.json",
            "github-tls/receipt.json", "clean-checks.json")])


if __name__ == "__main__":
    unittest.main()
