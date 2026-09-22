"""Inert compiler-helper contracts; never run main, real tools or native fixtures.

Phase/cleanup capabilities and all subprocess calls are inert mocks. Source inspection checks
the fixed caller inventory rather than executing hosted admission on the VPS.
"""
from __future__ import annotations

import ast
import __future__
from copy import deepcopy
from contextlib import ExitStack, redirect_stdout
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
    def test_windows_installed_tool_admission_distinguishes_hosted_git_input(self):
        # Real private role gate; only original metadata/stdout are inert.
        # This does not establish native Git provenance or execute a tool.
        def exercise(role, *, links=1, mode=stat.S_IFREG | 0o755, attributes=0,
                     admitted=True, error=None):
            calls = []

            class NamedInput:
                def lstat(self):
                    calls.append("lstat")
                    if error is not None:
                        raise error
                    return SimpleNamespace(st_mode=mode, st_nlink=links,
                                           st_file_attributes=attributes)

            output = io.StringIO()
            with redirect_stdout(output):
                if error is not None:
                    with self.assertRaises(type(error)) as caught:
                        helper.windows_installed_tool(NamedInput(), role)
                    self.assertIs(caught.exception, error)
                elif admitted:
                    helper.windows_installed_tool(NamedInput(), role)
                else:
                    with self.assertRaises(helper.CheckFailure) as caught:
                        helper.windows_installed_tool(NamedInput(), role)
                    self.assertEqual(str(caught.exception),
                        "Expected a regular, non-reparse hosted Git file with a positive link count"
                        if role == "git" else "Expected an ordinary, single-link file")
            self.assertEqual(calls, ["lstat"])
            if admitted or error is not None:
                self.assertEqual(output.getvalue(), "")
            else:
                expected = {"role": role, "regular": stat.S_ISREG(mode),
                            "singleLink": links == 1, "reparse": bool(attributes & 0x400)}
                self.assertEqual(output.getvalue(), "MRK_WINDOWS_INSTALLED_TOOL_REFUSED="
                    + json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n")
                self.assertLess(len(output.getvalue()), 160)

        for links in (1, 2, 32):
            exercise("git", links=links)
        for links in (0, -1):
            exercise("git", links=links, admitted=False)
        for role in ("python", "rustup"):
            exercise(role)
            for links in (0, -1, 2):
                exercise(role, links=links, admitted=False)
        for role in ("python", "git", "rustup"):
            exercise(role, mode=stat.S_IFDIR | 0o755, admitted=False)
            exercise(role, attributes=0x400, admitted=False)
            exercise(role, error=OSError("inert original metadata failure"))

        class Unobserved:
            def lstat(self):
                self_case.fail("Unknown role must be refused before metadata observation")

        self_case = self
        for role in ("cargo", "Git", None, []):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(helper.CheckFailure) as caught:
                helper.windows_installed_tool(Unobserved(), role)
            self.assertEqual(str(caught.exception), "Unknown Windows native tool role")
            self.assertEqual(output.getvalue(), "")

    def test_windows_installed_reader_preserves_native_metadata_identity(self):
        # Actual reader, inert bytes and only path/stream/stat boundaries doubled.
        # These are CPython metadata contracts, not native Windows evidence.
        content = b"INERT READER DATA; NEVER EXECUTED\n"
        common = {"st_dev": 7, "st_ino": 13, "st_nlink": 1, "st_size": len(content),
                  "st_mtime_ns": 10000, "st_birthtime_ns": 2000,
                  "st_file_attributes": 0x20, "st_reparse_tag": 0}
        named = SimpleNamespace(**common, st_mode=stat.S_IFREG | 0o777, st_ctime_ns=2000)
        opened = SimpleNamespace(**common, st_mode=stat.S_IFREG | 0o666, st_ctime_ns=3000)

        def changed(value, **fields):
            return SimpleNamespace(**{**vars(value), **fields})

        def exercise(*, name="python.exe", before=named, first=opened, after=opened,
                     final=named, payload=content, error=None, opens=1, limit=1024,
                     platform="nt", close_error=False):
            calls = {"named": 0, "opened": 0, "closed": 0, "fstat": 0, "read": []}

            class Stream:
                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    calls["closed"] += 1
                    if close_error:
                        raise OSError("inert close failure")

                def fileno(self):
                    return 73  # Never passed to a real OS function.

                def read(self, count):
                    calls["read"].append(count)
                    return payload[:count]

            class NamedInput:
                def lstat(self):
                    calls["named"] += 1
                    self_case.assertLessEqual(calls["named"], 2)
                    return before if calls["named"] == 1 else final

                def open(self, mode):
                    self_case.assertEqual(mode, "rb")
                    calls["opened"] += 1
                    return Stream()

            def fstat(fd):
                self.assertEqual(fd, 73)
                calls["fstat"] += 1
                self.assertLessEqual(calls["fstat"], 2)
                return first if calls["fstat"] == 1 else after

            self_case = self
            path = NamedInput()
            path.name = name
            with patch.object(helper, "os", SimpleNamespace(name=platform, fstat=fstat)):
                if error is None:
                    self.assertEqual(helper.windows_installed_bytes(path, limit), content)
                    self.assertEqual((calls["named"], calls["fstat"]), (2, 2))
                else:
                    with self.assertRaises(error):
                        helper.windows_installed_bytes(path, limit)
            self.assertEqual(calls["opened"], opens)
            self.assertEqual(calls["closed"], opens)
            self.assertIn(calls["read"], ([], [before.st_size + 1]))

        for name in ("python.EXE", "helper.bat", "helper.cmd", "helper.com"):
            with self.subTest(suffix=name):
                exercise(name=name)
        data_named = changed(named, st_mode=opened.st_mode)
        exercise(name="record.json", before=data_named, final=data_named)
        exercise(name="record.json", before=opened, final=opened, platform="posix")
        for changes in ({"st_ino": 14}, {"st_mode": stat.S_IFREG | 0o444},
                        {"st_birthtime_ns": 2001}, {"st_nlink": 2},
                        {"st_file_attributes": 0x400}, {"st_reparse_tag": 1}):
            with self.subTest(opened=changes):
                exercise(first=changed(opened, **changes), error=helper.CheckFailure)
        # Do not mask suffix bits globally or ignore real descriptor ChangeTime.
        exercise(name="record.json", error=helper.CheckFailure)
        exercise(after=changed(opened, st_ctime_ns=3001), error=helper.CheckFailure)
        exercise(final=changed(named, st_ctime_ns=2001), error=helper.CheckFailure)
        exercise(final=changed(named, st_mode=stat.S_IFREG | 0o775), error=helper.CheckFailure)
        exercise(after=changed(opened, st_nlink=2), error=helper.CheckFailure)
        exercise(final=changed(named, st_file_attributes=0x400), error=helper.CheckFailure)
        exercise(payload=content[:-1], error=helper.CheckFailure)
        exercise(payload=content + b"x", error=helper.CheckFailure)
        exercise(before=changed(named, st_nlink=2), error=helper.CheckFailure, opens=0)
        exercise(before=changed(named, st_file_attributes=0x400), error=helper.CheckFailure, opens=0)
        exercise(limit=len(content) - 1, error=helper.CheckFailure, opens=0)
        missing = SimpleNamespace(**{key: value for key, value in vars(opened).items() if key != "st_birthtime_ns"})
        exercise(first=missing, error=AttributeError)
        exercise(error=OSError, close_error=True)

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
                                           check=True, timeout=15, text=True, stdout=subprocess.PIPE, stderr=None)
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
        self.assertIsInstance(outer_keywords["timeout"], ast.Call)
        self.assertEqual(outer_keywords["timeout"].func.id, "github_tls_outer_seconds")
        self.assertEqual(outer_keywords["timeout"].args[0].id, "profile")
        self.assertEqual([helper.github_tls_outer_seconds(profile) for profile in (None, "hosts", "dns-withhold")], [300, 180, 60])
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
                     "desktop/src-tauri/src/candidate_evidence_protocol.rs", "desktop/tests/fixtures/candidate-evidence.json",
                     "desktop/src-tauri/src/asset_source.rs", "desktop/src-tauri/src/github_workflow_edit_protocol.rs",
                     "desktop/native/linux-mount-observation/src/lib.rs", "tests/native_desktop_config.py",
                     "src/mobile_release/api/data/github-setup-v1.json", "templates/workflows/mobile-production-submit.yml"):
            self.assertIn(path, helper.WORKFLOW_NATIVE_SOURCES)
        for path in ("desktop/package-lock.json", "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/tests/session_gtk_qualification.rs"):
            self.assertNotIn(path, helper.WORKFLOW_NATIVE_SOURCES)
        self.assertEqual(helper.WORKFLOW_NATIVE_SOURCES, tuple(sorted(set(helper.WORKFLOW_NATIVE_SOURCES))))
        for path in ("desktop/src-tauri/src/candidate_evidence_protocol.rs", "desktop/tests/fixtures/candidate-evidence.json"):
            self.assertNotIn(path, helper.WORKFLOW_OWNER_SOURCES.values())
            self.assertNotIn(path, helper.CONFIG_OWNER_SOURCES.values())
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
        self.assertEqual(workflow.count("ci_foundation.py "), len(helper.WORKFLOW_NATIVE_PHASES) + 3)
        # The new push-only metadata selection shares this compile, not the old
        # workflow-domain native sequence. Keep the original upload unchanged.
        workflow_upload = workflow.split("      - name: Retain only allowlisted synthetic receipts\n", 1)[1].split(
            "      - name: Retain only allowlisted synthetic metadata receipts\n", 1)[0]
        allowlist = [line.strip().split("${{ steps.prepare.outputs.root }}/", 1)[1]
                     for line in workflow_upload.splitlines() if line.strip().startswith("${{ steps.prepare.outputs.root }}/")]
        self.assertEqual(allowlist, ["public-bindings.json", "acquire-checks.json", "compile-checks.json", "workflow-owner-checks.json",
            "workflow-owner-source/receipt.json", "workflow-owner-zip/receipt.json", "workflow-transaction-eof-checks.json",
            "workflow-transaction-eof/receipt.json", "workflow-core-checks.json", "workflow-ordinary.json",
            "workflow-committed-fsync.json", "workflow-committed-close.json", "retention-checks.json"])


def metadata_environment() -> dict[str, str]:
    """Inert route data, not GitHub admission or an executed job."""
    return {"GITHUB_SHA": "1" * 40, "GITHUB_REPOSITORY": "Example/project", "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "MRK_PUSH_EVENT_AFTER": "1" * 40,
            "MRK_DESKTOP_HOSTED_CHECKS": "metadata-text-apply-native-v1",
            "GITHUB_REF": "refs/heads/verify/desktop-metadata-text-apply-native", "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_WORKFLOW_REF": "Example/project/.github/workflows/desktop-github-workflow-apply-native.yml@refs/heads/verify/desktop-metadata-text-apply-native"}


def metadata_context() -> dict:
    return {"root": "/never-opened/task", "source": "/never-opened/source", "sourceSha": "1" * 40, "sourceTree": "3" * 40,
            "platform": "linux", "executionScope": "metadata-text-apply-native-v1", "workflowSha": "1" * 40,
            "workflowPath": ".github/workflows/desktop-github-workflow-apply-native.yml", "workflowSha256": "4" * 64,
            "workflowRef": metadata_environment()["GITHUB_WORKFLOW_REF"], "repository": "Example/project",
            "runId": "123", "attempt": "1", "event": "push", "ref": "refs/heads/verify/desktop-metadata-text-apply-native",
            "pushEventAfter": "1" * 40, "observedHost": workflow_host_report(),
            "metadataInputs": {"sourceFiles": [{"path": path, "size": 123, "sha256": "3" * 64} for path in helper.METADATA_NATIVE_SOURCES],
                               "coreFiles": [{"path": "mobile_release/metadata_text.py", "size": 10, "sha256": "6" * 64}],
                               "coreZipSha256": "7" * 64, "pythonSha256": "2" * 64}}


def metadata_core_report(partition: str) -> dict:
    """Consumer test data only. The separately fixed oracle hash is checked below."""
    rows = helper.METADATA_CORE_ROWS[partition]
    return {"schemaVersion": 1, "suite": "desktop-metadata-text-native", "domain": "metadata_text",
            "partition": partition, "status": "passed", "reason": "none", "failedAt": None,
            "retained": True, "uncertaintyLatched": partition != "committed-fsync",
            "injection": helper.METADATA_CORE_INJECTIONS[partition], "host": workflow_host_report(),
            "bindings": {"sourceSha": "1" * 40, "sourceKind": "source", "sourceHashes": dict.fromkeys(helper.METADATA_CORE_SOURCES, "3" * 64),
                         "pythonSha256": "2" * 64, **deepcopy(helper.METADATA_PAYLOAD_BINDINGS)},
            "completed": [row[0] for row in rows],
            "cases": [{"case": name, "outcome": {"effect": effect, "journal": journal, "resources": resources, "reason": reason},
                       "owner": {"closed": True, "handlerRestored": True, "fatal": fatal}, "observed": deepcopy(observed)}
                      for name, effect, journal, resources, reason, fatal, observed in rows]}


def validate_metadata_core(report: object, partition: str) -> dict:
    return helper.validate_metadata_core_receipt(report, partition, source_sha="1" * 40,
        source_hashes=dict.fromkeys(helper.METADATA_CORE_SOURCES, "3" * 64), python_hash="2" * 64, host=workflow_host_report())


def metadata_phase_report(name: str) -> dict:
    context = metadata_context()
    return {"schemaVersion": 1, "scope": "desktop-metadata-text-apply-native-only-v1", "phase": name, "status": "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha", "workflowRef",
                "workflowSha256", "repository", "runId", "attempt", "event", "ref", "pushEventAfter", "metadataInputs")},
            "rust": {"release": helper.RUST, "target": "x86_64-unknown-linux-gnu"}, "python": helper.PYTHON,
            "features": ["development-runtime"], "testTarget": "lib",
            "checks": [{"check": key, "exitCode": 0} for key in helper.METADATA_NATIVE_CHECKS[name]],
            "notVerified": list(helper.METADATA_NOT_VERIFIED)}


def metadata_native_facts(*, domain="metadata_text", effect="committed", journal="clean", reason="none", native_reason="none",
                          applied=True, requests=3, responses=3, sequence=2, checkout=True, prepared=True, unknown=False, stderr=0):
    """Independent inert wire DATA; never an original resource/native receipt."""
    facts = {"originalWait": True, "stdoutEof": True, "stderrEof": True, "stdinClosed": True, "stdoutClosed": True,
             "stderrClosed": True, "startupJoined": True, "ioJoined": True, "driverJoined": True, "watchdogJoined": True,
             "managerJoined": True, "requestFrames": requests, "responseFrames": responses, "stdoutBytes": 100,
             "stderrBytes": stderr, "forceAttempted": False, "domain": domain, "nativePhase": "unknown" if unknown else "final",
             "nativeFinality": "unknown" if unknown else "settled", "nativeReason": native_reason, "applySubmitted": applied,
             "lateSettled": unknown, "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": reason},
             "terminalSeq": sequence}
    if domain == "metadata_text":
        facts.update(checkoutRetained=checkout, preparedRetained=prepared)
    return facts


def metadata_passive_facts(methods, start, error=None):
    return [{"method": method, "key": str(start + index), "error": error if method == "observe" else None,
             "observerJoin": "ok", "permitRetired": True, "resourceBookRetired": True,
             "native": {"inspection_joined": True, "acquisition_joined": True, "spawned": True, "waited": True, "exit_success": True,
                "writer_joined": True, "writer_complete": True, "stdout_eof": True, "stderr_eof": True, "stdout_joined": True,
                "stderr_joined": True, "stdout_bytes": 100, "stderr_bytes": 0, "driver_joined": True, "watchdog_joined": True}}
            for index, method in enumerate(methods)]


def metadata_owner_report(mode="source", *, eof=False):
    """Handwritten consumer examples following the independently fixed Rust wire contract."""
    context = metadata_context()
    inputs = context["metadataInputs"]
    source_hashes = dict.fromkeys(helper.METADATA_TRANSACTION_EOF_SOURCES if eof else helper.METADATA_OWNER_SOURCES, "3" * 64)
    bindings = {"sourceSha": "1" * 40, "sourceTree": "3" * 40, "workflowSha256": "4" * 64, "runId": "123", "attempt": "1",
        "ref": "refs/heads/verify/desktop-metadata-text-apply-native", "coreZipSha256": "7" * 64,
        "coreInventorySha256": hashlib.sha256(json.dumps(inputs["coreFiles"], sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest(),
        "domain": "metadata_text", "host": "linux", "target": "x86_64-unknown-linux-gnu", "runtimeMode": "trusted-development-only",
        "runtimeInput": mode, "pythonSha256": "2" * 64, "sourceHashes": source_hashes, "payloadHashes": deepcopy(helper.METADATA_OWNER_PAYLOAD_HASHES),
        "metadataResourceSha256": "3" * 64, "schemaResourceSha256": "3" * 64, "inheritedFileMaskObserved": True,
        "requestedCreateMode": 420, "observedCreateMode": 384, "newDirectoryMode": 493,
        "documentEvidence": "controlled-original-lifetime-not-gui-callbacks"}
    report = {"schemaVersion": 1, "scope": "metadata-text-transaction-eof-hosted-v1" if eof else "metadata-text-owner-hosted-v1",
        "domain": "metadata_text", "status": "passed", "allOwnersSettled": not eof, "originalResourcesSettled": True,
        "ownerDisabled": eof, "retainedEffectUnknown": eof, "failureCode": None, "bindings": bindings, "cases": [],
        "notVerified": ["production-runtime-custody", "production-metadata-save-enablement", "native-gui", "webview-callbacks-or-crash-hook",
            "parent-death", "native-stuck-wait-close", "persisted-recovery", "macos-windows-metadata-writes", "credentials", "remote-github",
            "stores", "mobile-builds", "installers"]}
    names = ("android-observe-create", "ios-observe-create", "android-observe-noop", "ios-observe-noop", "android-observe-replace-preserve",
             "ios-observe-mixed-create-replace-preserve", "observe-without-ignore-save-refused", "observe-last-sensitive-refused",
             "observe-last-nonutf8-refused", "stale-passive-baseline-refused", "three-domain-owner-isolation",
             "registration-changed-before-apply", "metadata-terminal-held-after-stop", "metadata-document-loss-before-apply")
    if eof:
        names = ("precommit-eof", "postcommit-eof", "precommit-conflict-eof")
    start = 1
    for index, name in enumerate(names):
        if mode == "zip" and index != 5:
            continue
        platform = "ios" if (index == 1 if eof else index in (1, 3, 5, 8)) else "android"
        locale = "fr-FR" if not eof and index == 4 else "en-US"
        error = None if eof else "metadata_text_sensitive" if index == 7 else "metadata_text_encoding" if index == 8 else None
        catalogue = not eof and (index == 0 or mode == "zip")
        methods = ["observe"] if error else ["catalogue", "observe", "validate"] if catalogue else ["observe", "validate"]
        passive = metadata_passive_facts(methods, start, error)
        start += len(methods)
        common = {"sourceProbesSettled": True, "passiveOriginalsSettled": True}
        if eof:
            committed, unknown = index == 1, index == 2
            boundary, checkpoint = (("before-COMMITTED", "publisher-entry"), ("after-durable-COMMITTED", "descriptor-close"),
                                    ("before-COMMITTED", "publisher-entry"))[index]
            # Exact original two-record wire text, not a native execution result.
            lines = [f"MRK_METADATA_TEXT_EOF_V1 {name} boundary={boundary}\n",
                     f"MRK_METADATA_TEXT_EOF_V1 {name} eof=1 nonempty=0 readErrors=0 checkpoint={checkpoint} applied=1 "
                     + ("committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
                        "committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
                        "committed=0 rolledBack=0 terminal=UNKNOWN durable=0 recovery=1 clean=0 settled=1 cancelled=1\n")[index]]
            native = metadata_native_facts(effect=("rolled_back", "committed", "unknown")[index],
                journal="recovery_required" if unknown else "clean", reason="cancelled", native_reason="cancelled", unknown=unknown,
                stderr=len("".join(lines).encode("ascii")))
            observed = {"evidenceKind": "real-stdin-eof-at-controlled-transaction-boundary", "bootstrapMode": "instrumented-genuine-engine",
                "boundary": boundary, "originalCheckpoint": checkpoint, "closeBeforeActiveDeadline": True, "controlRecords": 2,
                "actualStdinEof": True, "eofReadCount": 1, "nonemptyReadCount": 0, "readErrorCount": 0, "preparedCorrelationRetained": True,
                "metadataProfileAndControlProof": True, "committedPublication": committed, "rolledBackPublication": index == 0,
                "terminalDurable": not unknown, "fixedRecovery": True, "journalClean": not unknown, "journalAbsent": not unknown,
                "originalTreeRestored": index == 0, "selectedPayloadsRemain": index != 0, "unselectedAndDependenciesPreserved": True,
                "unrelatedIntroducedBeforeEof": unknown, "introducedOriginalPreserved": unknown, "recoveryEvidenceRetained": unknown,
                "sharedBlockedProject": unknown, "allThreeDomainsDisabled": unknown, "noFurtherAdmission": unknown, "fixtureFilesSettled": True, **common}
        elif error:
            native = None
            observed = {"closedError": error, "lastFieldRefused": True, "noPartialTextOrDigest": True, "noEditorAdmitted": True, "treeUnchanged": True, **common}
        elif index == 6:
            native = metadata_native_facts(effect="not_started", journal="not_created", reason="ignore_conflict", applied=False,
                requests=1, responses=1, sequence=0, checkout=False, prepared=False)
            observed = {"passiveObserveWithoutIgnore": True, "ignoreStillAbsent": True, "noCheckoutOrPlan": True, "treeUnchanged": True, **common}
        elif index == 9:
            native = metadata_native_facts(effect="not_started", journal="not_created", reason="stale_revision", applied=False,
                requests=2, responses=2, sequence=1, prepared=False)
            observed = {"olderPassiveBaselineRejected": True, "newerNativeCheckoutRetained": True, "noPlanOrRebase": True,
                        "externalChangeRetained": True, "treeUnchanged": True, **common}
        elif index in (11, 13):
            native = metadata_native_facts(effect="not_started", journal="not_created", reason="cancelled", applied=False,
                native_reason="caller_lost" if index == 11 else "window_lost", requests=2, responses=3, sequence=1)
            observed = {"preparedCorrelationRetained": True, "treeUnchanged": True, "staleCommandNotSent": True,
                "newRegistrationPublishedUnderDocumentLock": index == 11, "controlledOriginalDocumentLoss": index == 13,
                "replacementDocumentRefused": index == 13, "guiCallbacksNotClaimed": True, **common}
        else:
            counts = ((3, 0, 0), (5, 0, 0), (0, 0, 3), (0, 0, 5), (0, 1, 2), (1, 2, 2))[index] if index < 6 else (3, 0, 0)
            noop = index in (2, 3)
            native = metadata_native_facts(effect="unchanged" if noop else "committed", journal="not_created" if noop else "clean",
                                          native_reason="cancelled" if index == 12 else "none")
            directories = ["release/store", "release/store/ios", "release/store/ios/en-US"] if index == 1 else (
                ["public", "public/store", "public/store/android", "public/store/android/en-US"] if index in (0, 10, 12) else [])
            domains = [metadata_native_facts(domain=domain, effect="not_started", journal="not_created", reason="cancelled",
                native_reason="discarded", applied=False, requests=1, responses=2, sequence=0) for domain in ("configuration", "github_workflows")] if index == 10 else []
            observed = {"created": counts[0], "replaced": counts[1], "preserved": counts[2], "directoriesCreated": directories,
                "completePreparedBytes": True, "passiveBaselineMatchedCheckout": True, "preparedCorrelationRetained": True,
                "capturePrepareRawFactsUnchanged": True, "unselectedAndDependenciesPreserved": True, "existingModesPreserved": True,
                "createModesMasked": True, "directoryModesExact": True, "rawNoopUnchanged": noop, "duplicateApplyObservation": index == 0,
                "catalogueResourceMatched": catalogue, "sharedStatusRevision": True, "sharedLastTerminalDomainCorrect": True,
                "threeDomainIsolation": index == 10, "domains": domains, "heldBeforeAcceptance": index == 12,
                "realStopBeforeRelease": index == 12, "cancelledNotSaved": index == 12, **common}
        report["cases"].append({"name": name, "domain": "metadata_text", "platform": platform, "locale": locale,
                                "native": native, "passive": passive, "observations": observed})
    return report


def validate_metadata_owner(report, mode="source", *, eof=False):
    sources = dict.fromkeys(helper.METADATA_TRANSACTION_EOF_SOURCES if eof else helper.METADATA_OWNER_SOURCES, "3" * 64)
    if eof:
        return helper.validate_metadata_transaction_eof_receipt(report, context=metadata_context(), source_hashes=sources)
    return helper.validate_metadata_owner_receipt(report, mode, context=metadata_context(), source_hashes=sources)


class MetadataNativeHelperTests(unittest.TestCase):
    """Closed metadata grammar/lifecycle consumers; no real tools or subjects."""

    def test_core_rows_sources_and_seeds_match_the_independently_fixed_metadata_contract(self):
        # Digests were derived from the accepted literal cross-language contract,
        # not from the candidate/helper generator. No native result is claimed.
        canonical = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        cases = [case for partition in ("ordinary", "committed-fsync", "committed-close") for case in metadata_core_report(partition)["cases"]]
        self.assertEqual(len(cases), 22)
        self.assertEqual(canonical(cases), "1adb3df36daed910279f776cf1683367b0b85c73cba13057fa1e7967b18b2601")
        self.assertEqual(canonical(helper.METADATA_CORE_SOURCES), "d812ffa8c1a5e9a0798dd3736572ad16ba435dd62d9a5af07c8c74c9c66b9c2b")
        self.assertEqual(canonical(helper.METADATA_PAYLOAD_BINDINGS), "a0d9844865eed8a49f98ddbc640a9ebcb04c9c31e48774a83281dad5c45beb92")
        # Independent author oracle: literal seed bytes and the actual Rust
        # SOURCES26/EXTRA23 map, not this helper's receipt constructor.
        self.assertEqual(canonical(helper.METADATA_OWNER_PAYLOAD_HASHES), "3ab3654346ac8bc3d740c77e51e6313bce70cc2dbb2dc1817a2f552c669f05aa")
        self.assertEqual(canonical(helper.METADATA_OWNER_SOURCES), "0e18075b26b15a528a8f283ced045a0292252d5289ac60307d151a18502930e1")
        self.assertEqual(set(helper.METADATA_PAYLOAD_BINDINGS), {"configHashes", "ignoreSha256", "fieldHashes"})
        self.assertEqual(len(helper.METADATA_CORE_SOURCES), 20)
        self.assertEqual(len(helper.METADATA_OWNER_SOURCES), 49)
        self.assertEqual(len(helper.METADATA_TRANSACTION_EOF_SOURCES), 50)
        self.assertEqual(helper.METADATA_NATIVE_SOURCES, tuple(sorted(set(helper.METADATA_NATIVE_SOURCES))))
        for path in (*helper.METADATA_CORE_SOURCES.values(), *helper.METADATA_TRANSACTION_EOF_SOURCES.values(),
                     helper.METADATA_NATIVE_WORKFLOW, "desktop/tools/ci_foundation.py"):
            self.assertIn(path, helper.METADATA_NATIVE_SOURCES)
        for path in ("desktop/package-lock.json", "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/tests/session_gtk_qualification.rs"):
            self.assertNotIn(path, helper.METADATA_NATIVE_SOURCES)

    def test_core_exact_rows_separate_unknown_effect_resources_and_original_fatal_latch(self):
        for partition in ("ordinary", "committed-fsync", "committed-close"):
            report = metadata_core_report(partition)
            with patch.object(helper, "run", side_effect=AssertionError("no subprocess")), \
                    patch.object(helper, "hash_file", side_effect=AssertionError("no filesystem")):
                self.assertIs(validate_metadata_core(report, partition), report)
            for changed in ({"schemaVersion": True}, {"suite": "desktop-workflow-native"}, {"domain": "github_workflows"},
                            {"status": "failed"}, {"failedAt": "unobserved"}, {"retained": False}, {"reason": "filesystem_error"},
                            {"completed": []}, {"cases": []}, {"bindings": {}}, {"extra": True}):
                with self.subTest(partition=partition, change=changed), self.assertRaises(helper.CheckFailure):
                    validate_metadata_core({**report, **changed}, partition)
            for index, case in enumerate(report["cases"]):
                for section, key, value in (("owner", "closed", False), ("owner", "handlerRestored", 1),
                                             ("owner", "fatal", not case["owner"]["fatal"]),
                                             ("outcome", "resources", "settled" if partition == "committed-close" else "unknown"),
                                             ("outcome", "effect", "unchanged")):
                    changed = deepcopy(report)
                    changed["cases"][index][section][key] = value
                    with self.subTest(partition=partition, case=index, section=section, key=key), self.assertRaises(helper.CheckFailure):
                        validate_metadata_core(changed, partition)
                for key, original in case["observed"].items():
                    changed = deepcopy(report)
                    changed["cases"][index]["observed"][key] = int(original) if type(original) is bool else None
                    with self.subTest(partition=partition, case=index, observation=key), self.assertRaises(helper.CheckFailure):
                        validate_metadata_core(changed, partition)
        ordinary = metadata_core_report("ordinary")
        self.assertEqual(ordinary["completed"][-1], "dependency-drift-after-first-replacement")
        self.assertEqual(ordinary["cases"][-1]["outcome"], {"effect": "unknown", "journal": "recovery_required", "resources": "settled", "reason": "stale_revision"})
        for cases in (ordinary["cases"][:-1], list(reversed(ordinary["cases"])), [*ordinary["cases"], ordinary["cases"][-1]]):
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_core({**ordinary, "cases": cases}, "ordinary")
        last = metadata_core_report("committed-close")["cases"][0]
        self.assertEqual(last["outcome"], {"effect": "committed", "journal": "clean", "resources": "unknown", "reason": "cancelled"})
        self.assertIs(last["owner"]["fatal"], True)
        self.assertEqual(last["observed"]["afterUnknownProbes"], 0)

    def test_core_bindings_reject_workflow_templates_and_json_aliases(self):
        report = metadata_core_report("ordinary")
        for key, value in (("sourceKind", "zip"), ("sourceSha", "2" * 40), ("sourceHashes", {}), ("pythonSha256", "0" * 64),
                           ("configHashes", {}), ("ignoreSha256", "0" * 64), ("fieldHashes", {}), ("templateSet", {})):
            changed = deepcopy(report)
            changed["bindings"][key] = value
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                validate_metadata_core(changed, "ordinary")
        raw = json.dumps(report, separators=(",", ":")).encode("utf-8")
        self.assertEqual(helper.bounded_json(raw, 32 * 1024), report)
        for invalid in (b'{"status":"failed","status":"passed"}', b'{"schemaVersion":NaN}', b'\xff', b'{}' * 17000):
            with self.assertRaises(helper.CheckFailure):
                helper.bounded_json(invalid, 32 * 1024)
        with patch.object(helper, "ordinary"), patch.object(Path, "stat") as details, \
                patch.object(Path, "open", side_effect=AssertionError("oversized data cannot be opened")):
            details.return_value.st_size = 32769
            with self.assertRaises(helper.CheckFailure):
                helper.read_bounded_json(Path("/never-opened/metadata-ordinary.json"), 32768)

    def test_owner_source_zip_and_eof_examples_preserve_exact_original_fact_shapes(self):
        for mode, eof, expected_count in (("source", False, 14), ("zip", False, 1), ("source", True, 3)):
            report = metadata_owner_report(mode, eof=eof)
            with patch.object(helper, "run", side_effect=AssertionError("no process")), \
                    patch.object(helper, "hash_file", side_effect=AssertionError("no source/runtime probe")):
                self.assertIs(validate_metadata_owner(report, mode, eof=eof), report)
            self.assertEqual(len(report["cases"]), expected_count)
            self.assertLess(len(json.dumps(report, separators=(",", ":")).encode("ascii")), 64 * 1024)
            self.assertEqual(sum(len(row["passive"]) for row in report["cases"]), 6 if eof else 27 if mode == "source" else 3)
        source = metadata_owner_report()
        self.assertIsNone(source["cases"][7]["native"])
        self.assertIsNone(source["cases"][8]["native"])
        self.assertEqual(len(source["cases"][0]["native"]), 26)
        self.assertEqual(len(source["cases"][0]["passive"][0]["native"]), 15)
        self.assertEqual([len(row) for row in source["cases"][10]["observations"]["domains"]], [24, 24])
        self.assertEqual(metadata_owner_report("zip")["cases"][0]["name"], "ios-observe-mixed-create-replace-preserve")
        self.assertEqual([row["native"]["stderrBytes"] for row in metadata_owner_report(eof=True)["cases"]], [268, 276, 282])

    def test_owner_headers_bind_domain_source_runtime_mask_and_no_production_claim(self):
        report = metadata_owner_report()
        changes = {"schemaVersion": True, "scope": "github-workflow-owner-hosted-v1", "domain": "github_workflows", "status": "failed",
            "failureCode": "not_completed", "allOwnersSettled": False, "originalResourcesSettled": False, "ownerDisabled": True,
            "retainedEffectUnknown": True, "notVerified": [], "extra": True}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                validate_metadata_owner({**report, key: value})
        for key, value in (("ref", helper.WORKFLOW_NATIVE_REF), ("runtimeInput", "zip"), ("runtimeMode", "packaged"),
                           ("attempt", "2"), ("sourceSha", "2" * 40), ("sourceTree", "2" * 40), ("workflowSha256", "0" * 64),
                           ("sourceHashes", {}), ("payloadHashes", {}), ("pythonSha256", "0" * 64), ("coreZipSha256", "0" * 64),
                           ("coreInventorySha256", "0" * 64), ("metadataResourceSha256", "0" * 64), ("schemaResourceSha256", "0" * 64),
                           ("requestedCreateMode", 384), ("observedCreateMode", 420), ("newDirectoryMode", 448),
                           ("inheritedFileMaskObserved", 1), ("documentEvidence", "native-gui")):
            changed = deepcopy(report)
            changed["bindings"][key] = value
            with self.subTest(binding=key), self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)
        for rows in (report["cases"][:-1], list(reversed(report["cases"])), [*report["cases"], report["cases"][-1]]):
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner({**report, "cases": rows})
        for mode in ("zip", "packaged", "other"):
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(report, mode)

    def test_passive_originals_require_ordered_keys_all_joins_exact_errors_and_output_bounds(self):
        report = metadata_owner_report()
        changes = [("method", "observe"), ("observerJoin", "missing"), ("permitRetired", False), ("resourceBookRetired", False),
                   ("error", "metadata_text_sensitive"), ("key", "0"), ("key", "01"), ("key", str(2**64)), ("key", True)]
        changes.extend((f"native.{key}", None) for key in report["cases"][0]["passive"][0]["native"])
        changes.extend((f"native.{key}", value) for key, value in (("exit_success", 1), ("stdout_bytes", True),
            ("stdout_bytes", 0), ("stdout_bytes", 4 * 1024 * 1024 + 1), ("stderr_bytes", 1), ("observer_joined", True)))
        for key, value in changes:
            changed = deepcopy(report)
            item = changed["cases"][0]["passive"][0]
            if key.startswith("native."):
                item["native"][key.split(".")[1]] = value
            else:
                item[key] = value
            with self.subTest(field=key, value=value), self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)
        for index in (1, 7, 8):
            changed = deepcopy(report)
            changed["cases"][index]["passive"][0]["key"] = "1"
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)
        for value in ("metadata_text_sensitive", "metadata_text_encoding", None):
            index = 8 if value == "metadata_text_sensitive" else 7
            changed = deepcopy(report)
            changed["cases"][index]["passive"][0]["error"] = value
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)
        for index in (0, 1):
            changed = deepcopy(report)
            changed["cases"][index]["passive"][-1]["native"]["stdout_bytes"] = 2 * 1024 * 1024 + 1
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)

    def test_owner_observations_cannot_hide_no_editor_stale_cancelled_or_domain_loss(self):
        report = metadata_owner_report()
        for index, original in enumerate(report["cases"]):
            for key, value in (("domain", "github_workflows"), ("platform", "ios" if original["platform"] == "android" else "android"),
                               ("locale", "fr-FR" if original["locale"] == "en-US" else "en-US")):
                changed = deepcopy(report)
                changed["cases"][index][key] = value
                with self.subTest(case=index, field=key), self.assertRaises(helper.CheckFailure):
                    validate_metadata_owner(changed)
            for key, value in original["observations"].items():
                changed = deepcopy(report)
                changed["cases"][index]["observations"][key] = int(value) if type(value) is bool else None
                with self.subTest(case=index, observation=key), self.assertRaises(helper.CheckFailure):
                    validate_metadata_owner(changed)
            if original["native"] is None:
                changed = deepcopy(report)
                changed["cases"][index]["native"] = metadata_native_facts()
                with self.assertRaises(helper.CheckFailure):
                    validate_metadata_owner(changed)
            else:
                for key in original["native"]:
                    changed = deepcopy(report)
                    changed["cases"][index]["native"][key] = None
                    with self.subTest(case=index, native=key), self.assertRaises(helper.CheckFailure):
                        validate_metadata_owner(changed)
        for index in (0, 1):
            changed = deepcopy(report)
            changed["cases"][10]["observations"]["domains"][index]["managerJoined"] = False
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed)
        changed = deepcopy(report)
        changed["cases"][10]["observations"]["domains"].reverse()
        with self.assertRaises(helper.CheckFailure):
            validate_metadata_owner(changed)
        # A terminal's preserved committed core outcome cannot erase real STOP.
        self.assertEqual(report["cases"][12]["native"]["outcome"]["effect"], "committed")
        self.assertEqual(report["cases"][12]["native"]["nativeReason"], "cancelled")

    def test_eof_effect_unknown_stays_last_disabled_with_separate_original_resource_proof(self):
        report = metadata_owner_report(eof=True)
        for key in ("allOwnersSettled", "originalResourcesSettled", "ownerDisabled", "retainedEffectUnknown"):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                validate_metadata_owner({**report, key: not report[key]}, eof=True)
        for index, row in enumerate(report["cases"]):
            for key, original in row["observations"].items():
                changed = deepcopy(report)
                changed["cases"][index]["observations"][key] = int(original) if type(original) is bool else None
                with self.subTest(case=index, field=key), self.assertRaises(helper.CheckFailure):
                    validate_metadata_owner(changed, eof=True)
            changed = deepcopy(report)
            changed["cases"][index]["native"]["stderrBytes"] -= 1
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed, eof=True)
        for key, value in (("nativePhase", "final"), ("nativeFinality", "settled"), ("lateSettled", False), ("managerJoined", False)):
            changed = deepcopy(report)
            changed["cases"][-1]["native"][key] = value
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                validate_metadata_owner(changed, eof=True)
        changed = deepcopy(report)
        changed["cases"][-1]["native"]["outcome"]["resources"] = "unknown"
        with self.assertRaises(helper.CheckFailure):
            validate_metadata_owner(changed, eof=True)
        for rows in (report["cases"][:-1], list(reversed(report["cases"]))):
            with self.assertRaises(helper.CheckFailure):
                validate_metadata_owner({**report, "cases": rows}, eof=True)

    def test_push_only_binding_rejects_rerun_dispatch_cross_domain_and_source_mismatch(self):
        environment = metadata_environment()
        expected = helper.metadata_native_binding(environment)
        self.assertEqual((expected["ref"], expected["event"], expected["attempt"], expected["sourceSha"], expected["pushEventAfter"]),
                         ("refs/heads/verify/desktop-metadata-text-apply-native", "push", "1", "1" * 40, "1" * 40))
        for key, value in (("GITHUB_SHA", "0" * 40), ("GITHUB_SHA", "A" * 40), ("GITHUB_SHA", "1" * 39),
                           ("GITHUB_WORKFLOW_SHA", "2" * 40), ("GITHUB_REF", helper.WORKFLOW_NATIVE_REF),
                           ("MRK_DESKTOP_HOSTED_CHECKS", helper.WORKFLOW_NATIVE_SCOPE), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_WORKFLOW_REF", "other/workflow"), ("GITHUB_REPOSITORY", "other/project"),
                           ("GITHUB_REPOSITORY", "invalid"), ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ID", "1" * 21),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_RUN_ATTEMPT", "01"), ("GITHUB_EVENT_NAME", "pull_request"),
                           ("MRK_PUSH_EVENT_AFTER", "2" * 40), ("MRK_PUSH_EVENT_AFTER", "0" * 40),
                           ("GITHUB_EVENT_NAME", "workflow_dispatch")):
            with self.subTest(key=key, value=value), self.assertRaises(helper.CheckFailure):
                helper.metadata_native_binding({**environment, key: value, "MRK_EXPECTED_SHA": "1" * 40})
        for key in environment:
            for value in (None, True):
                with self.subTest(key=key, value=value), self.assertRaises(helper.CheckFailure):
                    helper.metadata_native_binding({**environment, key: value})
        with self.assertRaises(helper.CheckFailure):
            helper.workflow_native_binding(environment)
        for scope in helper.COMPILE_PROFILES:
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding(environment, scope)
        old = workflow_environment()
        self.assertEqual(helper.workflow_native_binding(old)["workflowPath"], helper.WORKFLOW_NATIVE_WORKFLOW)
        self.assertEqual(helper.workflow_native_binding({**old, "GITHUB_EVENT_NAME": "workflow_dispatch", "MRK_EXPECTED_SHA": "1" * 40})["sourceSha"], "1" * 40)

    def test_metadata_scope_refuses_foreign_phases_platforms_and_compiler_profiles_before_io(self):
        self.assertNotIn(helper.METADATA_NATIVE_SCOPE, helper.COMPILE_PROFILES)
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for name in ("native", "config-owner", "config-core", "workflow-owner", "workflow-transaction-eof", "workflow-core",
                         "github-owner", "github-tls", "github-tls-deadline", "windows-snapshot", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", helper.METADATA_NATIVE_SCOPE)
            for scope in (*helper.COMPILE_PROFILES, helper.BOUNDARY_SCOPE, helper.WORKFLOW_NATIVE_SCOPE,
                          helper.WINDOWS_SNAPSHOT_SCOPE, helper.GITHUB_READONLY_SCOPE, helper.GITHUB_TLS_SCOPE):
                for name in ("metadata-owner", "metadata-transaction-eof", "metadata-core"):
                    with self.subTest(scope=scope, phase=name), self.assertRaises(helper.CheckFailure):
                        helper.phase(name, "linux", scope)
            for platform in ("macos", "windows", "unexpected"):
                with self.subTest(platform=platform), self.assertRaises(helper.CheckFailure):
                    helper.prepare(platform, helper.METADATA_NATIVE_SCOPE)
        for name in ("prepare", "acquire", "compile", "metadata-owner", "metadata-transaction-eof", "metadata-core", "clean"):
            helper.admit_phase(helper.METADATA_NATIVE_SCOPE, name)
        with patch.object(helper.Path, "resolve", side_effect=AssertionError("bad route must refuse before IO")), \
                patch.dict(helper.os.environ, {**metadata_environment(), "GITHUB_EVENT_NAME": "workflow_dispatch"}, clear=True):
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("linux", helper.METADATA_NATIVE_SCOPE)

    def test_phase_and_claim_repeat_original_event_source_and_scope_binding(self):
        context = metadata_context()
        for name in helper.METADATA_NATIVE_CHECKS:
            report = metadata_phase_report(name)
            self.assertIs(helper.validate_metadata_phase_receipt(report, context, name), report)
            for key, value in (("scope", helper.WORKFLOW_NATIVE_EVIDENCE_SCOPE), ("schemaVersion", True), ("status", "failed"),
                               ("sourceTree", "0" * 40), ("attempt", "2"), ("event", "workflow_dispatch"), ("ref", helper.WORKFLOW_NATIVE_REF),
                               ("pushEventAfter", "2" * 40), ("metadataInputs", {}), ("checks", []), ("extra", True)):
                with self.subTest(phase=name, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_metadata_phase_receipt({**report, key: value}, context, name)
            wrong_type = deepcopy(report)
            wrong_type["checks"][0]["exitCode"] = False
            with self.assertRaises(helper.CheckFailure):
                helper.validate_metadata_phase_receipt(wrong_type, context, name)
            for key, value in (("executionScope", helper.WORKFLOW_NATIVE_SCOPE), ("ref", helper.WORKFLOW_NATIVE_REF),
                               ("event", "workflow_dispatch"), ("attempt", "2"), ("pushEventAfter", "2" * 40),
                               ("workflowPath", helper.COMPILE_WORKFLOW), ("platform", "macos"), ("sourceTree", "0" * 40)):
                with self.subTest(context_key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_metadata_phase_receipt(report, {**context, key: value}, name)
        claim = helper.metadata_phase_claim(context, "metadata-core")
        for key in ("event", "ref", "pushEventAfter", "workflowSha256", "sourceTree", "sourceSha", "runId", "attempt"):
            self.assertEqual(claim[key], context[key])
        metadata = helper.metadata_core_metadata(context)
        self.assertEqual(set(metadata), {"sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "ref", "coreFiles", "coreZipSha256"})
        self.assertEqual(metadata["ref"], "refs/heads/verify/desktop-metadata-text-apply-native")
        self.assertEqual(metadata["coreFiles"], context["metadataInputs"]["coreFiles"])

    def test_predecessors_require_original_source_zip_eof_before_core_and_refuse_replay(self):
        context, observed = metadata_context(), []
        def data(path, _limit):
            if path.name.endswith("-started.json"):
                return helper.metadata_phase_claim(context, path.name.removesuffix("-started.json"))
            return metadata_phase_report(path.name.removesuffix("-checks.json"))
        with patch.object(helper, "read_bounded_json", side_effect=data), patch.object(helper.os.path, "lexists", return_value=False), \
                patch.object(helper, "metadata_owner_receipt", side_effect=lambda _, mode: observed.append(mode)), \
                patch.object(helper, "metadata_transaction_eof_receipt", side_effect=lambda _: observed.append("eof")), \
                patch.object(helper, "metadata_core_receipt", side_effect=AssertionError("core has not run")), \
                patch.object(helper, "run", side_effect=AssertionError("no subprocess")):
            helper.metadata_predecessors(context, "metadata-core")
        self.assertEqual(observed, ["source", "zip", "eof"])
        def wrong_claim(path, limit):
            value = data(path, limit)
            if path.name == "compile-started.json":
                value["scope"] = helper.WORKFLOW_NATIVE_SCOPE
            return value
        with patch.object(helper, "read_bounded_json", side_effect=wrong_claim), \
                patch.object(helper, "metadata_owner_receipt", side_effect=AssertionError("no owner after foreign claim")):
            with self.assertRaises(helper.CheckFailure):
                helper.metadata_predecessors(context, "metadata-core")
        with patch.object(helper, "read_bounded_json", side_effect=data), \
                patch.object(helper, "metadata_owner_receipt", side_effect=helper.CheckFailure("unsettled original")), \
                patch.object(helper, "metadata_transaction_eof_receipt", side_effect=AssertionError("no EOF after unsettled owner")):
            with self.assertRaises(helper.CheckFailure):
                helper.metadata_predecessors(context, "metadata-core")
        with patch.object(helper.os.path, "lexists", return_value=True), patch.object(helper, "write_json") as emit:
            with self.assertRaises(helper.CheckFailure):
                helper.metadata_phase_start(context, "acquire")
        emit.assert_not_called()

    def test_fixed_metadata_sequence_has_no_unrelated_native_invocation_or_new_clock(self):
        source = HELPER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        phase = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "phase_metadata_native")
        calls = [node for node in ast.walk(phase) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run"]
        by_label = {next(keyword.value.value for keyword in call.keywords if keyword.arg == "check"): call for call in calls}
        bounds = {"rust-toolchain-install": 600, "metadata-locked-headless-metadata": 600, "headless-test-compile-only": 600,
                  "metadata-owner-source-native-contract": 180, "metadata-owner-zip-native-contract": 60,
                  "metadata-transaction-eof-native-contract": 90, "metadata-core-ordinary": 90,
                  "metadata-core-committed-fsync": 45, "metadata-core-committed-close": 45}
        self.assertEqual(set(by_label), set(bounds))
        self.assertEqual(len(calls), len(bounds))
        for label, timeout in bounds.items():
            self.assertEqual(next(keyword.value.value for keyword in by_label[label].keywords if keyword.arg == "timeout"), timeout)
        text = ast.get_source_segment(source, phase)
        for forbidden in ("npm", "vite", "desktop-shell", "WORKFLOW_OWNER_TEST", "CONFIG_OWNER_TEST", "GITHUB_TLS_TEST", "NATIVE_TEST",
                          "MRK_DESKTOP_WORKFLOW_NATIVE", "MRK_DESKTOP_CONFIG_NATIVE", "MRK_DESKTOP_EDIT_HOSTED_CHECKS"):
            self.assertNotIn(forbidden, text)
        self.assertIn('"--domain", "metadata_text", "--case"', text)
        self.assertIn('"--locked", "--offline", "--jobs", "1", "--no-default-features"', text)
        for label in ("metadata-owner-source-native-contract", "metadata-owner-zip-native-contract", "metadata-transaction-eof-native-contract"):
            constants = [node.value for node in by_label[label].args[0].elts if isinstance(node, ast.Constant)]
            self.assertEqual(constants, ["test", "--lib", "--features", "development-runtime", "--", "--exact", "--ignored", "--test-threads=1"])
        core = text.split('elif name == "metadata-core":', 1)[1].split('    else:', 1)[0]
        self.assertLess(core.index('check="metadata-core-ordinary"'), core.index('check="metadata-core-committed-fsync"'))
        self.assertLess(core.index('check="metadata-core-committed-fsync"'), core.index('check="metadata-core-committed-close"'))
        tail = core.split('check="metadata-core-committed-close"', 1)[1]
        for forbidden in ("run(", "source_unchanged(", "metadata_inputs_unchanged(", "hash_file(", "tools(", "rmtree", "unlink"):
            self.assertNotIn(forbidden, tail)
        self.assertIn('metadata_core_receipt(context, "committed-close")', tail)

    def test_retention_only_finish_never_probes_project_deletes_or_selects_tools(self):
        context = metadata_context()
        with patch.object(helper, "metadata_phase_start") as start, \
                patch.object(helper, "metadata_inputs_unchanged", side_effect=AssertionError("no source/runtime probes")), \
                patch.object(helper, "write_json") as emit, patch.object(helper, "run", side_effect=AssertionError("no subprocess")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tools")), \
                patch.object(helper.shutil, "rmtree", side_effect=AssertionError("no deletion")), redirect_stdout(io.StringIO()):
            helper.clean_metadata_native(context)
        start.assert_called_once_with(context, "clean")
        receipt = emit.call_args.args[1]
        self.assertEqual(receipt["status"], "retained")
        self.assertEqual(receipt["reason"], "lane-last-committed-close-resources-unknown")
        for key in ("deleted", "laterNativeWork", "projectProbes"):
            self.assertIs(receipt[key], False)
        self.assertIs(receipt["vmDisposalRequired"], True)

    def test_receipt_wrappers_use_previously_bound_data_without_rehashing_subjects(self):
        context, reads = metadata_context(), []
        reports = {"metadata-owner-source/receipt.json": metadata_owner_report(),
                   "metadata-owner-zip/receipt.json": metadata_owner_report("zip"),
                   "metadata-transaction-eof/receipt.json": metadata_owner_report(eof=True),
                   **{f"metadata-{part}.json": metadata_core_report(part) for part in ("ordinary", "committed-fsync", "committed-close")}}
        def read(path, maximum):
            relative = path.relative_to(Path(context["root"])).as_posix()
            self.assertEqual(maximum, 64 * 1024 if relative.endswith("/receipt.json") else 32 * 1024)
            reads.append(relative)
            return reports[relative]
        with patch.object(helper, "read_bounded_json", side_effect=read), \
                patch.object(helper, "hash_file", side_effect=AssertionError("no source/runtime rehash")), \
                patch.object(helper, "metadata_inputs_unchanged", side_effect=AssertionError("no original input re-probe")), \
                patch.object(helper, "run", side_effect=AssertionError("no process")):
            helper.metadata_owner_receipt(context, "source")
            helper.metadata_owner_receipt(context, "zip")
            helper.metadata_transaction_eof_receipt(context)
            for partition in ("ordinary", "committed-fsync", "committed-close"):
                helper.metadata_core_receipt(context, partition)
        self.assertEqual(set(reads), set(reports))
        for rows in ([], context["metadataInputs"]["sourceFiles"][:-1], list(reversed(context["metadataInputs"]["sourceFiles"]))):
            changed = deepcopy(context)
            changed["metadataInputs"]["sourceFiles"] = rows
            with self.assertRaises(helper.CheckFailure):
                helper.metadata_bound_source_hashes(changed, helper.METADATA_CORE_SOURCES)

    def test_retention_entry_uses_original_invocation_and_receipt_data_not_source_or_tool_probes(self):
        context = metadata_context()
        context["root"] = "/never-opened/runner-temp/mrk-desktop-foundation-metadata-123-1"
        environment = {**metadata_environment(), "GITHUB_WORKSPACE": "/never-opened/source", "MRK_PYTHON": "/never-opened/setup-python",
            "RUNNER_TEMP": "/never-opened/runner-temp", "MRK_DESKTOP_CI_ROOT": context["root"], "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted", "MRK_DESKTOP_PLATFORM": "linux", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24"}
        context["metadataInvocation"] = {key: environment[key] for key in ("GITHUB_WORKSPACE", "MRK_PYTHON", "RUNNER_TEMP")}
        context["metadataInvocation"]["executable"] = "/never-opened/python-executable"
        public = helper.metadata_public_bindings(context)
        reads = []
        def read(path, maximum):
            self.assertEqual(path.parent, Path(context["root"]))
            self.assertEqual(maximum, 256 * 1024)
            reads.append(path.name)
            return context if path.name == "context.json" else public if path.name == "public-bindings.json" else self.fail("unexpected receipt")
        with patch.dict(helper.os.environ, environment, clear=True), patch.object(helper.sys, "executable", "/never-opened/python-executable"), \
                patch.object(helper.sys, "version", helper.PYTHON + " inert"), patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper.os, "geteuid", return_value=1000), patch.object(helper.os, "uname", side_effect=AssertionError("no new host probe")), \
                patch.object(Path, "resolve", side_effect=AssertionError("no source/runtime resolution")), patch.object(Path, "is_symlink", return_value=False), \
                patch.object(helper, "ordinary"), patch.object(helper, "read_bounded_json", side_effect=read), \
                patch.object(helper, "metadata_inputs_unchanged", side_effect=AssertionError("no inputs re-probe")), \
                patch.object(helper, "hash_file", side_effect=AssertionError("no rehash")), patch.object(helper, "run", side_effect=AssertionError("no tool")):
            self.assertEqual(helper.admitted_host(retention_only=True), "linux")
            self.assertIs(helper.load_context("linux", helper.METADATA_NATIVE_SCOPE, retention_only=True), context)
            with patch.object(helper, "phase_metadata_native") as execute:
                helper.phase("clean", "linux", helper.METADATA_NATIVE_SCOPE)
                execute.assert_called_once_with("clean", context)
            for key in ("GITHUB_WORKSPACE", "MRK_PYTHON", "RUNNER_TEMP"):
                with patch.dict(helper.os.environ, {key: "/never-opened/changed"}), self.assertRaises(helper.CheckFailure):
                    helper.load_context("linux", helper.METADATA_NATIVE_SCOPE, retention_only=True)
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("linux", helper.WORKFLOW_NATIVE_SCOPE, retention_only=True)
        self.assertEqual(reads[:4], ["context.json", "public-bindings.json", "context.json", "public-bindings.json"])

    def test_workflow_selects_one_domain_before_checkout_and_compiles_only_once(self):
        workflow = (SOURCE / helper.METADATA_NATIVE_WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("branches: [verify/desktop-github-workflow-apply-native, verify/desktop-metadata-text-apply-native]", workflow)
        self.assertNotIn("qualification_domain", workflow)
        guard = workflow.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        for pair in ("push:refs/heads/verify/desktop-github-workflow-apply-native)",
                     "workflow_dispatch:refs/heads/verify/desktop-github-workflow-apply-native)",
                     "push:refs/heads/verify/desktop-metadata-text-apply-native)"):
            self.assertIn(pair, guard)
        self.assertEqual(guard.count("scope="), 4)  # Three assignments plus one fixed output line.
        for exact in ('[[ "$GITHUB_RUN_ATTEMPT" == 1 && "$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA" ]]',
                      '[[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]', '*) exit 1 ;;',
                      '[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]',
                      '[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$', '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"',
                      'printf \'MRK_DESKTOP_HOSTED_CHECKS=%s\\n\' "$scope" >> "$GITHUB_ENV"'):
            self.assertIn(exact, guard)
        self.assertNotIn("MRK_EXPECTED_SHA=$GITHUB_SHA", workflow)
        for phase in ("prepare", "acquire", "compile", "clean"):
            self.assertEqual(workflow.count(f"ci_foundation.py {phase}'"), 1)
        steps = workflow.split("      - name: ")
        for scope, phases in (("github-workflow-apply-native-v1", ("workflow-owner", "workflow-transaction-eof", "workflow-core")),
                              ("metadata-text-apply-native-v1", ("metadata-owner", "metadata-transaction-eof", "metadata-core"))):
            for phase in phases:
                matching = [step for step in steps if f"ci_foundation.py {phase}'" in step]
                self.assertEqual(len(matching), 1)
                self.assertIn(f"if: steps.lane.outputs.scope == '{scope}'", matching[0])
        self.assertEqual(workflow.count("runs-on:"), 1)
        for forbidden in ("strategy:", "matrix:", "continue-on-error", "secrets.", "workflow_dispatch:refs/heads/verify/desktop-metadata"):
            self.assertNotIn(forbidden, workflow)
        upload = workflow.split("      - name: Retain only allowlisted synthetic metadata receipts\n", 1)[1]
        self.assertIn("if: always() && steps.prepare.outcome == 'success' && steps.lane.outputs.scope == 'metadata-text-apply-native-v1'", upload)
        files = [line.strip().split("${{ steps.prepare.outputs.root }}/", 1)[1]
                 for line in upload.splitlines() if line.strip().startswith("${{ steps.prepare.outputs.root }}/")]
        self.assertEqual(files, ["public-bindings.json", "acquire-checks.json", "compile-checks.json", "metadata-owner-checks.json",
            "metadata-owner-source/receipt.json", "metadata-owner-zip/receipt.json", "metadata-transaction-eof-checks.json",
            "metadata-transaction-eof/receipt.json", "metadata-core-checks.json", "metadata-ordinary.json",
            "metadata-committed-fsync.json", "metadata-committed-close.json", "retention-checks.json"])


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
        self.assertIn('"workflow-core", "windows-snapshot", "github-owner", "github-tls", "github-tls-deadline"))', main)
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
    ("T6-header", 1, "response-limit", "source", "root-ca.pem", False, 1),
    ("T6-body", 1, "response-limit", "source", "root-ca.pem", False, 1),
    ("T6-chunk-metadata", 1, "response-limit", "source", "root-ca.pem", False, 1),
    ("T6-unauthorized", 1, "unauthorized", "source", "root-ca.pem", False, 1),
    ("T6-rate-expiry", 1, "response-invalid", "source", "root-ca.pem", False, 1),
    ("T6-target", 4, "target-changed", "source", "root-ca.pem", False, 4),
    ("T6-redirect", 1, "response-invalid", "source", "root-ca.pem", False, 1),
)
TLS_STREAMING_REPLIES = {
    "T6-header": ((40630,), (32768,)), "T6-body": ((262215,), (262215,)),
    "T6-chunk-metadata": ((35803,), (33143,)), "T6-unauthorized": ((99,), (80,)),
    "T6-rate-expiry": ((175,), (156,)), "T6-target": ((95, 222, 102, 222), (95, 222, 102, 222)),
    "T6-redirect": ((136,), (117,)),
}
TLS_NOT_VERIFIED = [
    "T4-ambient-proxy-default-ca-keylog", "T5-real-network-deadlines", "product-heap-allocation",
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
        product = {"settled": True, "projectionChecked": True, "reason": reason, "registeredOwners": 0,
            "disabled": False, "owners": [{"id": "github-read-1", "profile": "github-readonly", "terminal": True,
                "unknownLatched": False, "permitRetained": False, "observerJoined": True,
                "firstError": None, "native": native}]}
        if name in TLS_STREAMING_REPLIES:
            scripted, _ = TLS_STREAMING_REPLIES[name]
            terminal.update(replyBytes=list(scripted), wireWriteBytes=[size + 1024 for size in scripted],
                replyStops=["none"] * connections,
                completion={"bytes": 1, "eof": True, "closed": True, "primaryEmpty": True,
                    "primaryUnexpected": 0, "primaryClosed": True,
                    "redirect": {"empty": True, "unexpected": 0, "closed": True} if name == "T6-redirect" else None})
            peer["control"] = {**dict.fromkeys(("acquired", "started", "joined", "writeComplete", "shutdownComplete",
                "productSettled", "withinEndpoint", "released"), True), "failed": False}
            product["projection"] = {"account": "observed" if name == "T6-target" else "unavailable",
                "repository": "unavailable", "automation": "unavailable", "credentialExpiresAt": None,
                "cooldownSeconds": 120 if name == "T6-rate-expiry" else None, "cooldownBlocked": False}
        cases.append({"case": name, "passed": True, "failureCode": None, "elapsedMs": 100,
            "coreMode": mode, "trustFixture": trust, "product": product, "peer": peer})
    bindings = github_tls_binding_data()
    bindings["namespace"].update(netns="net:[101]", mntns="mnt:[201]")
    return {"schemaVersion": 1, "scope": "github-readonly-tls-hosted-v1", "status": "passed", "allOwnersSettled": True,
            "allPeersSettled": True, "failureCode": None, "bindings": bindings, "cases": cases,
            "outerWait": "external-original-observer-required", "notVerified": list(TLS_NOT_VERIFIED)}


class GitHubTLSListenerControlTests(unittest.TestCase):
    """Actual two peer functions with finite inert capabilities, never a peer import."""

    def model(self, blocks, *, redirect=True, unexpected_slot=None, simultaneous=False):
        peer = SOURCE / "desktop/src-tauri/tests/fixtures/github_tls_peer.py"
        parsed = ast.parse(peer.read_bytes(), filename=str(peer))
        names = {"no_pending", "complete_listener_observation"}
        definitions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in definitions}, names)
        self.assertEqual(len(definitions), 2)
        for definition in definitions:
            self.assertFalse(definition.decorator_list or definition.args.defaults or definition.args.kw_defaults)
            self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(definition)))

        class Refused(Exception):
            pass
        test, control, accepted = self, object(), object()
        reads, accepts, transitions = [], [], []
        pending_blocks, ticks = list(blocks), []
        class Listener:
            def __init__(self, slot):
                self.slot = slot
                self.blocking = None
            def setblocking(self, value):
                test.assertIs(value, False)
                self.blocking = value
                transitions.append((self.slot, "nonblocking"))
            def accept(self):
                test.assertIs(self.blocking, False)
                accepts.append(self.slot)
                if self.slot == unexpected_slot:
                    return accepted, ("inert-address", 0)
                raise BlockingIOError("inert empty listener")
        primary, sink = Listener(0), Listener(1) if redirect else None
        unexpected = [None, None]
        completion = {"bytes": 0, "eof": False, "closed": False, "primaryEmpty": False,
            "primaryUnexpected": 0, "primaryClosed": False,
            "redirect": {"empty": False, "unexpected": 0, "closed": False} if redirect else None}
        def require(condition, code):
            if not condition:
                raise Refused(code)
        def remaining():
            ticks.append(None)
            require(len(ticks) <= 24, "deadline")
            return 1.0
        def select(readers, writers, errors, timeout):
            test.assertEqual(readers, [primary, control] + ([sink] if sink is not None else []))
            test.assertEqual((writers, errors, timeout), ([], [], 1.0))
            require(bool(pending_blocks), "deadline")  # Finite exhausted schedule, never a hang.
            if simultaneous:
                endpoint = primary if unexpected_slot == 0 else sink
                test.assertIsNotNone(endpoint)
                return [control, endpoint], [], []
            return [control], [], []
        def read(descriptor, maximum):
            test.assertIs(descriptor, control)  # Opaque object, not an actual FD.
            test.assertIn(maximum, (1, 2))
            block = pending_blocks.pop(0)
            test.assertLessEqual(len(block), maximum)
            reads.append(block)
            return block
        namespace = {"__builtins__": {"len": len, "enumerate": enumerate, "bytearray": bytearray,
            "BlockingIOError": BlockingIOError}, "Refused": Refused, "require": require, "remaining": remaining,
            "select": SimpleNamespace(select=select), "os": SimpleNamespace(read=read)}
        unit = ast.Module(body=definitions, type_ignores=[])
        # Postponed annotations require no socket import. Only exact function
        # definitions execute: no containing imports, initialization or main.
        exec(compile(unit, str(peer), "exec", flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
        return SimpleNamespace(run=lambda: namespace["complete_listener_observation"](
            primary, sink, control, unexpected, completion), no_pending=namespace["no_pending"],
            refused=Refused, completion=completion, unexpected=unexpected, accepted=accepted,
            primary=primary, sink=sink, reads=reads, accepts=accepts, transitions=transitions)

    def test_original_listener_completion_requires_exact_signal_and_eof(self):
        for redirect in (False, True):
            model = self.model([b"S", b""], redirect=redirect)
            model.run()
            self.assertEqual(model.reads, [b"S", b""])
            self.assertEqual(model.accepts, [0, 1] if redirect else [0])
            self.assertEqual((model.completion["bytes"], model.completion["eof"], model.completion["primaryEmpty"]), (1, True, True))
            self.assertFalse(model.completion["closed"] or model.completion["primaryClosed"])
            if redirect:
                self.assertEqual(model.completion["redirect"], {"empty": True, "unexpected": 0, "closed": False})
            self.assertEqual(model.unexpected, [None, None])
        for blocks, reason in (([], "deadline"), ([b"S"], "deadline"), ([b""], "control"),
                               ([b"X"], "control"), ([b"SS"], "control"), ([b"S", b"X"], "control")):
            with self.subTest(blocks=blocks):
                model = self.model(blocks)
                with self.assertRaisesRegex(model.refused, "^" + reason + "$"):
                    model.run()
                self.assertFalse(model.completion["primaryEmpty"] or model.completion["redirect"]["empty"])
                self.assertEqual(model.accepts, [])

    def test_unexpected_connection_wins_simultaneous_control_and_is_retained(self):
        for slot in (0, 1):
            model = self.model([b"S", b""], unexpected_slot=slot, simultaneous=True)
            with self.assertRaisesRegex(model.refused, "^unexpected-connection$"):
                model.run()
            self.assertEqual(model.reads, [])  # Pending accept won even though control was listed first.
            self.assertIs(model.unexpected[slot], model.accepted)
            self.assertEqual(model.accepts, [slot])
            self.assertFalse(model.completion["primaryEmpty"] or model.completion["eof"])
            target = model.primary if slot == 0 else model.sink
            # The retained original cannot be replaced or drained by another
            # observation. This routine never supplies the later sole-close fact.
            with self.assertRaisesRegex(model.refused, "^unexpected-connection$"):
                model.no_pending(target, slot, model.unexpected, model.completion)
            self.assertEqual(model.accepts, [slot])
            self.assertIs(model.unexpected[slot], model.accepted)

    def test_final_probe_refuses_original_primary_and_redirect_accepts(self):
        for slot in (0, 1):
            model = self.model([b"S", b""], unexpected_slot=slot)
            with self.assertRaisesRegex(model.refused, "^unexpected-connection$"):
                model.run()
            self.assertEqual(model.reads, [b"S", b""])
            self.assertTrue(model.completion["eof"])
            self.assertEqual(model.accepts, [0] if slot == 0 else [0, 1])
            self.assertIs(model.unexpected[slot], model.accepted)
            self.assertEqual(model.completion["primaryUnexpected"], 1 if slot == 0 else 0)
            self.assertEqual(model.completion["primaryEmpty"], slot == 1)
            self.assertEqual(model.completion["redirect"]["unexpected"], slot)
            self.assertFalse(model.completion["redirect"]["empty"] or model.completion["closed"])


class GitHubTLSReceiptContractTests(unittest.TestCase):
    def reject_at(self, path, replacement):
        report = github_tls_report_data()
        target = report
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        with self.subTest(path=path, value=replacement), self.assertRaises(helper.CheckFailure):
            helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data())

    def test_tls_supplied_sixteen_case_data_is_not_execution_or_outer_finality(self):
        report = github_tls_report_data()
        self.assertEqual(tuple(row[0] for row in TLS_CASE_ROWS), helper.GITHUB_TLS_CASES)
        self.assertEqual(helper.GITHUB_TLS_STREAMING,
            {row[0]: (row[2], *TLS_STREAMING_REPLIES[row[0]]) for row in TLS_CASE_ROWS[9:]})
        self.assertEqual(TLS_NOT_VERIFIED, list(helper.GITHUB_TLS_NOT_VERIFIED))
        self.assertIs(report, helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data()))
        raw = json.dumps(report, separators=(",", ":")).encode("utf-8")
        self.assertEqual(report, helper.parse_github_tls_receipt(raw, bindings=github_tls_binding_data()))
        self.assertNotIn("outer", report)
        for original in report["cases"][:9]:
            self.assertNotIn("projection", original["product"])
            self.assertNotIn("control", original["peer"])
            self.assertNotIn("completion", original["peer"]["terminal"])
            self.assertNotIn("replyStops", original["peer"]["terminal"])
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
                ("cases", [report["cases"][0]] * 16), ("notVerified", TLS_NOT_VERIFIED[:-1])):
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
        # not a sixteen-case Cartesian replay of the same structural validator.
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

    def test_tls_streaming_control_and_peer_completion_are_independent_closed_facts(self):
        report = github_tls_report_data()
        # One representative exercises the shared writer and completion schema.
        # These DATA checks do not execute the actual writer or listener loop.
        control = report["cases"][9]["peer"]["control"]
        completion = report["cases"][9]["peer"]["terminal"]["completion"]
        for key, value in control.items():
            for wrong in (not value, int(value)):
                self.reject_at(("cases", 9, "peer", "control", key), wrong)
        for replacement in (None, {**control, "extra": True}, {key: value for key, value in control.items() if key != "released"}):
            self.reject_at(("cases", 9, "peer", "control"), replacement)
        for key, wrong in (("bytes", 0), ("bytes", True), ("eof", False), ("closed", False), ("primaryEmpty", False),
                ("primaryUnexpected", 1), ("primaryUnexpected", False), ("primaryClosed", False), ("redirect", {}), ("extra", True)):
            self.reject_at(("cases", 9, "peer", "terminal", "completion", key), wrong)
        for replacement in (None, {key: value for key, value in completion.items() if key != "redirect"}):
            self.reject_at(("cases", 9, "peer", "terminal", "completion"), replacement)
        for key, wrong in (("empty", False), ("unexpected", 1), ("unexpected", False), ("closed", False), ("extra", True)):
            self.reject_at(("cases", 15, "peer", "terminal", "completion", "redirect", key), wrong)
        self.reject_at(("cases", 15, "peer", "terminal", "completion", "redirect"), None)
        self.reject_at(("cases", 9, "product", "settled"), False)
        self.reject_at(("cases", 9, "peer", "withinEndpoint"), False)
        for path, value in ((("peer", "control"), control), (("peer", "terminal", "completion"), completion),
                            (("peer", "terminal", "replyStops"), ["none"] * 4),
                            (("product", "projection"), report["cases"][9]["product"]["projection"])):
            self.reject_at(("cases", 0, *path), value)  # New fields cannot reinterpret an old-nine receipt.

    def test_tls_streaming_reply_stops_require_case_local_actual_progress(self):
        stops = ("none", "reply:broken-pipe", "reply:connection-reset", "reply:tls-eof", "reply:tls-close-notify",
                 "notify:broken-pipe", "notify:connection-reset", "notify:tls-eof", "notify:tls-close-notify")
        self.assertEqual(set(stops), helper.GITHUB_TLS_REPLY_STOPS)
        for stop in stops:
            report = github_tls_report_data()
            terminal = report["cases"][9]["peer"]["terminal"]
            minimum = 32768 if stop.startswith("reply:") else 40630
            terminal.update(replyStops=[stop], replyBytes=[minimum], wireWriteBytes=[minimum],
                            closeNotify=int(stop == "none"))
            self.assertIs(report, helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data()))
            # Typed known-close categories never waive actual sent progress.
            terminal["wireWriteBytes"] = [minimum - 1]
            with self.subTest(stop=stop), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data())
        for index, (name, *_rest) in enumerate(TLS_CASE_ROWS[9:], start=9):
            if name == "T6-target":
                self.reject_at(("cases", index, "peer", "terminal", "replyStops"), ["notify:broken-pipe"] * 4)
                continue
            report = github_tls_report_data()
            terminal = report["cases"][index]["peer"]["terminal"]
            minimum = TLS_STREAMING_REPLIES[name][1][0]
            terminal.update(replyStops=["reply:broken-pipe"], replyBytes=[minimum], wireWriteBytes=[minimum], closeNotify=0)
            self.assertIs(report, helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data()))
            terminal["replyBytes"] = [minimum - 1]
            with self.subTest(case=name), self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data())
        for key, wrong in (("replyStops", []), ("replyStops", ["none", "none"]), ("replyStops", [None]),
                ("replyStops", [{}]), ("replyStops", ["reply:timeout"]), ("replyStops", ["reply:OSError"]),
                ("replyStops", ["none\n"]), ("replyBytes", [40629]), ("replyBytes", [40631]),
                ("closeNotify", 0), ("closeNotify", True)):
            self.reject_at(("cases", 9, "peer", "terminal", key), wrong)
        # Body-only upper bounds must not leak to either old or new small cases.
        for index, wire, reply in ((0, 128 * 1024, 64 * 1024), (9, 128 * 1024, 64 * 1024),
                                   (10, 512 * 1024, 320 * 1024)):
            connections = TLS_CASE_ROWS[index][1]
            for key, limit in (("wireReadBytes", wire), ("wireWriteBytes", wire), ("replyBytes", reply)):
                self.reject_at(("cases", index, "peer", "terminal", key), [limit + 1] * connections)

    def test_tls_streaming_cooldown_and_target_projections_are_distinct(self):
        for index, changes in (
                (9, (("account", "observed"), ("cooldownSeconds", 120))),
                (13, (("cooldownSeconds", None), ("cooldownSeconds", 7200), ("cooldownSeconds", 120.0),
                      ("credentialExpiresAt", "2030-01-01T00:00:00Z"), ("cooldownBlocked", True))),
                (14, (("account", "unavailable"), ("repository", "observed"), ("automation", "observed"),
                      ("repositoryValue", {"id": "23"}), ("accountObservedAt", "2030-01-01T00:00:00Z")))):
            for key, wrong in changes:
                self.reject_at(("cases", index, "product", "projection", key), wrong)
        for index in (9, 13, 14):
            projection = github_tls_report_data()["cases"][index]["product"]["projection"]
            for replacement in (None, {**projection, "extra": True},
                                {key: value for key, value in projection.items() if key != "credentialExpiresAt"}):
                self.reject_at(("cases", index, "product", "projection"), replacement)

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
    PHASES = ("prepare", "acquire", "compile", "github-tls", "github-tls-deadline", "clean")
    CHECKS = {
        "acquire": ("rust-toolchain-install", "rust-version-target", "github-tls-locked-headless-metadata"),
        "compile": ("rust-version-target", "github-tls-headless-test-compile-only", "github-tls-compiled-artifact"),
        "github-tls": ("github-tls-original-artifact", "github-tls-original-outer-wait", "github-tls-receipt"),
        "github-tls-deadline": ("github-tls-original-artifact", "github-tls-hosts-original-outer-wait",
                                "github-tls-hosts-receipt", "github-tls-dns-original-outer-wait", "github-tls-dns-receipt"),
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
            "workflowSha256": "4" * 64, "runId": "123", "attempt": "2", "tlsInputsSha256": "9" * 64, "tlsDeadlineInputsSha256": "6" * 64,
            "originalDirectories": {"inert": "original identities supplied separately"},
            "observedHost": {"kernelRelease": "inert-6.8", "machine": "x86_64", "nonRoot": True,
                "filesystem": {"device": "7", "blockSize": 4096, "fragmentSize": 4096, "nameMax": 255, "flags": 0}}}
        context["tlsInputs"] = cls.input_summary(context, cls.manifest(context))
        context["tlsDeadlineInputs"] = cls.input_summary(context, cls.deadline_manifest(context))
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
        names = {*roles.values(), "/inert/tls/lib/libc.so.6", *(str(source / name) for name in helper.GITHUB_TLS_SOURCES),
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
    def deadline_manifest(cls, context):
        value = cls.manifest(context)
        root = PurePosixPath(context["root"])
        removed = {value["roles"][name] for name in cls.CONFIG}
        roles = {key: path for key, path in value["roles"].items() if key not in cls.CONFIG}
        roles.update({f"{profile}:{name}": str(root / f"github-tls-deadline-namespace-{profile}" / name)
                      for profile in ("hosts", "dns-withhold") for name in cls.CONFIG})
        roles.update({"libc": "/inert/tls/lib/libc.so.6", "resolver:host.conf": "/etc/host.conf", "resolver:gai.conf": "/etc/gai.conf"})
        records = {row["path"]: row for row in value["files"] if row["path"] not in removed}
        for pathname in roles.values():
            if pathname not in records:
                records[pathname] = {"path": pathname, "size": 32, "sha256": "5" * 64}
        return {**value, "scope": "github-readonly-tls-deadline-native-v1", "roles": roles,
                "resolver": {"family": "glibc", "version": "2.39", "nss": "builtin-files-dns"},
                "files": [records[name] for name in sorted(records)]}

    @classmethod
    def input_summary(cls, context, manifest):
        source = PurePosixPath(context["source"])
        by_path = {row["path"]: row for row in manifest["files"]}
        def row(path, name):
            return {"path": name, "size": by_path[str(path)]["size"], "sha256": by_path[str(path)]["sha256"]}
        value = {"sourceFiles": [row(source / name, name) for name in helper.GITHUB_TLS_SOURCES],
            "coreFiles": [row(source / "src" / name, name) for name in helper.GTK_CORE_PATHS],
            "coreZipSha256": by_path[manifest["coreZip"]]["sha256"], "pythonSha256": by_path[manifest["python"]]["sha256"],
            "pythonBytes": by_path[manifest["python"]]["size"], "closureFiles": len(by_path),
            "closureBytes": sum(item["size"] for item in by_path.values()),
            "closureSha256": hashlib.sha256(cls.encoded(manifest["files"])).hexdigest(), "ssl": manifest["ssl"],
            "roles": {name: {key: by_path[path][key] for key in ("size", "sha256")} for name, path in manifest["roles"].items()}}
        if "resolver" in manifest:
            value["resolver"] = manifest["resolver"]
        return value

    @classmethod
    def artifact(cls):
        return {"schemaVersion": 1, "scope": cls.SCOPE, "sourceSha": "1" * 40, "sourceTree": "3" * 40,
            "tlsInputsSha256": "9" * 64, "tlsDeadlineInputsSha256": "6" * 64,
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
    def outer(cls, context, profile=None):
        return {"schemaVersion": 1, "scope": "github-readonly-tls-original-outer-v1" if profile is None else "github-readonly-tls-deadline-original-outer-v1",
            **({"profile": profile} if profile is not None else {}),
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
            "tlsInputsSha256": context["tlsInputsSha256" if profile is None else "tlsDeadlineInputsSha256"],
            "artifactSha256": "a" * 64, "artifactBytes": 144,
            "artifactIdentitySha256": hashlib.sha256(cls.encoded(cls.artifact()["identity"])).hexdigest(),
            "status": "passed", "waitObserved": True, "exitCode": 0, "timedOut": False,
            "elapsedMs": 125, "stdoutBytes": 256, "stderrBytes": 0}

    @classmethod
    def claim(cls, context, name):
        return {"scope": cls.SCOPE, "phase": name,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256", "tlsDeadlineInputsSha256")}}

    @classmethod
    def phase_report(cls, context, name):
        value = {"schemaVersion": 1, "scope": cls.EVIDENCE, "phase": name, "status": "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "tlsInputsSha256", "tlsDeadlineInputsSha256")},
            "inputSha256": hashlib.sha256(cls.encoded(context["tlsInputs"])).hexdigest(),
            "deadlineInputSha256": hashlib.sha256(cls.encoded(context["tlsDeadlineInputs"])).hexdigest(),
            "rust": {"release": helper.RUST, "target": "x86_64-unknown-linux-gnu"},
            "checks": [{"check": check, "exitCode": 0} for check in cls.CHECKS[name]]}
        if name in ("compile", "github-tls", "github-tls-deadline"):
            value["compiledTest"] = cls.compiled_public()
        if name == "github-tls":
            value.update(nativeReceiptSha256="d" * 64, outer=cls.outer(context))
        if name == "github-tls-deadline":
            value["profiles"] = cls.deadline_result(context)
        return value

    @classmethod
    def deadline_result(cls, context):
        return {profile: {"nativeReceiptSha256": digest * 64, "outer": cls.outer(context, profile)}
                for profile, digest in (("hosts", "e"), ("dns-withhold", "f"))}

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

    def test_tls_core_producer_and_both_summaries_include_current_metadata(self):
        # The real bounded SOURCE producer is the independent oracle, not a
        # second fixture regenerated solely from the consumer's literal tuple.
        metadata = {"mobile_release/api/_metadata_text.py",
                    "mobile_release/api/data/metadata-text-help-v1.json",
                    "mobile_release/metadata_text.py", "mobile_release/metadata_text_edit.py",
                    "mobile_release/api/_candidate_evidence.py",
                    "mobile_release/api/_release_version.py",
                    "mobile_release/api/_environment.py", "mobile_release/toolchain_policy.py",
                    "mobile_release/_desktop_environment_protocol.py", "mobile_release/_desktop_environment_control.py",
                    "mobile_release/_desktop_environment_engine.py", "mobile_release/environment_diagnostics.py",
                    "mobile_release/environment_diagnostics_tools.py"}
        context, forbidden = self.context(), self.forbidden
        with patch.multiple(helper, github_tls_runtime=forbidden, github_tls_file=forbidden,
                read_bounded_json=forbidden, write_json=forbidden, run=forbidden, tools=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden), \
                patch.object(helper.subprocess, "Popen", side_effect=forbidden):
            inventory = helper.workflow_core_inventory(SOURCE)
            self.assertEqual(len(inventory), 85)
            self.assertTrue(metadata <= {row["path"] for row in inventory})
            helper.validate_gtk_core_inventory(inventory)
            with patch.multiple(helper, Path=PurePosixPath, ordinary=forbidden, hash_file=forbidden,
                    workflow_core_inventory=forbidden):
                source = PurePosixPath(context["source"]) / "src"
                for deadline in (False, True):
                    manifest = self.deadline_manifest(context) if deadline else self.manifest(context)
                    records = {row["path"]: row for row in manifest["files"]}
                    for row in inventory:
                        name = str(source / row["path"])
                        records[name] = {**row, "path": name}
                    manifest["files"] = [records[name] for name in sorted(records)]
                    with self.subTest(deadline=deadline):
                        helper.validate_github_tls_manifest(manifest, context=context, deadline=deadline)
                        self.assertEqual(helper.github_tls_input_summary(context, manifest)["coreFiles"], inventory)
                    for name in sorted(metadata):
                        missing = deepcopy(manifest)
                        missing["files"] = [row for row in missing["files"] if row["path"] != str(source / name)]
                        with self.subTest(deadline=deadline, missing=name), self.assertRaises(helper.CheckFailure):
                            helper.validate_github_tls_manifest(missing, context=context, deadline=deadline)

    def test_tls_prepare_refuses_stale_or_unreviewed_core_before_capability_access(self):
        metadata = {"mobile_release/api/_metadata_text.py",
                    "mobile_release/api/data/metadata-text-help-v1.json",
                    "mobile_release/metadata_text.py", "mobile_release/metadata_text_edit.py"}
        environment = {"mobile_release/api/_environment.py", "mobile_release/toolchain_policy.py"}
        diagnostics = {"mobile_release/_desktop_environment_protocol.py", "mobile_release/_desktop_environment_control.py",
                        "mobile_release/_desktop_environment_engine.py", "mobile_release/environment_diagnostics.py",
                        "mobile_release/environment_diagnostics_tools.py"}
        release_version = {"mobile_release/api/_release_version.py"}
        candidate_evidence = {"mobile_release/api/_candidate_evidence.py"}
        inventory = [{"path": name, "size": 1, "sha256": "4" * 64} for name in helper.GTK_CORE_PATHS]
        # Historical snapshots exclude every later addition; do not relabel
        # their original72/76/78/83-file coverage as a new larger inventory.
        stale = [row for row in inventory if row["path"] not in metadata | environment | diagnostics | release_version | candidate_evidence]
        pre_environment = [row for row in inventory if row["path"] not in environment | diagnostics | release_version | candidate_evidence]
        pre_diagnostics = [row for row in inventory if row["path"] not in diagnostics | release_version | candidate_evidence]
        pre_version = [row for row in inventory if row["path"] not in release_version | candidate_evidence]
        pre_candidate = [row for row in inventory if row["path"] not in candidate_evidence]
        self.assertEqual(len(stale), 72)
        self.assertEqual(len(pre_environment), 76)
        self.assertEqual(len(pre_diagnostics), 78)
        self.assertEqual(len(pre_version), 83)
        self.assertEqual(len(pre_candidate), 84)
        extra = [*inventory, {"path": "mobile_release/unreviewed.py", "size": 1, "sha256": "4" * 64}]
        context, forbidden = self.context(), self.forbidden
        before = deepcopy(context)
        with patch.multiple(helper, Path=forbidden, github_tls_runtime=forbidden, github_tls_manifest=forbidden,
                github_tls_deadline_manifest=forbidden, github_tls_directories=forbidden, workflow_host=forbidden,
                ordinary=forbidden, hash_file=forbidden, read_bounded_json=forbidden, write_json=forbidden,
                run=forbidden, tools=forbidden), \
                patch.object(helper.subprocess, "run", side_effect=forbidden), \
                patch.object(helper.subprocess, "Popen", side_effect=forbidden):
            for value, count in ((stale, 72), (pre_environment, 76), (pre_diagnostics, 78), (pre_version, 83), (pre_candidate, 84), (extra, 86)):
                with self.subTest(count=count), self.assertRaises(helper.CheckFailure) as refused:
                    helper.prepare_github_tls_context(context, value)
                self.assertEqual(str(refused.exception),
                    f"Reviewed core inventory count differs: expected 85 files, observed {count}")
                self.assertEqual(context, before)

    def test_tls_manifest_roles_source_ca_ssl_and_file_bounds_are_closed_data(self):
        context, forbidden = self.context(), self.forbidden
        manifest = self.manifest(context)
        self.assertEqual(helper.GITHUB_TLS_CERTIFICATES, self.CERTIFICATES)
        self.assertEqual(helper.GITHUB_TLS_TOOLS, self.TOOLS)
        self.assertEqual(helper.GITHUB_TLS_CONFIG, self.CONFIG)
        self.assertEqual(set(helper.GITHUB_TLS_SOURCES) - set(helper.GITHUB_READONLY_SOURCES), {
            self.WORKFLOW, "desktop/src-tauri/tests/fixtures/github_tls_peer.py",
            "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh", "tests/desktop/test_github_tls_deadline_peer_contract.py",
            "desktop/github-connection-contract.md", "tests/desktop/test_github_tls_peer_compile.py",
            "tests/desktop/test_github_tls_resolver_policy.py",
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
        deadline = self.deadline_manifest(context)
        library = PurePosixPath(manifest["roles"]["ssl"]).parent
        expected = {PurePosixPath(row["path"]) for row in manifest["files"] if library in PurePosixPath(row["path"]).parents}
        rows = {row["path"]: row for value in (manifest, deadline) for row in value["files"]}

        def exercise(mutation):
            events = []
            def record(path, **kwargs):
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
                    github_tls_deadline_resolver_file=record,
                    github_tls_stdlib_files=roster, run=forbidden, tools=forbidden, ordinary=forbidden,
                    source_unchanged=forbidden, write_json=forbidden), \
                    patch.object(helper, "github_tls_directories", return_value=context["originalDirectories"]), \
                    patch.object(helper, "hash_file", side_effect=lambda path: "f" * 64 if mutation == "anchor" or mutation == "deadline-anchor" and path.name == "github-tls-deadline-inputs.json"
                                 else "6" * 64 if path.name == "github-tls-deadline-inputs.json" else "9" * 64), \
                    patch.object(helper, "read_bounded_json", side_effect=lambda path, limit: deepcopy(deadline if path.name == "github-tls-deadline-inputs.json" else manifest)), \
                    patch.object(helper, "github_tls_namespaces", return_value={"parentNetns": "net:[999]" if mutation == "namespace" else "net:[100]", "parentMntns": "mnt:[200]"}), \
                    patch.object(helper.os, "geteuid", return_value=1000, create=True), \
                    patch.object(helper.os, "getegid", return_value=1000, create=True), \
                    patch.object(helper.os.path, "lexists", side_effect=lambda path: mutation == "cache" and str(path) == "/run/nscd/socket"), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if mutation:
                    with test.assertRaises(helper.CheckFailure):
                        helper.github_tls_inputs_unchanged(context)
                else:
                    helper.github_tls_inputs_unchanged(context)
            if mutation in ("anchor", "deadline-anchor", "namespace"):
                test.assertEqual(events, [])
            elif mutation in ("added-cache", "cache"):
                test.assertEqual(events, [("roster", str(library))])
            else:
                ordered = sorted(rows)
                if mutation == "bytes":
                    ordered = ordered[:ordered.index(manifest["roles"]["server-key.pem"]) + 1]
                test.assertEqual(events, [("roster", str(library)), *(("file", path) for path in ordered)])

        for mutation in (None, "anchor", "deadline-anchor", "namespace", "added-cache", "cache", "bytes"):
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
                ("tlsInputsSha256", "f" * 64), ("tlsDeadlineInputsSha256", "9" * 64),
                ("tlsDeadlineInputsSha256", None), ("schemaVersion", True), ("size", 145), ("sha256", "e" * 64),
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
        deadline = self.deadline_manifest(context)
        with patch.object(helper, "Path", PurePosixPath):
            for profile in ("hosts", "dns-withhold"):
                self.assertEqual(helper.github_tls_expected_bindings(context, compiled, deadline, profile=profile), tls_deadline_binding_data())
                scoped = helper.github_tls_launch_argv(context, compiled, deadline, profile=profile)
                self.assertEqual(scoped, [*launch[:23], "6" * 64, *launch[24:], profile])
                self.assertEqual(len(scoped[15:]), 13)
                with self.assertRaises(helper.CheckFailure):
                    helper.github_tls_launch_argv(context, compiled, manifest, profile=profile)
            for profile in (True, "dns", "hosts-extra", "", "T5-read"):
                with self.subTest(foreign_profile=profile), self.assertRaises(helper.CheckFailure):
                    helper.github_tls_launch_argv(context, compiled, deadline, profile=profile)
            with self.assertRaises(helper.CheckFailure):
                helper.github_tls_launch_argv(context, compiled, deadline)

    def test_tls_original_outer_wait_not_inner_assertion_controls_success(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root = PurePosixPath(context["root"])
        base_environment = {"PATH": "/inert/no-executables", "HOME": str(root / "home")}
        original_validate = helper.validate_github_tls_outer
        diagnostic_faults = {"diagnostic-pipe": BrokenPipeError, "diagnostic-shape": ValueError}
        for profile, outcome in ((profile, outcome) for profile in (None, "hosts", "dns-withhold")
                                 for outcome in (0, 7, "timeout", "oserror", "subprocess-error", *diagnostic_faults, "existing")):
            manifest = self.manifest(context) if profile is None else self.deadline_manifest(context)
            expected = self.outer(context, profile)
            stem = "github-tls" if profile is None else f"github-tls-deadline-{profile}"
            inputs = "github-tls-inputs.json" if profile is None else "github-tls-deadline-inputs.json"
            seconds = {None: 300, "hosts": 180, "dns-withhold": 60}[profile]
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
                    test.assertIn(self.name, (f"{stem}.stdout", f"{stem}.stderr"))
                    test.assertNotIn(self.name, streams)
                    streams[self.name] = Writer(self.name)
                    events.append(("open", self.name))
                    return streams[self.name]
                def stat(self):
                    test.assertTrue(all(stream.closed for stream in streams.values()))
                    test.assertIn(self.name, streams)
                    return SimpleNamespace(st_size=256 if self.name.endswith("stdout") else 0)
            def read(path, limit):
                test.assertEqual((path, limit), (root / inputs, 1024 * 1024))
                return deepcopy(manifest)
            def process(argv, **kwargs):
                events.append(("run", "original-outer"))
                test.assertEqual(argv, helper.github_tls_launch_argv(context, compiled, manifest, profile=profile))
                test.assertEqual(set(kwargs), {"cwd", "env", "stdin", "stdout", "stderr", "check", "timeout", "preexec_fn"})
                test.assertEqual((kwargs["cwd"], kwargs["env"], kwargs["stdin"], kwargs["check"], kwargs["timeout"]),
                                 (root, base_environment, subprocess.DEVNULL, False, seconds))
                test.assertIs(kwargs["preexec_fn"], helper.github_tls_outer_limits)
                test.assertIs(kwargs["stdout"], streams[f"{stem}.stdout"])
                test.assertIs(kwargs["stderr"], streams[f"{stem}.stderr"])
                test.assertFalse(any(stream.closed for stream in streams.values()))
                if outcome == "timeout":
                    raise subprocess.TimeoutExpired("private-inert-command", seconds)
                if outcome == "oserror":
                    raise OSError("private-inert-error")
                if outcome == "subprocess-error":
                    raise subprocess.SubprocessError("private-inert-preexec")
                return subprocess.CompletedProcess(argv, 7 if outcome in diagnostic_faults else outcome)
            def emit(path, value):
                test.assertEqual(path, root / f"{stem}-outer.json")
                test.assertTrue(all(stream.closed for stream in streams.values()))
                test.assertFalse(written)
                written.update(deepcopy(value))
                events.append(("write", "original-outer"))
            def diagnose(actual_context, actual_compiled, original, launch_error, **routing):
                test.assertEqual((actual_context, actual_compiled), (context, compiled))
                test.assertEqual(routing, {"profile": profile})
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
            with self.subTest(profile=profile, outer=outcome), patch.multiple(helper, Path=OuterPath, read_bounded_json=read,
                    write_json=emit, run=forbidden, tools=forbidden, github_tls_result=forbidden,
                    github_tls_runtime=forbidden, hash_file=forbidden, github_tls_failure_diagnostics=diagnose,
                    validate_github_tls_outer=validate), \
                    patch.object(helper, "clean_environment", return_value=base_environment), \
                    patch.object(helper.time, "monotonic", side_effect=[10.0, 10.125]), \
                    patch.object(helper.os.path, "lexists", return_value=outcome == "existing"), \
                    patch.object(helper.subprocess, "run", side_effect=process), \
                    patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if outcome == 0:
                    self.assertEqual(helper.github_tls_run_outer(context, compiled, profile=profile), expected)
                else:
                    with self.assertRaises(helper.CheckFailure) as caught:
                        helper.github_tls_run_outer(context, compiled, profile=profile)
                    self.assertNotIn("private-inert", str(caught.exception))
                    if outcome != "existing":
                        self.assertEqual(len(failures), 1)
                        self.assertIs(caught.exception, failures[0])
            if outcome == "existing":
                self.assertEqual(events, [])
                self.assertEqual(written, {})
                self.assertEqual(diagnostics, [])
                continue
            self.assertEqual(events, [("open", f"{stem}.stdout"), ("open", f"{stem}.stderr"),
                ("run", "original-outer"), ("close", f"{stem}.stderr"), ("close", f"{stem}.stdout"), ("write", "original-outer")])
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
        for profile in (None, "hosts", "dns-withhold"):
            expected = self.outer(context, profile)
            seconds = {None: 300, "hosts": 180, "dns-withhold": 60}[profile]
            for key, value in (("waitObserved", 1), ("status", "unknown"), ("exitCode", False), ("timedOut", True),
                    ("elapsedMs", seconds * 1000 + 1), ("stdoutBytes", 1048577), ("artifactIdentitySha256", "f" * 64),
                    ("tlsInputsSha256", "f" * 64), ("profile", "other"), ("outerWait", "passed")):
                with self.subTest(profile=profile, forged_outer=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_outer({**expected, key: value}, context=context, compiled=compiled, profile=profile)
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
        for stage, code in (("admission", "profile"), ("resolver-inputs", "resolver-cache"), ("final-bindings", "ambient"),
                            *((stage, code) for stage in ("resource-limits", "final-resource-limits")
                              for code in ("limit-units", "limit-core", "limit-file", "limit-descriptors", "limit-address-space"))):
            self.assertEqual(helper.github_tls_namespace_refusal(f"github-tls-namespace: {stage}/{code}\n".encode("ascii")),
                             {"stage": stage, "code": code})
        for raw in (None, "github-tls-namespace: host-resolver/file-owner\n", b"", frame[:-1],
                b"private-path\n" + frame, frame + b"private-token", frame * 2,
                frame.replace(b"host-resolver", b"private-identity"), frame.replace(b"file-owner", b"unknown"),
                frame.replace(b"/", b"\xff"), frame + b"\0", b"x" * 65537):
            with self.subTest(kind=type(raw).__name__, size=len(raw) if raw is not None else None):
                self.assertIsNone(helper.github_tls_namespace_refusal(raw))

    def test_tls_admission_diagnostics_accept_only_original_closed_profile_frames(self):
        for profile in (None, "hosts", "dns-withhold"):
            selected = "original" if profile is None else profile
            for code in helper.GITHUB_TLS_ADMISSION_CODES:
                frame = f"github-tls-admission: {selected}/{code}\n".encode("ascii")
                self.assertLessEqual(len(frame), 256)
                self.assertEqual(helper.github_tls_admission_refusal(frame, profile=profile),
                                 {"stage": "admission", "profile": selected, "code": code})
            frame = f"github-tls-admission: {selected}/tls_libc_maps\n".encode("ascii")
            other = "hosts" if profile != "hosts" else "dns-withhold"
            for raw in (None, frame.decode(), b"", frame[:-1], b"private-path\n" + frame,
                        frame + b"private-token", frame * 2, frame.replace(b"tls_libc_maps", b"private_identity"),
                        frame.replace(b"/", b"\xff"), frame + b"\0", b"x" * 257,
                        f"github-tls-admission: {other}/tls_libc_maps\n".encode("ascii")):
                with self.subTest(profile=profile, raw_kind=type(raw).__name__):
                    self.assertIsNone(helper.github_tls_admission_refusal(raw, profile=profile))
        for profile in (True, "dns", "", "unclassified", "hosts/other", ["hosts"]):
            self.assertIsNone(helper.github_tls_admission_refusal(b"github-tls-admission: hosts/tls_libc_maps\n", profile=profile))

    def test_tls_admission_diagnostic_vocabulary_and_exit_are_source_bound(self):
        rust = (SOURCE / "desktop/src-tauri/src/hosted_tests.rs").read_text(encoding="utf-8")
        start = rust.index("    const ADMISSION_CODES: &[&str] = &[")
        literal = rust[start:rust.index("    ];", start)]
        codes = literal.split('"')[1::2]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(set(codes), helper.GITHUB_TLS_ADMISSION_CODES)
        self.assertIn("tls_admission_unclassified", codes)
        self.assertTrue({"tls_deadline_privilege_inheritable", "tls_deadline_privilege_permitted",
                         "tls_deadline_privilege_effective", "tls_deadline_privilege_bounding",
                         "tls_deadline_privilege_ambient", "tls_deadline_privilege_nonewprivs",
                         "tls_deadline_privilege_groups", "tls_deadline_privilege_drop"}.issubset(codes))
        self.assertTrue({"tls_resource_core", "tls_resource_file", "tls_resource_descriptors",
                         "tls_resource_address_space"}.issubset(codes))
        common = rust[rust.index("    struct Admitted { inputs: Inputs, common: Arc<Common> }"):]
        self.assertLess(common.index("admit_resource_limits()?;"), common.index("let anchor ="))
        self.assertEqual(rust.count("admit_resource_limits()?;"), 1)
        self.assertEqual(rust.count("refuse_before_cases("), 3)  # Definition + exactly two pre-case calls.
        self.assertIn("Err(code) => refuse_before_cases(None, code)", rust)
        self.assertIn("Err(code) => refuse_before_cases(Some(profile), code)", rust)
        start = rust.index("    fn refuse_before_cases(")
        refusal = rust[start:rust.index("    fn sha(value:", start)]
        self.assertIn("write_all(frame.as_bytes())", refusal)
        self.assertIn("std::process::exit(101)", refusal)
        self.assertNotIn("eprintln!", refusal)
        self.assertNotIn("set_hook", refusal)

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
        for profile in (None, "hosts", "dns-withhold"):
            phase = "github-tls" if profile is None else "github-tls-deadline"
            stem = "github-tls" if profile is None else f"github-tls-deadline-{profile}"
            outer = {**self.outer(context, profile), "status": "failed", "exitCode": 71, "stderrBytes": 53}
            # A private field in an observation must not be copied into public output.
            outer["private"] = "private-token-and-path"
            admission = f"github-tls-admission: {'original' if profile is None else profile}/tls_libc_maps\n".encode("ascii")
            for raw, write_fails in ((b"github-tls-namespace: host-resolver/file-owner\n", False),
                                     (admission, False), (b"private-token-and-path", False), (b"", True)):
                writes, snapshots, output = [], [], io.StringIO()
                def snapshot(path):
                    test.assertEqual(path, PurePosixPath(context["root"]) / f"{stem}.stderr")
                    snapshots.append(path)
                    return raw
                def emit(path, value):
                    test.assertEqual(path, PurePosixPath(context["root"]) / f"{phase}-checks.json")
                    writes.append(deepcopy(value))
                    if write_fails: raise OSError("private-token-and-path")
                with self.subTest(profile=profile, write_fails=write_fails), \
                        patch.multiple(helper, write_json=emit, github_tls_stderr_snapshot=snapshot), redirect_stdout(output):
                    helper.github_tls_failure_diagnostics(context, compiled, outer, "none", profile=profile)
                self.assertEqual(len(writes), 1)
                self.assertEqual(len(snapshots), 1)
                value = writes[0]
                self.assertEqual(set(value), {"schemaVersion", "scope", "phase", "status", "sourceSha", "sourceTree",
                    "workflowSha256", "runId", "attempt", "tlsInputsSha256", "compiledTest", "launchError",
                    "namespaceRefusal", "admissionRefusal", "outerObservation"} | ({"profile"} if profile is not None else set()))
                self.assertEqual((value["scope"], value["phase"], value["status"], value["launchError"]),
                                 (self.EVIDENCE, phase, "failed", "none"))
                self.assertEqual(value.get("profile"), profile)
                self.assertEqual(value["tlsInputsSha256"], context["tlsInputsSha256" if profile is None else "tlsDeadlineInputsSha256"])
                self.assertEqual(value["outerObservation"], {key: outer[key] for key in (
                    "status", "waitObserved", "exitCode", "timedOut", "elapsedMs", "stdoutBytes", "stderrBytes")})
                self.assertEqual(value["namespaceRefusal"], {"stage": "host-resolver", "code": "file-owner"}
                                 if raw.startswith(b"github-tls-namespace:") else None)
                self.assertEqual(value["admissionRefusal"], {"stage": "admission", "profile": "original" if profile is None else profile,
                                 "code": "tls_libc_maps"} if raw == admission else None)
                self.assertNotIn("private", output.getvalue())
                self.assertNotIn(context["root"], output.getvalue())
                self.assertNotIn(compiled["path"], output.getvalue())
                lines = output.getvalue().splitlines()
                self.assertEqual(json.loads(lines[-1].removeprefix("TLS failed-only diagnostic: ")), value)
                self.assertEqual(len(lines), 2 if write_fails else 1)
                with patch.object(helper, "github_tls_phase_value", return_value={"status": "passed"}):
                    for claimed_phase in ("github-tls", "github-tls-deadline"):
                        with self.assertRaises(helper.CheckFailure):
                            helper.validate_github_tls_phase_receipt(value, context, claimed_phase)
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_outer(value, context=context, compiled=compiled, profile=profile)
            for launch_error in ("timeout", "oserror", "subprocess-error"):
                unknown = {**outer, "status": "unknown", "waitObserved": False, "exitCode": None,
                           "timedOut": launch_error == "timeout", "stdoutBytes": None, "stderrBytes": None}
                writes, output = [], io.StringIO()
                with patch.multiple(helper, github_tls_stderr_snapshot=self.forbidden,
                        write_json=lambda path, value: writes.append(value)), redirect_stdout(output):
                    helper.github_tls_failure_diagnostics(context, compiled, unknown, launch_error, profile=profile)
                self.assertEqual((writes[0]["status"], writes[0]["namespaceRefusal"], writes[0]["launchError"]),
                                 ("failed", None, launch_error))
                self.assertFalse(writes[0]["outerObservation"]["waitObserved"])
                self.assertIsNone(writes[0]["outerObservation"]["exitCode"])
                self.assertIsNone(writes[0]["admissionRefusal"])
        # Unknown selectors refuse before observing a stream or emitting a
        # diagnostic, rather than becoming arbitrary path/report routing.
        for profile in (True, "dns", "", "hosts/other", ["hosts"]):
            with self.subTest(invalid_profile=profile), \
                    patch.multiple(helper, github_tls_stderr_snapshot=self.forbidden, write_json=self.forbidden), \
                    self.assertRaises(helper.CheckFailure):
                helper.github_tls_failure_diagnostics(context, compiled, outer, "none", profile=profile)

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
            data["github-tls-deadline-inputs.json"] = test.deadline_manifest(context)
            digests = {"github-tls/receipt.json": "d" * 64}
            for profile, digest in (("hosts", "e"), ("dns-withhold", "f")):
                path = f"github-tls-deadline/{profile}/receipt.json"
                data[path] = tls_deadline_report_data(profile)
                data[f"github-tls-deadline-{profile}-outer.json"] = test.outer(context, profile)
                digests[path] = digest * 64
            if mutation:
                path, keys, value = mutation
                row = data[path]
                for key in keys[:-1]:
                    row = row[key]
                row[keys[-1]] = value
            def read(path, limit):
                name = path.relative_to(root).as_posix()
                expected_limit = (4096 if name.endswith("-started.json") else 128 * 1024 if name.endswith("/receipt.json")
                                  else 1024 * 1024 if name.endswith("-inputs.json") else 16384 if name.endswith("-outer.json") else 32768)
                test.assertEqual(limit, expected_limit)
                events.append(("read", name))
                return deepcopy(data[name])
            def digest(path):
                name = path.relative_to(root).as_posix()
                test.assertIn(name, digests)
                events.append(("hash", name))
                return digests[name]
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

        for name in (*self.CHECKS, "clean"):
            events = exercise(name)
            previous = list(self.CHECKS) if name == "clean" else list(self.CHECKS)[:list(self.CHECKS).index(name)]
            expected = []
            for prior in previous:
                expected.extend(("read", f"{prior}-{suffix}.json") for suffix in ("started", "checks"))
                if prior == "github-tls":
                    expected.extend([("read", "github-tls-inputs.json"), ("read", "github-tls/receipt.json"),
                                     ("read", "github-tls-outer.json"), ("hash", "github-tls/receipt.json")])
                elif prior == "github-tls-deadline":
                    for profile in ("hosts", "dns-withhold"):
                        expected.extend([("read", "github-tls-deadline-inputs.json"),
                            ("read", f"github-tls-deadline/{profile}/receipt.json"),
                            ("read", f"github-tls-deadline-{profile}-outer.json"),
                            ("hash", f"github-tls-deadline/{profile}/receipt.json")])
            self.assertEqual(events, expected)
        mutations = (
            ("acquire-started.json", ("scope",), helper.GITHUB_READONLY_SCOPE),
            ("compile-started.json", ("attempt",), "3"), ("compile-started.json", ("tlsInputsSha256",), "f" * 64),
            ("compile-started.json", ("tlsDeadlineInputsSha256",), "9" * 64),
            ("compile-checks.json", ("compiledTest", "identitySha256"), "f" * 64),
            ("github-tls-checks.json", ("nativeReceiptSha256",), "f" * 64),
            ("github-tls/receipt.json", ("scope",), "github-readonly-hosted-v1"),
            ("github-tls/receipt.json", ("allPeersSettled",), False),
            ("github-tls/receipt.json", ("cases", 0, "product", "owners", 0, "unknownLatched"), True),
            ("github-tls/receipt.json", ("cases", 0, "peer", "stdoutJoined"), False),
            ("github-tls/receipt.json", ("cases", 9, "peer", "control", "writeComplete"), False),
            ("github-tls/receipt.json", ("cases", 15, "peer", "terminal", "completion", "redirect", "empty"), False),
            ("github-tls/receipt.json", ("cases", 13, "product", "projection", "cooldownSeconds"), None),
            ("github-tls-outer.json", ("waitObserved",), False),
            ("github-tls-outer.json", ("artifactSha256",), "f" * 64),
            ("github-tls-outer.json", ("exitCode",), 1),
            ("github-tls-deadline-started.json", ("tlsDeadlineInputsSha256",), "9" * 64),
            ("github-tls-deadline-checks.json", ("profiles", "hosts", "nativeReceiptSha256"), "d" * 64),
            ("github-tls-deadline-checks.json", ("deadlineInputSha256",), "9" * 64),
            ("github-tls-deadline/hosts/receipt.json", ("allProbesSettled",), False),
            ("github-tls-deadline/hosts/receipt.json", ("cases", 1, "probe", "stdoutJoined"), False),
            ("github-tls-deadline/hosts/receipt.json", ("cases", 0, "peer", "control", "shutdownComplete"), False),
            ("github-tls-deadline/dns-withhold/receipt.json", ("cases", 0, "product", "owners", 0, "unknownLatched"), True),
            ("github-tls-deadline-hosts-outer.json", ("waitObserved",), False),
            ("github-tls-deadline-dns-withhold-outer.json", ("timedOut",), True),
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
        for name in ("github-tls-deadline-started.json", "github-tls-deadline-checks.json",
                *(f"github-tls-deadline/{profile}" for profile in ("hosts", "dns-withhold")),
                *(f"github-tls-deadline-{profile}{suffix}" for profile in ("hosts", "dns-withhold")
                  for suffix in ("-outer.json", ".stdout", ".stderr"))):
            with self.subTest(spent_deadline=name):
                exercise("github-tls-deadline", present=(name,))

    def test_tls_phase_routes_compile_once_and_stop_on_original_outer_or_inner_failure(self):
        context, compiled, test, forbidden = self.context(), self.artifact(), self, self.forbidden
        root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
        cargo, rustc = "/inert/tls/selected/cargo", "/inert/tls/selected/rustc"
        environment = {"HOME": str(root / "home"), "PATH": "/inert/no-executables"}
        admitted_environment = {**environment, "GITHUB_SHA": "1" * 40, "MRK_GITHUB_TLS_INPUTS_SHA256": "9" * 64,
                                "MRK_GITHUB_TLS_DEADLINE_INPUTS_SHA256": "6" * 64}
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
            "github-tls-deadline": [],
        }
        for name, failure in (("acquire", None), ("compile", None), ("github-tls", None),
                ("compile", "compile"), ("github-tls", "outer"), ("github-tls", "inner"),
                ("github-tls-deadline", None), ("github-tls-deadline", "hosts-outer"),
                ("github-tls-deadline", "hosts-inner"), ("github-tls-deadline", "dns-withhold-outer"),
                ("github-tls-deadline", "dns-withhold-inner")):
            events, streams, writes, calls = [], {}, {}, []
            pair = {"acquire": ("cargo-metadata.json", "acquire.stderr"),
                    "compile": ("github-tls-compile-messages.jsonl", "compile.stderr"),
                    "github-tls": (), "github-tls-deadline": ()}[name]
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
            def outer(value, artifact, *, profile=None):
                test.assertIs(value, context); test.assertIs(artifact, compiled)
                test.assertIn(name, ("github-tls", "github-tls-deadline"))
                test.assertIn(profile, ("hosts", "dns-withhold") if name == "github-tls-deadline" else (None,))
                event = "outer" if profile is None else f"{profile}-outer"
                test.assertNotIn(event, events); events.append(event)
                if profile == "dns-withhold":
                    test.assertIn("hosts-inner", events)
                if failure == event:
                    raise helper.CheckFailure("inert original outer refusal")
                return test.outer(context, profile)
            def result(value, *, profile=None):
                test.assertIs(value, context); test.assertIn(name, ("github-tls", "github-tls-deadline"))
                test.assertIn("outer" if profile is None else f"{profile}-outer", events)
                event = "inner" if profile is None else f"{profile}-inner"
                events.append(event)
                if failure == event:
                    raise helper.CheckFailure("inert original peer/client refusal")
                return {"nativeReceiptSha256": {None: "d", "hosts": "e", "dns-withhold": "f"}[profile] * 64,
                        "outer": test.outer(context, profile)}
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
            elif name == "github-tls-deadline":
                self.assertEqual(events.count("tools"), 0)
                self.assertEqual(events.count("compile-record"), 0)
                prefix = ["hosts-outer", "hosts-inner", "dns-withhold-outer", "dns-withhold-inner"]
                if failure:
                    prefix = prefix[:prefix.index(failure) + 1]
                self.assertEqual(events[5:5 + len(prefix)], prefix)
                self.assertEqual(events.count("hosts-outer"), 1)
                self.assertEqual(events.count("dns-withhold-outer"), int(failure not in ("hosts-outer", "hosts-inner")))
                if failure:
                    self.assertEqual(events[5:], prefix)
                else:
                    # Later phase serialization revalidates supplied DATA; it
                    # does not relaunch a namespace or recompile the artifact.
                    self.assertEqual(events[9], "source")
                    self.assertEqual(events[-1], "receipt")
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
            "features": ["development-runtime"], "testTarget": "lib", "host": original["observedHost"], "notVerified": TLS_NOT_VERIFIED,
            "deadline": {"tlsInputsSha256": "6" * 64, "inputs": original["tlsDeadlineInputs"],
                         "notVerified": ["populated-ambient-ca-directory", "platform-trust-stores", "getaddrinfo-internal-cancellation",
                            "T6-streaming-controls", "CA-file-native-faults", "native-stuck-spawn-wait-close", "real-github-authentication",
                            "production-runtime-custody", "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement"]}}
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
        deadline = root / "github-tls-deadline"
        profile_cases = {"hosts": ("T4-owner-clear", "T4-ambient-fixed", "T4-ambient-no-rescue", "T5-handshake", "T5-read", "T5-helper-read"),
                         "dns-withhold": ("T5-dns",)}
        namespace_bytes = {root / "github-tls-namespace" / name: data for name, data in self.CONFIG.items()}
        for profile, configs in (("hosts", self.CONFIG), ("dns-withhold", {
                "hosts": b"127.0.0.1 localhost\n::1 localhost\n",
                "resolv.conf": b"nameserver 127.0.0.1\noptions timeout:15 attempts:1 ndots:1\n",
                "nsswitch.conf": b"passwd: files\ngroup: files\nhosts: dns\n"})):
            namespace_bytes.update({root / f"github-tls-deadline-namespace-{profile}" / name: data for name, data in configs.items()})
        profiles = tuple(deadline / name for name in profile_cases)
        ambient = (root / "github-tls-deadline-ambient", *(deadline / "hosts" / name / "ambient"
                    for name in ("T4-ambient-fixed", "T4-ambient-no-rescue", "T5-helper-read")))
        work = ("home", "cargo", "rustup", "tmp", "target", "github-tls-namespace",
                "github-tls-deadline-namespace-hosts", "github-tls-deadline-namespace-dns-withhold", "github-tls-deadline-ambient")
        private = ("core.zip", "gitconfig-empty", "cargo-metadata.json", "acquire.stderr", "github-tls-compile-messages.jsonl",
                   "compile.stderr", "github-tls-compiled-test.json", "github-tls.stdout", "github-tls.stderr",
                   *(f"github-tls-deadline-{profile}.{kind}" for profile in profile_cases for kind in ("stdout", "stderr")))
        evidence = ("context.json", "public-bindings.json", "github-tls-inputs.json", "github-tls-outer.json",
                    "github-tls-deadline-inputs.json", *(f"github-tls-deadline-{profile}-outer.json" for profile in profile_cases),
                    *(f"{phase}-{suffix}.json" for phase in self.CHECKS for suffix in ("started", "checks")))
        self.assertEqual(set(helper.GITHUB_TLS_DIRECTORIES), {*work, "github-tls", "github-tls-deadline"})

        for mutation in (None, "finality", "deadline-finality", "unexpected", "missing-streaming", "unexpected-profile", "profile-link",
                "keylog", "ambient-ca", "ambient-control", "nested-case", "nested-control", "nested-runtime", "nested-original",
                "runtime-copy", "release-control", "leaf-directory", "foreign-owner", "foreign-mount", "changed-leaf", "late-entry"):
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
            add(root, "directory"); add(native, "directory"); add(deadline, "directory")
            for profile in profiles:
                add(profile, "directory")
            add(outside, "directory"); add(outside / "protected.pem")
            add(PurePosixPath(context["source"]), "directory")
            add(PurePosixPath(context["source"]) / "protected.py")
            directories = {root / name for name in work}
            case_rows = TLS_CASE_ROWS[:-1] if mutation == "missing-streaming" else TLS_CASE_ROWS
            for name, *_ in case_rows:
                directories.update((native / name, native / name / "control", native / name / "runtime"))
            for profile, names in profile_cases.items():
                for name in names:
                    directories.update((deadline / profile / name, deadline / profile / name / "control", deadline / profile / name / "runtime"))
            directories.update(ambient)
            directories.update(path / "empty-ca-dir" for path in ambient)
            for path in sorted(directories, key=lambda path: (len(path.parts), str(path))):
                add(path, "directory")
            leaves = {root / name for name in private}
            for name, *_ in case_rows:
                # These are actual settled producer names, including the
                # reusable Case::settle release record (not an empty control).
                leaves.update((native / name / "control/release-github-read-1.json",
                    native / name / "runtime/github_connection_bootstrap.py", native / name / "runtime/github-ca.pem"))
            leaves.update(root / "github-tls-namespace" / name for name in self.CONFIG)
            for profile, names in profile_cases.items():
                leaves.update(root / f"github-tls-deadline-namespace-{profile}" / name for name in self.CONFIG)
                for name in names:
                    leaves.update((deadline / profile / name / "runtime/github_connection_bootstrap.py",
                                   deadline / profile / name / "runtime/github-ca.pem"))
                    if name not in ("T4-ambient-fixed", "T4-ambient-no-rescue", "T5-helper-read"):
                        leaves.add(deadline / profile / name / "control/release-github-read-1.json")
            controls = {path / "write-control" for path in ambient}
            leaves.update(controls)
            for path in sorted(leaves):
                add(path, size=1 if path in controls else len(namespace_bytes[path]) if path in namespace_bytes else 32)
                if path in controls:
                    nodes[path]["st_mode"] = stat.S_IFREG | 0o600
            for name in evidence:
                add(root / name)
            add(native / "receipt.json")
            for profile in profiles:
                add(profile / "receipt.json")
            link = root / "tmp/external-link"
            add(link, "link"); leaves.add(link)
            aliases = (root / "cargo/original-hardlink", root / "target/original-hardlink")
            add(aliases[0], inode=9999, links=2); add(aliases[1], inode=9999, links=2); leaves.update(aliases)
            if mutation == "unexpected":
                add(root / "unexpected.pem")
            elif mutation == "unexpected-profile":
                add(deadline / "another-profile", "directory")
            elif mutation == "profile-link":
                nodes[profiles[0]]["st_mode"] = stat.S_IFLNK | 0o777
            elif mutation == "keylog":
                add(ambient[1] / "client.keylog", "link")
            elif mutation == "ambient-ca":
                add(ambient[0] / "empty-ca-dir/unexpected.pem")
            elif mutation in ("nested-case", "nested-control", "nested-runtime", "nested-original"):
                parent = {"nested-case": deadline / "hosts/T5-read", "nested-control": deadline / "hosts/T5-read/control",
                          "nested-runtime": deadline / "hosts/T5-read/runtime", "nested-original": native / "T1-source/control"}[mutation]
                add(parent / "unexpected.pem")
            elif mutation == "leaf-directory":
                parent = deadline / "hosts/T5-read/runtime/github-ca.pem"
                nodes[parent]["st_mode"] = stat.S_IFDIR | 0o700
                add(parent / "unexpected.pem")
            elif mutation == "foreign-owner":
                nodes[root / private[-1]]["st_uid"] = 1001
            elif mutation == "foreign-mount":
                nodes[root / private[-1]]["st_dev"] = 8
            initial = deepcopy(nodes)
            protected = {root / name for name in evidence} | {native / "receipt.json", *(profile / "receipt.json" for profile in profiles)}
            protected.update(path for path in nodes if path != root and root not in path.parents)
            total = sum(nodes[path]["st_size"] for path in leaves)
            expected_receipt = {"schemaVersion": 1, "scope": self.EVIDENCE, "phase": "clean", "status": "passed",
                **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
                "allOriginalOwnersSettled": True, "allOriginalPeersSettled": True, "observerJoinsComplete": True,
                "originalOuterWaitObserved": True, "tlsInputsSha256": "9" * 64, "compiledTest": self.compiled_public(),
                "tlsDeadlineInputsSha256": "6" * 64, "allOriginalProbesSettled": True, "deadlineProfiles": self.deadline_result(context),
                "nativeReceiptSha256": "d" * 64, "outer": self.outer(context), "removedFiles": len(leaves),
                "removedDirectories": len(directories), "inventoriedBytes": total,
                "retained": ["redacted-evidence", "private-original-context", "private-tls-input-manifest", "private-original-outer-receipt",
                             "private-deadline-input-manifest", "private-deadline-original-outer-receipts"],
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
                    if mutation == "changed-leaf" and path == root / private[-1] and counts[path] == 2:
                        nodes[path]["st_mtime_ns"] += 1
                    return SimpleNamespace(**nodes[path])
                def iterdir(self):
                    path = PurePosixPath(self)
                    test.assertIn(path, (root, native, deadline, *profiles, *ambient, *(folder / "empty-ca-dir" for folder in ambient)))
                    test.assertTrue(stat.S_ISDIR(nodes[path]["st_mode"]))
                    return iter(FakePath(child) for child in children(path))
                def is_symlink(self):
                    return stat.S_ISLNK(nodes[PurePosixPath(self)]["st_mode"])
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
            def deadline_result(value):
                test.assertIs(value, context); events.append(("finality", "deadline"))
                if mutation == "deadline-finality":
                    raise helper.CheckFailure("inert original probe finality missing")
                return test.deadline_result(context)
            def bound_file(path):
                test.assertIn(path, leaves)
                if path in controls:
                    return {"path": str(path), "size": 1,
                            "sha256": "0" * 64 if mutation == "ambient-control" else hashlib.sha256(b"w").hexdigest()}
                if path in namespace_bytes:
                    data = namespace_bytes[path]
                    return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                test.assertIn(path.parent.name, ("control", "runtime"))
                return {"path": str(path), "size": 32,
                        "sha256": "0" * 64 if mutation == "runtime-copy" and path == deadline / "hosts/T5-read/runtime/github-ca.pem" else "5" * 64}
            def release_data(path, limit):
                test.assertEqual((path.name, path.parent.name, limit), ("release-github-read-1.json", "control", 512))
                test.assertIn(path, leaves)
                return {"nonce": "0" * 64 if mutation == "release-control" else hashlib.sha256(str(path.parent.parent).encode()).hexdigest(),
                        "id": "github-read-1", "release": True}
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
                    github_tls_result=result, github_tls_deadline_result=deadline_result, github_tls_file=bound_file,
                    write_json=emit, run=forbidden, tools=forbidden,
                    github_tls_source_unchanged=forbidden, source_unchanged=forbidden, clean_environment=forbidden,
                    read_bounded_json=release_data, hash_file=forbidden, ordinary=forbidden), \
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
                self.assertEqual(children(deadline), sorted(profiles))
                for profile in profiles:
                    self.assertEqual(children(profile), [profile / "receipt.json"])
                self.assertEqual(notice.getvalue(), "Removed only positively settled TLS compiler and fixture outputs; original evidence retained.\n")
            else:
                self.assertNotIn("clean-checks.json", writes); self.assertEqual(notice.getvalue(), "")
                self.assertEqual(set(writes), set() if mutation in ("finality", "deadline-finality") else {"clean-started.json"})
                if mutation != "late-entry":
                    self.assertEqual(unlinked, []); self.assertEqual(removed, [])
                else:
                    self.assertIn(root / "home/late.pem", nodes); self.assertNotIn(root / "home/late.pem", unlinked)
                    self.assertIn(root / "home", nodes)


TLS_DEADLINE_NOT_VERIFIED = ["populated-ambient-ca-directory", "platform-trust-stores", "getaddrinfo-internal-cancellation",
    "T6-streaming-controls", "CA-file-native-faults", "native-stuck-spawn-wait-close", "real-github-authentication",
    "production-runtime-custody", "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement"]


def tls_deadline_ambient_hashes_data(context):
    root, source = PurePosixPath(context["root"]), PurePosixPath(context["source"])
    values = {}
    for name in ("T4-owner-clear", "T4-ambient-fixed", "T4-ambient-no-rescue", "T5-helper-read"):
        folder = root / "github-tls-deadline-ambient" if name == "T4-owner-clear" else root / "github-tls-deadline/hosts" / name / "ambient"
        environment = {"LANG": "C", "LC_ALL": "C", "NO_PROXY": "", "no_proxy": "",
            "SSL_CERT_FILE": str(source / "desktop/src-tauri/tests/fixtures/github_tls" / ("root-ca.pem" if name == "T4-ambient-no-rescue" else "other-root-ca.pem")),
            "SSL_CERT_DIR": str(folder / "empty-ca-dir"), "SSLKEYLOGFILE": str(folder / ("owner-clear.keylog" if name == "T4-owner-clear" else "client.keylog"))}
        for scheme in ("HTTP", "HTTPS", "ALL"):
            environment[scheme + "_PROXY"] = environment[scheme.lower() + "_proxy"] = "http://127.0.0.1:18888"
        values[name] = hashlib.sha256(json.dumps(environment, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return values


def tls_deadline_binding_data():
    return {**github_tls_binding_data(), "tlsInputsSha256": "6" * 64}


def tls_deadline_report_data(profile):
    """Independent supplied DATA only: these observations are NOT native evidence."""
    names = {"hosts": ("T4-owner-clear", "T4-ambient-fixed", "T4-ambient-no-rescue", "T5-handshake", "T5-read", "T5-helper-read"),
             "dns-withhold": ("T5-dns",)}[profile]
    binding = tls_deadline_binding_data()
    binding["namespace"] = {**binding["namespace"], "netns": "net:[101]" if profile == "hosts" else "net:[102]",
                            "mntns": "mnt:[201]" if profile == "hosts" else "mnt:[202]"}
    hashes = tls_deadline_ambient_hashes_data(GitHubTLSCIIntegrationTests.context())
    cases = []
    for name in names:
        direct = name in ("T4-ambient-fixed", "T4-ambient-no-rescue", "T5-helper-read")
        dns, handshake, read, refusal = name == "T5-dns", name == "T5-handshake", name in ("T5-read", "T5-helper-read"), name == "T4-ambient-no-rescue"
        owner_timeout = dns or handshake or name == "T5-read"
        reason = "query_timeout" if owner_timeout else "network-unavailable" if name == "T5-helper-read" else "tls-failed" if refusal else "none"
        connections = 0 if dns else 4 if name in ("T4-owner-clear", "T4-ambient-fixed") else 1
        requests = 0 if dns or handshake or refusal else connections
        progress = []
        def event(kind, at, *, body=0, written=200, questions=0, a=0, aaaa=0, stop=None):
            progress.append({"event": kind, "sequence": len(progress) + 1, "requests": 0 if dns or handshake or refusal else 1,
                "bodyBytes": body, "wireReadBytes": 0 if dns else 100, "wireWriteBytes": written,
                "dnsQuestions": questions, "dnsA": a, "dnsAAAA": aaaa, "clientStop": stop, "afterPeerStartNs": at})
        if dns:
            event("dns-question", 1_100_000_000, written=0, questions=1, a=1)
            event("dns-question", 1_100_000_001, written=0, questions=2, a=1, aaaa=1)
        elif handshake:
            event("client-hello", 1_100_000_000, written=0)
            event("client-stop", 11_200_000_000, written=0, stop="tcp-eof")
        elif not refusal:
            event("first-get", 1_100_000_000)
            if read:
                for index in range(11):
                    event("body-byte", 1_100_000_000 + index * 1_000_000_000, body=index + 1, written=210 + index * 10)
                event("client-stop", 11_300_000_000, body=11, written=310, stop="tcp-eof")
        product = deepcopy(github_tls_report_data()["cases"][0]["product"])
        product["reason"] = reason
        if owner_timeout:
            product["owners"][0]["firstError"] = "query_timeout"
            product["owners"][0]["native"].update(exit_success=False, stdout_bytes=0, stderr_bytes=0)
        probe = dict.fromkeys(("acquisitionJoined", "spawned", "waited", "exitSuccess", "writerJoined", "writeComplete", "shutdownComplete",
            "stdinReleased", "stdoutJoined", "stderrJoined", "stdoutEof", "stderrEof", "settled", "withinEndpoint", "frameObserved"), True)
        probe.update(exitCode=0, stopAttempted=False, stdoutBytes=512, stderrBytes=0, stdoutOverflow=False, stderrOverflow=False)
        peer = deepcopy(github_tls_report_data()["cases"][0]["peer"])
        peer["stdoutBytes"] = 4096
        peer["control"] = dict.fromkeys(("acquired", "started", "joined", "writeComplete", "shutdownComplete", "productSettled", "withinEndpoint", "released"), True)
        peer["control"]["failed"] = False
        peer["terminal"] = {"schemaVersion": 1, "scope": "github-tls-peer-v1", "case": name, "state": "finished", "status": "passed", "code": None,
            "connections": connections, "handshakes": requests, "requests": requests,
            "decryptedBytes": requests * 100, "authBytes": requests * len(b"Bearer INERT_NOT_A_CREDENTIAL"),
            "closeNotify": 4 if name in ("T4-owner-clear", "T4-ambient-fixed") else 0, "tlsRefused": refusal,
            "wireReadBytes": [100] * connections, "wireWriteBytes": [0 if handshake else 310 if read else 1024] * connections,
            "replyBytes": [0 if handshake or refusal else 75 if read else 64] * connections, "allSocketsClosed": True,
            "sni": connections, "phase": "dns" if dns else "handshake" if handshake else "read" if read else "ambient",
            "withheldWireBytes": 512 if handshake else 0, "bodyBytes": 11 if read else 0, "incompleteBody": read,
            "clientStop": "tcp-eof" if handshake or read else None, "progressCount": len(progress),
            "dnsQuestions": 2 if dns else 0, "dnsA": 1 if dns else 0, "dnsAAAA": 1 if dns else 0, "dnsReplies": 0,
            "completion": {"bytes": 1, "eof": True, "closed": True, "primaryEmpty": True, "primaryUnexpected": 0, "primaryClosed": True,
                "proxy": {"empty": True, "unexpected": 0, "closed": True} if name.startswith("T4-") else None,
                "dnsEmpty": True if dns else None, "dnsClosed": True if dns else None}}
        ambient = None
        if name in hashes:
            ambient = dict.fromkeys(("writableControlCreated", "writableControlWritten", "writableControlSynced", "writableControlClosed",
                "keylogAbsentBefore", "keylogAbsentAfter", "emptyCaDirectoryBefore", "emptyCaDirectoryAfter", "fileSizeLimitNonzero"), True)
            ambient.update(roleSetSha256=hashes[name], initialEnvironment="observed-allowlist" if name == "T4-owner-clear" else None)
        if direct:
            timing = {"kind": "fixture-owned-bootstrap", "spawnAfterPeerStartNs": 1_000_000_000,
                "settledAfterPeerStartNs": 11_400_000_000 if read else 2_000_000_000,
                "firstGetAfterLaunchNs": None if refusal else 100_000_000, "responseAfterLaunchNs": 10_200_000_000 if read else 500_000_000,
                "clientStopAfterLaunchNs": 10_300_000_000 if read else None,
                "bodyProgressAfterLaunchNs": [100_000_000 + index * 1_000_000_000 for index in range(11)] if read else [],
                "helperWindowChecked": read}
        else:
            timing = {"kind": "ordinary-owner", "operationStartAfterPeerNs": 1_000_000_000, "operationEndpointAfterPeerNs": 11_000_000_000,
                "cleanupEndpointAfterPeerNs": 13_000_000_000 if owner_timeout else None,
                "settledAfterPeerNs": 11_400_000_000 if owner_timeout else 2_000_000_000,
                "phaseAfterPeerNs": 1_100_000_000, "phase": "dns-question" if dns else "client-hello" if handshake else "first-get",
                "originalDeadlineChecked": owner_timeout, "cleanupExact": owner_timeout}
        cases.append({"case": name, "entry": "fixture-owned-bootstrap" if direct else "ordinary-supervisor", "passed": True,
            "failureCode": None, "coreMode": "source", "trustFixture": "other-root-ca.pem" if refusal else "root-ca.pem", "elapsedMs": 12000,
            "clientSettled": True, "projectionChecked": True, "reason": reason, "product": None if direct else product,
            "probe": probe if direct else None, "ambient": ambient, "timing": timing, "progress": progress, "peer": peer,
            "resolverCacheAbsentAfter": True if dns else None})
    return {"schemaVersion": 1, "scope": "github-readonly-tls-deadline-hosted-v1", "profile": profile, "status": "passed",
        "allOwnersSettled": True, "allProbesSettled": True, "allPeersSettled": True, "failureCode": None,
        "bindings": binding, "cases": cases, "outerWait": "external-original-observer-required", "notVerified": list(TLS_DEADLINE_NOT_VERIFIED)}


class GitHubTLSDeadlineContractTests(unittest.TestCase):
    """Closed supplied-DATA contracts, not original native observations."""

    @staticmethod
    def validate(report, profile="hosts", *, bindings=None, ambient_hashes=None):
        return helper.validate_github_tls_deadline_receipt(report,
            bindings=tls_deadline_binding_data() if bindings is None else bindings, profile=profile,
            ambient_hashes=tls_deadline_ambient_hashes_data(GitHubTLSCIIntegrationTests.context()) if ambient_hashes is None else ambient_hashes)

    def reject_at(self, path, replacement, *, profile="hosts"):
        report = tls_deadline_report_data(profile)
        row = report
        for key in path[:-1]:
            row = row[key]
        row[path[-1]] = replacement
        with self.subTest(profile=profile, path=path, value=replacement), self.assertRaises(helper.CheckFailure):
            self.validate(report, profile)

    def test_deadline_manifest_replaces_only_resolver_roles_and_rejects_ordinary_null_descriptor(self):
        context = GitHubTLSCIIntegrationTests.context()
        original = GitHubTLSCIIntegrationTests.manifest(context)
        deadline = GitHubTLSCIIntegrationTests.deadline_manifest(context)
        roles = {f"{profile}:{name}" for profile in ("hosts", "dns-withhold") for name in ("hosts", "resolv.conf", "nsswitch.conf")}
        roles.update(("libc", "resolver:host.conf", "resolver:gai.conf"))
        self.assertEqual(set(deadline["roles"]) - set(original["roles"]), roles)
        self.assertEqual(set(original["roles"]) - set(deadline["roles"]), {"hosts", "resolv.conf", "nsswitch.conf"})
        mutations = []
        for descriptor in (None, {}, {"family": "glibc", "version": "2.38", "nss": "builtin-files-dns"},
                           {**deadline["resolver"], "extra": True}, {**deadline["resolver"], "nss": "dynamic"}):
            mutations.append({**deepcopy(deadline), "resolver": descriptor})
        missing = deepcopy(deadline); del missing["resolver"]; mutations.append(missing)
        for role in roles:
            missing = deepcopy(deadline); del missing["roles"][role]; mutations.append(missing)
        for role, path in (("hosts:hosts", original["roles"]["hosts"]),
                ("dns-withhold:nsswitch.conf", deadline["roles"]["hosts:nsswitch.conf"]),
                ("libc", deadline["roles"]["libssl"]), ("resolver:host.conf", "/etc/gai.conf")):
            changed = deepcopy(deadline); changed["roles"][role] = path; mutations.append(changed)
        changed = deepcopy(deadline); changed["roles"].update({key: original["roles"][key] for key in GitHubTLSCIIntegrationTests.CONFIG})
        mutations.append(changed)
        forbidden = GitHubTLSCIIntegrationTests.forbidden
        with patch.multiple(helper, Path=PurePosixPath, github_tls_runtime=forbidden, github_tls_file=forbidden,
                github_tls_deadline_resolver_file=forbidden, ordinary=forbidden, hash_file=forbidden,
                read_bounded_json=forbidden, run=forbidden, tools=forbidden):
            self.assertIs(helper.validate_github_tls_manifest(deadline, context=context, deadline=True), deadline)
            self.assertEqual(helper.github_tls_input_summary(context, deadline), context["tlsDeadlineInputs"])
            for index, value in enumerate(mutations):
                with self.subTest(manifest=index), self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_manifest(value, context=context, deadline=True)
            for value in (None, deadline["resolver"]):
                with self.subTest(ordinary_resolver=value), self.assertRaises(helper.CheckFailure):
                    helper.validate_github_tls_manifest({**original, "resolver": value}, context=context)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_manifest(deadline, context=context)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_manifest(original, context=context, deadline=True)

    def test_deadline_resolver_grammar_and_absence_checks_have_no_repair_or_lookup(self):
        for name, raw in (("host.conf", b"# comment\norder hosts,bind\nmulti on\n"),
                ("host.conf", b" \t order hosts,bind  # selected files/dns\r\n\tmulti on \r\n"),
                ("gai.conf", b"# default\n\t\r\n"), ("gai.conf", b"\n" * 127)):
            helper.github_tls_deadline_host_config(raw, name)
        for raw, name in ((b"", "host.conf"), (b"multi on\0", "host.conf"), (b"\xff", "gai.conf"),
                (b"#" * 513, "gai.conf"), (b"\n" * 128, "gai.conf"), (b"#" * 16385, "gai.conf"),
                (b"multi on\nmulti on\n", "host.conf"), (b"order bind,hosts\n", "host.conf"),
                (b"order hosts,bind\ntrim .test\n", "host.conf"), (b"multi\ton\n", "host.conf"),
                (b"multi on\n", "gai.conf"), (b"label ::1/128 0\n", "gai.conf"),
                (b"\xc2\xa0", "gai.conf"), (b"# comment\n", "resolv.conf"), (b"# comment\n", []),
                (bytearray(b"# default\n"), "gai.conf")):
            with self.subTest(name=name, raw=raw), self.assertRaises(helper.CheckFailure):
                helper.github_tls_deadline_host_config(raw, name)
        paths = ("/run/nscd/socket", "/var/run/nscd/socket", "/run/.nscd_socket", "/var/run/.nscd_socket")
        forbidden = GitHubTLSCIIntegrationTests.forbidden
        for present in (None, *paths):
            seen = []
            def exists(path):
                self.assertIn(path, paths); seen.append(path)
                return path == present  # Presence includes a dangling link, not just a live service.
            with patch.object(helper.os.path, "lexists", side_effect=exists), \
                    patch.multiple(helper, Path=forbidden, run=forbidden, tools=forbidden), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.os, "unlink", side_effect=forbidden):
                if present:
                    with self.assertRaises(helper.CheckFailure):
                        helper.github_tls_deadline_cache_absent()
                else:
                    helper.github_tls_deadline_cache_absent()
            self.assertEqual(seen, list(paths if present is None else paths[:paths.index(present) + 1]))

    def test_deadline_runtime_observer_requires_one_supported_original_libc_not_one_vma(self):
        # All imported modules, mapping bytes and path observations below are
        # supplied finite capabilities. No SSLContext, libc probe or proc file
        # on the test host is consulted; this is not native version evidence.
        prefix, test = PurePosixPath("/inert/resolver/python"), self
        library = prefix / "lib/python3.14"
        module_paths = {name: library / (name + ".py") for name in ("ssl", "socket")}
        module_paths.update({name: library / "lib-dynload" / (name + ".cpython-314-x86_64-linux-gnu.so")
                             for name in ("_ssl", "_socket", "resource")})
        native_paths = {name: PurePosixPath("/inert/resolver/lib") / filename for name, filename in (
            ("libssl", "libssl.so.3"), ("libcrypto", "libcrypto.so.3"), ("loader", "ld-linux-x86-64.so.2"), ("libc", "libc.so.6"))}
        forbidden = GitHubTLSCIIntegrationTests.forbidden
        for mutation in (None, "version", "second-libc", "backing-identity", "deleted", "dynamic-nss"):
            streams, probes, mappings = [], [], []
            for path in native_paths.values():
                # Normal ELF VMA repetition of the same canonical inode is
                # expected and cannot be misclassified as duplicate libc.
                mappings.extend(f"1000-2000 {mode} 00000000 07:03 500 {path}" for mode in ("r--p", "r-xp", "r-xp"))
            if mutation == "second-libc":
                mappings.append("1000-2000 r-xp 00000000 07:03 501 /inert/resolver/other/libc.so.6")
            elif mutation == "dynamic-nss":
                mappings.append("1000-2000 r--p 00000000 07:03 500 /inert/resolver/lib/libnss_dns.so.2")
            elif mutation == "deleted":
                mappings[-1] += " (deleted)"
            raw = ("\n".join(mappings) + "\n").encode("utf-8")
            class RuntimePath(PurePosixPath):
                def resolve(self, *, strict=False):
                    test.assertTrue(strict); return self
                def open(self, mode):
                    test.assertEqual((str(self), mode), ("/proc/self/maps", "rb"))
                    stream = io.BytesIO(raw); streams.append(stream); return stream
                def lstat(self):
                    test.assertTrue(str(self).startswith("/inert/resolver/"))
                    inode = 501 if (mutation == "backing-identity" and self.name == "libc.so.6"
                                    or mutation == "second-libc" and self.parent.name == "other") else 500
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_dev=1795, st_ino=inode)
            def ssl_context(protocol):
                test.assertEqual(protocol, 1); probes.append("supplied-ssl-options")
                return SimpleNamespace(options=0)
            modules = {name: SimpleNamespace(__file__=str(path)) for name, path in module_paths.items()}
            modules["ssl"] = SimpleNamespace(__file__=str(module_paths["ssl"]), OP_IGNORE_UNEXPECTED_EOF=128,
                OPENSSL_VERSION="OpenSSL 3.0.0 supplied DATA", PROTOCOL_TLS_CLIENT=1, SSLContext=ssl_context)
            modules["sysconfig"] = SimpleNamespace(get_path=lambda key: str(library) if key == "stdlib" else forbidden())
            supplied_sys = SimpleNamespace(version=helper.PYTHON, flags=SimpleNamespace(isolated=True, no_site=True, optimize=0),
                dont_write_bytecode=True, platform="linux", base_prefix=str(prefix), executable=str(prefix / "bin/python3.14"),
                path=[str(library), str(library / "lib-dynload"), str(prefix / "lib/python314.zip")], modules=modules)
            with self.subTest(runtime=mutation), patch.dict(helper.sys.modules, modules), \
                    patch.multiple(helper, Path=RuntimePath, sys=supplied_sys, run=forbidden, tools=forbidden,
                                   github_tls_file=forbidden, hash_file=forbidden, read_bounded_json=forbidden), \
                    patch.object(helper, "github_tls_stdlib_files", return_value=set(module_paths.values())) as roster, \
                    patch.object(helper.os, "confstr", return_value="glibc 2.38" if mutation == "version" else "glibc 2.39", create=True) as version, \
                    patch.object(helper.os, "major", return_value=7, create=True), patch.object(helper.os, "minor", return_value=3, create=True), \
                    patch.object(helper.subprocess, "run", side_effect=forbidden), patch.object(helper.subprocess, "Popen", side_effect=forbidden):
                if mutation:
                    with self.assertRaises(helper.CheckFailure):
                        helper.github_tls_runtime()
                else:
                    ssl, roles, files = helper.github_tls_runtime()
                    self.assertEqual(ssl, {"opensslVersion": "OpenSSL 3.0.0 supplied DATA", "ignoreUnexpectedEof": 128})
                    self.assertEqual(roles["libc"], str(native_paths["libc"]))
                    self.assertEqual(files, set(module_paths.values()) | set(native_paths.values()))
                version.assert_called_once_with("CS_GNU_LIBC_VERSION")
                if mutation == "version":
                    roster.assert_not_called()
                else:
                    roster.assert_called_once_with(library)
            self.assertEqual(probes, [] if mutation == "version" else ["supplied-ssl-options"])
            self.assertEqual(len(streams), 0 if mutation == "version" else 1)
            self.assertTrue(all(stream.closed for stream in streams))

    def test_deadline_supplied_profiles_require_external_bindings_and_exact_ambient_roles(self):
        context = GitHubTLSCIIntegrationTests.context()
        hashes = tls_deadline_ambient_hashes_data(context)
        with patch.object(helper, "Path", PurePosixPath):
            self.assertEqual(helper.github_tls_deadline_ambient_hashes(context), hashes)
        self.assertEqual(list(helper.GITHUB_TLS_DEADLINE_NOT_VERIFIED), TLS_DEADLINE_NOT_VERIFIED)
        for profile in ("hosts", "dns-withhold"):
            report = tls_deadline_report_data(profile)
            self.assertIs(self.validate(report, profile), report)
            raw = GitHubTLSCIIntegrationTests.encoded(report)
            self.assertEqual(helper.parse_github_tls_deadline_receipt(raw, bindings=tls_deadline_binding_data(),
                             profile=profile, ambient_hashes=hashes), report)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_github_tls_receipt(report, bindings=github_tls_binding_data())
            self.reject_at(("profile",), "dns-withhold" if profile == "hosts" else "hosts", profile=profile)
            self.reject_at(("cases",), list(reversed(report["cases"])) if profile == "hosts" else [], profile=profile)
        report = tls_deadline_report_data("hosts")
        for key, value in (("schemaVersion", True), ("status", "failed-retained"), ("allOwnersSettled", 1),
                ("allProbesSettled", False), ("allPeersSettled", False), ("failureCode", "unsettled"),
                ("outerWait", "passed"), ("notVerified", TLS_DEADLINE_NOT_VERIFIED[:-1]), ("extra", True)):
            self.reject_at((key,), value)
        for key in report:
            missing = deepcopy(report); del missing[key]
            with self.subTest(missing=key), self.assertRaises(helper.CheckFailure):
                self.validate(missing)
        for key, value in (("tlsInputsSha256", "9" * 64), ("artifactSha256", "0" * 64), ("attempt", "3")):
            self.reject_at(("bindings", key), value)
        self.reject_at(("bindings", "namespace", "netns"), "net:[100]")
        for index in (0, 1, 2, 5):
            name = report["cases"][index]["case"]
            self.reject_at(("cases", index, "ambient", "roleSetSha256"), "0" * 64)
            with self.subTest(expected_role=name), self.assertRaises(helper.CheckFailure):
                self.validate(report, ambient_hashes={**hashes, name: "0" * 64})
        for key, value in report["cases"][0]["ambient"].items():
            if type(value) is bool:
                self.reject_at(("cases", 0, "ambient", key), False)
        for state in (None, "unavailable-source-only", "observed-disallowed", True):
            self.reject_at(("cases", 0, "ambient", "initialEnvironment"), state)
        self.reject_at(("cases", 1, "ambient", "initialEnvironment"), "observed-allowlist")
        self.reject_at(("cases", 3, "ambient"), report["cases"][0]["ambient"])
        self.reject_at(("cases", 0, "resolverCacheAbsentAfter"), False, profile="dns-withhold")

    def test_deadline_client_roles_and_original_join_evidence_cannot_substitute_for_each_other(self):
        report = tls_deadline_report_data("hosts")
        for index, row in enumerate(report["cases"]):
            for key, value in (("reason", "engine_failed"), ("clientSettled", False), ("projectionChecked", 1),
                    ("entry", "ordinary-supervisor" if row["product"] is None else "fixture-owned-bootstrap")):
                self.reject_at(("cases", index, key), value)
        self.reject_at(("cases", 1, "product"), report["cases"][0]["product"])
        self.reject_at(("cases", 0, "probe"), report["cases"][1]["probe"])
        for key, value in report["cases"][1]["probe"].items():
            if type(value) is bool:
                self.reject_at(("cases", 1, "probe", key), not value)
        for key, value in (("exitCode", 1), ("exitCode", False), ("stdoutBytes", 0), ("stdoutBytes", 65537),
                           ("stderrBytes", 1), ("extra", True)):
            self.reject_at(("cases", 1, "probe", key), value)
        timeout = report["cases"][3]["product"]["owners"][0]
        for key, value in (("terminal", False), ("unknownLatched", True), ("permitRetained", True),
                           ("observerJoined", False), ("firstError", None)):
            self.reject_at(("cases", 3, "product", "owners", 0, key), value)
        for key, value in timeout["native"].items():
            self.reject_at(("cases", 3, "product", "owners", 0, "native", key), not value if type(value) is bool else 1)
        # Ordinary positive validation remains strict; a timeout outcome is not
        # accepted by either T1-T3 or the ordinary owner-clear predicate.
        self.reject_at(("cases", 0, "product", "owners", 0, "native", "exit_success"), False)
        self.reject_at(("cases", 0, "peer", "waited"), False, profile="dns-withhold")
        for key, value in report["cases"][1]["peer"]["control"].items():
            self.reject_at(("cases", 1, "peer", "control", key), not value)
        for key, value in (("bytes", 0), ("eof", False), ("closed", False), ("primaryEmpty", False),
                           ("primaryUnexpected", 1), ("primaryClosed", False)):
            self.reject_at(("cases", 1, "peer", "terminal", "completion", key), value)
        for key, value in (("empty", False), ("unexpected", 1), ("closed", False)):
            self.reject_at(("cases", 1, "peer", "terminal", "completion", "proxy", key), value)
        for key in ("dnsEmpty", "dnsClosed"):
            self.reject_at(("cases", 0, "peer", "terminal", "completion", key), False, profile="dns-withhold")
        for key, value in (("dnsReplies", 1), ("dnsQuestions", 0), ("dnsA", 3)):
            self.reject_at(("cases", 0, "peer", "terminal", key), value, profile="dns-withhold")
        self.reject_at(("cases", 3, "peer", "terminal", "clientStop"), "broken-pipe")
        self.reject_at(("cases", 3, "peer", "terminal", "withheldWireBytes"), 0)

    def test_deadline_original_clocks_progress_and_immediate_lf_cannot_be_retimed_by_join(self):
        report = tls_deadline_report_data("hosts")
        for field, value in (("responseAfterLaunchNs", 9_999_999_999), ("responseAfterLaunchNs", 12_000_000_001),
                ("clientStopAfterLaunchNs", 9_999_999_999), ("firstGetAfterLaunchNs", 2_000_000_001),
                ("helperWindowChecked", False), ("spawnAfterPeerStartNs", 2_000_000_000),
                ("bodyProgressAfterLaunchNs", []), ("settledAfterPeerStartNs", 11_199_999_999)):
            self.reject_at(("cases", 5, "timing", field), value)
        for frame in (10_000_000_000, 12_000_000_000):
            boundary = deepcopy(report)
            boundary["cases"][5]["timing"].update(responseAfterLaunchNs=frame, settledAfterPeerStartNs=13_400_000_000)
            self.assertIs(self.validate(boundary), boundary)
        early = deepcopy(report)
        early["cases"][5]["timing"].update(responseAfterLaunchNs=1_000_000_000, settledAfterPeerStartNs=15_000_000_000)
        with self.assertRaises(helper.CheckFailure):
            self.validate(early)  # Fifteen-second wait cannot move the original first LF to ten seconds.
        for index in (3, 4):
            for field, value in (("operationEndpointAfterPeerNs", 12_000_000_000),
                    ("cleanupEndpointAfterPeerNs", 14_000_000_000), ("settledAfterPeerNs", 10_999_999_999),
                    ("settledAfterPeerNs", 13_000_000_000), ("phaseAfterPeerNs", 11_000_000_000),
                    ("originalDeadlineChecked", False), ("cleanupExact", 1)):
                self.reject_at(("cases", index, "timing", field), value)
        self.reject_at(("cases", 3, "progress", 1, "afterPeerStartNs"), 10_900_000_000)
        self.reject_at(("cases", 5, "progress", 1, "wireWriteBytes"), 200)
        self.reject_at(("cases", 5, "progress", 2, "sequence"), 2)
        self.reject_at(("cases", 5, "progress", 1, "bodyBytes"), 0)
        self.reject_at(("cases", 5, "peer", "terminal", "incompleteBody"), False)
        # Keep both clocks correlated while introducing a real observation gap
        # or missing coverage; a false hash/schema mismatch must not mask it.
        for mutation in ("gap", "missing-body", "early-stop", "late-get"):
            changed = deepcopy(report); case = changed["cases"][5]
            if mutation == "gap":
                case["progress"][2]["afterPeerStartNs"] += 600_000_000
            elif mutation == "missing-body":
                case["progress"] = [case["progress"][0], case["progress"][1], case["progress"][-1]]
                case["progress"][-1]["bodyBytes"] = 1
                case["peer"]["terminal"]["bodyBytes"] = 1
            elif mutation == "early-stop":
                del case["progress"][-2]
                case["progress"][-1]["bodyBytes"] = 10
                case["peer"]["terminal"]["bodyBytes"] = 10
                case["progress"][-1]["afterPeerStartNs"] = 10_999_999_999
            else:
                for item in case["progress"]:
                    item["afterPeerStartNs"] += 2_000_000_001
                case["timing"].update(responseAfterLaunchNs=12_000_000_000, settledAfterPeerStartNs=13_600_000_000)
            launch = case["timing"]["spawnAfterPeerStartNs"]
            for sequence, item in enumerate(case["progress"], 1):
                item["sequence"] = sequence
            case["peer"]["terminal"]["progressCount"] = len(case["progress"])
            case["timing"]["firstGetAfterLaunchNs"] = case["progress"][0]["afterPeerStartNs"] - launch
            case["timing"]["clientStopAfterLaunchNs"] = case["progress"][-1]["afterPeerStartNs"] - launch
            case["timing"]["bodyProgressAfterLaunchNs"] = [item["afterPeerStartNs"] - launch for item in case["progress"] if item["event"] == "body-byte"]
            with self.subTest(progress=mutation), self.assertRaises(helper.CheckFailure):
                self.validate(changed)

    def test_deadline_raw_receipt_is_bounded_closed_and_not_a_native_receipt_claim(self):
        raw = GitHubTLSCIIntegrationTests.encoded(tls_deadline_report_data("hosts"))
        hashes = tls_deadline_ambient_hashes_data(GitHubTLSCIIntegrationTests.context())
        for index, value in enumerate((b"", bytearray(raw), raw.decode(), raw[:-1], raw + b"{}", b"\xff", b"x" * 131073,
                raw.replace(b'"passed":true', b'"passed":true,"passed":true', 1),
                raw.replace(b'"elapsedMs":12000', b'"elapsedMs":NaN', 1),
                raw.replace(b'"elapsedMs":12000', b'"elapsedMs":1.0', 1),
                b'{"nested":' + b'[' * 17 + b'0' + b']' * 17 + b'}')):
            with self.subTest(raw=index), self.assertRaises(helper.CheckFailure):
                helper.parse_github_tls_deadline_receipt(value, bindings=tls_deadline_binding_data(), profile="hosts", ambient_hashes=hashes)


class GitHubTLSWorkflowContractTests(unittest.TestCase):
    def test_tls_workflow_has_one_compilation_fixed_profiles_and_only_nine_redacted_artifacts(self):
        # One bounded SOURCE read. No YAML loader, workflow dispatch or shell.
        import re
        path = SOURCE / ".github/workflows/desktop-github-connection-tls.yml"
        with path.open("rb") as stream:
            raw = stream.read(16384 + 1)
        self.assertLessEqual(len(raw), 16384)
        workflow = raw.decode("utf-8")
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9-]*):$", workflow.split("\njobs:\n", 1)[1], re.MULTILINE), ["github-readonly-tls-native"])
        self.assertEqual(re.findall(r"ci_foundation\.py ([a-z-]+)'", workflow), ["prepare", "acquire", "compile", "github-tls", "github-tls-deadline", "clean"])
        self.assertEqual(len(re.findall(r"^        run:", workflow, re.MULTILINE)), 8)
        compiler_check = '"$MRK_PYTHON" -I -S -B tests/desktop/test_github_tls_peer_compile.py PeerCompileWarningTests -v'
        self.assertEqual(workflow.count(compiler_check), 1)
        self.assertLess(workflow.index("ci_foundation.py prepare"), workflow.index(compiler_check))
        self.assertLess(workflow.index(compiler_check), workflow.index("ci_foundation.py acquire"))
        self.assertIn("      - tests/desktop/test_github_tls_peer_compile.py\n", workflow)
        self.assertEqual(workflow.count("runs-on: ubuntu-24.04"), 1)
        self.assertIn("Verify sixteen fixed TLS cases", workflow)
        self.assertIn("T1-T3 and T6", workflow)
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
        self.assertEqual(workflow.count('"$MRK_PYTHON" -I -S -B desktop/tools/ci_foundation.py'), 6)
        self.assertEqual(workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("      - tests/desktop/test_github_tls_deadline_peer_contract.py\n", workflow)
        self.assertIn("      - tests/desktop/test_github_tls_resolver_policy.py\n", workflow)
        self.assertEqual(re.findall(r"uses: ([^\s]+)", workflow), [
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"])
        paths = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], ["${{ steps.prepare.outputs.root }}/" + name for name in (
            "public-bindings.json", "acquire-checks.json", "compile-checks.json", "github-tls-checks.json",
            "github-tls/receipt.json", "github-tls-deadline-checks.json", "github-tls-deadline/hosts/receipt.json",
            "github-tls-deadline/dns-withhold/receipt.json", "clean-checks.json")])

    def test_tls_build_explicitly_anchors_both_manifests_without_promoting_adjacent_bytes(self):
        # One bounded SOURCE read; this never executes the build script.
        with (SOURCE / "desktop/src-tauri/build.rs").open("rb") as stream:
            raw = stream.read(8192 + 1)
        self.assertLessEqual(len(raw), 8192)
        build = raw.decode("utf-8")
        for key in ("MRK_GITHUB_TLS_INPUTS_SHA256", "MRK_GITHUB_TLS_DEADLINE_INPUTS_SHA256"):
            self.assertEqual(build.count(f'anchor("{key}");'), 1)
        self.assertIn('println!("cargo:rerun-if-env-changed={name}")', build)
        self.assertIn('println!("cargo:rustc-env={name}={value}")', build)
        self.assertIn('value.len() != 64', build)
        self.assertIn("(b'a'..=b'f').contains(&c)", build)
        for dynamic in ("std::fs", "read_to_string", "std::process", "Command::new", "github-tls-inputs.json", "github-tls-deadline-inputs.json"):
            self.assertNotIn(dynamic, build)


class WindowsReaderGateTests(unittest.TestCase):
    """Inert DATA/source contracts only; these records are not native receipts."""

    @staticmethod
    def context():
        return {"source": "/reviewed-source", "root": "/owned-windows-gate", "sourceSha": "1" * 40,
                "sourceTree": "2" * 40, "runId": "123456", "attempt": 1,
                "imageOS": "win25-vs2026", "imageVersion": "20260920.1.0", "git": "/fixed-git"}

    @classmethod
    def graph_data(cls):
        context = cls.context()
        source, root = Path(context["source"]), Path(context["root"])
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        versions = {"getrandom": "0.3.4", "serde": "1.0.228", "serde_json": "1.0.145", "sha2": "0.10.9",
                    "tokio": "1.48.0", "windows-sys": "0.61.2", "windows-link": "0.2.1"}
        packages, locked, ids = [], [], {}
        declared = {"mobile-release-kit-desktop": "desktop/src-tauri/Cargo.toml",
                    "mrk-linux-mount-observation": "desktop/native/linux-mount-observation/Cargo.toml",
                    "mrk-macos-installed-native": "desktop/native/macos-installed-native/Cargo.toml",
                    "mrk-windows-installed-native": "desktop/native/windows-installed-native/Cargo.toml"}
        targets = {
            "mrk-linux-mount-observation": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
            "mrk-macos-installed-native": 'cfg(all(target_os = "macos", target_arch = "aarch64"))',
            "mrk-windows-installed-native": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
        }
        dependencies = [{"name": name, "source": None, "req": "*", "kind": None, "rename": None,
            "optional": False, "uses_default_features": True, "features": [], "target": target,
            "registry": None, "path": str((source / declared[name]).parent)} for name, target in targets.items()]
        dependencies.append({**deepcopy(dependencies[2]), "kind": "dev", "features": ["qualification-result"]})
        for name, manifest in declared.items():
            ids[name] = name + "@0.1.0"
            locked.append({"name": name, "version": "0.1.0"})
            if name not in {"mobile-release-kit-desktop", "mrk-windows-installed-native"}:
                continue  # Real filtered metadata keeps declarations, not these packages.
            path = source / manifest
            target = {"name": "mobile_release_desktop" if name == "mobile-release-kit-desktop" else name.replace("-", "_"),
                      "kind": ["lib"], "crate_types": ["lib"], "src_path": str(path.parent / "src/lib.rs")}
            units = [target]
            if name == "mobile-release-kit-desktop":
                units.append({"name": "build-script-build", "kind": ["custom-build"], "crate_types": ["bin"],
                              "src_path": str(path.parent / "build.rs")})
            packages.append({"id": ids[name], "name": name, "version": "0.1.0", "source": None,
                             "manifest_path": str(path), "features": {"qualification-result": []}
                                 if name == "mrk-windows-installed-native" else {"allowed": []}, "targets": units,
                             "dependencies": deepcopy(dependencies) if name == "mobile-release-kit-desktop" else []})
        for name, version in versions.items():
            ids[name] = name + "@" + version
            directory = root / "cargo/registry/src/index.crates.io-fixed" / (name + "-" + version)
            units = [{"name": name.replace("-", "_"), "kind": ["lib"], "crate_types": ["lib"],
                      "src_path": str(directory / "src/lib.rs")}]
            if name == "tokio":
                # Match the genuine locked dependency's declaration count, not
                # a claim that Cargo compiles/runs these integration tests.
                units.extend({"name": "case_" + str(index), "kind": ["test"], "crate_types": ["bin"],
                              "src_path": str(directory / "tests" / ("case_" + str(index) + ".rs"))}
                             for index in range(157))
            packages.append({"id": ids[name], "name": name, "version": version, "source": registry,
                "manifest_path": str(directory / "Cargo.toml"), "features": {"allowed": []},
                "targets": units})
            locked.append({"name": name, "version": version, "source": registry, "checksum": "3" * 64})
        direct = ["getrandom", "serde", "serde_json", "sha2", "tokio", "mrk-windows-installed-native"]
        packages[0]["dependencies"].extend({"name": name, "source": registry, "req": "=" + versions[name],
            "kind": None, "rename": None, "optional": False, "uses_default_features": True, "features": [],
            "target": None, "registry": None} for name in direct if name in versions)
        packages[1]["dependencies"] = [{"name": "windows-sys", "source": registry, "req": "=0.61.2",
            "kind": None, "rename": None, "optional": False, "uses_default_features": True, "features": [],
            "target": None, "registry": None}]
        edges = {"mobile-release-kit-desktop": direct, "mrk-windows-installed-native": ["windows-sys"], "windows-sys": ["windows-link"]}
        nodes = []
        for name in ["mobile-release-kit-desktop", "mrk-windows-installed-native", *versions]:
            dependencies = edges.get(name, [])
            nodes.append({"id": ids[name], "features": ["qualification-result"] if name == "mrk-windows-installed-native" else [],
                "dependencies": [ids[item] for item in dependencies],
                "deps": [{"name": item.replace("-", "_"), "pkg": ids[item], "dep_kinds":
                    [{"kind": kind, "target": targets[item]} for kind in (None, "dev")]
                    if name == "mobile-release-kit-desktop" and item == "mrk-windows-installed-native"
                    else [{"kind": None, "target": None}]}
                         for item in dependencies]})
        app = ids["mobile-release-kit-desktop"]
        value = {"version": 1, "packages": packages, "workspace_root": str(source / "desktop/src-tauri"),
                 "workspace_members": [app], "workspace_default_members": [app], "target_directory": str(root / "target"),
                 "resolve": {"root": app, "nodes": nodes}}
        return value, {"version": 4, "package": locked}, context

    def test_windows_reader_active_graph_binds_declared_locals_and_locked_resolution(self):
        value, lock, context = self.graph_data()
        arguments = {"source": Path(context["source"]), "root": Path(context["root"])}
        graph = helper.windows_installed_app_graph(value, lock, **arguments)
        self.assertEqual(set(graph["localIds"]), {"mobile-release-kit-desktop", "mrk-windows-installed-native"})
        self.assertEqual(set(graph["nodes"]) & set(graph["localIds"].values()), set(graph["localIds"].values()))
        native = graph["localIds"]["mrk-windows-installed-native"]
        self.assertEqual(graph["nodes"][native]["features"], ["qualification-result"])
        reordered = deepcopy(value)
        reordered["packages"][0]["dependencies"].reverse()
        reordered["resolve"]["nodes"][0]["deps"][-1]["dep_kinds"].reverse()
        helper.windows_installed_app_graph(reordered, lock, **arguments)
        mutations = {
            "missing-inactive-declaration": lambda row: row["packages"][0]["dependencies"].pop(1),
            "duplicate-local-declaration": lambda row: row["packages"][0]["dependencies"].append(deepcopy(row["packages"][0]["dependencies"][0])),
            "reserved-name-registry-alias": lambda row: row["packages"][0]["dependencies"].append(
                {"name": "mrk-macos-installed-native", "source": "registry+https://github.com/rust-lang/crates.io-index"}),
            "reserved-name-git-alias": lambda row: row["packages"][0]["dependencies"].append(
                {"name": "mrk-linux-mount-observation", "source": "git+https://example.invalid/other"}),
            "unrelated-path-key": lambda row: row["packages"][0]["dependencies"].append(
                {"name": "other-local", "source": "registry+https://github.com/rust-lang/crates.io-index", "path": None}),
            "active-inactive-local": lambda row: row["resolve"]["nodes"].append({"id": "mrk-macos-installed-native@0.1.0",
                "features": [], "deps": [], "dependencies": []}),
            "inactive-local-package": lambda row: row["packages"].append({**deepcopy(row["packages"][1]),
                "id": "mrk-macos-installed-native@0.1.0", "name": "mrk-macos-installed-native",
                "manifest_path": str(Path(context["source"]) / "desktop/native/macos-installed-native/Cargo.toml")}),
            "missing-edge": lambda row: row["resolve"]["nodes"][0]["deps"][0].update(pkg="absent"),
            "root-feature": lambda row: row["resolve"]["nodes"][0].update(features=["allowed"]),
            "missing-qualification-dev": lambda row: row["packages"][0]["dependencies"].pop(3),
            "feature-on-normal-declaration": lambda row: row["packages"][0]["dependencies"][2].update(features=["qualification-result"]),
            "missing-qualification-feature": lambda row: row["packages"][0]["dependencies"][3].update(features=[]),
            "duplicate-qualification-dev": lambda row: row["packages"][0]["dependencies"].append(deepcopy(row["packages"][0]["dependencies"][3])),
            "wrong-dev-kind": lambda row: row["packages"][0]["dependencies"][3].update(kind="build"),
            "wrong-dev-target": lambda row: row["packages"][0]["dependencies"][3].update(target="cfg(windows)"),
            "native-feature-not-active": lambda row: row["resolve"]["nodes"][1].update(features=[]),
            "native-default-feature": lambda row: row["packages"][1]["features"].update(default=["qualification-result"]),
            "dev-edge-missing": lambda row: row["resolve"]["nodes"][0]["deps"][-1]["dep_kinds"].pop(),
            "dev-edge-duplicate": lambda row: row["resolve"]["nodes"][0]["deps"][-1]["dep_kinds"].__setitem__(1, {"kind": None, "target": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))'}),
            "dev-edge-wrong-target": lambda row: row["resolve"]["nodes"][0]["deps"][-1]["dep_kinds"][1].update(target=None),
            "unknown-feature": lambda row: row["resolve"]["nodes"][2].update(features=["unknown"]),
            "registry-path": lambda row: row["packages"][2].update(manifest_path="/other/registry/Cargo.toml"),
            "local-path": lambda row: row["packages"][0].update(manifest_path="/other/Cargo.toml"),
            "workspace": lambda row: row.update(workspace_members=[]),
            "target": lambda row: row.update(target_directory="/other-target"),
            "duplicate-package": lambda row: row["packages"].append(deepcopy(row["packages"][2])),
            "typed-version": lambda row: row.update(version=True),
        }
        for label, change in mutations.items():
            with self.subTest(case=label):
                altered = deepcopy(value); change(altered)
                with self.assertRaises(helper.CheckFailure): helper.windows_installed_app_graph(altered, lock, **arguments)
        for field, changed in (("name", "other-local"), ("path", "/other/native"), ("target", 'cfg(unix)'),
                ("kind", "build"), ("source", "registry+https://github.com/rust-lang/crates.io-index"),
                ("registry", "other"), ("rename", "alias"), ("req", "^0.1"),
                ("optional", True), ("uses_default_features", False), ("features", ["other"]),
                ("optional", 0), ("uses_default_features", 1), ("extra", None)):
            with self.subTest(declaration=field, value=changed):
                altered = deepcopy(value); altered["packages"][0]["dependencies"][1][field] = changed
                with self.assertRaises(helper.CheckFailure): helper.windows_installed_app_graph(altered, lock, **arguments)
        altered = deepcopy(value); del altered["packages"][0]["dependencies"][1]["path"]
        with self.assertRaises(helper.CheckFailure): helper.windows_installed_app_graph(altered, lock, **arguments)
        wrong_lock = deepcopy(lock); wrong_lock["package"][4]["source"] = "git+https://example.invalid/input"
        with self.assertRaises(helper.CheckFailure): helper.windows_installed_app_graph(value, wrong_lock, **arguments)
        wrong_lock = deepcopy(lock); wrong_lock["package"].pop(2)  # Inactive Mac still belongs to the complete source lock.
        with self.assertRaises(helper.CheckFailure): helper.windows_installed_app_graph(value, wrong_lock, **arguments)

    def test_windows_reader_declared_target_inventory_is_bounded_not_compiler_permission(self):
        value, lock, context = self.graph_data()
        arguments = {"source": Path(context["source"]), "root": Path(context["root"])}
        dependency = next(package for package in value["packages"] if package["name"] == "tokio")
        self.assertEqual(len(dependency["targets"]), 158)
        graph = helper.windows_installed_app_graph(value, lock, **arguments)
        self.assertEqual(len(graph["packages"][dependency["id"]]["targets"]), 158)
        targets = dependency["targets"]
        dependency["targets"] = targets + [
            {**targets[1], "name": "extra_" + str(index), "src_path": "/inert/extra_" + str(index) + ".rs"}
            for index in range(512 - len(targets))]
        self.assertEqual(len(dependency["targets"]), 512)
        helper.windows_installed_app_graph(value, lock, **arguments)
        for invalid in (dependency["targets"] + [deepcopy(targets[1])], [], (), None, True):
            with self.subTest(target_type=type(invalid).__name__, count=len(invalid) if type(invalid) is list else None):
                dependency["targets"] = invalid
                with self.assertRaisesRegex(helper.CheckFailure, "declared target inventory"):
                    helper.windows_installed_app_graph(value, lock, **arguments)

    def test_windows_reader_artifact_accepts_active_declared_units_and_exact_libtest(self):
        value, lock, context = self.graph_data()
        source, root = Path(context["source"]), Path(context["root"])
        graph = helper.windows_installed_app_graph(value, lock, source=source, root=root)
        app = graph["packages"][graph["appId"]]
        compiled = {"reason": "compiler-artifact", "package_id": graph["appId"], "manifest_path": app["manifest_path"],
                    "target": app["targets"][1], "features": [], "profile": {"test": False, "debug_assertions": True},
                    "executable": None, "fresh": False}
        script = {"reason": "build-script-executed", "package_id": graph["appId"], "out_dir": str(root / "target/debug/build/app/out")}
        executable = root / "target/x86_64-pc-windows-msvc/debug/deps/mobile_release_desktop-fixed.exe"
        libtest = {**compiled, "target": app["targets"][0], "profile": {"test": True, "debug_assertions": True}, "executable": str(executable)}
        rows = [compiled, script, libtest, {"reason": "build-finished", "success": True}]
        def parse(items):
            raw = b"\n".join(json.dumps(item, separators=(",", ":")).encode("ascii") for item in items)
            with patch.object(helper, "ordinary_windows_executable", side_effect=lambda path, **_: Path(path)):
                return helper.windows_installed_app_test_path(raw, graph, source=source, root=root)
        self.assertEqual(parse(rows), executable)
        native = graph["packages"][graph["localIds"]["mrk-windows-installed-native"]]
        native_unit = {**compiled, "package_id": native["id"], "manifest_path": native["manifest_path"],
                       "target": native["targets"][0], "profile": {"test": False}, "features": ["qualification-result"]}
        self.assertEqual(parse([native_unit, *rows]), executable)
        for features in ([], ["default"], ["qualification-result", "other"]):
            with self.subTest(native_features=features), self.assertRaises(helper.CheckFailure):
                parse([{**native_unit, "features": features}, *rows])
        dependency = next(package for package in graph["packages"].values() if package["name"] == "tokio")
        dependency_unit = {**compiled, "package_id": dependency["id"], "manifest_path": dependency["manifest_path"],
                           "target": dependency["targets"][1], "profile": {"test": True, "debug_assertions": True}}
        mutations = {
            "declared-but-unselected-dependency-test": lambda data: data.insert(0, deepcopy(dependency_unit)),
            "dependency-library-test-profile": lambda data: data.insert(0, {**deepcopy(dependency_unit), "target": dependency["targets"][0]}),
            "other-dependency-feature-equality": lambda data: data.insert(0, {**deepcopy(dependency_unit),
                "target": dependency["targets"][0], "profile": {"test": False}, "features": ["allowed"]}),
            "duplicate-libtest": lambda data: data.insert(3, deepcopy(data[2])),
            "after-final": lambda data: data.append(deepcopy(data[2])),
            "failed-build": lambda data: data[-1].update(success=False),
            "wrong-feature": lambda data: data[2].update(features=["allowed"]),
            "wrong-manifest": lambda data: data[2].update(manifest_path="/other/Cargo.toml"),
            "wrong-profile": lambda data: data[2]["profile"].update(test=False),
            "wrong-target": lambda data: data[2].update(target={**app["targets"][0], "name": "other"}),
            "inactive-build-script": lambda data: data[1].update(package_id="mrk-macos-installed-native@0.1.0"),
            "uncompiled-build-script": lambda data: data.pop(0),
            "script-target-escape": lambda data: data[1].update(out_dir=str(root / "target/../outside")),
            "unknown-message": lambda data: data[1].update(reason="other"),
        }
        for label, change in mutations.items():
            with self.subTest(case=label):
                altered = deepcopy(rows); change(altered)
                with self.assertRaises(helper.CheckFailure): parse(altered)

    @classmethod
    def feature_graph_data(cls):
        value, lock, context = cls.graph_data()
        packages = {row["name"]: row for row in value["packages"]}
        nodes = {row["id"]: row for row in value["resolve"]["nodes"]}
        native, tokio, platform = (packages[name] for name in ("mrk-windows-installed-native", "tokio", "windows-sys"))
        platform["features"] = {"default": ["Base"], "Base": ["Win32"], "Win32": ["Base"],
                                "Declared": ["Base"], "Forwarded": ["Base"], "Weak": ["Base"], "Inactive": []}
        nodes[platform["id"]]["features"] = sorted(platform["features"])
        native["dependencies"][0]["features"] = ["Declared"]
        tokio["dependencies"] = [{**deepcopy(native["dependencies"][0]), "features": [], "optional": True,
                                  "uses_default_features": False, "target": "cfg(windows)"}]
        tokio["dependencies"].append({**deepcopy(tokio["dependencies"][0]), "kind": "dev", "features": ["Inactive"]})
        tokio["features"] = {"process": ["windows-sys/Forwarded", "windows-sys?/Weak", "other?/Inactive"],
                             "unselected": ["windows-sys/Inactive"]}
        nodes[tokio["id"]].update(features=["process"], dependencies=[platform["id"]],
            deps=[{"name": "windows_sys", "pkg": platform["id"], "dep_kinds": [{"kind": None, "target": "cfg(windows)"}]}])
        return value, lock, context, packages, nodes

    def test_windows_reader_active_features_are_exact_closed_and_not_metadata_surplus(self):
        value, lock, context, packages, _ = self.feature_graph_data()
        source, root = Path(context["source"]), Path(context["root"])
        graph = helper.windows_installed_app_graph(value, lock, source=source, root=root)
        platform, tokio = packages["windows-sys"], packages["tokio"]
        expected = ["Base", "Declared", "Forwarded", "Weak", "Win32", "default"]
        unit_features = helper.windows_installed_app_unit_features(graph)
        self.assertEqual(unit_features[platform["id"]], expected)
        self.assertIn("Inactive", graph["nodes"][platform["id"]]["features"])
        self.assertEqual(unit_features[tokio["id"]], ["process"])
        # Match forwarding to the actual declaration alias, not its normalized edge spelling.
        tokio["dependencies"][0]["rename"] = "platform-api"
        tokio["features"]["process"] = ["platform-api/Forwarded", "platform-api?/Weak"]
        graph["nodes"][tokio["id"]]["deps"][0]["name"] = "platform_api"
        self.assertEqual(helper.windows_installed_app_unit_features(graph)[platform["id"]], expected)
        app = packages["mobile-release-kit-desktop"]
        executable = root / "target/x86_64-pc-windows-msvc/debug/deps/mobile_release_desktop-fixed.exe"
        unit = {"reason": "compiler-artifact", "package_id": platform["id"], "manifest_path": platform["manifest_path"],
                "target": platform["targets"][0], "profile": {"test": False}, "features": expected, "executable": None}
        libtest = {**unit, "package_id": app["id"], "manifest_path": app["manifest_path"], "target": app["targets"][0],
                   "profile": {"test": True, "debug_assertions": True}, "features": [], "executable": str(executable), "fresh": False}
        for features in (expected, expected[:-1], sorted(expected + ["Inactive"]), expected + ["Base"]):
            raw = b"\n".join(json.dumps(row).encode("ascii") for row in (
                {**unit, "features": features}, libtest, {"reason": "build-finished", "success": True}))
            with patch.object(helper, "ordinary_windows_executable", side_effect=lambda path, **_: Path(path)):
                if features == expected:
                    self.assertEqual(helper.windows_installed_app_test_path(raw, graph, source=source, root=root), executable)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.windows_installed_app_test_path(raw, graph, source=source, root=root)

    def test_windows_reader_active_feature_declarations_fail_closed(self):
        def invalid(label, change):
            with self.subTest(case=label):
                value, lock, context, packages, nodes = self.feature_graph_data()
                change(packages, nodes)
                with self.assertRaises(helper.CheckFailure):
                    graph = helper.windows_installed_app_graph(value, lock,
                        source=Path(context["source"]), root=Path(context["root"]))
                    helper.windows_installed_app_unit_features(graph)
        for field, changed in (("target", "cfg(unix)"), ("source", "git+https://example.invalid/other"),
                               ("rename", "foreign"), ("uses_default_features", 1), ("optional", 0),
                               ("features", ["Unknown"]), ("features", ()), ("kind", "build")):
            invalid(field, lambda p, n, f=field, v=changed: p["tokio"]["dependencies"][0].update({f: v}))
        for field in ("name", "source", "req", "kind", "rename", "optional", "uses_default_features",
                      "features", "target", "registry"):
            invalid("missing-" + field, lambda p, n, f=field: p["tokio"]["dependencies"][0].pop(f))
        invalid("ambiguous-declaration", lambda p, n: p["tokio"]["dependencies"].append(deepcopy(p["tokio"]["dependencies"][0])))
        invalid("duplicate-edge", lambda p, n: n[p["tokio"]["id"]]["deps"].append(deepcopy(n[p["tokio"]["id"]]["deps"][0])))
        invalid("unreviewed-dev-unit", lambda p, n: n[p["tokio"]["id"]]["deps"][0]["dep_kinds"][0].update(kind="dev"))
        invalid("missing-metadata-feature", lambda p, n: n[p["windows-sys"]["id"]]["features"].remove("Forwarded"))
        invalid("unknown-forwarding", lambda p, n: p["tokio"]["features"].update(process=["windows-sys/Unknown"]))
        invalid("aliased-forwarding", lambda p, n: p["tokio"]["features"].update(process=["windows_sys/Forwarded"]))
        for expression in ("dep:windows-link", "windows-link/feature", "Unknown"):
            invalid(expression, lambda p, n, e=expression: p["windows-sys"]["features"].update(Base=[e]))
        invalid("feature-map-bound", lambda p, n: p["windows-sys"]["features"].update({"extra_" + str(i): [] for i in range(512)}))
        invalid("feature-list-bound", lambda p, n: p["windows-sys"]["features"].update(Base=["Win32"] * 129))

    def test_windows_reader_selected_eleven_and_compile_argv_are_closed(self):
        names = (
            "runtime::windows_version::tests::windows_manifest_and_observed_inventory_are_exact",
            "runtime::windows_version::tests::windows_manifest_anchors_schema_and_inventory_are_bound_before_use",
            "runtime::windows_version::tests::windows_manifest_rejects_case_aliases_and_file_directory_conflicts",
            "runtime::windows_version::tests::windows_manifest_preserves_every_supplier_member_and_hash",
            "runtime::windows_version::tests::windows_manifest_budgets_include_manifest_not_only_payload",
            "runtime::windows_version::tests::windows_six_method_data_does_not_enable_any_production_profile",
            "installed_runtime_windows::tests::stopped_expired_and_lost_channel_inspection_never_enters_native_work",
            "installed_runtime_windows::tests::unknown_completion_precedes_post_call_stop_and_deadline",
            "installed_runtime_windows::tests::ordinary_returned_refusal_is_not_unknown_and_pending_is_not_a_join",
            "installed_runtime_windows::tests::settlement_and_interruption_are_one_shot_not_close_by_drop",
            "installed_runtime_windows::tests::selected_ancestors_remain_live_but_unrelated_subtrees_do_not",
        )
        self.assertEqual(helper.WINDOWS_INSTALLED_APP_INERT, names)
        raw = ("running 11 tests\n" + "\n".join("test " + name + " ... ok" for name in names)
               + "\ntest result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 173 filtered out; finished in 0.01s\n").encode("ascii")
        self.assertEqual(helper.windows_installed_app_libtest(raw)["filteredObserved"], 173)
        variants = (raw.replace(names[0].encode(), names[1].encode()), raw.replace(b"0 ignored", b"1 ignored"),
                    raw.replace(b"11 passed", b"10 passed"), raw.replace(b" ... ok", b" ... FAILED", 1),
                    raw + b"extra\n", b"x" * (64 * 1024 + 1), raw.replace(b"running 11 tests", b"running 0 tests"))
        for number, altered in enumerate(variants):
            with self.subTest(case=number), self.assertRaises(helper.CheckFailure): helper.windows_installed_app_libtest(altered)
        context = self.context()
        self.assertEqual(helper.windows_installed_app_argv("/fixed-cargo", context), ["/fixed-cargo", "test", "--locked", "--offline", "--jobs", "1",
            "--no-default-features", "--target", "x86_64-pc-windows-msvc", "--manifest-path", "/reviewed-source/desktop/src-tauri/Cargo.toml",
            "--target-dir", "/owned-windows-gate/target", "--lib", "--no-run", "--message-format=json"])

    def test_windows_reader_runtime_data_binds_actual_outcome_and_redacts_paths(self):
        context = self.context()
        value = {"schemaVersion": 1, **{key: context[key] for key in ("sourceSha", "runId", "attempt", "imageOS", "imageVersion")},
            "powerShell": {"path": r"C:\Program Files\PowerShell\7\pwsh.exe", "version": "7.5.3", "edition": "Core"},
            "runtime": {"version": "10.0.0", "framework": ".NET 10.0.0"},
            "processAssembly": {"path": r"C:\Program Files\PowerShell\7\System.Diagnostics.Process.dll", "name": "System.Diagnostics.Process",
                "version": "10.0.0.0", "moduleVersionId": "11111111-2222-3333-4444-555555555555",
                "informationalVersion": "10.0.0+" + "a" * 40, "sourceRevision": None}}
        public, paths = helper.windows_installed_runtime_identity(value, context)
        self.assertEqual(set(paths), {"powerShell", "processAssembly"})
        self.assertNotIn("Program Files", json.dumps(public)); self.assertNotIn('"path"', json.dumps(public))
        for role in paths: public[role].update(size=123, sha256="4" * 64)
        record = helper.windows_installed_phase_receipt(context, "windows-installed-runtime-data", identity=public)
        summary, observed = helper.windows_installed_runtime_retention(record, context, "success")
        self.assertEqual(summary["status"], "failed"); self.assertEqual(observed, record)  # Validation is not retained publication.
        self.assertIs(summary["sourceMappingAuthenticated"], False); self.assertIs(summary["ordinaryStartAuthorized"], False)
        for outcome, status in (("failure", "failed"), ("skipped", "unavailable"), ("cancelled", "unavailable")):
            summary, observed = helper.windows_installed_runtime_retention(record, context, outcome)
            self.assertEqual(summary["status"], status); self.assertIsNone(observed)
        self.assertEqual(helper.windows_installed_runtime_retention(None, context, "success")[0]["status"], "failed")
        mutations = {
            "foreign-source": lambda item: item.update(sourceSha="9" * 40),
            "typed-attempt": lambda item: item.update(attempt=True),
            "path-alias": lambda item: item["powerShell"].update(path=r"C:\Program Files\..\pwsh.exe"),
            "wrong-role": lambda item: item["processAssembly"].update(path=r"C:\Program Files\other.dll"),
            "extra-field": lambda item: item["powerShell"].update(extra="unrelated"),
            "module-shape": lambda item: item["processAssembly"].update(moduleVersionId="not-an-id"),
            "framework-path": lambda item: item["runtime"].update(framework=r"C:\private"),
            "source-revision": lambda item: item["processAssembly"].update(sourceRevision="unknown/revision"),
        }
        for label, change in mutations.items():
            with self.subTest(case=label):
                altered = deepcopy(value); change(altered)
                with self.assertRaises(helper.CheckFailure): helper.windows_installed_runtime_identity(altered, context)
        altered = deepcopy(record); altered["identity"]["powerShell"]["path"] = value["powerShell"]["path"]
        self.assertEqual(helper.windows_installed_runtime_retention(altered, context, "success")[0]["status"], "failed")
        with self.assertRaises(helper.CheckFailure): helper.windows_installed_runtime_retention(record, context, "queued")

        for role, fields in {"powerShell": ("version", "edition"), "runtime": ("version", "framework"),
                             "processAssembly": ("name", "version", "moduleVersionId")}.items():
            for field in fields:
                for missing in (False, True):
                    with self.subTest(role=role, field=field, missing=missing):
                        altered = deepcopy(record)
                        if missing: del altered["identity"][role][field]
                        else: altered["identity"][role][field] = None
                        summary, accepted = helper.windows_installed_runtime_retention(altered, context, "success")
                        self.assertEqual(summary["status"], "failed"); self.assertIsNone(accepted)
        for role, field, wrong in (("powerShell", "edition", "Desktop"), ("powerShell", "version", "unknown"),
                ("runtime", "framework", "other-runtime"), ("processAssembly", "name", "Other.Assembly"),
                ("processAssembly", "moduleVersionId", "not-a-module-id"), ("processAssembly", "sourceRevision", "not-hex")):
            with self.subTest(role=role, field=field):
                altered = deepcopy(record); altered["identity"][role][field] = wrong
                self.assertIsNone(helper.windows_installed_runtime_retention(altered, context, "success")[1])
        altered = deepcopy(record); altered["attempt"] = True
        self.assertIsNone(helper.windows_installed_runtime_retention(altered, context, "success")[1])
        altered = deepcopy(record); altered["identity"]["processAssembly"]["informationalVersion"] = None
        self.assertEqual(helper.windows_installed_runtime_retention(altered, context, "success")[1], altered)

        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        source = Path(context["root"]) / "runtime-data-checks.json"
        destination = Path(context["root"]) / "public/runtime-data-checks.json"

        def retain(*, outcome="success", input_error=None, payload=raw, output_error=None,
                   short_write=False, close_error=False, readback_error=None, readback=raw):
            reads, written = [], []

            def read(path, limit):
                reads.append(path)
                self.assertEqual(limit, 64 << 10)
                if path == source:
                    if input_error is not None: raise input_error
                    return payload
                self.assertEqual(path, destination)
                if readback_error is not None: raise readback_error
                return readback

            class Output:
                def __enter__(self):
                    return self

                def write(self, data):
                    written.append(data)
                    if output_error is not None: raise output_error
                    return len(data) - int(short_write)

                def __exit__(self, *_):
                    if close_error: raise OSError("inert public close failure")

            with patch.object(helper, "windows_installed_bytes", side_effect=read), \
                 patch.object(helper.Path, "open", autospec=True, return_value=Output()) as opened:
                result = helper.windows_installed_retain_runtime(context, outcome)
                if result[1] is None: opened.assert_not_called()
                else: opened.assert_called_once_with(destination, "xb")
            return result, reads, written

        (summary, accepted), reads, written = retain()
        self.assertEqual(summary["status"], "observed")
        self.assertEqual(reads, [source, destination]); self.assertEqual(written, [raw])
        self.assertEqual(accepted, {"path": source.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        for failure in (FileNotFoundError("inert missing"), PermissionError("inert unreadable"),
                helper.CheckFailure("inert nonordinary"), helper.CheckFailure("inert over-bound"),
                helper.CheckFailure("inert changed during stable read")):
            with self.subTest(input_failure=str(failure)):
                (summary, accepted), reads, written = retain(input_error=failure)
                self.assertEqual(summary["status"], "failed"); self.assertIsNone(accepted)
                self.assertEqual(reads, [source]); self.assertEqual(written, [])
        for payload in (b"{}", b"not-json", b"x" * (64 * 1024 + 1),
                        raw.replace(b'"edition":"Core"', b'"edition":null')):
            with self.subTest(invalid_input=len(payload)):
                (summary, accepted), reads, written = retain(payload=payload)
                self.assertEqual(summary["status"], "failed"); self.assertIsNone(accepted)
                self.assertEqual(reads, [source]); self.assertEqual(written, [])
        for outcome in ("failure", "skipped", "cancelled", "unavailable"):
            (summary, accepted), reads, written = retain(outcome=outcome)
            self.assertEqual(summary["status"], "failed" if outcome == "failure" else "unavailable")
            self.assertIsNone(accepted); self.assertEqual(reads, []); self.assertEqual(written, [])
        for options in ({"output_error": OSError("inert public write failure")}, {"short_write": True},
                        {"close_error": True}, {"readback_error": OSError("inert public readback failure")},
                        {"readback": raw + b"changed"}):
            with self.subTest(public_failure=next(iter(options))), self.assertRaises((OSError, helper.CheckFailure)):
                retain(**options)

    def test_windows_reader_source_custody_and_original_aggregate_deadline(self):
        context = self.context()
        rows = [{"path": name, "size": 1, "sha256": "5" * 64} for name in helper.WINDOWS_INSTALLED_SOURCES]
        raw = "\0".join(row["path"] for row in rows) + "\0"
        with patch.object(helper, "clean_environment", return_value={}), patch.object(helper, "run", side_effect=["", raw]) as run, \
             patch.object(helper, "fixed_file_inventory", return_value=rows):
            self.assertEqual(helper.windows_installed_source_files(Path(context["source"]), Path(context["root"]), context["git"]), rows)
            self.assertEqual([call.kwargs["check"] for call in run.call_args_list],
                             ["windows-installed-source-status", "windows-installed-source-inventory"])
        for outputs in ([" M tracked"], ["", raw[:-1]], ["", "other\0"]):
            with patch.object(helper, "clean_environment", return_value={}), patch.object(helper, "run", side_effect=outputs), \
                 patch.object(helper, "fixed_file_inventory", return_value=rows), self.assertRaises(helper.CheckFailure):
                helper.windows_installed_source_files(Path(context["source"]), Path(context["root"]), context["git"])
        context["sourceFiles"] = rows
        with patch.object(helper, "windows_installed_directories"), patch.object(helper, "fixed_file_inventory", return_value=rows), \
             patch.object(helper, "no_cargo_configuration"), patch.object(helper.Path, "exists", return_value=False), \
             patch.object(helper.Path, "is_symlink", return_value=False), patch.dict(helper.os.environ, {}, clear=True), \
             patch.object(helper, "run", side_effect=AssertionError("retention must not launch any tool")):
            helper.windows_installed_inputs(context, retention_only=True)
        with patch.object(helper.time, "monotonic", return_value=100.0):
            self.assertEqual(helper.windows_installed_remaining(200.0, 60), 60)
            self.assertEqual(helper.windows_installed_remaining(105.9, 60), 5)
            with self.assertRaises(helper.CheckFailure): helper.windows_installed_remaining(100.9, 60)
        with patch.object(helper.time, "monotonic", return_value=106.0), self.assertRaises(helper.CheckFailure):
            helper.windows_installed_remaining(105.9, 60)  # Same deadline, never renewed per command.

    def test_windows_reader_existing_job_and_phase_routes_remain_narrow(self):
        text = HELPER.read_text(encoding="utf-8")
        phase = text.split("def windows_installed_phase(", 1)[1].split("def main(", 1)[0]
        self.assertIn('retention_only=name in {\n        "retain", "windows-installed-native-finalize", *WINDOWS_FULLWALK_DATA_PHASES}', phase)
        self.assertLess(phase.index('if name == "windows-installed-native-finalize"'), phase.index('phases = ("acquire", "compile", "windows-installed-native")'))
        self.assertLess(phase.index('if name == "windows-installed-runtime-data"'), phase.index('phases = ("acquire", "compile", "windows-installed-native")'))
        retained = phase.split('if name == "retain":', 1)[1].split('phases = ("acquire", "compile", "windows-installed-native")', 1)[0]
        for unavailable in ('run(', 'tools(', 'runtime-identity.private.json', 'source_unchanged('): self.assertNotIn(unavailable, retained)
        self.assertNotIn('files["runtime-data-checks.json"]', retained)
        self.assertLess(retained.index('for filename, limit in files.items()'),
                        retained.index('windows_installed_retain_runtime(context, outcome)'))
        self.assertIn('"runtimeIdentity": runtime', retained)
        self.assertEqual(phase.count('app_argv = windows_installed_app_argv(cargo, context)'), 1)
        self.assertIn('[app_artifact["path"], *WINDOWS_INSTALLED_APP_INERT, "--exact", "--test-threads=1"]', phase)
        self.assertIn('[artifact["path"], *WINDOWS_INSTALLED_INERT, "--exact", "--test-threads=1"]', phase)
        self.assertNotIn('[artifact["path"], WINDOWS_INSTALLED_TEST,', phase)
        self.assertNotIn('"native.stdout"', phase)
        self.assertNotIn('"native.stderr"', phase)
        self.assertIn('WINDOWS_INSTALLED_INERT, 5)', phase)
        self.assertNotIn('[app_artifact["path"], WINDOWS_FULLWALK_TEST,', phase)
        workflow = (SOURCE / ".github/workflows/desktop-foundation.yml").read_text(encoding="utf-8").split("  windows-installed-native:\n", 1)[1]
        self.assertIn("runs-on: windows-2025-vs2026", workflow)
        self.assertEqual(workflow.count("continue-on-error: true"), 1)
        self.assertIn("MRK_WINDOWS_RUNTIME_DATA_STEP_OUTCOME: ${{ steps.runtime-data.outcome }}", workflow)
        self.assertLess(workflow.index('id: ordinary-preflight'), workflow.index('id: ordinary-owner'))
        self.assertLess(workflow.index('id: ordinary-owner'), workflow.index('ci_foundation.py windows-installed-native-finalize'))
        self.assertLess(workflow.index('ci_foundation.py windows-installed-native-finalize'), workflow.index('id: runtime-data'))
        self.assertIn('MRK_WINDOWS_ORDINARY_OWNER_STEP_OUTCOME: ${{ steps.ordinary-owner.outcome }}', workflow)
        self.assertIn('& $env:MRK_WINDOWS_NATIVE_ARTIFACT ordinary_owner::hosted_ordinary_original_handle_contract --exact --ignored --nocapture --test-threads=1', workflow)
        direct = workflow.split('id: ordinary-owner', 1)[1].split('      - name: Validate separately', 1)[0]
        self.assertIn('timeout-minutes: 4', direct)
        self.assertIn('$originalExitCode = $LASTEXITCODE', direct)
        self.assertNotIn('MRK_PYTHON', direct)
        self.assertIn('[System.IO.FileMode]::CreateNew', direct)
        self.assertNotIn('ordinary-owner-intent.private.json', retained)
        self.assertNotIn('ordinary-request.txt', retained)
        self.assertNotIn('ordinary-owner-result.private.json', retained)
        self.assertNotIn('ordinary-owner-exit.private.json', retained)
        self.assertNotIn('windows-installed-native-preflight-checks.json', retained)
        self.assertNotIn('ordinary-output', retained)
        self.assertLess(workflow.index('id: runtime-data'), workflow.index('id: retain'))
        self.assertIn('[System.Diagnostics.Process].Assembly', workflow)
        for unavailable in ('Process.Start', 'New-LocalUser', 'Set-Acl', 'Add-Type', 'Start-Process', 'Get-Process'):
            self.assertNotIn(unavailable, workflow)


    @classmethod
    def ordinary_data(cls):
        context = {**cls.context(), "root": r"C:\runner\_temp\mrk-windows-installed-native-123456-1"}
        artifact = {"path": context["root"] + r"\target\x86_64-pc-windows-msvc\debug\deps\mrk_windows_installed_native-aaaaaaaaaaaaaaaa.exe",
                    "size": 37, "sha256": "3" * 64}
        stamp = {"volume": 77, "fileId": "11" * 16, "creation": 100, "write": 200, "change": 300,
                 "size": 37, "allocation": 4096, "links": 1, "attributes": 128}
        transitions = []
        for number, (role, mask) in enumerate(helper.WINDOWS_ORDINARY_ACLS, 1):
            before = (dict(stamp) if role == "artifact" else
                      {**stamp, "fileId": f"{number:032x}", "size": 0, "allocation": 0, "attributes": 16})
            transitions.append({"role": role, "mask": mask, "before": before, "after": {**before, "change": before["change"] + 1},
                "securityBefore": "4" * 64, "securityAfter": "5" * 64, "singleExplicitNoninheritingAce": True})
        before, after = (helper.windows_ordinary_wire(transitions[5][key]) for key in ("before", "after"))
        request = helper.windows_ordinary_request(context, artifact, before)
        command_sha = request.decode("ascii").split("\ncommandSha256=", 1)[1].split("\n", 1)[0]
        binding = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "sourceTree": context["sourceTree"],
                   "runId": context["runId"], "attempt": 1, "artifactBytes": artifact["size"],
                   "artifactSha256": artifact["sha256"], "commandSha256": command_sha}
        native = {"context": "ordinary-admitted", "contextContracts": 1, "admitted": 1, "refused": 0,
                  "rootContracts": 1, "rootNotExecuted": 0, "primaryOriginals": 1, "absentThreadReceipts": 6,
                  "closedOriginals": 2, "unknown": 0, "bookSettled": True}
        child = {**binding, "accountSidSha256": "6" * 64, "test": helper.WINDOWS_INSTALLED_TEST, "native": native,
                 "resultFile": {"createNew": True, "writeCalls": 1, "closeGate": "original-child-exit-zero-required"}}
        count = len(helper.PureWindowsPath(context["root"]).parents) + 1 + 8
        owner = {**binding, "accountSidSha256": "6" * 64, "ownerTest": helper.WINDOWS_ORDINARY_OWNER,
            "childTest": helper.WINDOWS_INSTALLED_TEST, "createCalls": 1, "createReturn": 1, "createError": None, "firstWait": 0,
            "exitReturn": 1, "originalExitCode": 0, "terminateCalls": 0, "processCloseReturn": 1, "threadCloseReturn": 1,
            "deadlineLatched": False, "unknown": False, "parentBookSettled": True, "inputOriginals": count,
            "inputOriginalsClosed": count, "freshAccountVerified": True, "onlyUsersMembership": True,
            "accountRemovedAfterSettlement": True, "nativeResultSha256": hashlib.sha256(helper.canonical_json(child)).hexdigest(),
            "aclTransitions": transitions, "ownerResult": {"createNew": True, "writeCalls": 1,
            "closeGate": "original-owner-exit-zero-required"}, "managedSourceMappingAuthenticated": False,
            "managedOrdinaryStartAuthorized": False, "protectedFullwalk": False, "productionEnabled": False}
        original_exit = {key: binding[key] for key in ("schemaVersion", "sourceSha", "sourceTree", "runId", "attempt", "artifactSha256")}
        original_exit.update(ownerTest=helper.WINDOWS_ORDINARY_OWNER, originalWaitReturned=True, exitCode=0,
                             writerCloseGate="original-owner-step-success-required")
        return context, artifact, before, after, owner, child, original_exit

    @staticmethod
    def ordinary_accept(data, outcome="success"):
        context, artifact, before, after, owner, child, original_exit = data
        return helper.windows_ordinary_records(context, artifact, before, after,
            helper.canonical_json(owner), helper.canonical_json(child), helper.canonical_json(original_exit), outcome)

    @classmethod
    def fullwalk_prepared_fixture(cls):
        # Synthetic current-source/payload records only. No preparer or runtime is executed.
        context = {**cls.ordinary_data()[0], "qualificationProfile": helper.WINDOWS_FULLWALK_PROFILE,
                   "python": "/inert-host-python", "platform": "windows",
                   "fullwalkInputs": {"pins": [{"path": name, "size": size, "sha256": sha}
                       for name, (size, sha) in helper.WINDOWS_FULLWALK_PINS.items()],
                       "curl": {"path": r"C:\Windows\System32\curl.exe", "sha256": "e" * 64}}}
        bootstrap_names = ("engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
            "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py", "github-ca.pem")
        names = set(helper.WINDOWS_INSTALLED_SOURCES) | set(helper.WINDOWS_FULLWALK_PINS) | {
            "src/mobile_release/__init__.py", "src/mobile_release/_desktop_engine.py",
            *("desktop/" + name for name in bootstrap_names), *helper.WINDOWS_FULLWALK_HEADLESS_SOURCES.values()}
        sources = {name: ("INERT SOURCE " + name + "\n").encode("ascii") for name in names}
        sources["src/mobile_release/__init__.py"] = b'__version__ = "0.1.0"\n'
        source_rows = {name: {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                       for name, raw in sources.items()}
        for name, (size, digest) in helper.WINDOWS_FULLWALK_PINS.items():
            source_rows[name] = {"path": name, "size": size, "sha256": digest}
        context["sourceFiles"] = [source_rows[name] for name in sorted(source_rows)]
        payload = {name: {"path": name, "size": len(name), "sha256": hashlib.sha256(name.encode("ascii")).hexdigest()}
                   for name in helper.WINDOWS_FULLWALK_PAYLOAD_NAMES if name != "manifest.json"}
        for name in bootstrap_names:
            payload[name] = {**source_rows["desktop/" + name], "path": name}
        size, digest = helper.WINDOWS_FULLWALK_PINS["desktop/licenses/windows-embedded-runtime.txt"]
        payload["python/MRK-EMBEDDED-NOTICES.txt"] = {"path": "python/MRK-EMBEDDED-NOTICES.txt", "size": size, "sha256": digest}
        rows = [payload[name] for name in sorted(payload)]
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "0.1.0", "target": helper.TARGETS["windows"],
            "coreSha256": payload["core.zip"]["sha256"], "protocolSha256": source_rows["src/mobile_release/_desktop_engine.py"]["sha256"],
            "inventorySha256": hashlib.sha256(helper.canonical_json(rows)).hexdigest(), "files": rows}
        manifest_raw = helper.canonical_json(manifest) + b"\n"
        receipt = {"manifestSha256": hashlib.sha256(manifest_raw).hexdigest(), "protocolSha256": manifest["protocolSha256"],
            "qualification": "prepared-not-native-verified", "inputSha256": helper.WINDOWS_FULLWALK_ZIP_SHA256,
            "supplierInventorySha256": "172b1201a41ba5d9b2d3fa605426a6cac9f12aeaf23616665e4c70bf8caa6000",
            "stdlibInventorySha256": "a36ba4a114629fb0d42a56f0449b5ce2f14381b8a2880d9fbe1ba6b77380fcc7",
            "noticeSha256": digest}
        receipt_raw = helper.canonical_json(receipt) + b"\n"
        physical = [{**payload[name]} if name != "manifest.json" else
                    {"path": name, "size": len(manifest_raw), "sha256": hashlib.sha256(manifest_raw).hexdigest()}
                    for name in helper.WINDOWS_FULLWALK_PAYLOAD_NAMES]
        prepared = helper.windows_fullwalk_prepared_data(context, receipt_raw, manifest_raw, physical)
        return {"context": context, "sources": sources, "manifest": manifest, "manifest_raw": manifest_raw,
                "receipt": receipt, "receipt_raw": receipt_raw, "physical": physical, "prepared": prepared}

    @classmethod
    def fullwalk_data(cls):
        # Entirely synthetic DATA; neither this chain nor its assertions are native evidence.
        prepared_case = cls.fullwalk_prepared_fixture()
        context = prepared_case["context"]
        _, standalone, before, ordinary_after, ordinary_owner, ordinary_child, ordinary_exit = cls.ordinary_data()
        standalone["messages"] = {"size": 987, "sha256": "c" * 64}
        app = {"path": standalone["path"].replace("mrk_windows_installed_native-aaaaaaaaaaaaaaaa", "mobile_release_desktop-bbbbbbbbbbbbbbbb"),
               "size": 73, "sha256": "7" * 64, "messages": {"size": 1234, "sha256": "b" * 64}}
        app_before = before.replace("11" * 16, "22" * 16)
        app_after = ordinary_after.replace("11" * 16, "22" * 16)
        compiled = {"invocationSha256": hashlib.sha256(helper.canonical_json(
            helper.windows_fullwalk_native_argv("/inert-compiler/cargo.exe", context))).hexdigest(),
            "appInvocationSha256": hashlib.sha256(helper.canonical_json(
                helper.windows_installed_app_argv("/inert-compiler/cargo.exe", context))).hexdigest()}
        prepared = prepared_case["prepared"]
        roster_raw = helper.windows_fullwalk_roster_text(prepared["physical"])
        precheck_raw = helper.windows_fullwalk_precheck_text(context, standalone, app, compiled, prepared, before, app_before, roster_raw)
        pre = helper.windows_fullwalk_precheck_data(context, precheck_raw)
        publication_fields = {"profile": helper.WINDOWS_FULLWALK_PROFILE,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
            "publisherTest": helper.WINDOWS_FULLWALK_PUBLISHER, "artifactBytes": standalone["size"],
            "artifactSha256": standalone["sha256"], "artifactIdentity": before,
            "precheckBytes": len(precheck_raw), "precheckSha256": hashlib.sha256(precheck_raw).hexdigest(),
            "rosterBytes": len(roster_raw), "rosterSha256": hashlib.sha256(roster_raw).hexdigest(),
            **{key: prepared[key] for key in ("manifestSha256", "protocolSha256", "inventorySha256", "coreSha256", "payloadFiles", "payloadBytes")},
            "createdFiles": 47, "createdDirectories": 5, "sourceReaders": 47, "sourceReadersClosed": 47,
            "payloadWriters": 47, "payloadWritersClosed": 47, "postcheckReaders": 94, "postcheckReadersClosed": 94,
            "fileOriginals": 214, "fileOriginalsClosed": 214, "parentBookSettled": "true",
            "occupiedCreateCalls": 1, "occupiedCreateError": 183, "occupiedObjectsUnchanged": "true",
            "unknown": "false", "productionEnabled": "false", "resultCloseGate": "original-publisher-exit-zero-required", "objectCount": 52}
        selected = {"version": "44" * 16, "python/python.exe": "55" * 16, "engine_bootstrap.py": "66" * 16, "core.zip": "77" * 16}
        wire_stamp = lambda row: ":".join(str(row[key]) for key in
            ("volume", "fileId", "creation", "write", "change", "size", "allocation", "links", "attributes"))
        object_lines = []
        for index, name in enumerate((*helper.WINDOWS_FULLWALK_DIRECTORY_ROLES, *helper.WINDOWS_FULLWALK_PAYLOAD_NAMES)):
            directory = index < 5
            original = {"volume": 77, "fileId": selected.get(name, f"{2**120 + index:032x}"), "creation": 100,
                        "write": 200, "change": 300, "size": 0, "allocation": 0, "links": 1, "attributes": 16 if directory else 128}
            size = 0 if directory else prepared["physical"][index - 5]["size"]
            sealed = {**original, "write": 201, "change": 301, "size": size, "allocation": (size + 4095) // 4096 * 4096}
            digest = "-" if directory else prepared["physical"][index - 5]["sha256"]
            object_lines.append("object=" + "|".join((name, "directory" if directory else "file",
                wire_stamp(original), wire_stamp(sealed), "4" * 64, "5" * 64, digest)) + "\n")
        publisher_raw = helper.windows_fullwalk_text("publication", publication_fields) + "".join(object_lines).encode("ascii")
        publication = helper.windows_fullwalk_publication_data(context, publisher_raw, precheck_raw, roster_raw)
        publisher_exit = {"schemaVersion": 1, **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
            "artifactSha256": standalone["sha256"], "publisherTest": helper.WINDOWS_FULLWALK_PUBLISHER,
            "precheckSha256": hashlib.sha256(precheck_raw).hexdigest(), "originalWaitReturned": True, "exitCode": 0,
            "writerCloseGate": "original-publisher-step-success-required"}
        ordinary_request = helper.windows_ordinary_request(context, standalone, before)
        invocation = helper.windows_fullwalk_invocation(context, standalone, before, ordinary_request, 1000)
        ordinary_intent = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "runId": context["runId"], "attempt": 1,
            "accountName": "mrk0123456789abcdef", "freshAccountIntent": True, "fixedNativeChildOnly": True, "fullwalkBatch": invocation}
        ordinary_intent_raw = helper.canonical_json(ordinary_intent)
        ordinary_prewrite = 5000
        ordinary_owner["aggregate"] = {**invocation, "ordinaryIntentBytes": len(ordinary_intent_raw),
            "ordinaryIntentSha256": hashlib.sha256(ordinary_intent_raw).hexdigest(), "resultPrewriteTickMs": ordinary_prewrite}
        blobs = {"precheck": precheck_raw, "roster": roster_raw, "publisherReceipt": publisher_raw,
            "publisherExit": helper.canonical_json(publisher_exit), "ordinaryRequest": ordinary_request,
            "ordinaryIntent": ordinary_intent_raw, "ordinaryOwnerResult": helper.canonical_json(ordinary_owner),
            "ordinaryChildResult": helper.canonical_json(ordinary_child), "ordinaryOwnerExit": helper.canonical_json(ordinary_exit)}
        blobs["ordinaryFinality"] = helper.windows_fullwalk_finality_text(context, pre, standalone, ordinary_after, blobs, ordinary_owner)
        finality, ordinary_facts = helper.windows_fullwalk_ordinary_finality(context, pre, standalone, ordinary_after, blobs, "success")
        envelope_raw = helper.windows_fullwalk_envelope_data(context, pre, publication, finality, blobs,
            {key: "success" for key in helper.WINDOWS_FULLWALK_OUTCOMES})
        admitted = {"pre": pre, "owner": standalone, "app": app, "compiled": compiled, "prepared": prepared,
            "blobs": blobs, "publication": publication, "finality": finality, "envelope": envelope_raw,
            "ownerAfterIdentity": ordinary_after, "ordinaryFacts": ordinary_facts}
        request = helper.windows_fullwalk_request_from_prerequisites(context, admitted)
        request_data = helper.windows_fullwalk_request_data(request, root=context["root"])
        fixture = {key: request_data[key] for key in helper.WINDOWS_FULLWALK_REQUEST_FIELDS[22:]}
        arguments = {"app_identity": app_before, "owner_identity": ordinary_after,
                    "app_compile_argv_sha256": compiled["appInvocationSha256"], "owner_compile_argv_sha256": compiled["invocationSha256"], "fixture": fixture}
        binding = {"schemaVersion": 1, **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
            "requestSha256": hashlib.sha256(request).hexdigest(), "artifactBytes": app["size"], "artifactSha256": app["sha256"],
            "commandSha256": request_data["appCommandSha256"], "ownerArtifactSha256": standalone["sha256"]}
        identity = lambda byte: {"volume": 77, "fileId": byte * 16}
        entries = 61  # Synthetic observed count, deliberately neither47 nor52; admission never invents this count.
        child = {**binding, "accountSidSha256": "6" * 64, "test": helper.WINDOWS_FULLWALK_TEST,
            "observation": {"target": helper.TARGETS["windows"],
                **{key: fixture[key] for key in ("manifestSha256", "protocolSha256", "inventorySha256", "coreSha256")},
                "files": 46, "entries": entries, "payloadBytes": prepared["payloadBytes"], "versionIdentity": identity("44"),
                "selectedIdentities": [identity(byte) for byte in ("55", "66", "77")], "inspectionComplete": True, "bookSettled": True},
            "resultFile": {"createNew": True, "writeCalls": 1, "closeGate": "original-child-exit-zero-required"}}
        batch = {"profile": helper.WINDOWS_FULLWALK_PROFILE, "ordinaryInvocationSha256": invocation["ordinaryInvocationSha256"],
            "prerequisiteBytes": len(envelope_raw), "prerequisiteSha256": hashlib.sha256(envelope_raw).hexdigest(),
            "originTickMs": invocation["originTickMs"], "deadlineTickMs": invocation["deadlineTickMs"],
            "aggregateBudgetMs": helper.WINDOWS_FULLWALK_AGGREGATE_MS, "entryTickMs": 6000}
        intent = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "runId": context["runId"], "attempt": 1,
            "accountName": "mrkfedcba9876543210", "freshAccountIntent": True, "fixedFullwalkChildOnly": True, "fullwalkBatch": batch}
        intent_raw = helper.canonical_json(intent)
        count = len(helper.PureWindowsPath(context["root"]).parents) + 1 + 21
        owner = deepcopy(ordinary_owner)
        owner.update({**binding, "ownerArtifactBytes": standalone["size"], "ownerCommandSha256": request_data["ownerCommandSha256"],
            "fullwalkEntries": entries, "ownerTest": helper.WINDOWS_FULLWALK_OWNER, "childTest": helper.WINDOWS_FULLWALK_TEST,
            "inputOriginals": count, "inputOriginalsClosed": count, "protectedFullwalk": True,
            "nativeResultSha256": hashlib.sha256(helper.canonical_json(child)).hexdigest(),
            "aggregate": {**batch, "ownerIntentBytes": len(intent_raw), "ownerIntentSha256": hashlib.sha256(intent_raw).hexdigest(),
                          "prelaunchTickMs": 6500, "resultPrewriteTickMs": 9000}})
        owner["aclTransitions"][-1]["role"] = "fullwalk-output"
        for key in ("before", "after"):
            owner["aclTransitions"][5][key].update(size=app["size"], fileId="22" * 16)
        original_exit = {key: binding[key] for key in ("schemaVersion", "sourceSha", "sourceTree", "runId", "attempt",
                                                       "artifactSha256", "ownerArtifactSha256", "requestSha256")}
        original_exit.update(ownerTest=helper.WINDOWS_FULLWALK_OWNER, originalWaitReturned=True, exitCode=0,
                             writerCloseGate="original-owner-step-success-required")
        return {"context": context, "app": app, "standalone": standalone, "arguments": arguments, "request": request,
            "after": app_after, "owner": owner, "child": child, "exit": original_exit, "entries": entries,
            "ordinary": (context, standalone, before, ordinary_after, ordinary_owner, ordinary_child, ordinary_exit),
            "pre": pre, "precheck_raw": precheck_raw, "roster_raw": roster_raw, "publication": publication,
            "publication_fields": publication_fields, "publisher_exit": publisher_exit, "blobs": blobs,
            "envelope": envelope_raw, "intent": intent, "intent_raw": intent_raw, "ordinary_prewrite": ordinary_prewrite,
            "admitted": admitted, "prepared_case": prepared_case}

    @staticmethod
    def fullwalk_accept(data, outcome="success"):
        return helper.windows_fullwalk_records(data["context"], data["request"], data["after"],
            *(helper.canonical_json(data[key]) for key in ("owner", "child", "exit")), outcome,
            envelope_raw=data["envelope"], intent_raw=data["intent_raw"], ordinary_prewrite_tick=data["ordinary_prewrite"])

    @staticmethod
    def fullwalk_originals(data):
        """Original DATA at inert I/O edges; changed chain validators are NOT replaced."""
        context, root = data["context"], Path(data["context"]["root"])
        record = lambda raw: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        encode = helper.canonical_json
        files = {root / name: data["blobs"][role] for role, (name, _) in helper.WINDOWS_FULLWALK_BLOBS.items()}
        files.update({root / "metadata.json": b"INERT existing native metadata boundary",
                      root / "app-metadata.json": b"INERT existing app metadata boundary"})
        compiler = {role: {"path": "/inert-compiler/" + role + ".exe", **record(role.encode("ascii"))}
                    for role in ("cargo", "rustc")}
        files.update({Path(row["path"]): role.encode("ascii") for role, row in compiler.items()})
        files[root / "compiler-tools.json"] = encode(compiler)
        native_packages = {name: {"version": version} for name, version in
            (("mrk-windows-installed-native", "0.1.0"), ("windows-sys", "0.61.2"), ("windows-link", "0.2.1"))}
        graph = {"nodes": {"app@0.1.0": {}, "native@0.1.0": {}, "registry@1.0.0": {}}}
        acquisition = {"supplier": {"size": helper.WINDOWS_FULLWALK_ZIP_BYTES, "sha256": helper.WINDOWS_FULLWALK_ZIP_SHA256},
            "supplierInvocationSha256": hashlib.sha256(encode(helper.windows_fullwalk_curl_argv(context))).hexdigest(),
            "supplierOriginalExitCode": 0,
            "prepareInvocationSha256": hashlib.sha256(encode(helper.windows_fullwalk_preparer_argv(context))).hexdigest(),
            "prepareOriginalExitCode": 0, "prepared": data["prepared_case"]["prepared"]}
        acquired = helper.windows_installed_phase_receipt(context, "acquire", rust=helper.RUST, target=helper.TARGETS["windows"],
            packages={name: row["version"] for name, row in native_packages.items()},
            metadata=record(files[root / "metadata.json"]), appMetadata=record(files[root / "app-metadata.json"]),
            compilerTools=record(files[root / "compiler-tools.json"]), originalExitCode=0, appOriginalExitCode=0,
            appActivePackageIds=sorted(graph["nodes"]), fullwalk=acquisition)
        prepared = data["prepared_case"]["prepared"]
        compiled = helper.windows_installed_phase_receipt(context, "compile", rust=helper.RUST, target=helper.TARGETS["windows"],
            compiledTest=data["standalone"], originalExitCode=0, standaloneOnly=False,
            appCompiledTest=data["app"], appOriginalExitCode=0, **data["admitted"]["compiled"],
            fullwalk={"manifestSha256": prepared["manifestSha256"], "protocolSha256": prepared["protocolSha256"],
                "preparedReceipt": prepared["receipt"], "anchoredNativeBuilds": 1, "anchoredAppBuilds": 1})
        files.update({root / "acquire-checks.json": encode(acquired), root / "compile-checks.json": encode(compiled),
                      root / "compiled-test.json": encode(data["standalone"]), root / "app-compiled-test.json": encode(data["app"])})
        for name in ("acquire", "compile", "windows-installed-native"):
            files[root / (name + "-started.json")] = encode(helper.windows_installed_phase_receipt(context, name, claimOnly=True))
        for prefix, names, filtered in (("app-inert", helper.WINDOWS_INSTALLED_APP_INERT, 173), ("inert", helper.WINDOWS_INSTALLED_INERT, 5)):
            files[root / (prefix + ".stdout")] = ("running " + str(len(names)) + " tests\n"
                + "".join("test " + name + " ... ok\n" for name in names)
                + "test result: ok. " + str(len(names)) + " passed; 0 failed; 0 ignored; 0 measured; "
                + str(filtered) + " filtered out; finished in 0.01s\n").encode("ascii")
            files[root / (prefix + ".stderr")] = b""
        app_inert = helper.windows_installed_app_libtest(files[root / "app-inert.stdout"])
        preflight = helper.windows_installed_phase_receipt(context, "windows-installed-native-preflight",
            compiledTest=data["standalone"], inertContracts={"passed": 9, "failed": 0, "ignored": 0}, appCompiledTest=data["app"],
            appInertContracts=app_inert, appOriginalExitCode=0, inertOriginalExitCode=0,
            originalOutputs={name: record(files[root / name]) for name in ("app-inert.stdout", "app-inert.stderr", "inert.stdout", "inert.stderr")},
            artifactNativeIdentity=data["pre"]["ownerArtifactIdentity"], request=record(data["blobs"]["ordinaryRequest"]),
            nativeNotStarted=True, notVerified=list(helper.WINDOWS_INSTALLED_COMBINED_NOT_VERIFIED),
            fullwalk={"precheck": record(data["precheck_raw"]), "roster": record(data["roster_raw"])})
        files[root / "windows-installed-native-preflight-checks.json"] = encode(preflight)
        publisher = helper.windows_fullwalk_fixture_facts(context, data["precheck_raw"], data["roster_raw"],
            data["blobs"]["publisherReceipt"], data["blobs"]["publisherExit"], "success")
        files[root / "windows-installed-fixture-checks.json"] = encode(helper.windows_installed_phase_receipt(
            context, "windows-installed-fixture-finalize", **publisher))
        files[root / "windows-installed-native-checks.json"] = encode(helper.windows_installed_phase_receipt(
            context, "windows-installed-native", compiledTest=data["standalone"], appCompiledTest=data["app"],
            inertContracts={"passed": 9, "failed": 0, "ignored": 0}, appInertContracts=app_inert, appOriginalExitCode=0,
            inertOriginalExitCode=0, nativeOriginalExitCode=0, originalProcessWaitReturned=True,
            **data["admitted"]["ordinaryFacts"], notVerified=list(helper.WINDOWS_INSTALLED_COMBINED_NOT_VERIFIED)))
        files[root / "fullwalk-publication.private.txt"] = data["envelope"]
        files[root / "fullwalk-request.txt"] = data["request"]
        files[root / "fullwalk-owner-intent.private.json"] = data["intent_raw"]
        files[root / "fullwalk-owner-result.private.json"] = encode(data["owner"])
        files[root / "fullwalk-owner-exit.private.json"] = encode(data["exit"])
        files[root / "fullwalk-output/fullwalk-result.private.json"] = encode(data["child"])
        files[root / "windows-installed-fullwalk-preflight-checks.json"] = encode(helper.windows_installed_phase_receipt(
            context, "windows-installed-fullwalk-preflight", precheckSha256=hashlib.sha256(data["precheck_raw"]).hexdigest(),
            prerequisiteSha256=hashlib.sha256(data["envelope"]).hexdigest(), requestSha256=hashlib.sha256(data["request"]).hexdigest(),
            ordinaryInvocationSha256=data["admitted"]["finality"]["ordinaryInvocationSha256"], nativeFullwalkNotStarted=True))
        facts = WindowsReaderGateTests.fullwalk_accept(data)
        facts.update(prerequisiteSha256=hashlib.sha256(data["envelope"]).hexdigest(),
            requestSha256=hashlib.sha256(data["request"]).hexdigest(),
            ordinaryInvocationSha256=data["admitted"]["finality"]["ordinaryInvocationSha256"], originalOrdinaryThenFullwalkAggregateChecked=True)
        files[root / "windows-installed-fullwalk-checks.json"] = encode(helper.windows_installed_phase_receipt(
            context, "windows-installed-fullwalk-finalize", **facts,
            notVerified=["production-enablements", "real-installed-loaded-image-import-custody", "native-pending-failure-injection",
                         "msi-ui-save-snapshots", "rust-1.88-minimum"]))
        return files, native_packages, graph

    def fullwalk_edges(self, data, files, native_packages, graph):
        # Only OS DATA/unchanged graph and artifact decoder edges are inert.
        # Existing graph/artifact cases above exercise those strict decoders.
        stack = ExitStack()
        def read(path, limit):
            raw = files[Path(path)]
            self.assertLessEqual(len(raw), limit)
            return raw
        def record(path, limit):
            raw = read(path, limit)
            return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for name, value in (("windows_installed_bytes", read),
                            ("read_bounded_json", lambda path, limit: helper.bounded_json(read(path, limit), limit)),
                            ("windows_installed_record", record)):
            stack.enter_context(patch.object(helper, name, side_effect=value))
        for name, value in (("windows_fullwalk_prepared", data["prepared_case"]["prepared"]),
                            ("windows_installed_metadata", native_packages), ("windows_installed_app_metadata", graph),
                            ("windows_installed_artifact", data["standalone"]), ("windows_installed_app_artifact", data["app"])):
            stack.enter_context(patch.object(helper, name, return_value=value))
        stack.enter_context(patch.object(helper, "windows_ordinary_original",
            side_effect=lambda artifact, **kw: data["after"] if kw.get("app_role") else data["ordinary"][3]))
        for name in ("run", "tools", "source_unchanged"):
            stack.enter_context(patch.object(helper, name, side_effect=AssertionError("DATA chain cannot run tools or commands")))
        return stack

    def test_windows_fullwalk_profile_is_explicit_and_data_routes_cannot_launch(self):
        context = self.context()
        sha, repository, ref = context["sourceSha"], "inert/repository", "refs/heads/verify/desktop-windows-installed-native"
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows",
            "RUNNER_ARCH": "X64", "ImageOS": context["imageOS"], "ImageVersion": context["imageVersion"],
            "GITHUB_JOB": "windows-installed-native", "GITHUB_RUN_ATTEMPT": "1", "MRK_DESKTOP_HOSTED_CHECKS": helper.WINDOWS_INSTALLED_SCOPE,
            "GITHUB_SHA": sha, "GITHUB_REPOSITORY": repository, "GITHUB_REF": ref, "GITHUB_WORKFLOW_SHA": sha,
            "GITHUB_WORKFLOW_REF": repository + "/.github/workflows/desktop-foundation.yml@" + ref, "GITHUB_RUN_ID": context["runId"]}
        def bind(event, dispatch, expected):
            with patch.object(helper, "sys", SimpleNamespace(platform="win32", maxsize=2**63 - 1, version=helper.PYTHON)), \
                 patch.dict(helper.os.environ, {**environment, "GITHUB_EVENT_NAME": event,
                    "MRK_DESKTOP_DISPATCH_SCOPE": dispatch, "MRK_DESKTOP_EXPECTED_SHA": expected}, clear=True):
                return helper.windows_installed_binding()
        self.assertNotIn("qualificationProfile", bind("push", "", ""))
        self.assertNotIn("qualificationProfile", bind("workflow_dispatch", "windows-installed-native", sha))
        self.assertEqual(bind("workflow_dispatch", helper.WINDOWS_FULLWALK_DISPATCH, sha)["qualificationProfile"], helper.WINDOWS_FULLWALK_PROFILE)
        for event, dispatch, expected in (("push", helper.WINDOWS_FULLWALK_DISPATCH, ""), ("push", "", sha),
                ("push", "windows-installed-native", sha), ("workflow_dispatch", "", sha),
                ("workflow_dispatch", helper.WINDOWS_FULLWALK_DISPATCH, ""), ("workflow_dispatch", helper.WINDOWS_FULLWALK_DISPATCH, "f" * 40),
                ("pull_request", helper.WINDOWS_FULLWALK_DISPATCH, sha), ("workflow_dispatch", helper.WINDOWS_FULLWALK_PROFILE, sha)):
            with self.subTest(event=event, selector=dispatch, expected=expected), self.assertRaises(helper.CheckFailure):
                bind(event, dispatch, expected)
        self.assertFalse(helper.windows_fullwalk_profile(context))
        for value in (None, True, False, "", "windows-installed-native", {"profile": helper.WINDOWS_FULLWALK_PROFILE}):
            with self.subTest(marker=value), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_profile({**context, "qualificationProfile": value})
        for phase, target in (("windows-installed-fixture-finalize", "windows_fullwalk_fixture_finalize"),
                              ("windows-installed-fullwalk", "windows_fullwalk_preflight"),
                              ("windows-installed-fullwalk-finalize", "windows_fullwalk_finalize")):
            for batch in (True, False):
                chosen = {**context, **({"qualificationProfile": helper.WINDOWS_FULLWALK_PROFILE} if batch else {})}
                with self.subTest(phase=phase, batch=batch), patch.object(helper, "windows_installed_context", return_value=chosen) as admission, \
                     patch.object(helper, target) as selected, patch.object(helper, "run", side_effect=AssertionError("DATA route command")), \
                     patch.object(helper, "tools", side_effect=AssertionError("DATA route compiler")):
                    if batch:
                        helper.windows_installed_phase(phase, helper.WINDOWS_INSTALLED_SCOPE)
                        selected.assert_called_once_with(chosen)
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.windows_installed_phase(phase, helper.WINDOWS_INSTALLED_SCOPE)
                        selected.assert_not_called()
                    admission.assert_called_once_with(create=False, retention_only=True)

    def test_windows_fullwalk_supplier_source_pins_and_fixed_invocations(self):
        data = self.fullwalk_prepared_fixture()
        context = data["context"]
        pins = [{"path": name, "size": size, "sha256": digest} for name, (size, digest) in helper.WINDOWS_FULLWALK_PINS.items()]
        current = {Path(context["source"]) / row["path"]: {"size": row["size"], "sha256": row["sha256"]} for row in pins}
        with patch.object(helper, "windows_installed_record", side_effect=lambda path, _: current[path]):
            self.assertEqual(helper.windows_fullwalk_pins(context), pins)
            for key, wrong in (("size", 1), ("sha256", "0" * 64)):
                changed = deepcopy(context)
                next(row for row in changed["sourceFiles"] if row["path"] == pins[0]["path"])[key] = wrong
                with self.subTest(pin=key), self.assertRaises(helper.CheckFailure):
                    helper.windows_fullwalk_pins(changed)
            saved = current[Path(context["source"]) / pins[0]["path"]]
            current[Path(context["source"]) / pins[0]["path"]] = {**saved, "sha256": "0" * 64}
            with self.assertRaises(helper.CheckFailure): helper.windows_fullwalk_pins(context)
        argv = helper.windows_fullwalk_curl_argv(context)
        self.assertEqual(argv[:8], [r"C:\Windows\System32\curl.exe", "--disable", "--proto", "=https", "--tlsv1.2", "--noproxy", "*", "--connect-timeout"])
        self.assertEqual(argv[argv.index("--retry") + 1], "0")
        self.assertEqual(argv[argv.index("--max-redirs") + 1], "0")
        self.assertEqual(argv[-1], "https://www.python.org/ftp/python/3.14.7/python-3.14.7-embed-amd64.zip")
        self.assertEqual(helper.WINDOWS_FULLWALK_ZIP_BYTES, 12673227)
        self.assertEqual(helper.WINDOWS_FULLWALK_ZIP_SHA256, "d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15")
        self.assertEqual(argv[argv.index("--write-out") + 1],
                         "%{http_code}\n%{url_effective}\n%{num_redirects}\n%{size_download}\n")
        fields = (b"200", helper.WINDOWS_FULLWALK_URL.encode("ascii"), b"0", b"12673227")
        labels = ("http", "effective-url", "redirect", "byte-count")
        cases = []
        for framing, ending in (("lf", b"\n"), ("crlf", b"\r\n")):
            status = ending.join(fields) + ending
            with self.subTest(framing=framing, case="exact-frame"):
                self.assertIsNone(helper.windows_fullwalk_supplier_status(status))
            changes = [
                (0, "wrong-http", b"302"),
                (1, "wrong-scheme", fields[1].replace(b"https:", b"http:")),
                (1, "wrong-url-case", fields[1].replace(b"www.python.org", b"WWW.PYTHON.ORG")),
                (1, "wrong-url-suffix", fields[1] + b"?unexpected=1"),
                (2, "wrong-redirect", b"1"), (3, "wrong-byte-count", b"12673228"),
            ]
            for index, value in enumerate(fields):
                changes.extend((index, case, wrong) for case, wrong in (
                    ("leading-space", b" " + value), ("trailing-space", value + b" "),
                    ("leading-tab", b"\t" + value), ("trailing-tab", value + b"\t"),
                    ("non-ascii", value + b"\x80"), ("nul", value + b"\x00"), ("empty", b"")))
                if index != 1:
                    changes.extend((index, case, wrong) for case, wrong in (
                        ("leading-zero", b"0" + value), ("plus", b"+" + value),
                        ("decimal", value + b".0"), ("exponent", value + b"e0")))
            for index, case, wrong in changes:
                bad = ending.join(fields[:index] + (wrong,) + fields[index + 1:]) + ending
                cases.append((framing + "-" + labels[index] + "-" + case, bad, labels[index]))
            for first in range(3):
                bad_fields = fields[:first] + (b"different",) * (4 - first)
                cases.append((framing + "-first-field-" + str(first), ending.join(bad_fields) + ending, labels[first]))
            malformed = [
                ("missing-final", status[:-len(ending)]),
                ("extra-final", status + ending),
                ("missing-record", ending.join(fields[:-1]) + ending),
                ("extra-record", status + b"extra" + ending),
                ("extra-blank-record", ending.join(fields[:1] + (b"",) + fields[1:]) + ending),
                ("trailing-space", status + b" "), ("trailing-tab", status + b"\t"),
                ("trailing-nul", status + b"\x00"), ("trailing-data", status + b"extra"),
                ("embedded-cr", ending.join((fields[0] + b"\rX",) + fields[1:]) + ending),
                ("embedded-lf", ending.join((fields[0] + b"\nX",) + fields[1:]) + ending),
                ("doubled-cr", fields[0] + b"\r\r\n" + ending.join(fields[1:]) + ending),
                ("framing-before-http", ending.join((b"302",) + fields[1:]) + ending + b"\x00"),
            ]
            cases.extend((framing + "-" + case, bad, "framing") for case, bad in malformed)
        cases.append(("bare-cr", b"\r".join(fields) + b"\r", "framing"))
        for mask in range(1, 15):
            mixed = b"".join(value + (b"\r\n" if mask & (1 << index) else b"\n")
                             for index, value in enumerate(fields))
            cases.append(("mixed-terminators-" + str(mask), mixed, "framing"))
        for case, bad, label in cases:
            with self.subTest(case=case):
                with self.assertRaises(helper.CheckFailure) as caught:
                    helper.windows_fullwalk_supplier_status(bad)
                self.assertEqual(str(caught.exception), "Windows supplier " + label + " differs")
        self.assertEqual(helper.windows_fullwalk_preparer_argv(context), [context["python"], "-I", "-S", "-B",
            str(Path(context["source"]) / "desktop/tools/prepare_windows_embedded_payload.py"), "--source", context["source"],
            "--archive", str(Path(context["root"]) / "inputs" / helper.WINDOWS_FULLWALK_ZIP),
            "--runtime-root", str(Path(context["root"]) / "runtime")])
        source = HELPER.read_text(encoding="utf-8")
        prepare = source.split("def windows_fullwalk_prepare_inputs(", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(prepare.index("windows_fullwalk_pins(context)"), prepare.index('.mkdir(mode=0o700)'))
        self.assertLess(prepare.index("windows_fullwalk_curl_sha256(curl)"), prepare.index('.mkdir(mode=0o700)'))
        self.assertIn('not (root / "runtime").exists() and not (root / "runtime").is_symlink()', prepare)
        acquire = source.split("def windows_fullwalk_acquire(", 1)[1].split("\ndef ", 1)[0]
        self.assertEqual(acquire.count("run("), 2)
        self.assertNotIn("time.monotonic()", acquire)
        self.assertIn("windows_installed_remaining(deadline, 135)", acquire)
        self.assertIn("windows_installed_remaining(deadline, 180)", acquire)
        self.assertIn("windows_installed_remaining(deadline, 1)", acquire)
        self.assertLess(acquire.index("== {\"size\": WINDOWS_FULLWALK_ZIP_BYTES"), acquire.index('check="windows-fullwalk-fixed-offline-preparer"'))
        for forbidden in ("--location", "--insecure", "python/python.exe", "core.zip", "Start-Process", "retry("):
            self.assertNotIn(forbidden, acquire)

    def test_windows_fullwalk_fixed_system_curl_preserves_generic_single_link_policy(self):
        # These Windows names/stat results and >one-chunk bytes are inert DATA.
        # Exercise real role/path/hash/state predicates, not a Windows tool.
        system_root = r"C:\Windows"
        fixed = helper.PureWindowsPath(system_root) / "System32" / "curl.exe"
        content = b"INERT fixed-System32 curl DATA; never executed.\n" + b"x" * (64 * 1024)
        case = self

        def exercise(changes=None, *, refused=False, before_open=False, no_metadata=False, generic=None):
            changes = {} if changes is None else changes
            selected = helper.PureWindowsPath(changes.get("path", fixed))
            common = {"st_dev": 7, "st_ino": 13, "st_nlink": changes.get("links", 2),
                      "st_size": len(content), "st_mtime_ns": 10000, "st_birthtime_ns": 2000,
                      "st_file_attributes": 0x20, "st_reparse_tag": 0}
            named = SimpleNamespace(**{**common, "st_mode": stat.S_IFREG | 0o777, "st_ctime_ns": 2000,
                                       **changes.get("named", {})})
            opened = SimpleNamespace(**{**common, "st_mode": stat.S_IFREG | 0o666, "st_ctime_ns": 3000,
                                        **changes.get("opened", {})})
            after = SimpleNamespace(**{**vars(opened), **changes.get("after", {})})
            last = SimpleNamespace(**{**vars(named), **changes.get("last", {})})
            calls = {"open": 0, "leaf": 0, "parent": 0, "fstat": 0, "bytes": 0, "reads": []}

            class Stream(io.BytesIO):
                def fileno(self):
                    case.assertFalse(self.closed)
                    return 73

                def read(self, size=-1):
                    case.assertGreater(size, 0)
                    case.assertLessEqual(size, 64 * 1024)
                    calls["reads"].append(size)
                    if changes.get("read_error"):
                        raise OSError("INERT read boundary refusal")
                    block = super().read(size)
                    calls["bytes"] += len(block)
                    return block

            stream = Stream(changes.get("body", content))

            class NamedPath:
                def __init__(self, value):
                    self.value = value

                def __str__(self):
                    return str(self.value)

                @property
                def parents(self):
                    return tuple(NamedPath(parent) for parent in self.value.parents)

                def lstat(self):
                    if self.value == selected:
                        calls["leaf"] += 1
                        if calls["leaf"] > 1:
                            case.assertFalse(stream.closed)
                        return named if calls["leaf"] == 1 else last
                    calls["parent"] += 1
                    later = calls["parent"] > len(selected.parents)
                    if later:
                        case.assertFalse(stream.closed)
                    altered = changes.get("parent_after" if later else "parent", {}) if self.value == selected.parent else {}
                    return SimpleNamespace(**{"st_mode": stat.S_IFDIR | 0o777,
                                              "st_file_attributes": 0x10, "st_reparse_tag": 0, **altered})

                def open(self, mode):
                    case.assertEqual(self.value, selected)
                    case.assertEqual(mode, "rb")
                    calls["open"] += 1
                    case.assertEqual(calls["open"], 1)
                    return stream

            def descriptor(fd):
                case.assertEqual(fd, 73)
                case.assertFalse(stream.closed)
                calls["fstat"] += 1
                case.assertLessEqual(calls["fstat"], 2)
                return opened if calls["fstat"] == 1 else after

            root_value = changes.get("root", system_root)
            environment = {} if root_value is None else {"SystemRoot": root_value}
            reader = helper.windows_fullwalk_curl_sha256 if generic is None else generic
            try:
                with patch.object(helper, "os", SimpleNamespace(name="nt", environ=environment, fstat=descriptor)), \
                        patch.object(helper, "run", side_effect=AssertionError("Curl DATA must not run a tool")):
                    if refused:
                        label = "Windows fixed System32 curl" if generic is None else "ordinary, single-link"
                        with self.assertRaisesRegex(helper.CheckFailure, label):
                            reader(NamedPath(selected))
                    else:
                        self.assertEqual(reader(NamedPath(selected)), hashlib.sha256(content).hexdigest())
                        self.assertEqual((calls["open"], calls["leaf"], calls["fstat"]), (1, 2, 2))
                        self.assertEqual(calls["parent"], 2 * len(selected.parents))
                        self.assertGreaterEqual(len(calls["reads"]), 2)
                if before_open:
                    self.assertEqual((calls["open"], calls["fstat"], calls["reads"]), (0, 0, []))
                if no_metadata:
                    self.assertEqual((calls["leaf"], calls["parent"]), (0, 0))
                self.assertLessEqual(calls["bytes"], max(0, named.st_size + 1))
                if calls["open"]:
                    self.assertTrue(stream.closed)
            finally:
                # Only this in-memory fixture is ours; unopened fixtures need no
                # product cleanup, and an opened descriptor had to close above.
                stream.close()

        for links in (1, 2, 1024):
            with self.subTest(accepted_links=links):
                exercise({"links": links})
        for root in (None, "", "Windows", r"C:Windows", r"\Windows", r"\\host\share\Windows",
                     r"\\?\C:\Windows", r"C:\Windows\..\Other", r"C:\OtherWindows", system_root + "\0"):
            with self.subTest(root=root):
                exercise({"root": root}, refused=True, before_open=True, no_metadata=True)
        for wrong in (r"C:\Windows\SysWOW64\curl.exe", r"C:\Windows\System32\other.exe",
                      r"C:\Windows\System32\curl.exe:other", r"C:\Windows\System32\..\System32\curl.exe"):
            with self.subTest(path=wrong):
                exercise({"path": wrong}, refused=True, before_open=True, no_metadata=True)
        for changed in ({"links": 0}, {"links": -1}, {"links": 1025}, {"links": True},
                        {"named": {"st_size": 0}}, {"named": {"st_size": 16 * 1024 * 1024 + 1}},
                        {"named": {"st_mode": stat.S_IFDIR | 0o777}},
                        {"named": {"st_file_attributes": 0x420}}, {"named": {"st_reparse_tag": 1}},
                        {"parent": {"st_mode": stat.S_IFREG | 0o777}},
                        {"parent": {"st_file_attributes": 0x410}}, {"parent": {"st_reparse_tag": 1}}):
            with self.subTest(before_open=changed):
                exercise(changed, refused=True, before_open=True)
        for changed in ({"opened": {"st_ino": 14}}, {"opened": {"st_birthtime_ns": 2001}},
                        {"after": {"st_ctime_ns": 3001}}, {"after": {"st_nlink": 3}},
                        {"last": {"st_ino": 14}}, {"last": {"st_file_attributes": 0x420}},
                        {"parent_after": {"st_reparse_tag": 1}}, {"body": content[:-1]},
                        {"body": content + b"x"}, {"read_error": True}):
            with self.subTest(drift=tuple(changed)):
                exercise(changed, refused=True)
        for generic in (helper.ordinary, helper.hash_file, lambda path: helper.windows_installed_bytes(path, 1 << 20)):
            with self.subTest(unchanged_generic=generic.__name__):
                exercise({"links": 2}, refused=True, before_open=True, generic=generic)

    def test_windows_fullwalk_prepared_data_is_closed_canonical_and_current_source_bound(self):
        data = self.fullwalk_prepared_fixture()
        context, receipt, manifest, physical = (data[key] for key in ("context", "receipt", "manifest", "physical"))
        def accept(r=receipt, m=manifest, p=physical, c=context, raw=None):
            return helper.windows_fullwalk_prepared_data(c, helper.canonical_json(r) + b"\n",
                helper.canonical_json(m) + b"\n" if raw is None else raw, p)
        accepted = accept()
        self.assertEqual((accepted["payloadFiles"], len(accepted["physical"])), (46, 47))
        self.assertEqual(accepted["payloadBytes"], sum(row["size"] for row in manifest["files"]))
        for key in receipt:
            for value in ("native-verified" if key == "qualification" else "0" * 64, None, True):
                with self.subTest(receipt=key, value=value), self.assertRaises(helper.CheckFailure):
                    accept(r={**receipt, key: value})
        for r in ({key: value for key, value in receipt.items() if key != "noticeSha256"}, {**receipt, "nativeVerified": True}):
            with self.assertRaises(helper.CheckFailure): accept(r=r)
        for key, value in (("schemaVersion", True), ("protocol", True), ("target", "x86_64-unknown-linux-gnu"),
                ("coreVersion", "native"), ("coreSha256", "0" * 64), ("protocolSha256", "0" * 64),
                ("inventorySha256", "0" * 64), ("extra", False)):
            with self.subTest(manifest=key), self.assertRaises(helper.CheckFailure): accept(m={**manifest, key: value})
        for invalid in (data["manifest_raw"][:-1], b" " + data["manifest_raw"], data["manifest_raw"] + b"\n",
                        data["manifest_raw"].replace(b'"protocol":1', b'"protocol":1,"protocol":1')):
            with self.subTest(canonical=len(invalid)), self.assertRaises(helper.CheckFailure): accept(raw=invalid)
        for number in (0, 7, 11, 46):
            for key, value in (("path", "alias"), ("size", True), ("size", 0), ("size", (128 << 20) + 1),
                               ("sha256", "F" * 64), ("extra", 0)):
                changed = deepcopy(physical); changed[number][key] = value
                with self.subTest(physical=number, field=key), self.assertRaises(helper.CheckFailure): accept(p=changed)
        for invalid in (physical[:-1], physical + [physical[-1]], list(reversed(physical)), tuple(physical)):
            with self.subTest(physical_type=type(invalid).__name__), self.assertRaises(helper.CheckFailure): accept(p=invalid)
        for path in ("desktop/engine_bootstrap.py", "desktop/github-ca.pem", "src/mobile_release/_desktop_engine.py"):
            changed = deepcopy(context)
            next(row for row in changed["sourceFiles"] if row["path"] == path)["sha256"] = "0" * 64
            with self.subTest(current_source=path), self.assertRaises(helper.CheckFailure): accept(c=changed)
        # Purpose bound only. Generic source inventories remain at8MiB/member.
        large = deepcopy(physical); large[0]["size"] = 128 << 20
        self.assertEqual(helper.windows_fullwalk_payload_rows(large, physical=True), large)
        with self.assertRaises(helper.CheckFailure): helper.validate_environment_inventory(large, maximum=1 << 30)
        large[0]["size"] += 1
        with self.assertRaises(helper.CheckFailure): helper.windows_fullwalk_payload_rows(large, physical=True)
        with self.assertRaises(helper.CheckFailure):
            accept(c={key: value for key, value in context.items() if key != "qualificationProfile"})

    def test_windows_fullwalk_prepared_reader_checks_core_members_and_fixed_two_directory_shape(self):
        # Memory ZIP bytes and inert lstat/scandir/read edges; no candidate import,
        # supplier fetch, archive extraction, runtime launch or filesystem write.
        def exercise(mutation=None):
            data = self.fullwalk_prepared_fixture()
            context, sources = data["context"], data["sources"]
            root, source = Path(context["root"]), Path(context["source"])
            core_rows = [row for row in context["sourceFiles"] if row["path"].startswith("src/mobile_release/")]
            with io.BytesIO() as original:
                with helper.zipfile.ZipFile(original, "w", compression=helper.zipfile.ZIP_DEFLATED) as archive:
                    for index, row in enumerate(core_rows):
                        name = row["path"].removeprefix("src/")
                        info = helper.zipfile.ZipInfo(name.upper() if mutation == "member-case" and index == 0 else name, (1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | (0o600 if mutation == "member-mode" and index == 0 else 0o644)) << 16
                        info.compress_type = helper.zipfile.ZIP_DEFLATED
                        raw = sources[row["path"]]
                        archive.writestr(info, raw + b"x" if mutation == "member-bytes" and index == 0 else raw)
                    if mutation == "member-extra": archive.writestr("mobile_release/unlisted.py", b"inert")
                core = original.getvalue()
            manifest = data["manifest"]
            core_row = next(row for row in manifest["files"] if row["path"] == "core.zip")
            core_row.update(size=len(core), sha256=hashlib.sha256(core).hexdigest())
            manifest["coreSha256"] = core_row["sha256"]
            manifest["inventorySha256"] = hashlib.sha256(helper.canonical_json(manifest["files"])).hexdigest()
            if mutation == "version": manifest["coreVersion"] = "99.99.99"
            manifest_raw = helper.canonical_json(manifest) + b"\n"
            data["receipt"]["manifestSha256"] = hashlib.sha256(manifest_raw).hexdigest()
            physical = {row["path"]: row for row in manifest["files"]}
            physical["manifest.json"] = {"path": "manifest.json", "size": len(manifest_raw), "sha256": hashlib.sha256(manifest_raw).hexdigest()}
            records = {root / "runtime" / name: {key: row[key] for key in ("size", "sha256")} for name, row in physical.items()}
            records.update({source / name: {"size": size, "sha256": sha} for name, (size, sha) in helper.WINDOWS_FULLWALK_PINS.items()})
            originals = {root / "runtime/manifest.json": manifest_raw, root / "runtime/core.zip": core,
                root / "fullwalk-prepared-receipt.private.json": helper.canonical_json(data["receipt"]) + b"\n",
                **{source / name: raw for name, raw in sources.items()}}
            directories = {root / "runtime": [name for name in helper.WINDOWS_FULLWALK_PAYLOAD_NAMES if "/" not in name] + ["python"],
                           root / "runtime/python": [name.split("/", 1)[1] for name in helper.WINDOWS_FULLWALK_PAYLOAD_NAMES if "/" in name]}
            if mutation == "directory-extra": directories[root / "runtime"].append("unlisted")
            if mutation == "directory-missing": directories[root / "runtime/python"].pop()
            if mutation == "directory-case": directories[root / "runtime/python"][0] = directories[root / "runtime/python"][0].upper()
            class Entries:
                def __init__(self, path): self.path = path
                def __enter__(self): return iter(SimpleNamespace(name=name) for name in directories[self.path])
                def __exit__(self, *_): pass
            state = SimpleNamespace(st_dev=77, st_ino=99, st_mode=stat.S_IFDIR | 0o755, st_nlink=1,
                st_size=0, st_mtime_ns=100, st_ctime_ns=100, st_birthtime_ns=100, st_file_attributes=16, st_reparse_tag=0)
            def read(path, limit):
                raw = originals[path]; self.assertLessEqual(len(raw), limit); return raw
            with patch.object(helper, "windows_installed_record", side_effect=lambda path, _: records[path]), \
                 patch.object(helper, "windows_installed_bytes", side_effect=read), \
                 patch.object(helper, "windows_installed_directories", side_effect=lambda path: self.assertIn(path, directories)), \
                 patch.object(helper.Path, "lstat", return_value=state), patch.object(helper.os, "scandir", side_effect=Entries), \
                 patch.object(helper, "run", side_effect=AssertionError("Prepared DATA cannot run anything")):
                return helper.windows_fullwalk_prepared(context)
        self.assertEqual(exercise()["payloadFiles"], 46)
        for mutation in ("member-case", "member-mode", "member-bytes", "member-extra", "version",
                         "directory-extra", "directory-missing", "directory-case"):
            with self.subTest(mutation=mutation), self.assertRaises(helper.CheckFailure): exercise(mutation)

    def test_windows_fullwalk_precheck_publication_and_separate_exit_are_closed(self):
        data = self.fullwalk_data()
        context, pre = data["context"], data["pre"]
        self.assertEqual(len(data["publication"]["objects"]), 52)
        self.assertEqual(len(helper.windows_fullwalk_roster(data["roster_raw"])), 47)
        helper.windows_fullwalk_publisher_exit(context, data["blobs"]["publisherExit"], data["precheck_raw"], "success")
        for key, value in (("profile", "ordinary"), ("sourceSha", "f" * 40), ("attempt", "2"),
                ("sourceInventorySha256", "0" * 64), ("readerSourceSha256", "0" * 64),
                ("appTest", helper.WINDOWS_INSTALLED_TEST), ("appArtifact", data["standalone"]["path"]),
                ("appCommandSha256", "0" * 64), ("appRootFeatures", "default"), ("standaloneFeatures", "qualification-result"),
                ("appNativeDevFeatures", "none"), ("headlessContract", "desktop-probe"), ("payloadFiles", "45"),
                ("payloadBytes", "0"), ("preparedReceiptBytes", "4097")):
            altered = helper.windows_fullwalk_text("precheck", {**pre, key: value})
            with self.subTest(precheck=key), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_precheck_data(context, altered)
        for kind, raw in (("precheck", data["precheck_raw"]), ("prerequisite", data["envelope"]),
                          ("finality", data["blobs"]["ordinaryFinality"])):
            lines = raw.splitlines()
            for invalid in (raw[:-1], raw + b"\n", raw.replace(b"\n", b"\r\n"), raw + b"x=1\n",
                    b"\n".join([lines[0], *reversed(lines[1:])]) + b"\n", raw.replace(b"profile=", b"unknown=", 1)):
                with self.subTest(schema=kind, bad=invalid[:40]), self.assertRaises(helper.CheckFailure):
                    helper.windows_fullwalk_wire(invalid, kind)
        prefix = len(helper.WINDOWS_FULLWALK_PUBLICATION_FIELDS) + 1
        suffix = b"".join(data["blobs"]["publisherReceipt"].splitlines(keepends=True)[prefix:])
        for key, value in (("artifactIdentity", data["ordinary"][3]), ("artifactSha256", data["app"]["sha256"]),
                ("precheckSha256", "0" * 64), ("createdFiles", 46), ("createdDirectories", 4),
                ("sourceReadersClosed", 46), ("payloadWritersClosed", 46), ("postcheckReadersClosed", 93),
                ("fileOriginalsClosed", 213), ("fileOriginals", 197), ("parentBookSettled", "false"),
                ("occupiedCreateCalls", 0), ("occupiedCreateError", 5), ("occupiedObjectsUnchanged", "false"),
                ("unknown", "true"), ("productionEnabled", "true"), ("resultCloseGate", "self-certified"), ("objectCount", 51)):
            raw = helper.windows_fullwalk_text("publication", {**data["publication_fields"], key: value}) + suffix
            with self.subTest(publication=key), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_publication_data(context, raw, data["precheck_raw"], data["roster_raw"])
        lines = data["blobs"]["publisherReceipt"].decode("ascii").splitlines()
        for row, column, replacement in ((0, 0, "foreign"), (0, 1, "file"), (0, 6, "a" * 64),
                (5, 6, "0" * 64), (5, 4, "5" * 64)):
            changed = list(lines); fields = changed[prefix + row].removeprefix("object=").split("|"); fields[column] = replacement
            changed[prefix + row] = "object=" + "|".join(fields)
            with self.subTest(object=row, field=column), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_publication_data(context, ("\n".join(changed) + "\n").encode(), data["precheck_raw"], data["roster_raw"])
        for field, value in ((0, "78"), (1, "01" + "0" * 30), (2, "101"), (5, "999"), (7, "2"), (8, "1024")):
            changed = list(lines); columns = changed[prefix + 5].removeprefix("object=").split("|")
            stamp = columns[3].split(":"); stamp[field] = value; columns[3] = ":".join(stamp)
            changed[prefix + 5] = "object=" + "|".join(columns)
            with self.subTest(full_stamp=field), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_publication_data(context, ("\n".join(changed) + "\n").encode(), data["precheck_raw"], data["roster_raw"])
        for outcome in ("failure", "cancelled", "skipped", "unavailable"):
            with self.subTest(outcome=outcome), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_publisher_exit(context, data["blobs"]["publisherExit"], data["precheck_raw"], outcome)
        for key, value in (("exitCode", True), ("exitCode", 1), ("originalWaitReturned", False), ("writerCloseGate", "self-certified"),
                           ("precheckSha256", "0" * 64), ("extra", False)):
            with self.subTest(exit_field=key), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_publisher_exit(context, helper.canonical_json({**data["publisher_exit"], key: value}), data["precheck_raw"], "success")

    def test_windows_fullwalk_ordinary_batch_preserves_legacy_originals_and_first_clock(self):
        data = self.fullwalk_data()
        context, artifact, before, after, owner, child, original_exit = data["ordinary"]
        def accept(o=owner, intent=data["blobs"]["ordinaryIntent"], c=context):
            return helper.windows_ordinary_records(c, artifact, before, after, helper.canonical_json(o),
                helper.canonical_json(child), helper.canonical_json(original_exit), "success", intent_raw=intent)
        public = accept()
        self.assertEqual(public["ordinaryOwner"]["inputOriginalsClosed"], len(helper.PureWindowsPath(context["root"]).parents) + 1 + 8)
        self.assertEqual(public["ordinaryBatch"]["aggregateBudgetMs"], 210000)
        self.assertNotIn("ordinaryBatch", self.ordinary_accept(self.ordinary_data()))
        with self.assertRaises(helper.CheckFailure): self.ordinary_accept(data["ordinary"])  # Batch intent cannot be omitted.
        legacy = {key: value for key, value in context.items() if key != "qualificationProfile"}
        with self.assertRaises(helper.CheckFailure): accept(c=legacy)  # No silent ordinary-only admission of batch fields.
        for key in owner["aggregate"]:
            changed = deepcopy(owner); changed["aggregate"][key] = None
            with self.subTest(aggregate_field=key), self.assertRaises(helper.CheckFailure): accept(o=changed)
        for tick in (999, 211000, True, "5000"):
            changed = deepcopy(owner); changed["aggregate"]["resultPrewriteTickMs"] = tick
            with self.subTest(prewrite=tick), self.assertRaises(helper.CheckFailure): accept(o=changed)
        changed = deepcopy(owner); changed["aggregate"]["extra"] = False
        with self.assertRaises(helper.CheckFailure): accept(o=changed)
        intent = helper.bounded_json(data["blobs"]["ordinaryIntent"], 4096)
        for key, value in (("accountName", "foreign"), ("fixedNativeChildOnly", False), ("freshAccountIntent", False),
                           ("sourceSha", "f" * 40), ("attempt", True), ("extra", False)):
            raw = helper.canonical_json({**intent, key: value})
            changed = deepcopy(owner); changed["aggregate"].update(ordinaryIntentBytes=len(raw), ordinaryIntentSha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(intent=key), self.assertRaises(helper.CheckFailure): accept(o=changed, intent=raw)
        with patch.object(helper.time, "monotonic", side_effect=AssertionError("DATA cannot resample an origin")):
            invocation = helper.windows_fullwalk_invocation(context, artifact, before, data["blobs"]["ordinaryRequest"], 1000)
        self.assertEqual((invocation["originTickMs"], invocation["deadlineTickMs"]), (1000, 211000))
        for origin in (-1, True, "1000", 2**64 - 210000):
            with self.subTest(origin=origin), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_invocation(context, artifact, before, data["blobs"]["ordinaryRequest"], origin)
        for request in (data["blobs"]["ordinaryRequest"][:-1], data["blobs"]["ordinaryRequest"].replace(b"runId=123456", b"runId=123457")):
            with self.assertRaises(helper.CheckFailure): helper.windows_fullwalk_invocation(context, artifact, before, request, 1000)

    def test_windows_fullwalk_original_acquire_compile_preflight_and_finality_chain(self):
        data = self.fullwalk_data()
        originals, packages, graph = self.fullwalk_originals(data)
        context, root = data["context"], Path(data["context"]["root"])
        environment = {name: "success" for name in (*helper.WINDOWS_FULLWALK_OUTCOMES.values(),
            "MRK_WINDOWS_FULLWALK_PREFLIGHT_STEP_OUTCOME", "MRK_WINDOWS_FULLWALK_OWNER_STEP_OUTCOME")}
        with patch.dict(helper.os.environ, environment, clear=True), self.fullwalk_edges(data, originals, packages, graph):
            owner, app, compiled, prepared = helper.windows_fullwalk_compile_bindings(context)
            self.assertEqual((owner, app, prepared), (data["standalone"], data["app"], data["prepared_case"]["prepared"]))
            self.assertEqual(compiled["fullwalk"]["anchoredNativeBuilds"], 1)
            admitted = helper.windows_fullwalk_prerequisites(context, envelope_raw=data["envelope"])
            self.assertEqual(admitted["ownerAfterIdentity"], data["ordinary"][3])
            self.assertNotEqual(admitted["ownerAfterIdentity"], admitted["pre"]["ownerArtifactIdentity"])
            self.assertEqual(helper.windows_fullwalk_request_from_prerequisites(context, admitted), data["request"])
            self.assertTrue(helper.windows_fullwalk_observe_final(context, admitted)["protectedFullwalk"])
        for name, key, value in (("acquire-checks.json", "sourceSha", "f" * 40), ("acquire-checks.json", "originalExitCode", True),
                ("acquire-checks.json", "appOriginalExitCode", 1), ("acquire-checks.json", "extra", False),
                ("compile-checks.json", "appOriginalExitCode", 1), ("compile-checks.json", "invocationSha256", "0" * 64),
                ("compile-checks.json", "standaloneOnly", True), ("compile-started.json", "claimOnly", 1),
                ("windows-installed-native-preflight-checks.json", "inertOriginalExitCode", True),
                ("windows-installed-native-preflight-checks.json", "nativeNotStarted", False),
                ("windows-installed-native-preflight-checks.json", "extra", "not-admitted"),
                ("windows-installed-fixture-checks.json", "publisherOriginalExitCode", 1),
                ("windows-installed-native-checks.json", "nativeOriginalExitCode", True),
                ("windows-installed-native-checks.json", "extra", "not-admitted")):
            files = dict(originals); row = helper.bounded_json(files[root / name], 64 << 10)
            row[key] = value; files[root / name] = helper.canonical_json(row)
            with self.subTest(original=name, field=key), patch.dict(helper.os.environ, environment, clear=True), \
                 self.fullwalk_edges(data, files, packages, graph), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_prerequisites(context, envelope_raw=data["envelope"])
        for name, parent, key, value in (("acquire-checks.json", "fullwalk", "supplierOriginalExitCode", True),
                ("acquire-checks.json", "fullwalk", "prepareInvocationSha256", "0" * 64),
                ("compile-checks.json", "fullwalk", "anchoredAppBuilds", 2),
                ("compile-checks.json", "fullwalk", "anchoredNativeBuilds", 0),
                ("compile-checks.json", "fullwalk", "manifestSha256", "0" * 64)):
            files = dict(originals); row = helper.bounded_json(files[root / name], 64 << 10)
            row[parent][key] = value; files[root / name] = helper.canonical_json(row)
            with self.subTest(binding=key), self.fullwalk_edges(data, files, packages, graph), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_compile_bindings(context)
        for name in helper.WINDOWS_FULLWALK_OUTCOMES.values():
            with self.subTest(original_step=name), patch.dict(helper.os.environ, {**environment, name: "skipped"}, clear=True), \
                 self.fullwalk_edges(data, originals, packages, graph), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_prerequisites(context)
        for role in ("ordinaryRequest", "ordinaryIntent", "ordinaryOwnerResult", "ordinaryChildResult", "ordinaryOwnerExit", "ordinaryFinality"):
            files = dict(originals); name, _ = helper.WINDOWS_FULLWALK_BLOBS[role]; files[root / name] += b" "
            with self.subTest(retained_original=role), patch.dict(helper.os.environ, environment, clear=True), \
                 self.fullwalk_edges(data, files, packages, graph), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_prerequisites(context, envelope_raw=data["envelope"])
        with patch.dict(helper.os.environ, environment, clear=True), self.fullwalk_edges(data, originals, packages, graph), \
             patch.object(helper, "windows_ordinary_original", return_value=data["ordinary"][2]), self.assertRaises(helper.CheckFailure):
            helper.windows_fullwalk_prerequisites(context)  # Publisher-before epoch is not ordinary-after.
        with patch.dict(helper.os.environ, environment, clear=True), self.fullwalk_edges(data, originals, packages, graph), \
             self.assertRaises(helper.CheckFailure):
            helper.windows_fullwalk_prerequisites(context, envelope_raw=data["envelope"] + b"\n")

    def test_windows_fullwalk_second_clock_and_intent_cannot_renew_or_overtake_ordinary(self):
        data = self.fullwalk_data()
        def changed(**ticks):
            item = deepcopy(data); item["owner"]["aggregate"].update(ticks)
            if "entryTickMs" in ticks:
                item["intent"]["fullwalkBatch"]["entryTickMs"] = ticks["entryTickMs"]
                item["intent_raw"] = helper.canonical_json(item["intent"])
                item["owner"]["aggregate"].update(ownerIntentBytes=len(item["intent_raw"]), ownerIntentSha256=hashlib.sha256(item["intent_raw"]).hexdigest())
            return item
        boundary = changed(prelaunchTickMs=111000, resultPrewriteTickMs=111001)
        self.assertTrue(self.fullwalk_accept(boundary)["aggregate"]["originalClockAndIntentBindingsChecked"])
        for ticks in ({"entryTickMs": 4999}, {"entryTickMs": 111001}, {"prelaunchTickMs": 5999},
                {"prelaunchTickMs": 111001, "resultPrewriteTickMs": 111002}, {"resultPrewriteTickMs": 6499},
                {"resultPrewriteTickMs": 211000}, {"originTickMs": 1001}, {"deadlineTickMs": 211001},
                {"aggregateBudgetMs": 210001}, {"entryTickMs": True}, {"prelaunchTickMs": True}):
            with self.subTest(ticks=ticks), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(changed(**ticks))
        for key in data["owner"]["aggregate"]:
            item = deepcopy(data); item["owner"]["aggregate"][key] = None
            with self.subTest(aggregate_field=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(item)
        for tick in (True, 999, 6001):
            item = deepcopy(data); item["ordinary_prewrite"] = tick
            with self.subTest(ordinary_prewrite=tick), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(item)
        for extra in ("owner", "intent"):
            item = deepcopy(data)
            if extra == "owner": item["owner"]["aggregate"]["extra"] = False
            else:
                item["intent"]["fullwalkBatch"]["extra"] = False; item["intent_raw"] = helper.canonical_json(item["intent"])
                item["owner"]["aggregate"].update(ownerIntentBytes=len(item["intent_raw"]), ownerIntentSha256=hashlib.sha256(item["intent_raw"]).hexdigest())
            with self.subTest(extra=extra), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(item)
        item = deepcopy(data); item["owner"]["inputOriginals"] -= 10; item["owner"]["inputOriginalsClosed"] -= 10
        with self.assertRaises(helper.CheckFailure): self.fullwalk_accept(item)  # Stale seam A+11 cannot pass.
        envelope = helper.windows_fullwalk_wire(data["envelope"], "prerequisite")
        for key, value in (("ownerArtifactAfterOrdinaryIdentity", data["ordinary"][2]),
                           ("publisherFinalizeStepOutcome", "skipped"), ("envelopeCloseGate", "self-certified")):
            item = deepcopy(data); item["envelope"] = helper.windows_fullwalk_text("prerequisite", {**envelope, key: value})
            with self.subTest(envelope=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(item)

    def test_windows_fullwalk_phase_uses_only_two_original_anchored_compiles(self):
        data = self.fullwalk_data()
        files, packages, graph = self.fullwalk_originals(data)
        context = {**data["context"], "sdk": {"version": helper.WINDOWS_SDK_VERSION, "headers": []}}
        root = Path(context["root"])
        opened = []
        class Output:
            def __enter__(self): return self
            def __exit__(self, *_): pass
        def open_output(path, mode, **_):
            self.assertEqual(mode, "x"); self.assertEqual(path.parent, root)
            self.assertIn(path.name, ("compile-messages.jsonl", "compile.stderr", "app-compile-messages.jsonl", "app-compile.stderr"))
            self.assertNotIn(path, opened); opened.append(path)
            return Output()
        with self.fullwalk_edges(data, files, packages, graph), \
             patch.object(helper, "windows_installed_context", return_value=context), \
             patch.object(helper, "source_unchanged"), patch.object(helper, "windows_installed_inputs"), \
             patch.object(helper, "clean_environment", return_value={}), \
             patch.object(helper, "windows_sdk_root", return_value=Path("/inert-sdk")), \
             patch.object(helper, "fixed_file_inventory", return_value=[]), \
             patch.object(helper, "tools", return_value=("/inert-compiler/cargo.exe", "/inert-compiler/rustc.exe")), \
             patch.object(helper.Path, "open", autospec=True, side_effect=open_output), \
             patch.object(helper.time, "monotonic", return_value=100.0), \
             patch.object(helper, "write_json") as written, patch.object(helper, "run", return_value=None) as run:
            helper.windows_installed_phase("compile", helper.WINDOWS_INSTALLED_SCOPE)
        self.assertEqual(len(run.call_args_list), 2)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            helper.windows_fullwalk_native_argv("/inert-compiler/cargo.exe", context),
            helper.windows_installed_app_argv("/inert-compiler/cargo.exe", context)])
        self.assertEqual([call.kwargs["check"] for call in run.call_args_list],
                         ["windows-installed-test-compile-only", "windows-installed-app-test-compile-only"])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["timeout"], 600)
            self.assertEqual(call.kwargs["env"]["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], data["prepared_case"]["prepared"]["manifestSha256"])
            self.assertEqual(call.kwargs["env"]["MRK_BUNDLED_PROTOCOL_SHA256"], data["prepared_case"]["prepared"]["protocolSha256"])
            self.assertIn("--offline", call.args[0]); self.assertIn("--no-default-features", call.args[0])
            self.assertNotIn("--features", call.args[0])
        results = {call.args[0].name: call.args[1] for call in written.call_args_list}
        self.assertEqual(set(results), {"compile-started.json", "compiled-test.json", "app-compiled-test.json", "compile-checks.json"})
        self.assertEqual((results["compile-checks.json"]["fullwalk"]["anchoredNativeBuilds"],
                          results["compile-checks.json"]["fullwalk"]["anchoredAppBuilds"]), (1, 1))
        self.assertEqual(len(opened), 4)
        source = HELPER.read_text(encoding="utf-8")
        phase = source.split("def windows_installed_phase(", 1)[1].split("\ndef main(", 1)[0]
        self.assertEqual(phase.count('check="windows-installed-test-compile-only"'), 1)
        self.assertEqual(phase.count('check="windows-installed-app-test-compile-only"'), 1)
        self.assertLess(phase.index("environment.update(MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"), phase.index('check="windows-installed-test-compile-only"'))
        self.assertLess(phase.index('check="windows-installed-test-compile-only"'), phase.index('check="windows-installed-app-test-compile-only"'))
        self.assertLess(phase.index('windows_fullwalk_acquire(context, environment, deadline)'), phase.index('check="windows-installed-locked-metadata"'))

    def test_windows_fullwalk_app_original_role_keeps_512mib_and_raw_same_api_state_narrow(self):
        raw = b"exe"
        before = SimpleNamespace(st_dev=77, st_ino=2**100 + 7, st_mode=stat.S_IFREG | 0o755, st_nlink=1, st_size=len(raw),
            st_mtime_ns=200, st_birthtime_ns=100, st_ctime_ns=100, st_file_attributes=128, st_reparse_tag=0)
        opened = SimpleNamespace(**{**vars(before), "st_mode": stat.S_IFREG | 0o644, "st_ctime_ns": 700})
        name = "mobile_release_desktop-bbbbbbbbbbbbbbbb.exe"
        identity = [before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns,
                    before.st_birthtime_ns, before.st_file_attributes, before.st_reparse_tag, before.st_ctime_ns]
        artifact = {"path": "C:\\owned\\" + name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "identity": identity}
        class Input(io.BytesIO):
            def fileno(self): return 91
        def observe(*, last=None, end=None, role=True, selected=name, claimed=None, details=before):
            stream = Input(raw)
            named = SimpleNamespace(name=selected, lstat=lambda: details, open=lambda *_: stream)
            count = [details, details if last is None else last]
            named.lstat = lambda: count.pop(0)
            try:
                with patch.object(helper, "Path", return_value=named), patch.object(helper.os, "name", "nt"), \
                     patch.object(helper.os, "fstat", side_effect=[opened, opened if end is None else end]):
                    value = helper.windows_ordinary_original(artifact if claimed is None else claimed, app_role=role)
                self.assertTrue(stream.closed)
                return value
            finally:
                stream.close()
        expected = "77:" + before.st_ino.to_bytes(16, "little").hex() + ":116444736000000001:116444736000000002:116444736000000007:128"
        self.assertEqual(observe(), expected)
        for field in ("st_ctime_ns", "st_birthtime_ns", "st_mode", "st_ino", "st_file_attributes", "st_mtime_ns", "st_size", "st_nlink"):
            for edge in ("last", "end"):
                state = before if edge == "last" else opened
                changed = SimpleNamespace(**{**vars(state), field: getattr(state, field) + 1})
                with self.subTest(api=edge, field=field), self.assertRaises(helper.CheckFailure): observe(**{edge: changed})
        for options in ({"role": False}, {"role": 1}, {"selected": "mrk_windows_installed_native-aaaaaaaaaaaaaaaa.exe"},
                        {"claimed": {**artifact, "identity": [77, before.st_ino, 3, 200, 100]}}):
            with self.subTest(role=options), self.assertRaises(helper.CheckFailure): observe(**options)
        too_large = SimpleNamespace(**{**vars(before), "st_size": (512 << 20) + 1})
        with self.assertRaises(helper.CheckFailure):
            observe(details=too_large, claimed={**artifact, "size": too_large.st_size, "identity": [*identity[:4], too_large.st_size, *identity[5:]]})

    def test_windows_fullwalk_retirement_and_redacted_retention_keep_distinct_ordinary_pass(self):
        data = self.fullwalk_data()
        context, request = data["context"], helper.windows_fullwalk_request_data(data["request"], root=data["context"]["root"])
        base = {"schemaVersion": 1, "profile": helper.WINDOWS_FULLWALK_PROFILE,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
            "retirementTest": helper.WINDOWS_FULLWALK_RETIRE, "artifactSha256": request["ownerArtifactSha256"],
            "requestSha256": hashlib.sha256(data["request"]).hexdigest(), "publisherReceiptSha256": hashlib.sha256(data["blobs"]["publisherReceipt"]).hexdigest()}
        result = {**base, "deletedFiles": 47, "deletedDirectories": 5, "absentPostconditions": 52, "dispositionCalls": 52,
            "fileOriginals": 111, "fileOriginalsClosed": 111, "parentBookSettled": True, "unknown": False,
            "productionEnabled": False, "resultCloseGate": "original-retirement-exit-zero-required"}
        original_exit = {**base, "originalWaitReturned": True, "exitCode": 0, "writerCloseGate": "original-retirement-step-success-required"}
        def accept(row=result, exited=original_exit, outcome="success"):
            return helper.windows_fullwalk_retirement_data(context, data["request"], data["blobs"]["publisherReceipt"],
                helper.canonical_json(row), helper.canonical_json(exited), outcome)
        self.assertEqual(accept()["absentPostconditions"], 52)
        for key, value in (("fileOriginals", True), ("fileOriginals", 104), ("fileOriginalsClosed", 110), ("deletedFiles", 46),
                ("deletedDirectories", 4), ("absentPostconditions", 51), ("dispositionCalls", 53), ("parentBookSettled", False),
                ("unknown", True), ("productionEnabled", True), ("resultCloseGate", "self-certified"), ("extra", False)):
            with self.subTest(retirement=key), self.assertRaises(helper.CheckFailure): accept(row={**result, key: value})
        for key, value in (("exitCode", 1), ("exitCode", True), ("originalWaitReturned", False),
                           ("writerCloseGate", "self-certified"), ("publisherReceiptSha256", "0" * 64), ("extra", False)):
            with self.subTest(exit=key), self.assertRaises(helper.CheckFailure): accept(exited={**original_exit, key: value})
        for outcome in ("failure", "cancelled", "skipped", "unavailable"):
            with self.subTest(outcome=outcome), self.assertRaises(helper.CheckFailure): accept(outcome=outcome)
        files, packages, graph = self.fullwalk_originals(data)
        root = Path(context["root"])
        files[root / "fullwalk-retirement-result.private.json"] = helper.canonical_json(result)
        files[root / "fullwalk-retirement-exit.private.json"] = helper.canonical_json(original_exit)
        environment = {name: "success" for name in (*helper.WINDOWS_FULLWALK_OUTCOMES.values(),
            "MRK_WINDOWS_FULLWALK_PREFLIGHT_STEP_OUTCOME", "MRK_WINDOWS_FULLWALK_OWNER_STEP_OUTCOME",
            "MRK_WINDOWS_FULLWALK_FINALIZE_STEP_OUTCOME", "MRK_WINDOWS_RETIREMENT_STEP_OUTCOME")}
        for fullwalk_passed in (True, False):
            outcomes = {**environment, **({} if fullwalk_passed else {
                "MRK_WINDOWS_FULLWALK_OWNER_STEP_OUTCOME": "failure", "MRK_WINDOWS_FULLWALK_FINALIZE_STEP_OUTCOME": "skipped",
                "MRK_WINDOWS_RETIREMENT_STEP_OUTCOME": "skipped"})}
            with self.subTest(fullwalk=fullwalk_passed), patch.dict(helper.os.environ, outcomes, clear=True), \
                 self.fullwalk_edges(data, files, packages, graph), \
                 patch.object(helper, "windows_installed_retain_runtime", return_value=({"status": "unavailable"}, None)), \
                 patch.object(helper, "write_json") as publication:
                helper.windows_fullwalk_retain(context)
            publication.assert_called_once()
            destination, public = publication.call_args.args
            self.assertEqual(destination, root / "public/windows-fullwalk-qualification.json")
            self.assertEqual(public["results"]["ordinary"]["status"], "passed")
            self.assertEqual(public["results"]["publisher"]["status"], "passed")
            self.assertEqual(public["results"]["fullwalk"]["status"], "passed" if fullwalk_passed else "failed")
            self.assertEqual(public["results"]["retirement"]["status"], "passed" if fullwalk_passed else "unavailable")
            self.assertIs(public["combinedPassed"], fullwalk_passed)
            exported = helper.canonical_json(public)
            for private in (context["root"].encode(), data["app"]["path"].encode(), b"accountName", b"accountSidSha256",
                            b"fileId", b"securityBefore", b"ordinary-owner-intent", b"fullwalk-request", b"stdout", b"stderr",
                            b"mrk0123456789abcdef", b"mrkfedcba9876543210"):
                self.assertNotIn(private, exported)
        # A successful step cannot bless an extra/missing/renewed finalizer field.
        # Its failure must still leave the distinct, closed ordinary pass intact.
        final = root / "windows-installed-fullwalk-checks.json"
        for key, value in (("extra", False), ("notVerified", []), ("requestSha256", "0" * 64), ("protectedFullwalk", 1)):
            originals = dict(files)
            row = helper.bounded_json(files[final], 64 << 10)
            row[key] = value
            originals[final] = helper.canonical_json(row)
            with self.subTest(finalizer=key), patch.dict(helper.os.environ, environment, clear=True), \
                 self.fullwalk_edges(data, originals, packages, graph), \
                 patch.object(helper, "windows_installed_retain_runtime", return_value=({"status": "unavailable"}, None)), \
                 patch.object(helper, "write_json") as publication:
                helper.windows_fullwalk_retain(context)
            public = publication.call_args.args[1]
            self.assertEqual(public["results"]["ordinary"]["status"], "passed")
            self.assertEqual(public["results"]["fullwalk"]["status"], "failed")
            self.assertNotEqual(public["results"]["retirement"]["status"], "passed")
            self.assertFalse(public["combinedPassed"])

    def test_windows_fullwalk_native_schema_custody_and_reviewed_gate_source_parity(self):
        # SOURCE parity only, never a claim that a Linux check exercised an OS call.
        base = SOURCE / helper.WINDOWS_INSTALLED_CRATE / "src"
        fixture = (base / "qualification_fixture.rs").read_text(encoding="utf-8")
        shared = (base / "qualification_result.rs").read_text(encoding="utf-8")
        owner = (base / "ordinary_owner.rs").read_text(encoding="utf-8")
        library = (base / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("#[cfg(test)]\nmod qualification_fixture;", library)
        for kind, (header, fields, _) in helper.WINDOWS_FULLWALK_SCHEMAS.items():
            name = kind.upper()
            prefix = "pub(super) const " + name + "_FIELDS: [&str; " + str(len(fields)) + "] = [\n"
            block = fixture.split(prefix, 1)[1].split("\n];", 1)[0]
            self.assertEqual(tuple(line.strip()[1:-2] for line in block.splitlines()), fields)
            self.assertIn('pub(super) const ' + name + '_HEADER: &str = "' + header + '";', fixture)
        block = fixture.split("pub(super) const PAYLOAD_NAMES: [&str; 47] = [\n", 1)[1].split("\n];", 1)[0]
        self.assertEqual(tuple(line.strip()[1:-2] for line in block.splitlines()), helper.WINDOWS_FULLWALK_PAYLOAD_NAMES)
        self.assertIn("FULLWALK_PREREQUISITES_REVIEWED: bool = true;", owner)
        driver = fixture.split("fn fixture_run(", 1)[1]
        self.assertLess(driver.index("need(super::ordinary_owner::FULLWALK_PREREQUISITES_REVIEWED)?;"),
                        driver.index("profile()?;"))
        self.assertEqual(driver.count("std::panic::catch_unwind("), 2)
        self.assertEqual(driver.count("std::hint::black_box(&mut original)"), 2)
        restart = fixture.split("fn borrowed_restart(", 1)[1].split("    fn stamp(", 1)[0]
        self.assertIn("Call::Info(FS::FileIdExtdDirectoryRestartInfo,BUFFER)", restart)
        self.assertIn("self.book.mark_entered(call)?;", restart)
        self.assertEqual(restart.count("invoke(frame)"), 1)
        self.assertIn("frame.returned.set(Some(returned));frame.phase.set(Phase::Returned);", restart)
        for duplicate in ("CreateFileW(", "GetFileInformationByHandleEx(", "CloseHandle(", "owned_file("):
            self.assertNotIn(duplicate, restart)
        cursor = fixture.split("pub(super) struct CursorEpoch", 1)[1].split("\nstruct Fixture", 1)[0]
        self.assertIn("need(epoch <= 52 && !self.entered)?;", cursor)
        self.assertIn("need(self.eof && epoch > previous)?;", cursor)
        self.assertIn("need(self.entered && !self.eof)?;", cursor)
        dispose = fixture.split("fn dispose(", 1)[1].split("\n    fn ", 1)[0]
        self.assertLess(dispose.index("self.close(index)?;"), dispose.index("self.absent(parent,&name)?;"))
        self.assertEqual(shared.count("FS::WriteFile("), 1)
        self.assertNotIn("FS::WriteFile(", fixture)
        self.assertIn("complete_write_bounded(ok,actual,expected,closed,OWNER_LIMIT)", shared)
        self.assertIn("complete_write_bounded(ok,actual,expected,closed,ORDINARY_ARTIFACT_LIMIT)", shared)
        self.assertIn("complete_write_bounded(ok != 0, b.count, value.len(), true, limit)", shared)
        for body in (fixture, shared):
            for forbidden in ("std::thread::spawn", "std::process::Command", "SetNamedSecurityInfoW(", "RemoveDirectoryW("):
                self.assertNotIn(forbidden, body)

    def test_windows_fullwalk_workflow_is_serial_direct_and_never_protected_always_cleanup(self):
        source = (SOURCE / ".github/workflows/desktop-foundation.yml").read_text(encoding="utf-8")
        workflow = source.split("  windows-installed-native:\n", 1)[1]
        self.assertIn("options: [foundation, windows-snapshot, windows-installed-native, windows-installed-fullwalk,", source)
        ordered = ("ordinary-preflight", "fixture-publisher", "fixture-finalize", "ordinary-owner", "ordinary-finalize",
                   "fullwalk-preflight", "fullwalk-owner", "fullwalk-finalize", "fixture-retirement", "runtime-data", "retain")
        offsets = [workflow.index("        id: " + name + "\n") for name in ordered]
        self.assertEqual(offsets, sorted(offsets))
        for name, test, gate in (("fixture-publisher", helper.WINDOWS_FULLWALK_PUBLISHER, "ordinary-preflight"),
                ("ordinary-owner", helper.WINDOWS_ORDINARY_OWNER, "fixture-finalize"),
                ("fullwalk-owner", helper.WINDOWS_FULLWALK_OWNER, "fullwalk-preflight"),
                ("fixture-retirement", helper.WINDOWS_FULLWALK_RETIRE, "fullwalk-finalize")):
            step = workflow.split("        id: " + name + "\n", 1)[1].split("      - name:", 1)[0]
            command = "& $env:MRK_WINDOWS_NATIVE_ARTIFACT " + test + " --exact --ignored --nocapture --test-threads=1"
            self.assertEqual(step.count(command), 1)
            self.assertIn("if: success()", step); self.assertIn("steps." + gate + ".outcome == 'success'", step)
            self.assertIn("timeout-minutes: 4", step)
            self.assertIn(command + "\n            $originalExitCode = $LASTEXITCODE", step)
            self.assertIn("[System.IO.FileMode]::CreateNew", step)
            self.assertIn("finally { $stream.Dispose() }", step)
            self.assertLess(step.index("$stream.Dispose()"), step.index("exit $originalExitCode"))
            self.assertNotIn(command + " |", step)
            for forbidden in ("MRK_PYTHON", "always()", "Start-Process", "Process.Start", "Remove-Item", "Set-Acl", "icacls", "Wait-Process", "Stop-Process"):
                self.assertNotIn(forbidden, step)
        self.assertNotIn(helper.WINDOWS_FULLWALK_TEST, workflow)
        for name in helper.WINDOWS_FULLWALK_OUTCOMES.values():
            self.assertIn(name + ": " + "$" + "{{ steps.", workflow)
        for command in ("acquire", "compile", "windows-installed-native", "windows-installed-fixture-finalize",
                        "windows-installed-native-finalize", "windows-installed-fullwalk", "windows-installed-fullwalk-finalize"):
            self.assertEqual(workflow.count("ci_foundation.py " + command + "\'"), 1)
        retirement = workflow.split("        id: fixture-retirement\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("steps.ordinary-finalize.outcome == 'success'", retirement)
        self.assertIn("steps.fullwalk-finalize.outcome == 'success'", retirement)
        self.assertNotIn("Remove-Item", workflow)
        self.assertIn("timeout-minutes: 35", workflow)
        self.assertEqual(workflow.count("runs-on:"), 1)

    def test_windows_reader_fullwalk_request_binds_both_originals_and_complete_inventory(self):
        data = self.fullwalk_data()
        context, app, standalone, arguments, raw = (data[key] for key in ("context", "app", "standalone", "arguments", "request"))
        self.assertTrue(raw.isascii() and raw.endswith(b"\n"))
        self.assertEqual(len(raw.splitlines()), 35)
        self.assertEqual(raw.splitlines()[0], b"MRK_WINDOWS_FULLWALK_REQUEST_V1")
        self.assertEqual([line.split(b"=", 1)[0].decode() for line in raw.splitlines()[1:]], list(helper.WINDOWS_FULLWALK_REQUEST_FIELDS))
        parsed = helper.windows_fullwalk_request_data(raw, root=context["root"])
        self.assertEqual((parsed["appArtifactBytes"], parsed["ownerArtifactBytes"]), (73, 37))
        self.assertEqual(parsed["selectedCoreIdentity"], "77:" + "77" * 16)
        for role, artifact, test in (("app", app, helper.WINDOWS_FULLWALK_TEST), ("owner", standalone, helper.WINDOWS_FULLWALK_OWNER)):
            command = '"' + artifact["path"] + '" ' + test + " --exact --ignored --nocapture --test-threads=1"
            self.assertEqual(parsed[role + "CommandSha256"], hashlib.sha256(command.encode("utf-16-le")).hexdigest())
        for role, limit in (("app", 512 << 20), ("standalone", 128 << 20)):
            for key, value in (("size", 0), ("size", True), ("size", limit + 1), ("sha256", "X" * 64),
                               ("sha256", int("3" * 64)), ("path", standalone["path"] if role == "app" else app["path"]),
                               ("messages", {"size": True, "sha256": "b" * 64}),
                               ("messages", {"size": (16 << 20) + 1, "sha256": "b" * 64})):
                changed = deepcopy(data); changed[role][key] = value
                with self.subTest(role=role, field=key), self.assertRaises(helper.CheckFailure):
                    helper.windows_fullwalk_request(changed["context"], changed["app"], changed["standalone"], **changed["arguments"])
            changed = deepcopy(data)
            changed[role]["path"] = changed[role]["path"].replace("\\target\\", "\\TARGET\\")
            self.assertNotEqual(changed[role]["path"], data[role]["path"])
            # The formatter recomputes commandSha256: reject spelling parity,
            # not an unrelated stale command digest.
            with self.subTest(case_alias=role), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_request(changed["context"], changed["app"], changed["standalone"], **changed["arguments"])
        for key, value in (("attempt", True), ("attempt", 2), ("runId", "0"), ("runId", 123456),
                           ("sourceSha", "0" * 40), ("sourceTree", "z" * 40)):
            with self.subTest(context=key), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_request({**context, key: value}, app, standalone, **arguments)
        for key, value in (("payloadFiles", 2048), ("payloadFiles", True), ("payloadFiles", 0),
                           ("payloadBytes", (1 << 30) + 1), ("publicationReceiptBytes", (64 << 10) + 1),
                           ("publicationReceiptSha256", ""), ("manifestSha256", "F" * 64),
                           ("versionIdentity", "0:" + "44" * 16), ("versionIdentity", "77:" + "0" * 32),
                           ("versionIdentity", "77:" + "44" * 8), ("selectedPythonIdentity", "77:" + "44" * 16),
                           ("selectedCoreIdentity", "78:" + "77" * 16), ("extra", "unreviewed")):
            altered = {**arguments, "fixture": {**arguments["fixture"], key: value}}
            with self.subTest(fixture=key, value=value), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_request(context, app, standalone, **altered)
        with self.assertRaises(helper.CheckFailure):
            helper.windows_fullwalk_request(context, app, standalone, **{**arguments, "owner_identity": arguments["app_identity"]})
        bad_frames = (raw[:-1], raw + b"\n", raw.replace(b"\n", b"\r\n"), raw + b"x" * 4096,
            raw.replace(b"role=protected-version-fullwalk", b"role=ordinary"), raw.replace(b"test=", b"unknown=", 1),
            raw.replace(b"runId=123456", b"runId=123457"), raw.replace(b"coreSha256=", b"inventorySha256=", 1),
            raw.replace(b"payloadFiles=46", b"payloadFiles=046"), raw.replace(b"sourceSha=", b"sourceSha=\xff", 1),
            raw.replace(parsed["appCommandSha256"].encode(), b"0" * 64, 1),
            b"\n".join([raw.splitlines()[0], *reversed(raw.splitlines()[1:])]) + b"\n")
        for malformed in bad_frames:
            with self.subTest(frame=malformed[:64]), self.assertRaises(helper.CheckFailure):
                helper.windows_fullwalk_request_data(malformed, root=context["root"])

    def test_windows_reader_fullwalk_records_require_original_finality_and_redact_private_data(self):
        data = self.fullwalk_data()
        public = self.fullwalk_accept(data)
        self.assertIs(public["protectedFullwalk"], True)
        self.assertIs(public["productionEnabled"], False)
        self.assertEqual(public["protectedVersionWalk"]["entries"], data["entries"])
        self.assertTrue(public["fullwalkOwner"]["distinctOriginalAppAndOwnerArtifacts"])
        self.assertTrue(public["fullwalkOwner"]["resultFilesClosedBySeparateExitGates"])
        exported = helper.canonical_json(public)
        for private in (b"accountSidSha256", b"fileId", b"versionIdentity", b"selectedIdentities", b"securityBefore",
                        data["app"]["path"].encode(), data["standalone"]["path"].encode(), b"stdout", b"EOF"):
            self.assertNotIn(private, exported)
        for outcome in ("failure", "cancelled", "skipped", "unavailable", "queued"):
            with self.subTest(outcome=outcome), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(data, outcome)
        for record in ("owner", "child", "exit"):
            for key, value in (("sourceSha", "f" * 40), ("runId", "123457"), ("attempt", True),
                               ("requestSha256", "0" * 64), ("ownerArtifactSha256", data["app"]["sha256"]), ("extra", False)):
                altered = deepcopy(data); altered[record][key] = value
                with self.subTest(record=record, field=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        for key, value in (("entries", 12), ("entries", 8193), ("entries", True), ("files", 13), ("payloadBytes", 4097),
                           ("manifestSha256", "f" * 64), ("inspectionComplete", False), ("bookSettled", False),
                           ("versionIdentity", {"volume": 77, "fileId": "44" * 8}),
                           ("selectedIdentities", list(reversed(data["child"]["observation"]["selectedIdentities"])))):
            altered = deepcopy(data); altered["child"]["observation"][key] = value
            altered["owner"]["nativeResultSha256"] = hashlib.sha256(helper.canonical_json(altered["child"])).hexdigest()
            with self.subTest(observation=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        failures = {"createCalls": 0, "createReturn": True, "createError": 5, "firstWait": 258, "exitReturn": 0,
            "originalExitCode": 259, "terminateCalls": 1, "processCloseReturn": 0, "threadCloseReturn": 0,
            "deadlineLatched": True, "unknown": True, "parentBookSettled": False, "inputOriginalsClosed": 0,
            "freshAccountVerified": False, "onlyUsersMembership": False, "accountRemovedAfterSettlement": False,
            "managedSourceMappingAuthenticated": True, "managedOrdinaryStartAuthorized": True,
            "productionEnabled": True, "fullwalkEntries": 28, "ownerArtifactBytes": data["app"]["size"],
            "ownerCommandSha256": "0" * 64, "nativeResultSha256": "0" * 64}
        for key, value in failures.items():
            altered = deepcopy(data); altered["owner"][key] = value
            with self.subTest(owner=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        for record, key, value in (("child", "resultFile", {"createNew": True, "writeCalls": 1, "closed": True}),
            ("owner", "ownerResult", {"createNew": True, "writeCalls": 1, "closed": True}),
            ("exit", "exitCode", 1), ("exit", "originalWaitReturned", False), ("exit", "writerCloseGate", "self-certified")):
            altered = deepcopy(data); altered[record][key] = value
            with self.subTest(record=record, field=key), self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        altered = deepcopy(data); altered["owner"]["aclTransitions"][-1]["role"] = "ordinary-output"
        with self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        altered = deepcopy(data); altered["after"] = data["arguments"]["app_identity"]
        with self.assertRaises(helper.CheckFailure): self.fullwalk_accept(altered)
        raw = [helper.canonical_json(data[key]) for key in ("owner", "child", "exit")]
        for number, limit in ((0, 64 << 10), (1, 4096), (2, 4096)):
            for malformed in (b"{}", b"not-json", b"x" * (limit + 1), raw[number][:-1],
                              b'{"schemaVersion":1,' + raw[number][1:]):
                changed = list(raw); changed[number] = malformed
                with self.subTest(record=number, size=len(malformed)), self.assertRaises(helper.CheckFailure):
                    helper.windows_fullwalk_records(data["context"], data["request"], data["after"], *changed, "success",
                        envelope_raw=data["envelope"], intent_raw=data["intent_raw"], ordinary_prewrite_tick=data["ordinary_prewrite"])

    def test_windows_reader_ordinary_request_is_fixed_bounded_data(self):
        context, artifact, before, *_ = self.ordinary_data()
        raw = helper.windows_ordinary_request(context, artifact, before)
        self.assertEqual(len(raw.splitlines()), 10)
        self.assertTrue(raw.startswith(b"MRK_WINDOWS_ORDINARY_REQUEST_V1\n") and raw.endswith(b"\n"))
        command = '"' + artifact["path"] + '" ' + helper.WINDOWS_INSTALLED_TEST + " --exact --ignored --nocapture --test-threads=1"
        self.assertIn(b"\ncommandSha256=" + hashlib.sha256(command.encode("utf-16-le")).hexdigest().encode("ascii") + b"\n", raw)
        for key, value in (("size", 0), ("size", True), ("size", 128 * 1024 * 1024 + 1), ("sha256", "X" * 64),
                           ("path", artifact["path"].replace("aaaaaaaaaaaaaaaa", "bbbb")),
                           ("path", artifact["path"].replace("debug\\deps", "release\\deps")),
                           ("path", artifact["path"] + "\ncommand=other"), ("path", r"\\host\share\fake.exe")):
            with self.subTest(artifact=key, value=value), self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_request(context, {**artifact, key: value}, before)
        for key, value in (("attempt", True), ("attempt", 2), ("runId", "0"), ("sourceSha", "0" * 40), ("sourceTree", "z" * 40)):
            with self.subTest(binding=key), self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_request({**context, key: value}, artifact, before)
        for identity in ("", before + ":extra", before.replace(":300:", ":-1:"), before.replace("77:", "0:", 1),
                         before.replace("11" * 16, "0" * 32), before.replace(":128", ":" + str(2**32))):
            with self.subTest(identity=identity), self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_request(context, artifact, identity)
        long_root = r"C:\runner" + r"\abcdefghij" * 80
        long_context = {**context, "root": long_root}
        long_artifact = {**artifact, "path": long_root + artifact["path"][len(context["root"]):]}
        with self.assertRaises(helper.CheckFailure): helper.windows_ordinary_request(long_context, long_artifact, before)

    def test_windows_reader_ordinary_acl_transition_is_exact_not_ctime_exemption(self):
        context, artifact, before, after, owner, *_ = self.ordinary_data()
        rows = owner["aclTransitions"]
        public = helper.windows_ordinary_transitions(rows, artifact, before, after)
        self.assertEqual([row["role"] for row in public], [role for role, _ in helper.WINDOWS_ORDINARY_ACLS])
        for key in ("volume", "creation", "write", "size", "allocation", "links", "attributes"):
            altered = deepcopy(rows); altered[5]["after"][key] += 1
            with self.subTest(drift=key), self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_transitions(altered, artifact, before, after)
        changes = [
            (5, "role", "other"), (5, "mask", 0x1f01ff), (5, "mask", True),
            (5, "singleExplicitNoninheritingAce", False), (5, "securityAfter", "4" * 64),
        ]
        for index, key, value in changes:
            altered = deepcopy(rows); altered[index][key] = value
            with self.subTest(transition=key), self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_transitions(altered, artifact, before, after)
        for altered in (rows[:-1], rows + [rows[0]], list(reversed(rows))):
            with self.assertRaises(helper.CheckFailure): helper.windows_ordinary_transitions(altered, artifact, before, after)
        for identity in (before, after.replace("11" * 16, "12" * 16), after.replace(":301:", ":302:")):
            with self.assertRaises(helper.CheckFailure): helper.windows_ordinary_transitions(rows, artifact, before, identity)
        altered = deepcopy(rows); altered[1]["before"]["fileId"] = altered[0]["before"]["fileId"]
        altered[1]["after"]["fileId"] = altered[0]["after"]["fileId"]
        with self.assertRaises(helper.CheckFailure): helper.windows_ordinary_transitions(altered, artifact, before, after)

    def test_windows_reader_ordinary_records_require_closed_exact_source_bound_schema(self):
        data = self.ordinary_data()
        public = self.ordinary_accept(data)
        self.assertEqual(public["native"]["admitted"], 1)
        self.assertEqual(public["native"]["rootContracts"], 1)
        self.assertTrue(public["ordinaryOwner"]["resultFilesClosedBySeparateExitGates"])
        self.assertIs(public["managedOrdinaryStartAuthorized"], False)
        self.assertIs(public["managedSourceMappingAuthenticated"], False)
        self.assertIs(public["protectedFullwalk"], False)
        text = helper.canonical_json(public).decode()
        for absent in ("accountName", "accountSidSha256", "fileId", "securityBefore", "stdout", "EOF"):
            self.assertNotIn(absent, text)
        for number in (4, 5, 6):
            for key, value in (("sourceSha", "f" * 40), ("sourceTree", "e" * 40),
                               ("runId", "123457"), ("attempt", True), ("extra", "not-admitted")):
                altered = deepcopy(data); altered[number][key] = value
                with self.subTest(record=number, field=key), self.assertRaises(helper.CheckFailure):
                    self.ordinary_accept(altered)
        context, artifact, before, after, owner, child, original_exit = data
        good = [helper.canonical_json(row) for row in (owner, child, original_exit)]
        for number, limit in ((0, 64 << 10), (1, 4096), (2, 4096)):
            for bad in (b"{}", b"not-json", b"x" * (limit + 1), good[number][:-1],
                        b'{"schemaVersion":1,' + good[number][1:]):
                values = list(good); values[number] = bad
                with self.subTest(record=number, bytes=len(bad)), self.assertRaises(helper.CheckFailure):
                    helper.windows_ordinary_records(context, artifact, before, after, *values, "success")

        # Exercise the actual retain selection/copy loop, not just the redacted
        # record return above. All filesystem/context/runtime edges are inert.
        root = Path(context["root"])
        private_names = ("windows-installed-native-preflight-checks.json", "ordinary-request.txt",
            "ordinary-owner-intent.private.json", "ordinary-owner-result.private.json",
            "ordinary-owner-exit.private.json", "ordinary-output/native-result.json")
        private_raw = helper.canonical_json({"artifactNativeIdentity": before,
            "accountName": "inert-private-account", "privateMarker": "never-publish-this-original"})
        originals = {root / name: private_raw for name in private_names}
        public_name = "windows-installed-native-checks.json"
        originals[root / public_name] = helper.canonical_json(public)
        original_bytes = dict(originals)
        written, closed = {}, set()

        def info(path):
            if path not in originals: raise FileNotFoundError("inert absent retained input")
            return SimpleNamespace(st_size=len(originals[path]))

        def read(path, limit):
            if path in originals:
                raw = originals[path]
            else:
                self.assertIn(path, closed)
                raw = written[path]
            self.assertLessEqual(len(raw), limit)
            return raw

        class Output:
            def __init__(self, path): self.path = path
            def __enter__(self): return self
            def write(self, raw):
                written[self.path] = raw
                return len(raw)
            def __exit__(self, *_): closed.add(self.path)

        def open_public(path, mode):
            self.assertEqual((path.parent, mode), (root / "public", "xb"))
            self.assertNotIn(path, written)
            return Output(path)

        with patch.object(helper, "windows_installed_context", return_value=context) as selected_context, \
             patch.object(helper.Path, "lstat", autospec=True, side_effect=info), \
             patch.object(helper.Path, "open", autospec=True, side_effect=open_public), \
             patch.object(helper, "ordinary", side_effect=lambda path: self.assertIn(path, originals)), \
             patch.object(helper, "windows_installed_bytes", side_effect=read), \
             patch.object(helper, "windows_installed_retain_runtime", return_value=({"status": "unavailable"}, None)), \
             patch.object(helper, "write_json") as retention, \
             patch.object(helper, "run", side_effect=AssertionError("retention must not launch a tool")):
            helper.windows_installed_phase("retain", helper.WINDOWS_INSTALLED_SCOPE)
        selected_context.assert_called_once_with(create=False, retention_only=True)
        retention.assert_called_once()
        destination, summary = retention.call_args.args
        self.assertEqual(destination, root / "public/retention.json")
        self.assertEqual(set(written), {root / "public" / public_name})
        self.assertEqual(closed, set(written))
        self.assertEqual(written[root / "public" / public_name], originals[root / public_name])
        self.assertEqual([row["path"] for row in summary["files"]], [public_name])
        self.assertEqual(originals, original_bytes)  # Authoritative private bytes are never rewritten.
        exported = b"\n".join(written.values()) + helper.canonical_json(summary)
        for forbidden in (before.encode("ascii"), b"artifactNativeIdentity", b"inert-private-account",
                          b"never-publish-this-original", *(name.encode("ascii") for name in private_names)):
            self.assertNotIn(forbidden, exported)

    def test_windows_reader_ordinary_failures_and_late_success_are_not_receipts(self):
        for outcome in ("failure", "cancelled", "skipped", "unavailable", "queued"):
            with self.subTest(outcome=outcome), self.assertRaises(helper.CheckFailure):
                self.ordinary_accept(self.ordinary_data(), outcome)
        failures = {"createCalls": 0, "createReturn": 0, "createError": 5, "firstWait": 258, "exitReturn": 0,
            "originalExitCode": 259, "terminateCalls": 1, "processCloseReturn": 0, "threadCloseReturn": 0,
            "deadlineLatched": True, "unknown": True, "parentBookSettled": False, "inputOriginalsClosed": 0,
            "freshAccountVerified": False, "onlyUsersMembership": False, "accountRemovedAfterSettlement": False,
            "managedSourceMappingAuthenticated": True, "managedOrdinaryStartAuthorized": True,
            "protectedFullwalk": True, "productionEnabled": True}
        for key, value in failures.items():
            data = self.ordinary_data(); data[4][key] = value
            with self.subTest(owner=key), self.assertRaises(helper.CheckFailure): self.ordinary_accept(data)
        for key in ("createCalls", "createReturn", "exitReturn", "processCloseReturn", "threadCloseReturn"):
            data = self.ordinary_data(); data[4][key] = True
            with self.subTest(boolean=key), self.assertRaises(helper.CheckFailure): self.ordinary_accept(data)
        for key, value in (("context", "elevated-primary-refused"), ("admitted", 0), ("refused", 1),
                           ("rootContracts", 0), ("rootNotExecuted", 1), ("absentThreadReceipts", 4),
                           ("closedOriginals", 1), ("unknown", 1), ("bookSettled", False)):
            data = self.ordinary_data(); data[5]["native"][key] = value
            data[4]["nativeResultSha256"] = hashlib.sha256(helper.canonical_json(data[5])).hexdigest()
            with self.subTest(child=key), self.assertRaises(helper.CheckFailure): self.ordinary_accept(data)
        for record, key, value in ((4, "ownerResult", {"createNew": True, "writeCalls": 1, "closed": True}),
            (5, "resultFile", {"createNew": True, "writeCalls": 1, "closed": True}),
            (6, "exitCode", 1), (6, "originalWaitReturned", False), (6, "writerCloseGate", "self-certified")):
            data = self.ordinary_data(); data[record][key] = value
            with self.subTest(record=record, field=key), self.assertRaises(helper.CheckFailure): self.ordinary_accept(data)

    def test_windows_reader_ordinary_original_keeps_raw_descriptor_change_time(self):
        raw = b"exe"
        before = SimpleNamespace(st_dev=77, st_ino=1, st_mode=stat.S_IFREG | 0o755, st_nlink=1, st_size=len(raw),
            st_mtime_ns=200, st_birthtime_ns=100, st_ctime_ns=100, st_file_attributes=128, st_reparse_tag=0)
        opened = SimpleNamespace(**{**vars(before), "st_mode": stat.S_IFREG | 0o644, "st_ctime_ns": 700})
        artifact = {"path": r"C:\owned\native.exe", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "identity": [77, 1, len(raw), 200, 100]}
        class Input:
            closed = False
            def __enter__(self): return self
            def __exit__(self, *_): self.closed = True
            def fileno(self): return 91
            def read(self, limit):
                if limit != len(raw) + 1: raise AssertionError("unbounded original read")
                return raw
        stream = Input()
        path = SimpleNamespace(lstat=lambda: before, open=lambda *_: stream)
        with patch.object(helper, "Path", return_value=path), patch.object(helper.os, "name", "nt"), \
             patch.object(helper.os, "fstat", side_effect=[opened, opened]):
            identity = helper.windows_ordinary_original(artifact)
        self.assertTrue(stream.closed)
        self.assertEqual(identity, "77:" + (1).to_bytes(16, "little").hex() + ":116444736000000001:116444736000000002:116444736000000007:128")
        self.assertEqual(artifact["identity"], [77, 1, len(raw), 200, 100])  # Compile receipt not rewritten.
        for key in ("st_ctime_ns", "st_birthtime_ns", "st_ino", "st_file_attributes", "st_mtime_ns"):
            changed = SimpleNamespace(**{**vars(opened), key: getattr(opened, key) + 1})
            with self.subTest(raw_descriptor_drift=key), patch.object(helper, "Path", return_value=path), \
                 patch.object(helper.os, "name", "nt"), patch.object(helper.os, "fstat", side_effect=[opened, changed]), \
                 self.assertRaises(helper.CheckFailure):
                helper.windows_ordinary_original(artifact)

    def test_windows_reader_ordinary_native_source_has_one_retained_original_owner(self):
        native = (SOURCE / helper.WINDOWS_INSTALLED_CRATE / "src/ordinary_owner.rs").read_text(encoding="utf-8")
        shared = (SOURCE / helper.WINDOWS_INSTALLED_CRATE / "src/qualification_result.rs").read_text(encoding="utf-8")
        self.assertIn(helper.WINDOWS_INSTALLED_CRATE + "/src/ordinary_owner.rs", helper.WINDOWS_INSTALLED_SOURCES)
        self.assertIn(helper.WINDOWS_INSTALLED_CRATE + "/src/qualification_result.rs", helper.WINDOWS_INSTALLED_SOURCES)
        for api in ("T::CreateProcessWithLogonW(", "T::TerminateProcess(",
                    "F::CloseHandle(this.outputs.hProcess)", "F::CloseHandle(this.outputs.hThread)"):
            self.assertEqual(native.count(api), 1)
        enter = native.split("    fn enter(self:", 1)[1].split("    fn finish(self:", 1)[0]
        self.assertLess(enter.index("this.facts.begin()?"), enter.index("T::CreateProcessWithLogonW("))
        self.assertLess(enter.index("this.error ="), enter.index("account.zero()"))
        self.assertIn("this.domain.as_ptr()", enter)
        self.assertIn("domain: [u16; 2]", native)
        self.assertIn("startup: T::STARTUPINFOW, outputs: T::PROCESS_INFORMATION", native)
        self.assertIn("Pin<Box<Self>>", native)
        self.assertIn("std::thread::park()", native)
        self.assertIn("if file.close().is_err() { return false; }", shared)
        self.assertIn("pub(super) use super::qualification_result::*;", native)
        for api in ("FS::CreateFileW(", "FS::ReadFile(", "FS::WriteFile(", "F::CloseHandle(", "BC::BCryptHash("):
            self.assertEqual(shared.count(api), 1)
            self.assertEqual(native.count(api), 2 if api == "F::CloseHandle(" else 0)
        self.assertIn("const NATIVE_SECONDS: u64 = 90;", native)
        self.assertIn("const SETTLE_MS: u32 = 10_000;", native)
        deadline = native.split("pub(super) fn next_effect(", 1)[1].split("fn command(", 1)[0]
        self.assertIn("*deadline_latched |= elapsed >= Duration::from_secs(NATIVE_SECONDS)", deadline)
        self.assertIn("need(!*deadline_latched)", deadline)
        self.assertNotIn("Instant::now()", deadline)
        effect = native.split("fn owner_effect(", 1)[1].split("fn batch_return(", 1)[0]
        self.assertIn("next_effect(start.elapsed(), latched)", effect)
        self.assertIn("clock.sample(false)", effect)
        self.assertIn("None => Ok(())", effect)  # Legacy ordinary remains the original90s guard.
        guard = "owner_effect(start, deadline_latched, aggregate)?;"
        self.assertLess(enter.index(guard), enter.index("this.facts.begin()?"))
        # Bind the guard after the last prerequisite observation, not merely at
        # helper entry or at the later successful-result check.
        for start, end, observation, mutation in (
            ("    fn create(", "    fn retire(", "self.query()?.is_none()", "NM::NetUserAdd("),
            ("    fn create(", "    fn retire(", "if self.groups()?.is_empty()", "NM::NetLocalGroupAddMembers("),
            ("    fn retire(", "impl Drop for Account", "self.query()?.as_deref()", "NM::NetUserDel("),
            ("fn grant(", "// NetAPI allocation", "file.descriptor_traced(trace)?", "S::SetKernelObjectSecurity("),
        ):
            body = native.split(start, 1)[1].split(end, 1)[0]
            before_mutation = body.split(mutation, 1)[0]
            effect_guard = ("trace.observed(owner_effect(start, deadline_latched, aggregate), InputCheck::AclDeadline)?;"
                            if start == "fn grant(" else guard)
            self.assertGreater(before_mutation.rindex(effect_guard), before_mutation.index(observation))
        driver = native.split("fn run_owner(variant: OwnerVariant, entry_tick: u64)", 1)[1]
        before_output = driver.split("FS::CreateDirectoryW(", 1)[0]
        self.assertGreater(before_output.rindex("input_trace.observed(owner_effect(start, &mut deadline_latched, &mut aggregate), InputCheck::AclDeadline)?;"),
                           before_output.index("let output_name ="))
        self.assertIn("current.create(&parent, start, &mut deadline_latched, &mut aggregate)?", driver)
        self.assertIn("current.retire(start, &mut deadline_latched, &mut aggregate)", driver)
        self.assertIn("start, &mut deadline_latched, &mut aggregate, &mut input_trace)?",
                      driver.split("for ((index, role), acl_role) in directories.into_iter().zip([", 1)[1])
        self.assertEqual(native.count("let start = Instant::now();"), 1)
        for unavailable in ("std::thread::spawn", "std::process::Command", "LogonUserW(", "ImpersonateLoggedOnUser(",
                            "AdjustTokenPrivileges(", "CreateProcessAsUserW(", "AuthzAccessCheck(", "SetNamedSecurityInfoW("):
            self.assertNotIn(unavailable, native)
            self.assertNotIn(unavailable, shared)
        # These are SOURCE guards, not a claim Linux executed the Rust refusal.
        self.assertIn("FULLWALK_PREREQUISITES_REVIEWED: bool = true;", native)
        closed = "need(variant == OwnerVariant::Ordinary || FULLWALK_PREREQUISITES_REVIEWED)?;"
        for first_effect in ("super::hosted_tests::hosted_source()?", 'std::env::var("MRK_DESKTOP_CI_ROOT")',
                             "NativeBook::new()", "owned_file_traced(", "current.create(", "grant(", "Launch::"):
            self.assertLess(driver.index(closed), driver.index(first_effect))
        for entry, variant in (("hosted_ordinary_original_handle_contract", "Ordinary"), ("hosted_protected_version_fullwalk_contract", "Fullwalk")):
            body = native.split("fn " + entry + "() -> Result<()> {", 1)[1].split("\n}", 1)[0]
            self.assertTrue(body.lstrip().startswith("let entry_tick = unsafe { SI::GetTickCount64() };"))
            self.assertIn("run_owner(OwnerVariant::" + variant + ", entry_tick)", body)
        lib = (SOURCE / helper.WINDOWS_INSTALLED_CRATE / "src/lib.rs").read_text(encoding="utf-8")
        self.assertIn('#[cfg(any(test, feature = "qualification-result"))]\nmod qualification_result;', lib)
        self.assertIn('#[cfg(feature = "qualification-result")]\npub use qualification_result::{write_fullwalk_result_once, FullwalkFacts};', lib)
        self.assertIn("#[cfg(test)]\nmod ordinary_owner;", lib)
        for test_only in ("struct Account", "struct Launch", "fn run_owner", "mod hosted_tests", "T::CreateProcessWithLogonW("):
            self.assertNotIn(test_only, shared)
        native_manifest = helper.tomllib.loads((SOURCE / helper.WINDOWS_INSTALLED_CRATE / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(native_manifest["features"], {"qualification-result": []})
        app_manifest = helper.tomllib.loads((SOURCE / "desktop/src-tauri/Cargo.toml").read_text(encoding="utf-8"))
        windows = app_manifest["target"]['cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))']
        self.assertEqual(windows["dependencies"]["mrk-windows-installed-native"], {"path": "../native/windows-installed-native"})
        self.assertEqual(windows["dev-dependencies"]["mrk-windows-installed-native"],
                         {"path": "../native/windows-installed-native", "features": ["qualification-result"]})
        app = (SOURCE / "desktop/src-tauri/src/installed_runtime_windows.rs").read_text(encoding="utf-8")
        walk = app.split("fn native_protected_version_walk_and_original_settlement()", 1)[1].split("    #[test]", 1)[0]
        self.assertIn("let original_end = Instant::now() + Duration::from_secs(10);", walk)
        self.assertIn("let reporting_end = original_end + Duration::from_secs(2);", walk)
        self.assertLess(walk.index("book.settle_originals()"), walk.index("assert!"))
        self.assertLess(walk.index("book.settle_originals()"), walk.index("native::write_fullwalk_result_once(&actual, reporting_end)"))
        phase = HELPER.read_text(encoding="utf-8").split("def windows_installed_phase(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("windows_fullwalk_preflight", phase)
        self.assertNotIn("[app_artifact[\"path\"], WINDOWS_FULLWALK_TEST,", phase)
        self.assertIn("WINDOWS_INSTALLED_INERT, 5)", phase)
        workflow = (SOURCE / ".github/workflows/desktop-foundation.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("& $env:MRK_WINDOWS_NATIVE_ARTIFACT " + helper.WINDOWS_FULLWALK_OWNER + " --exact --ignored --nocapture --test-threads=1"), 1)
        self.assertNotIn(helper.WINDOWS_FULLWALK_TEST, workflow)  # Only the native owner launches the app child.
        child = (SOURCE / helper.WINDOWS_INSTALLED_CRATE / "src/hosted_tests.rs").read_text(encoding="utf-8")
        self.assertLess(child.index("let settlement = book.settle_once()"), child.index("ordinary_owner::write_native_result"))
        self.assertLess(child.index("&& absent == if admitted { 6 } else { 4 }"), child.index("ordinary_owner::write_native_result"))
        self.assertIn("require_fact(admitted)?;", child)



if __name__ == "__main__":
    unittest.main()
