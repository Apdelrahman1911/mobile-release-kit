"""Inert DATA/privacy tests; never native tools, secret inputs or Apple requests."""
import ast
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
from subprocess import CompletedProcess
import tempfile
import time
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macos_public_verification_evidence", ROOT / "desktop/tools/macos_public_verification_evidence.py")
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)
CONTEXT = {"profile": "installed", "source": "1" * 40, "workflowSource": "1" * 40,
           "runId": "123", "runAttempt": "2", "target": "aarch64-apple-darwin"}
SENTINEL = "PRIVATE_SENTINEL_do_not_publish_/key/file_or_argv"


def budget():
    return {"nodes": 0, "deadline": time.monotonic_ns() + 45_000_000_000}


def receipt(phase="finalize-image"):
    return {"schemaVersion": 1, "phase": phase, **CONTEXT, "passed": True,
            "targetRetired": True, "originalClosesKnown": True, "outerFinalityRequired": True,
            "originalCalls": [{"role": "final-image-log", "entered": True, "returned": True,
                "capturesSettled": True, "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}],
            "credentialOriginals": [], "credentialContexts": [],
            "notaryAuthentication": {"created": True, "closed": True, "retired": True},
            "notarySubmission": {"id": "12345678-1234-1234-1234-123456789abc", "status": "Accepted"},
            "finalImage": {"schemaVersion": 1, "kind": "mrk-final-user-image", "target": CONTEXT["target"], "submissionId": "12345678-1234-1234-1234-123456789abc", "status": "Accepted",
                "logSha256": "a" * 64, "sha256Compared": False, "errorCount": 0, "warningCount": 2,
                "ticketRowCount": 3, "imageSha256": "c" * 64, "imageBytes": 4096,
                "actualStaplerValidation": True, "originalMountDetached": True}}


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def project(root, *, removal_case="disabled"):
    return DATA.project(str(root), profile="installed", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                        run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"], removal_case=removal_case)


def normal_diagnostic_data(*, removal=False):
    """Compile only genuine DATA writers/constants, never import the native runner.

    CompletedProcess is only an inert record constructor; no subprocess runner
    or native-owner namespace is exposed. The optional output-DATA resultPost
    branch is outside these build/query fixtures and is never entered.
    """
    path = ROOT / "desktop/tools/macos_normal_ui_runner.py"
    names = {"Refused", "need", "sha", "pairs", "document", "encoded", "failure_base",
        "normal_failure_diagnostics", "normal_admission_failure", "classify_normal_admission_failure", "ADMISSION_OWNER_REASONS",
        "NORMAL_SELECTIONS", "OUTPUT_DATA_RESULT",
        "IOS_UNSIGNED_RESULT", "IOS_UNSIGNED_METHOD", "LOADER", "TOOLCHAIN_QUERIES", "ADMISSION_STAGES",
        "ADMISSION_EXCEPTION_TYPES", "ADMISSION_EXCEPTION_LABELS", "ADMISSION_SOURCE_FILES", "ADMISSION_COMMAND_ROLES"}
    if removal:
        names.update(("TARGET", "CLASS", "REMOVAL_METHODS", "removal_selection", "removal_ui_result"))
    nodes, found = [], set()
    for node in ast.parse(path.read_text()).body:
        name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in names:
            nodes.append(node); found.add(name)
    if found != names:
        raise AssertionError("finite-normal-diagnostic-DATA-dependencies")
    namespace = {"hashlib": hashlib, "json": json, "re": re, "Path": Path, "__file__": str(path),
                 "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def build_diagnostic(normal, phase="build", *, fallback=False):
    original = CompletedProcess([], 70, b"Error Domain=NSPOSIXErrorDomain Code=2\n", (
        b"NormalAppUITests.swift:123:7: error: cannot find '" + SENTINEL.encode() + b"' in scope\n"
        b"** BUILD FAILED **\nxcodebuild: error: " + SENTINEL.encode() + b"\n"))
    return normal["failure_base" if fallback else "normal_failure_diagnostics"](phase, None, original)


def admission_diagnostic(normal):
    raw = {"schemaVersion": 1, "scope": "generated-ui-runner-refused", "productReady": False,
        "error": "runner-admission-or-owner-error", "stage": "execute", "exceptionClass": "ProcessError",
        "unknownStateRetained": True, "sourceFrames": [{"source": "owned_process.py", "line": 321}],
        "ownerFailure": {"dispatched": True, "contained": False, "cleanupComplete": None},
        "commands": [{"role": "normal-toolchain-sdkPath", "returncode": 70, "timeoutSeconds": 30,
            "roleCapSeconds": 30, "outputLimitBytes": 4096, "argvSha256": "1" * 64,
            "stdoutBytes": 0, "stdoutSha256": "2" * 64, "stderrBytes": 256, "stderrSha256": "3" * 64}]}
    return normal["classify_normal_admission_failure"](json.dumps(raw).encode())


def removal_data():
    """Only existing terminal-comparison and fixed-role DATA, no native owners."""
    result = []
    for filename, names in (
        ("stage_macos_installed.py", {"Refused", "need", "maintenance_hex", "REMOVAL_FIXTURE_CASES", "REMOVAL_FIXTURE_PHASES",
            "removal_fixture_case_data", "removal_fixture_observation_pair", "removal_fixture_terminal_data"}),
        ("macos_android_helper_package.py", {"Refused", "need", "REMOVAL_CASES", "removal_runtime_roles", "removal_native_result_data"}),
    ):
        path = ROOT / "desktop/tools" / filename
        nodes, found = [], set()
        for node in ast.parse(path.read_text()).body:
            name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
                node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) else None)
            if name in names:
                nodes.append(node); found.add(name)
        if found != names:
            raise AssertionError("finite-removal-DATA-dependencies")
        namespace = {"re": re}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
        result.append(namespace)
    return result


def removal_receipt(case, stager, helper, normal):
    """Synthetic normalized observations, never native/removal authority."""
    binding = {"sourceCommit": CONTEXT["source"], "target": CONTEXT["target"], "release": DATA.REMOVAL_RELEASE,
        "inventorySha256": "b" * 64, "packageSha256": "c" * 64, "removeDescriptorSha256": "d" * 64,
        "removeSignatureSha256": "e" * 64}
    before = {"phase": "before", "binding": binding, "rootIdentity": [1, 2, 3, 4, 5, 6, 7, 8, 9],
        "expectedFiles": 3, "expectedDirectories": 2, "presentFiles": 3, "presentDirectories": 2,
        "archives": [], "appPresent": True, "firstEligibleAbsent": False, "allPayloadAbsent": False,
        **{key: "f" * 64 for key in ("installationStateSha256", "installedProducerSha256", "installedSignatureSha256", "payloadCommitmentSha256")}}
    old = {"invocation": "1" * 32, "snapshotSha256": "4" * 64, "tipSha256": "5" * 64, "prefix": 3,
        "requestId": "6" * 32, "rootNonce": "1" * 32, "previousTipSha256": None, "genesisSnapshotSha256": "4" * 64}
    new = {"invocation": "2" * 32, "snapshotSha256": None, "tipSha256": "8" * 64, "prefix": 4,
        "requestId": "9" * 32, "rootNonce": "2" * 32, "previousTipSha256": old["tipSha256"], "genesisSnapshotSha256": old["genesisSnapshotSha256"]}
    middle = dict(before, phase="after-cancel") if case == "ordinary" else dict(before,
        phase="after-cut", presentFiles=2, firstEligibleAbsent=True, archives=[old])
    terminal = dict(before, phase="terminal", presentFiles=0, presentDirectories=0,
        appPresent=False, firstEligibleAbsent=True, allPayloadAbsent=True,
        archives=[dict(old, prefix=4)] if case == "ordinary" else [old, new])
    arguments = {} if case == "ordinary" else {
        "effects_sha": "a" * 64, "supervisor": {"role": "resume", "actualChildReturncode": 0,
            "originalChildWaitObserved": True, "effectsSha256": "a" * 64},
        "effects": {"requestId": new["requestId"], "rootNonce": new["rootNonce"], "previousTipSha256": old["tipSha256"],
            "genesisSnapshotSha256": old["genesisSnapshotSha256"], "returnedUnlinks": 4, "appRootUnlinkOrdinal": 4}}
    final = stager["removal_fixture_terminal_data"](case, before, middle, terminal, **arguments)
    method = normal["REMOVAL_METHODS"][case]
    selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
    output = ("MRK_MACOS_REMOVAL_UI=v1;case=" + case + ";cancelObserved=" + ("1" if case == "ordinary" else "0")
        + ";continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1\n"
        + "Test Case '" + selected + "' started.\nTest Case '" + selected + "' passed (1.0 seconds).\n").encode()
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    tree = {"testNodes": [{"name": "MRKNormalAppUITests", "nodeType": "Test Suite", "children": [
        {"name": method + "()", "nodeType": "Test Case", "nodeIdentifier": "NormalAppUITests/" + method + "()", "result": "Passed"}]}]}
    ui = normal["removal_ui_result"](output, json.dumps(counts).encode(), json.dumps(tree).encode(), case)
    value = receipt("package-removal-fixture"); del value["finalImage"]
    value["notarySubmission"] = value["notaryAuthentication"] = None
    value["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
        "returncode": 1 if role in ("removal-live-cancel", "removal-live-cut") else 0,
        "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64} for role in helper["removal_runtime_roles"](case)]
    value["removalFixture"] = dict(final, originalUIJoined=True, uiObservation=ui, outputs=3 if case == "ordinary" else 6,
        outputsSha256="c" * 64, requestsDirectoryNamedOnly=True, mountedInputsDetached=True,
        sourcePrePostMatched=True, firstOriginalErrorPreserved=True, productReady=False)
    return value


def data_contract_diagnostics():
    """Only genuine inline DATA reducers/constants; never execute the shell/owner."""
    path = ROOT / "desktop/tools/macos_installed_data_contracts.sh"
    source = path.read_text().split("<<'PY_DATA_CONTRACTS'\n", 1)[1].rsplit("\nPY_DATA_CONTRACTS", 1)[0]
    tree = ast.parse(source)
    wanted = {"DATA_FAILURE_GUARDS", "data_failure_guard", "data_failure_json", "data_failure_python",
              "data_failure_cargo", "data_failure_document"}
    nodes, found, assignments = [], set(), {}
    for node in tree.body:
        name = node.name if isinstance(node, ast.FunctionDef) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in wanted:
            nodes.append(node); found.add(name)
        if isinstance(node, ast.Assign) and name is not None:
            assignments[name] = node.value
    if found != wanted:
        raise AssertionError("finite-data-contract-diagnostic-closure")
    names = ast.literal_eval(assignments["names"])
    child = ast.literal_eval(assignments["child_code"].right)
    functions = [node for node in ast.parse(child).body
                 if isinstance(node, ast.FunctionDef) and node.name == "data_failed_test_rows"]
    if len(functions) != 1:
        raise AssertionError("finite-child-failure-ID-reducer")
    namespace = {"json": json, "hashlib": hashlib, "re": re}
    exec(compile(ast.Module(body=nodes + functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace, names


def data_contract_failure(data, names, *, phase="python", code=1, raw=None, flags=None,
                          guard="command-not-complete", source_paths=(), failed_names=None):
    if raw is None:
        if phase == "python":
            selected = [names[0]] if failed_names is None else failed_names
            failures = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in selected]
            value = dict(testsRun=84, failures=len(failures), errors=0, skipped=0, expectedFailures=0,
                unexpectedSuccesses=0, testIds=names, actualHostBeforeAndAfter=True,
                **data["data_failed_test_rows"](failures, [], names))
            raw = json.dumps(value).encode()
        else:
            raw = b""
    command = dict(phase=phase, returnCode=code, originalReturned=True, outputComplete=True,
                   captureClosed=True, timedOut=False, outputOverflow=False)
    command.update(flags or {})
    context = {key: CONTEXT[key] for key in ("source", "workflowSource", "runId", "runAttempt", "target")}
    return json.loads(data["data_failure_document"](command, {"stdout": raw, "stderr": SENTINEL.encode()},
        guard, context, names, source_paths, "/public/checkout"))


class PublicVerificationEvidenceData(unittest.TestCase):
    def test_genuine_removal_data_preserves_case_facts_and_expected_nonzero(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        self.assertEqual(DATA.REMOVAL_RELEASE, json.loads((ROOT / "desktop/macos-installed-inputs/build-release.json").read_text())["release"])
        self.assertEqual(DATA.REMOVAL_METHODS, normal["REMOVAL_METHODS"])
        union = set()
        for case in ("ordinary", "abrupt"):
            roles = helper["removal_runtime_roles"](case)
            self.assertEqual(DATA.REMOVAL_ROLES[case], roles)
            union.update(roles)
            value = removal_receipt(case, stager, helper, normal)
            row = DATA.project_receipt(value, {**CONTEXT, "expectedRemovalCase": case}, "package-removal-fixture")
            self.assertEqual(row["originalCalls"]["recordedCount"], 9)
            self.assertEqual(row["originalCalls"]["unclassifiedCount"], 0)
            nonzero = [call for call in row["originalCalls"]["calls"] if call["returncode"] != 0]
            self.assertEqual(len(nonzero), 1)
            self.assertTrue(helper["removal_native_result_data"](case, nonzero[0]["role"], nonzero[0]["returncode"]))
            final = row["removalFixture"]
            self.assertEqual(final, value["removalFixture"])
            self.assertEqual(final["qualification"], "pending-original-owner-finality")
            self.assertIs(final["powerLossQualified"], False)
            self.assertIs(final["productReady"], False)
            self.assertEqual(final["uiObservation"]["gateFree"], "unqualified")
            self.assertIs(final["uiObservation"]["normalQuit"], False)
            self.assertIs(row["recordedPassed"], True)  # Separate from pending fixture qualification.
        self.assertEqual(len(union), 12)
        self.assertTrue(union <= DATA.NATIVE_ROLES)

    def test_removal_mixed_cases_context_and_closed_fields_are_refused(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        value = removal_receipt("ordinary", stager, helper, normal)
        context = {**CONTEXT, "expectedRemovalCase": "ordinary"}
        for key, bad in (("expectedRemovalCase", "disabled"), ("expectedRemovalCase", "abrupt"),
                         ("target", "x86_64-apple-darwin"), ("profile", "aqua"), ("source", "2" * 40)):
            with self.subTest(context=key), self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, {**context, key: bad}, "package-removal-fixture")
        mutations = (((), "case", "abrupt"), ((), "archives", True), ((), "outputs", 6),
            ((), "qualification", "passed"), ((), "powerLossQualified", True), ((), "originalUIJoined", False),
            ((), "allPayloadAbsent", 1), ((), "abruptProcessCutObserved", True), ((), "outputsSha256", SENTINEL),
            (("targetBinding",), "release", SENTINEL), (("targetBinding",), "sourceCommit", "2" * 40),
            (("targetBinding",), "target", "x86_64-apple-darwin"), (("targetBinding",), "packageSha256", SENTINEL),
            (("uiObservation",), "case", "abrupt"), (("uiObservation",), "testIdentifier", SENTINEL),
            (("uiObservation",), "normalQuit", True), (("uiObservation",), "gateFree", "qualified"),
            (("uiObservation",), "nativeSummarySha256", SENTINEL), (("uiObservation", "testCounts"), "passedTests", True))
        for path, name, bad in mutations:
            broken = copy.deepcopy(value); node = broken["removalFixture"]
            for part in path: node = node[part]
            node[name] = bad
            with self.subTest(path=path, name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for key in value["removalFixture"]:
            broken = copy.deepcopy(value); del broken["removalFixture"][key]
            with self.subTest(missing=key), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for path in ((), ("targetBinding",), ("uiObservation",), ("uiObservation", "testCounts")):
            broken = copy.deepcopy(value); node = broken["removalFixture"]
            for part in path: node = node[part]
            node["rawMessage"] = SENTINEL
            with self.subTest(extra=path), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for role in ("removal-live-cut", SENTINEL):
            broken = copy.deepcopy(value); broken["originalCalls"][3]["role"] = role
            with self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        broken = copy.deepcopy(value); broken["originalCalls"] *= 15
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(broken, context, "package-removal-fixture")
        broken = copy.deepcopy(value); broken["phase"] = "package-remove"
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(broken, context, "package-remove")

    def test_removal_failed_parent_and_partial_originals_never_become_success(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        value = removal_receipt("ordinary", stager, helper, normal)
        context = {**CONTEXT, "expectedRemovalCase": "ordinary"}
        value.update(passed=False, originalClosesKnown=False, targetRetired=False)
        row = DATA.project_receipt(value, context, "package-removal-fixture")
        self.assertIs(row["recordedPassed"], False)
        self.assertIs(row["originalClosesKnown"], False)
        self.assertEqual(row["removalFixture"]["qualification"], "pending-original-owner-finality")
        del value["removalFixture"]
        value["originalCalls"] = [{"role": "removal-target-attach", "entered": True, "returned": False, "capturesSettled": False}]
        row = DATA.project_receipt(value, context, "package-removal-fixture")
        self.assertIsNone(row["removalFixture"])
        self.assertEqual(row["originalCalls"]["recordedCount"], 1)
        self.assertIsNone(row["originalCalls"]["calls"][0].get("returncode"))
        self.assertIs(row["originalCalls"]["calls"][0]["returned"], False)

    def test_removal_cli_case_suffix_is_optional_explicit_and_fixed(self):
        choices = (("installed", CONTEXT["target"], [], 0, "disabled"),
            ("aqua", CONTEXT["target"], [], 0, "disabled"),
            ("installed", "x86_64-apple-darwin", [], 0, "disabled"),
            *( ("installed", CONTEXT["target"], ["--removal-case", case], 0, case) for case in ("disabled", "ordinary", "abrupt") ),
            ("aqua", CONTEXT["target"], ["--removal-case", "ordinary"], 1, None),
            ("installed", "x86_64-apple-darwin", ["--removal-case", "ordinary"], 1, None),
            ("installed", CONTEXT["target"], ["--removal-case", SENTINEL], 1, None),
            ("installed", CONTEXT["target"], ["--other", "ordinary"], 1, None),
            ("installed", CONTEXT["target"], ["--removal-case", "ordinary", "--removal-case", "ordinary"], 1, None))
        for profile, target, suffix, expected, case in choices:
            with self.subTest(profile=profile, target=target, suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = ["--profile", profile, "--work", str(root), "--target", target, "--source", CONTEXT["source"],
                    "--workflow-source", CONTEXT["workflowSource"], "--run-id", CONTEXT["runId"], "--run-attempt", CONTEXT["runAttempt"]]
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(DATA.main(args + suffix), expected)
                if expected == 0:
                    self.assertEqual(json.loads((root / DATA.OUTPUT).read_text())["expectedRemovalCase"], case)
                else:
                    self.assertFalse((root / DATA.OUTPUT).exists())
                # A recognized option in the wrong position is not a generic CLI.
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(DATA.main(["--removal-case", "ordinary"] + args), 1)

    def test_removal_file_projection_keeps_case_and_caller_status_independent(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        for case in ("ordinary", "abrupt"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); value = removal_receipt(case, stager, helper, normal)
                path = write(root, "android-helper-package-removal-fixture.json", value); before = path.read_bytes()
                result = project(root, removal_case=case)
                self.assertEqual(result["expectedRemovalCase"], case)
                row = result["phases"]["package-removal-fixture"]
                self.assertEqual(row["removalFixture"]["case"], case)
                self.assertEqual(row["callerStatus"], {"receiptState": "absent"})
                self.assertEqual(path.read_bytes(), before)

    def test_data_contract_five_statuses_are_observations_not_phase_acceptance(self):
        names = tuple("data-contracts/" + role + ".status" for role in ("mount", "apfs", "build", "rust", "python"))
        self.assertEqual(tuple(name for name in DATA.STATUS_FILES if name.startswith("data-contracts/")), names)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [write(root, name, body) for name, body in zip(names, (b"0\n", b"1\n", b"unavailable\n", b"0 0 0\n"))]
            raw = write(root, "data-contracts/result.json", SENTINEL.encode())
            before = [path.read_bytes() for path in paths + [raw]]
            result = project(root)
            self.assertEqual(result["statuses"][names[0]], {"receiptState": "observed", "returncode": 0})
            self.assertEqual(result["statuses"][names[1]], {"receiptState": "observed", "returncode": 1})
            self.assertEqual(result["statuses"][names[2]], {"receiptState": "refused"})
            self.assertEqual(result["statuses"][names[3]], {"receiptState": "refused"})
            self.assertEqual(result["statuses"][names[4]], {"receiptState": "absent"})
            self.assertEqual([path.read_bytes() for path in paths + [raw]], before)
            self.assertIs(result["diagnosticOnly"], True)
            self.assertIs(result["productReady"], False)
            self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())

    def test_genuine_normal_build_writer_preserves_finite_cause_without_compiler_prose(self):
        value = build_diagnostic(normal_diagnostic_data())
        row = DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": 70})
        self.assertEqual(row["originalReturncode"], 70)
        self.assertEqual(row["status"], "classified")
        self.assertEqual(row["errorCodes"], [{"stream": "stdout", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertEqual(row["compilerDiagnostics"], [{"stream": "stderr", "source": "NormalAppUITests.swift",
            "line": 123, "column": 7, "severity": "error", "reasonCodes": ["missing-name"]}])
        self.assertIs(row["markers"]["buildFailed"], True)
        self.assertIs(row["markers"]["xcodebuildError"], True)
        self.assertEqual(row["stderrSha256"], value["stderrSha256"])
        self.assertEqual(row["binding"], "same-work-root-parent-context-only")
        self.assertIs(row["nativeSuccessInferred"], False)
        self.assertNotIn(SENTINEL, json.dumps(row))
        self.assertNotIn("source", row)  # The writer did not bind a source commit.

    def test_genuine_query_and_fallback_keep_unavailable_distinct(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        for role, phase in (("build", "build"), ("toolchain", "query")):
            for fallback in (True, False):
                value = build_diagnostic(normal, phase, fallback=fallback)
                row = DATA.project_ui_diagnostic(value, role, status)
                self.assertEqual(row["status"], "unavailable" if fallback else "classified")
                self.assertEqual("compilerDiagnostics" in row, role == "build")
                self.assertIs(row["nativeSuccessInferred"], False)
        value = build_diagnostic(normal, "query"); value["stdoutBytes"] = 4097
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "toolchain", status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(build_diagnostic(normal), "toolchain", status)
        original = CompletedProcess([], 70, b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=identifier;matches=5;exceedsFour=1;nonAtomic=1\n", b"")
        value = normal["normal_failure_diagnostics"]("query", None, original)
        row = DATA.project_ui_diagnostic(value, "toolchain", status)
        self.assertEqual(row["queryObservations"], [{"stream": "stdout", "kind": "dashboard", "observation": "identifier",
            "matches": 5, "exceedsFour": True, "nonAtomic": True}])
        for key, bad in (("matches", True), ("matches", 6), ("exceedsFour", False), ("nonAtomic", False),
                         ("kind", SENTINEL), ("observation", SENTINEL), ("stream", SENTINEL)):
            broken = copy.deepcopy(value); broken["queryObservations"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "toolchain", status)

    def test_genuine_admission_projection_preserves_only_exception_facts(self):
        normal = normal_diagnostic_data()
        self.assertEqual(DATA.UI_ADMISSION_STAGES, frozenset(normal["ADMISSION_STAGES"]))
        self.assertEqual(DATA.UI_ADMISSION_EXCEPTIONS, frozenset(normal["ADMISSION_EXCEPTION_LABELS"]))
        self.assertEqual(DATA.UI_ADMISSION_SOURCES, frozenset(Path(name).name for name in normal["ADMISSION_SOURCE_FILES"]))
        self.assertEqual(DATA.UI_ADMISSION_ROLES, frozenset(normal["ADMISSION_COMMAND_ROLES"]))
        value = admission_diagnostic(normal)
        row = DATA.project_ui_diagnostic(value, "admission", {"receiptState": "observed", "returncode": 70})
        self.assertEqual(row["status"], "observed-exception-only")
        self.assertEqual((row["stage"], row["exceptionClass"]), ("execute", "ProcessError"))
        self.assertEqual(row["sourceFrames"], [{"source": "owned_process.py", "line": 321}])
        self.assertEqual(row["commands"], [{"role": "normal-toolchain-sdkPath", "returncode": 70,
                                          "stdoutBytes": 0, "stderrBytes": 256}])
        self.assertIsNone(row["ownerFailure"]["cleanupComplete"])
        self.assertIs(row["ownerFailure"]["contained"], False)
        self.assertIs(row["nativeSuccessInferred"], False)
        unavailable = normal["classify_normal_admission_failure"](SENTINEL.encode())
        self.assertEqual(DATA.project_ui_diagnostic(unavailable, "admission",
            {"receiptState": "observed", "returncode": 70})["status"], "unavailable")
        self.assertNotIn(SENTINEL, json.dumps(row))

    def test_owner_predicates_and_frame_omission_are_closed_optional_observations(self):
        normal = normal_diagnostic_data()
        self.assertEqual(DATA.UI_OWNER_REASONS, frozenset((*normal["ADMISSION_OWNER_REASONS"].values(), "unknown")))
        class OwnerError(Exception):
            dispatched = contained = cleanup_complete = True
            owner_failure_mask = 63
            def __str__(self):
                raise AssertionError("private-owner-text-must-not-be-read")
        owner = SimpleNamespace(ProcessError=OwnerError, ProcessInterrupted=KeyboardInterrupt,
            ProcessCleanupError=type("CleanupError", (OwnerError,), {}),
            ProcessOutcomeUnknown=type("OutcomeUnknown", (OwnerError,), {}))
        raw = normal["normal_admission_failure"]("execute",
            OwnerError("owned command produced incomplete output"), owner, [])
        raw["sourceFrames"] = [{"source": "_command_process.py", "line": 1000000}]
        raw["sourceFramesTruncated"] = True
        value = normal["classify_normal_admission_failure"](normal["encoded"](raw))
        status = {"receiptState": "observed", "returncode": 1}
        for mask in (None, 32, *range(48, 64)):
            value["ownerDiagnostic"]["failureMask"] = mask
            row = DATA.project_ui_diagnostic(value, "admission", status)
            self.assertEqual(row["ownerDiagnostic"], {"reason": "incomplete-output", "failureMask": mask})
            self.assertEqual(row["sourceFrames"], raw["sourceFrames"])
            self.assertIs(row["sourceFramesTruncated"], True)
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual(row["binding"], "same-work-root-parent-context-only")
        legacy = admission_diagnostic(normal)
        self.assertNotIn("ownerDiagnostic", DATA.project_ui_diagnostic(legacy, "admission", status))
        value.update(ownerDiagnostic=None, sourceFramesTruncated=False)
        self.assertIsNone(DATA.project_ui_diagnostic(value, "admission", status)["ownerDiagnostic"])
        self.assertIs(DATA.project_ui_diagnostic(value, "admission", status)["sourceFramesTruncated"], False)
        good = {"reason": "incomplete-output", "failureMask": 63}
        for bad in (True, [], {}, {**good, "message": SENTINEL}, {**good, "reason": SENTINEL},
                    *({**good, "failureMask": mask} for mask in (True, False, 0, 1, 31, 33, 47, 64, "63"))):
            with self.subTest(bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic({**value, "ownerDiagnostic": bad}, "admission", status)
        for broken in ({**value, "ownerDiagnostic": good, "exceptionClass": "Refused"},
                       {**value, "sourceFramesTruncated": None}, {**value, "sourceFramesTruncated": 1},
                       {**value, "sourceFrames": [{"source": SENTINEL, "line": 1}]},
                       {**value, "sourceFrames": [{"source": "_command_process.py", "line": True}]}):
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "admission", status)
        unavailable = normal["classify_normal_admission_failure"](b"{}")
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic({**unavailable, "ownerDiagnostic": None}, "admission", status)
        self.assertNotIn(SENTINEL, json.dumps(value))

    def test_optional_build_destination_reasons_are_closed_and_backward_compatible(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        value = build_diagnostic(normal); value.pop("buildFailureReasons", None)
        self.assertNotIn("buildFailureReasons", DATA.project_ui_diagnostic(value, "build", status))
        for reasons in ([], [{"stream": stream, "code": code} for stream in ("stdout", "stderr")
                            for code in ("destination-not-found", "no-eligible-destination")]):
            value["buildFailureReasons"] = reasons
            self.assertEqual(DATA.project_ui_diagnostic(value, "build", status)["buildFailureReasons"], reasons)
        valid = {"stream": "stderr", "code": "destination-not-found"}
        for reasons in (None, {}, [valid] * 5, [valid] * 2, [{**valid, "message": SENTINEL}],
                        [{**valid, "code": SENTINEL}], [{**valid, "stream": SENTINEL}],
                        [{**valid, "stream": True}], [{**valid, "code": 1}], [{}]):
            value["buildFailureReasons"] = reasons
            with self.subTest(reasons=reasons), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "build", status)
        query = build_diagnostic(normal, "query"); query["buildFailureReasons"] = []
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(query, "toolchain", status)

    def test_ui_diagnostic_typed_and_closed_schema_mutations_are_refused(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        cases = {
            "build": (("schemaVersion", True), ("status", SENTINEL), ("phase", "test"), ("selection", SENTINEL),
                ("stdoutBytes", True), ("stdoutBytes", 1048577), ("stderrSha256", SENTINEL), ("findingsTruncated", 1),
                ("errorCodes", [{}] * 9), ("errorCodes", [{"stream": "stdout", "domain": SENTINEL, "code": 2}]),
                ("errorCodes", [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": True}]),
                ("queryObservations", [{}] * 5), ("compilerDiagnostics", [{}] * 5), ("markers", {}),
                ("sourceFailures", [SENTINEL]), ("requireObservations", [SENTINEL]), ("dashboardReadiness", {})),
            "admission": (("schemaVersion", True), ("stage", SENTINEL), ("exceptionClass", SENTINEL),
                ("nativeSuccessInferred", True), ("productReady", True), ("unknownStateRetained", False),
                ("sourceFrames", [{"source": SENTINEL, "line": 1}]), ("sourceFrames", [{}] * 5),
                ("commands", [{}] * 17), ("ownerFailure", {"dispatched": 1, "contained": False, "cleanupComplete": None})),
        }
        for role, mutations in cases.items():
            base = build_diagnostic(normal) if role == "build" else admission_diagnostic(normal)
            for key, bad in mutations:
                value = copy.deepcopy(base); value[key] = bad
                with self.subTest(role=role, key=key, bad=bad), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
            for key in base.keys() - {"buildFailureReasons", "destinationTable"}:
                value = copy.deepcopy(base); del value[key]
                with self.subTest(role=role, missing=key), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
            for key in ("message", "path", "argv", "resultPost"):
                value = copy.deepcopy(base); value[key] = SENTINEL
                with self.subTest(role=role, extra=key), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
        value = build_diagnostic(normal); value["compilerDiagnostics"][0]["reasonCodes"] = [SENTINEL]
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "build", status)
        for code in (True, 256, -1):
            value = admission_diagnostic(normal); value["commands"][0]["returncode"] = code
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "admission", status)

    def test_ui_diagnostics_require_independent_failed_scalar_status(self):
        normal = normal_diagnostic_data()
        for role, value in (("build", build_diagnostic(normal)), ("admission", admission_diagnostic(normal))):
            for status in (None, {}, {"receiptState": "absent"}, {"receiptState": "refused"},
                           *({"receiptState": "observed", "returncode": code} for code in (0, True, "70", "0 0 0", -1, 256))):
                with self.subTest(role=role, status=status), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(build_diagnostic(normal), "build", {"receiptState": "observed", "returncode": 1})

    def test_build_only_fixed_projection_needs_no_helper_phases_or_raw_log(self):
        normal = normal_diagnostic_data()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [write(root, "normal-ui/build.status", b"70\n"),
                write(root, "normal-ui/build.failure-diagnostics.json", build_diagnostic(normal)),
                write(root, "normal-ui/build.admission-diagnostics.json", admission_diagnostic(normal)),
                write(root, "normal-ui/build.log", SENTINEL.encode())]
            before = [path.read_bytes() for path in files]
            value = project(root)
            self.assertTrue(all(row["receiptState"] == "absent" for row in value["phases"].values()))
            self.assertEqual(value["normalUiBuildDiagnostics"]["build"]["status"], "classified")
            self.assertEqual(value["normalUiBuildDiagnostics"]["admission"]["status"], "observed-exception-only")
            self.assertEqual(value["normalUiBuildDiagnostics"]["toolchain"], {"receiptState": "absent"})
            self.assertEqual({key: value[key] for key in CONTEXT}, CONTEXT)
            self.assertEqual([path.read_bytes() for path in files], before)
            self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())
        for status in (b"0\n", b"0 0 0\n", b"71\n"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, "normal-ui/build.status", status)
                write(root, "normal-ui/build.failure-diagnostics.json", build_diagnostic(normal))
                self.assertEqual(project(root)["normalUiBuildDiagnostics"]["build"], {"receiptState": "refused"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "normal-ui/build.status", b"70\n")
            write(root, "normal-ui/build.failure-diagnostics.json", b" " * 4097)
            self.assertEqual(project(root)["normalUiBuildDiagnostics"]["build"], {"receiptState": "refused"})

    def test_correlated_finality_hashes_and_unknown_fields_are_not_raw_exports(self):
        value = receipt()
        value.update(private=SENTINEL, tools={"output": SENTINEL}, argv=[SENTINEL], environment={SENTINEL: SENTINEL})
        value["originalCalls"][0].update(stdout=SENTINEL, stderr=SENTINEL, path=SENTINEL)
        value["finalImage"].update(issues=[{"message": SENTINEL}], tickets=[{"path": SENTINEL}])
        row = DATA.project_receipt(value, CONTEXT, "finalize-image")
        encoded = json.dumps(row)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("tools", row)
        self.assertNotIn("stdout", row["originalCalls"]["calls"][0])
        self.assertEqual(row["originalCalls"]["calls"][0]["stdoutSha256"], "a" * 64)
        self.assertIs(row["notaryAuthentication"]["retired"], True)
        self.assertIs(row["finalImage"]["actualStaplerValidation"], True)
        self.assertIs(row["finalImage"]["sha256Compared"], False)
        self.assertIsNone(row["finalImage"].get("strictSignatureBeforeAndAfter"))
        self.assertEqual(row["finalImage"]["warningCount"], 2)
        self.assertIsNone(row["originalCalls"]["calls"][0].get("dispatched"))

    def test_entire_exact_correlation_tuple_is_required(self):
        for field in ("source", "workflowSource", "runId", "runAttempt", "target", "phase"):
            for change in ("wrong", 1, True, None, ["wrong"]):
                with self.subTest(field=field, change=change):
                    value = receipt(); value[field] = change
                    with self.assertRaises(DATA.Refused):
                        DATA.project_receipt(value, CONTEXT, "finalize-image")
            value = receipt(); del value[field]
            with self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, CONTEXT, "finalize-image")
        for field, changed in (("submissionId", "23456789-1234-1234-1234-123456789abc"),
                               ("status", "Invalid"), ("kind", "mrk-final-removal-image"),
                               ("target", "x86_64-apple-darwin")):
            value = receipt(); value["finalImage"][field] = changed
            with self.subTest(conflict=field), self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, CONTEXT, "finalize-image")
        failed_observer = {"schemaVersion": 1, "phase": "prepare-removal-observers", "source": CONTEXT["source"],
                           "target": CONTEXT["target"], "passed": False}
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(failed_observer, CONTEXT, "prepare-removal-observers")

    def test_typed_facts_do_not_promote_malformed_values_or_missing_facts(self):
        mutations = (("passed", 1), ("targetRetired", "true"), ("originalCalls", [{}] * 129),
                     ("credentialContexts", [{}] * 17), ("nativeCalls", 1000001))
        for name, value in mutations:
            broken = receipt(); broken[name] = value
            with self.subTest(name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, CONTEXT, "finalize-image")
        for name, bad in (("imageBytes", True), ("imageBytes", 2**40 + 1), ("warningCount", 2049),
                          ("actualStaplerValidation", 1), ("logSha256", SENTINEL), ("status", SENTINEL)):
            broken = receipt(); broken["finalImage"][name] = bad
            with self.subTest(name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, CONTEXT, "finalize-image")

    def test_json_duplicate_numbers_depth_and_total_nodes_are_bounded(self):
        for raw in (b'{"source":1,"source":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                    b'{"x":1e999}', b'{"x":1.0}', b'{"x":' + b'[' * 18 + b'0' + b']' * 18 + b'}',
                    b'{"x":123456789012345678901}'):
            with self.subTest(raw=raw), self.assertRaises(DATA.Refused):
                DATA.decode(raw, budget())
        exhausted = budget(); exhausted["nodes"] = DATA.JSON_NODE_LIMIT
        with self.assertRaises(DATA.Refused):
            DATA.decode(b'{"ok":true}', exhausted)
        expired = budget(); expired["deadline"] = 0
        with self.assertRaises(DATA.Refused):
            DATA.decode(b'{}', expired)

    def test_real_source_inventory_row_ceiling_has_sufficient_graph_budget(self):
        rows = [{"path": "public/source-%d.py" % index, "gitMode": "100644", "blob": "2" * 40,
                 "size": 1, "sha256": "3" * 64} for index in range(4095)]
        value = {"source": CONTEXT["source"], "tree": "4" * 40, "files": rows}
        body = json.dumps(value).encode()
        observed = DATA.project_inventory(DATA.decode(body, budget(), inventory=True), body, CONTEXT)
        self.assertEqual(observed["fileCount"], 4095)
        self.assertNotIn("files", observed)
        value["files"].append(dict(rows[0]))
        with self.assertRaises(DATA.Refused):
            DATA.decode(json.dumps(value).encode(), budget(), inventory=True)

    def test_finite_failure_roles_keep_original_classification_not_messages(self):
        value = receipt(); value["passed"] = False
        value["failure"] = {"stage": "final-image-log", "type": "Refused", "reason": "notary-log-" + SENTINEL}
        call = value["originalCalls"][0]
        call.update(returned=False, capturesSettled=False, returncode=None, dispatched=True, contained=False,
                    cleanup_complete=False, originalFailure={"available": True, "ownerErrorType": "ProcessOutcomeUnknown",
                    "classification": "deadline", "timeoutSeconds": 30, "outputLimitBytes": 1048576,
                    "frames": [{"path": SENTINEL}], "message": SENTINEL})
        value["originalCalls"].append({"role": SENTINEL, "message": SENTINEL})
        result = DATA.project_receipt(value, CONTEXT, "finalize-image")
        self.assertEqual(result["failure"]["reason"], "notary-log")
        self.assertEqual(result["originalCalls"]["unclassifiedCount"], 1)
        self.assertEqual(result["originalCalls"]["calls"][0]["originalFailure"]["classification"], "deadline")
        self.assertIsNone(result["originalCalls"]["calls"][0]["returncode"])
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assertEqual(DATA.project_failure({"stage": SENTINEL, "type": SENTINEL, "reason": SENTINEL}),
                         {"stage": "unclassified", "type": "unclassified", "reason": "unclassified", "errno": None})

    def test_fixed_signature_and_notary_refusals_remain_distinguishable(self):
        reasons = ("package-signature-bound", "package-signature-header", "package-signature-trust-timestamp",
                   "package-signature-source-chain", "package-signature-source-fingerprint", "notary-submit-terminal",
                   "notary-submit-metadata", "notary-submit-archive", "notary-uuid")
        for reason in reasons:
            self.assertEqual(DATA.project_failure({"reason": reason})["reason"], reason)
        self.assertEqual(DATA.project_failure({"reason": "package-signature-" + SENTINEL})["reason"], "unclassified")

    def test_successful_normalized_receipt_and_original_zero_survive_file_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "android-helper-finalize-image.json", receipt())
            write(root, "image-finalization.status", b"0\n")
            result = project(root)
            observed = result["phases"]["finalize-image"]
            self.assertEqual(observed["receiptState"], "observed")
            self.assertIs(observed["recordedPassed"], True)
            self.assertIs(observed["originalClosesKnown"], True)
            self.assertIs(observed["notaryAuthentication"]["closed"], True)
            self.assertEqual(observed["callerStatus"]["returncode"], 0)
            self.assertEqual(observed["finalImage"]["imageSha256"], "c" * 64)
            self.assertEqual(observed["finalImage"]["logSha256"], "a" * 64)
            self.assertIs(observed["finalImage"]["actualStaplerValidation"], True)
            self.assertEqual(observed["notarySubmission"]["status"], "Accepted")
            self.assertIs(result["productReady"], False)

    def test_full_preview_original_rosters_fit_fixed_public_output_bound(self):
        def literals(path, names):
            module = ast.parse(path.read_text())
            return {node.targets[0].id: ast.literal_eval(node.value) for node in module.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names}
        fixed = literals(ROOT / "desktop/tools/macos_android_helper_package.py",
                         {"PREPARE_ROLES", "CREDENTIAL_ROLES", "SIGNING_PHASES", "NOTARY_ROLES",
                          "FINAL_PACKAGE_ROLES", "FINAL_IMAGE_ROLES", "INSTALLER_CREDENTIAL_ROSTER", "REMOVE_PACKAGE_ROLES"})
        package = literals(ROOT / "desktop/tools/stage_macos_installed.py", {"PACKAGING_CALL_ROLES"})["PACKAGING_CALL_ROLES"]
        application = fixed["CREDENTIAL_ROLES"][:17] + ("search-final", "default-after")
        ad_hoc = ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
        roster = {
            "prepare": (fixed["PREPARE_ROLES"], application * 2, 2),
            "verify-before": (("verify-before", "verify-before-resident-image", "verify-before-history-provider", "verify-before-github-seal"), (), 0),
            "verify-after": (("verify-after", "verify-after-resident-image", "verify-after-history-provider", "verify-after-github-seal"), (), 0),
            **{phase: ((phase, phase + "-verify"), application, 1) for phase in fixed["SIGNING_PHASES"]},
            "notarize-payload": (fixed["NOTARY_ROLES"], (), 0),
            "finalize-package": (("final-package-productbuild",) + fixed["FINAL_PACKAGE_ROLES"], fixed["INSTALLER_CREDENTIAL_ROSTER"], 1),
            "package-install": (package, ad_hoc + application * 3, 3),
            "finalize-image": (fixed["FINAL_IMAGE_ROLES"], (), 0),
            "finalize-remove-package": (fixed["FINAL_PACKAGE_ROLES"], fixed["INSTALLER_CREDENTIAL_ROSTER"], 1),
            "package-remove": (fixed["REMOVE_PACKAGE_ROLES"], ad_hoc + application * 2, 2),
            "finalize-remove-image": (fixed["FINAL_IMAGE_ROLES"], (), 0),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for phase, (native, credentials, contexts) in roster.items():
                value = receipt(phase); del value["finalImage"]
                value["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
                    "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64} for role in native]
                value["credentialOriginals"] = [{"role": role, "entered": True, "returned": True, "settled": True,
                    "status": 0} for role in credentials]
                value["credentialContexts"] = [{"purpose": "installer", "retired": True, "closed": True,
                    "searchRestored": True, "defaultUnchanged": True} for _ in range(contexts)]
                # Conservative all-allowlisted finite final fields, beyond each
                # genuine sparse writer, plus every actual native/credential row.
                final = {**{key: True for key in DATA.FINAL_BOOLS}, **{key: "c" * 64 for key in DATA.FINAL_HASHES},
                         **{key: 4096 for key in DATA.FINAL_SIZES}, "submissionId": value["notarySubmission"]["id"],
                         "status": "Accepted", "errorCount": 0, "warningCount": 2048, "ticketRowCount": 2048}
                if phase == "notarize-payload":
                    value["payloadNotarization"] = final
                elif phase in ("finalize-package", "finalize-remove-package", "package-install", "package-remove"):
                    value["finalPackage"] = {**final, "schemaVersion": 1, "kind":
                        "mrk-final-remover-package" if "remove" in phase else "mrk-final-installer-package"}
                elif phase in ("finalize-image", "finalize-remove-image"):
                    value["finalImage"] = {**final, "schemaVersion": 1, "kind":
                        "mrk-final-removal-image" if "remove" in phase else "mrk-final-user-image"}
                body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                self.assertLessEqual(len(body), 16384)
                write(root, "android-helper-" + phase + ".json", body)
            for name in DATA.STATUS_FILES:
                write(root, name, b"0\n")
            # Conservative simultaneous maxima (beyond the genuine mutually
            # exclusive failure paths) must still fit alongside full preview.
            normal = normal_diagnostic_data()
            write(root, "normal-ui/build.status", b"70\n")
            for role, path in DATA.UI_DIAGNOSTICS:
                if role == "admission":
                    diagnostic = admission_diagnostic(normal)
                    diagnostic["sourceFrames"] *= 4
                    diagnostic["commands"] *= 16
                    diagnostic["ownerDiagnostic"] = {"reason": "command-failed-or-incomplete", "failureMask": 63}
                    diagnostic["sourceFramesTruncated"] = True
                else:
                    diagnostic = build_diagnostic(normal, "build" if role == "build" else "query")
                    diagnostic["errorCodes"] = [{"stream": "stderr", "domain": "IDETestOperationsObserverErrorDomain",
                        "code": -2147483648 + index} for index in range(8)]
                    diagnostic["queryObservations"] = [{"stream": "stderr", "kind": "dashboard",
                        "observation": "containingSameStaticText", "matches": 5, "exceedsFour": True,
                        "nonAtomic": True} for _ in range(4)]
                    if role == "build":
                        diagnostic["buildFailureReasons"] = [{"stream": stream, "code": code}
                            for stream in ("stdout", "stderr") for code in ("destination-not-found", "no-eligible-destination")]
                        diagnostic["compilerDiagnostics"] = [{"stream": "stderr", "source": "NormalAppUITests.swift",
                            "line": 65535 - index, "column": 4096, "severity": "error",
                            "reasonCodes": ["ambiguous-overload", "missing-argument", "actor-isolation"]} for index in range(4)]
                body = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode()
                self.assertLessEqual(len(body), 4096)
                write(root, path, body)
            stager, helper = removal_data()
            removal = removal_receipt("ordinary", stager, helper, normal_diagnostic_data(removal=True))
            write(root, "android-helper-package-removal-fixture.json", removal)
            diagnostic_data, diagnostic_names = data_contract_diagnostics()
            longest = sorted(diagnostic_names, key=len, reverse=True)[:16]
            failure = data_contract_failure(diagnostic_data, diagnostic_names, failed_names=longest)
            self.assertEqual(len(failure["python"]["failureTests"]), 16)
            write(root, "data-contracts/failure-diagnostics.json", failure)
            write(root, "data-contracts/python.status", b"1\n")
            result = project(root, removal_case="ordinary")
            self.assertEqual(result["dataContractFailure"]["receiptState"], "observed")
            self.assertEqual(len(result["dataContractFailure"]["python"]["failureTests"]), 16)
            for phase in roster:
                self.assertEqual(result["phases"][phase]["receiptState"], "observed", phase)
                self.assertIs(result["phases"][phase]["recordedPassed"], True, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["unclassifiedCount"], 0, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["recordedCount"], len(roster[phase][0]))
            self.assertTrue(all(row["receiptState"] == "observed" for row in result["normalUiBuildDiagnostics"].values()))
            self.assertEqual(result["phases"]["package-removal-fixture"]["originalCalls"]["recordedCount"], 9)
            self.assertEqual(result["phases"]["package-removal-fixture"]["removalFixture"]["case"], "ordinary")
            self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)

    def test_fixed_roster_preserves_originals_and_independent_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = write(root, "source-binding.json", SENTINEL.encode())
            raw_log = write(root, "android-helper-final-image-log.stdout", SENTINEL.encode())
            value = receipt(); value["runAttempt"] = "99"
            original = write(root, "android-helper-finalize-image.json", value)
            before = original.read_bytes()
            write(root, "image-finalization.status", b"13\n")
            result = project(root)
            phase = result["phases"]["finalize-image"]
            self.assertEqual(phase["receiptState"], "refused")
            self.assertNotIn("recordedPassed", phase)
            self.assertEqual(phase["callerStatus"], {"receiptState": "observed", "returncode": 13})
            self.assertEqual(result["statuses"]["package-install.status"], {"receiptState": "absent"})
            self.assertEqual(original.read_bytes(), before)
            self.assertEqual(private.read_bytes(), SENTINEL.encode())
            self.assertEqual(raw_log.read_bytes(), SENTINEL.encode())
            output = root / DATA.OUTPUT
            self.assertNotIn(SENTINEL.encode(), output.read_bytes())
            self.assertNotIn(str(root).encode(), output.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(output.stat().st_size, DATA.OUTPUT_LIMIT)
            self.assertIs(result["diagnosticOnly"], True)
            self.assertIs(result["productReady"], False)
            saved = output.read_bytes()
            with self.assertRaises(FileExistsError):
                project(root)
            self.assertEqual(output.read_bytes(), saved)

    def test_invalid_scalar_statuses_are_never_success(self):
        for body in (b"", b"0", b"00\n", b"True\n", b"0 0 0\n", b"65536\n", b"-65537\n", SENTINEL.encode()):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); write(root, "image-finalization.status", body)
                self.assertEqual(project(root)["statuses"]["image-finalization.status"], {"receiptState": "refused"})

    def test_linked_receipts_and_oversize_inputs_are_not_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = write(root, "unread-private", SENTINEL.encode())
            os.link(original, root / "android-helper-finalize-image.json")
            write(root, "android-helper-finalize-package.json", b"x" * 16385)
            os.symlink("unread-private", root / "android-helper-prepare.json")
            result = project(root)
            for phase in ("prepare", "finalize-package", "finalize-image"):
                self.assertEqual(result["phases"][phase]["receiptState"], "refused")
            self.assertEqual(original.read_bytes(), SENTINEL.encode())

    def test_delivery_projection_excludes_guide_text_and_unknown_fields(self):
        value = {"schemaVersion": 2, "scope": "normal-macos-early-preview", "sourceCommit": CONTEXT["source"],
                 "sourceTree": "4" * 40, "runId": "123", "runAttempt": "2", "platform": "macOS26-arm64",
                 "distributionSha256": "5" * 64, "originalImageFinalizationReturnedZero": True,
                 "guide": SENTINEL, "error": SENTINEL}
        observed = DATA.project_summary(value, CONTEXT, False)
        self.assertNotIn(SENTINEL, json.dumps(observed))
        self.assertIs(observed["originalImageFinalizationReturnedZero"], True)
        self.assertIsNone(observed.get("originalInstallerReturnedZero"))
        value["platform"] = "macOS26-x86_64"
        with self.assertRaises(DATA.Refused):
            DATA.project_summary(value, CONTEXT, False)

    def test_genuine_destination_table_projection_preserves_partial_observations_only(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        good = b'{ platform:macOS, arch:x86_64, name:' + SENTINEL.encode() + b' }\n'
        for raw in (b'', header, header + good, header + b'{ platform:iOS, name:unknown }\n',
                    header + b'{ platform:macOS }\n', header + good * 9,
                    header + good.rstrip(b'\n')):
            original = CompletedProcess([], 70, raw, b'')
            value = normal["normal_failure_diagnostics"]("build", None, original)
            row = DATA.project_ui_diagnostic(value, "build", status)
            self.assertEqual(row["destinationTable"], value["destinationTable"])
            self.assertEqual(row["originalReturncode"], 70)
            self.assertEqual(row["binding"], "same-work-root-parent-context-only")
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertNotIn(SENTINEL, json.dumps(row))
        value = normal["failure_base"]("build", None, CompletedProcess([], 70, b'', b''))
        self.assertEqual(DATA.project_ui_diagnostic(value, "build", status)["destinationTable"]["state"], "unavailable")
        value.pop("destinationTable")
        self.assertNotIn("destinationTable", DATA.project_ui_diagnostic(value, "build", status))

    def test_destination_table_public_schema_is_optional_typed_and_closed(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        original = CompletedProcess([], 70, b'Available destinations for the "MRKNormalAppUI" scheme:\n'
            b'{ platform:macOS, name:Any Mac }\n', b'')
        value = normal["normal_failure_diagnostics"]("build", None, original)
        table = value["destinationTable"]
        row = table["rows"][0]
        for key, bad in (("stream", SENTINEL), ("stream", True), ("section", SENTINEL), ("section", 1),
                         ("platform", "iOS"), ("platform", None), ("architecture", "i386"), ("architecture", False),
                         ("errorPresent", 1), ("errorPresent", None), ("name", SENTINEL)):
            broken = copy.deepcopy(value); broken["destinationTable"]["rows"] = [{**row, key: bad}]
            with self.subTest(key=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "build", status)
        for bad in (None, [], {}, {**table, "state": SENTINEL}, {**table, "state": True},
                    {**table, "state": "absent"}, {**table, "state": "unavailable"},
                    {**table, "rows": [row] * 9}, {**table, "rows": [None]}, {**table, "rows": None},
                    {**table, "unknownRowObserved": 1}, {**table, "malformedRowObserved": None},
                    {**table, "rowsTruncated": 1}, {**table, "rowsTruncated": True},
                    {**table, "complete": True}, {**table, "error": SENTINEL}):
            broken = copy.deepcopy(value); broken["destinationTable"] = bad
            with self.subTest(table=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "build", status)
        for state in ("absent", "unavailable"):
            for flag in ("unknownRowObserved", "malformedRowObserved", "rowsTruncated"):
                broken = copy.deepcopy(value); broken["findingsTruncated"] = True
                broken["destinationTable"] = {**table, "state": state, "rows": [], flag: True}
                with self.subTest(state=state, flag=flag), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(broken, "build", status)
        query = build_diagnostic(normal, "query"); query["destinationTable"] = table
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(query, "toolchain", status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": 0})

    def test_destination_table_fixed_file_projection_keeps_full_eight_rows_and_status70(self):
        normal = normal_diagnostic_data()
        header = b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        raw = header + (b'{ platform:macOS, arch:arm64, id:' + SENTINEL.encode()
                        + b', name:Private Mac, error:' + SENTINEL.encode() + b' }\n') * 8
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, b'', raw))
        self.assertEqual(len(value["destinationTable"]["rows"]), 8)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write(root, "normal-ui/build.failure-diagnostics.json", value)
            before = path.read_bytes()
            self.assertLessEqual(len(before), 4096)
            write(root, "normal-ui/build.status", b"70\n")
            result = project(root)
            observed = result["normalUiBuildDiagnostics"]["build"]
            self.assertEqual(observed["receiptState"], "observed")
            self.assertEqual(observed["destinationTable"], value["destinationTable"])
            self.assertEqual(observed["originalReturncode"], 70)
            self.assertIs(observed["nativeSuccessInferred"], False)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
            self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)


    def test_data_contract_failure_genuine_python_rows_and_context(self):
        data, names = data_contract_diagnostics()
        self.assertEqual(DATA.DATA_CONTRACT_TEST_IDS, tuple(names))
        self.assertEqual(DATA.DATA_CONTRACT_GUARDS, set(data["DATA_FAILURE_GUARDS"].values()) | {"unclassified"})
        failures = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in names]
        errors = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in names]
        unknown = (SimpleNamespace(id=lambda: names[0] + " (private=" + SENTINEL + ")"), SENTINEL)
        facts = dict(testsRun=84, failures=85, errors=84, skipped=0, expectedFailures=0, unexpectedSuccesses=0,
            actualHostBeforeAndAfter=False, testIds=names,
            **data["data_failed_test_rows"](failures + [unknown], errors, names))
        value = data_contract_failure(data, names, raw=json.dumps(facts).encode())
        row = DATA.project_data_contract_failure(value, CONTEXT, {
            "data-contracts/python.status": {"receiptState": "observed", "returncode": 1}}, set())
        self.assertEqual(row["python"], value["python"])
        self.assertEqual((len(row["python"]["failureTests"]), row["python"]["classifiedTestCount"],
                          row["python"]["omittedTestCount"], row["python"]["unclassifiedTestCount"]), (16, 168, 152, 1))
        self.assertIs(row["python"]["actualHostBeforeAndAfter"], False)
        self.assertIs(row["statusMatched"], True)
        self.assertIs(row["nativeSuccessInferred"], False)
        self.assertEqual(row["binding"], "same-source-run-target-context")
        self.assertNotIn(SENTINEL, json.dumps(row))
        for key in ("source", "workflowSource", "runId", "runAttempt", "target"):
            broken = copy.deepcopy(value); broken[key] = "2" * 40 if key.endswith("ource") else "wrong"
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, {}, set())

    def test_data_contract_failure_phase_capture_and_scalar_observations(self):
        data, names = data_contract_diagnostics()
        for phase in DATA.DATA_CONTRACT_PHASES:
            for code in (-15, 0, 1):
                value = data_contract_failure(data, names, phase=phase, code=code, guard="source-post", failed_names=[])
                status_name = "data-contracts/" + phase + ".status"
                for state in ("observed", "absent", "refused"):
                    status = {"receiptState": state, **({"returncode": code} if state == "observed" else {})}
                    row = DATA.project_data_contract_failure(value, CONTEXT, {status_name: status}, set())
                    self.assertEqual(row["originalReturncode"], code)
                    self.assertEqual(row["callerStatus"], status)
                    self.assertIs(row["statusMatched"], True if state == "observed" else None)
                    self.assertIs(row["nativeSuccessInferred"], False)
                with self.assertRaises(DATA.Refused):
                    DATA.project_data_contract_failure(value, CONTEXT, {
                        status_name: {"receiptState": "observed", "returncode": code + 1}}, set())
        complete = data_contract_failure(data, names)
        for flag, observed in (("originalReturned", False), ("outputComplete", False), ("captureClosed", False),
                               ("timedOut", True), ("outputOverflow", True)):
            value = data_contract_failure(data, names, code=None if flag == "originalReturned" else 1, flags={flag: observed})
            row = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
            self.assertIsNone(row["python"])
            self.assertIs(row[flag], observed)
            self.assertIsNone(row["statusMatched"])
            value["python"] = complete["python"]
            with self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_cargo_sources_require_validated_inventory(self):
        data, names = data_contract_diagnostics()
        path = "desktop/src-tauri/src/bin/macos_install.rs"
        def message(name, code="E0123", line=12):
            return {"reason": "compiler-message", "manifest_path": "/public/checkout/desktop/src-tauri/Cargo.toml",
                "message": {"level": "error", "message": SENTINEL, "rendered": SENTINEL, "code": {"code": code},
                    "spans": [{"is_primary": True, "file_name": name, "line_start": line, "column_start": 7}]}}
        raw = b"\n".join(json.dumps(message("src/bin/macos_install.rs", "E%04d" % index)).encode() for index in range(8))
        value = data_contract_failure(data, names, phase="build", raw=raw, source_paths={path})
        inventory = {"source": CONTEXT["source"], "tree": "2" * 40, "files": [
            {"path": path, "gitMode": "100644", "blob": "3" * 40, "size": 1, "sha256": "4" * 64}]}
        paths = set()
        DATA.project_inventory(inventory, json.dumps(inventory).encode(), CONTEXT, collect_paths=paths)
        row = DATA.project_data_contract_failure(value, CONTEXT, {}, paths)
        self.assertEqual(len(row["cargo"]["errors"]), 8)
        self.assertTrue(all(error["source"] == path for error in row["cargo"]["errors"]))
        self.assertNotIn(SENTINEL, json.dumps(row))
        redacted = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        self.assertTrue(all(error["source"] is error["line"] is error["column"] is None for error in redacted["cargo"]["errors"]))
        self.assertEqual([error["code"] for error in redacted["cargo"]["errors"]], ["E%04d" % n for n in range(8)])
        broken_inventory = copy.deepcopy(inventory)
        broken_inventory["files"].append({**inventory["files"][0], "path": "other", "sha256": SENTINEL})
        paths = set()
        with self.assertRaises(DATA.Refused):
            DATA.project_inventory(broken_inventory, b"synthetic", CONTEXT, collect_paths=paths)
        self.assertEqual(paths, set())  # Earlier valid row cannot escape failed whole-inventory validation.
        other = "desktop/src-tauri/src/other.rs"
        raw = b"\n".join(json.dumps(message(name)).encode() for name in (path, other))
        value = data_contract_failure(data, names, phase="build", raw=raw, source_paths={path, other})
        row = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        self.assertEqual(len(row["cargo"]["errors"]), 2)
        self.assertEqual(row["cargo"]["errors"][0], row["cargo"]["errors"][1])  # No post-redaction dedup/count invention.
        value["cargo"]["errors"][1] = copy.deepcopy(value["cargo"]["errors"][0])
        with self.assertRaises(DATA.Refused):
            DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_closed_schema_and_bounds(self):
        data, names = data_contract_diagnostics()
        base = data_contract_failure(data, names)
        for key in base:
            value = copy.deepcopy(base); del value[key]
            with self.subTest(missing=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        for key, bad in (("schemaVersion", True), ("kind", SENTINEL), ("phase", None), ("phase", "other"),
                         ("originalReturncode", True), ("originalReturncode", 65536), ("originalReturncode", None),
                         ("originalReturned", 1), ("outputComplete", None), ("captureClosed", 0), ("timedOut", 1),
                         ("outputOverflow", 1), ("stdoutBytes", True), ("stderrBytes", 4194305),
                         ("stdoutSha256", SENTINEL), ("guardCode", SENTINEL), ("diagnosticOnly", False),
                         ("productReady", True), ("message", SENTINEL), ("cargo", {})):
            value = copy.deepcopy(base); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        for key, bad in (("testsRun", 85), ("errors", True), ("actualHostBeforeAndAfter", 1),
                         ("classifiedTestCount", 169), ("omittedTestCount", 153), ("unclassifiedTestCount", 65536),
                         ("classifiedTestCount", 0), ("failures", 0), ("extra", SENTINEL),
                         ("failureTests", [{"kind": "failure", "id": SENTINEL}]),
                         ("failureTests", [{"kind": "other", "id": names[0]}]),
                         ("failureTests", base["python"]["failureTests"] * 17),
                         ("failureTests", base["python"]["failureTests"] * 2)):
            value = copy.deepcopy(base); value["python"][key] = bad
            with self.subTest(python=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        value = copy.deepcopy(base); value["python"] = None
        self.assertIsNone(DATA.project_data_contract_failure(value, CONTEXT, {}, set())["python"])
        value["python"] = {}
        with self.assertRaises(DATA.Refused):
            DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        cargo = data_contract_failure(data, names, phase="build")
        good = {"code": "E0001", "source": None, "line": None, "column": None}
        cargo["cargo"] = {"errors": [good], "unclassifiedErrors": 0, "omittedErrors": 0}
        for bad in ({"errors": [good] * 9, "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [good], "unclassifiedErrors": 4097, "omittedErrors": 0},
                    {"errors": [{**good, "code": SENTINEL}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "line": 1}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "source": "/private/file", "line": 1, "column": 1}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "source": "public/file", "line": True, "column": 1}], "unclassifiedErrors": 0, "omittedErrors": 0}):
            value = copy.deepcopy(cargo); value["cargo"] = bad
            with self.subTest(cargo=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_fixed_files_preserve_originals(self):
        data, names = data_contract_diagnostics()
        value = data_contract_failure(data, names, code=0, guard="source-post", failed_names=[])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar = write(root, "data-contracts/failure-diagnostics.json", value)
            raw = [write(root, name, SENTINEL.encode()) for name in
                   ("data-contracts/result.json", "data-contracts/python.stdout", "data-contracts/python.stderr")]
            before = [path.read_bytes() for path in [sidecar] + raw]
            write(root, "data-contracts/python.status", b"0\n")
            result = project(root)
            row = result["dataContractFailure"]
            self.assertEqual(row["receiptState"], "observed")
            self.assertEqual(row["originalReturncode"], 0)
            self.assertIs(row["statusMatched"], True)
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual([path.read_bytes() for path in [sidecar] + raw], before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
        for raw in (b"{}", b"x" * 16385, b'{"schemaVersion":1,"schemaVersion":1}'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); write(root, "data-contracts/failure-diagnostics.json", raw)
                self.assertEqual(project(root)["dataContractFailure"], {"receiptState": "refused"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = write(root, "data-contracts/failure-diagnostics.json", SENTINEL.encode())
            result = DATA.project(str(root), profile="aqua", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"])
            self.assertIsNone(result["dataContractFailure"])
            self.assertEqual(path.read_bytes(), SENTINEL.encode())



if __name__ == "__main__":
    unittest.main()
