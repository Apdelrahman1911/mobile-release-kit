"""Inert DATA/privacy tests; never native tools, secret inputs or Apple requests."""
import ast
import copy
import hashlib
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


def project(root):
    return DATA.project(str(root), profile="installed", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                        run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"])


def normal_diagnostic_data():
    """Compile only genuine DATA writers/constants, never import the native runner.

    CompletedProcess is only an inert record constructor; no subprocess runner
    or native-owner namespace is exposed. The optional output-DATA resultPost
    branch is outside these build/query fixtures and is never entered.
    """
    path = ROOT / "desktop/tools/macos_normal_ui_runner.py"
    names = {"Refused", "need", "sha", "pairs", "document", "encoded", "failure_base",
        "normal_failure_diagnostics", "classify_normal_admission_failure", "NORMAL_SELECTIONS", "OUTPUT_DATA_RESULT",
        "IOS_UNSIGNED_RESULT", "IOS_UNSIGNED_METHOD", "LOADER", "TOOLCHAIN_QUERIES", "ADMISSION_STAGES",
        "ADMISSION_EXCEPTION_TYPES", "ADMISSION_EXCEPTION_LABELS", "ADMISSION_SOURCE_FILES", "ADMISSION_COMMAND_ROLES"}
    nodes, found = [], set()
    for node in ast.parse(path.read_text()).body:
        name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in names:
            nodes.append(node); found.add(name)
    if found != names:
        raise AssertionError("finite-normal-diagnostic-DATA-dependencies")
    namespace = {"hashlib": hashlib, "json": json, "re": re, "Path": Path,
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


class PublicVerificationEvidenceData(unittest.TestCase):
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
            for key in base.keys() - {"buildFailureReasons"}:
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
            result = project(root)
            for phase in roster:
                self.assertEqual(result["phases"][phase]["receiptState"], "observed", phase)
                self.assertIs(result["phases"][phase]["recordedPassed"], True, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["unclassifiedCount"], 0, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["recordedCount"], len(roster[phase][0]))
            self.assertTrue(all(row["receiptState"] == "observed" for row in result["normalUiBuildDiagnostics"].values()))
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


if __name__ == "__main__":
    unittest.main()
