"""Inert DATA/privacy tests; never native tools, secret inputs or Apple requests."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
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


class PublicVerificationEvidenceData(unittest.TestCase):
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
            result = project(root)
            for phase in roster:
                self.assertEqual(result["phases"][phase]["receiptState"], "observed", phase)
                self.assertIs(result["phases"][phase]["recordedPassed"], True, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["unclassifiedCount"], 0, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["recordedCount"], len(roster[phase][0]))
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
