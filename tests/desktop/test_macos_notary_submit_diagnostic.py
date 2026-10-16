"""Passive same-original notarization diagnostics; no Apple or native execution."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HELPER = load("notary_submit_helper_data", "macos_android_helper_package.py")
PUBLIC = load("notary_submit_public_data", "macos_public_verification_evidence.py")
PRIVATE = b"PRIVATE_SENTINEL_/secret/key.p8-password-no-export"


class NotarySubmitDiagnosticTests(unittest.TestCase):
    def test_bounded_lexical_facts_keep_unknown_conflict_and_private_text(self):
        cases = ((b"", "empty", "none", "unclassified"),
            (b"HTTP status code: 401", "bounded-utf8", "single-known", "http-authentication"),
            (b"NSURLErrorDomain Code=-1001", "bounded-utf8", "single-known", "network-timeout"),
            (b"HTTP status 401; HTTP status 999", "bounded-utf8", "unrecognized", "unclassified"),
            (b"HTTP status 401; HTTP status 401", "bounded-utf8", "multiple-or-conflicting", "unclassified"),
            (b"HTTP status 403; NSURLErrorDomain Code=-1004", "bounded-utf8", "multiple-or-conflicting", "unclassified"),
            (b"NSURLErrorDomain Code=99999999999999999999999", "bounded-utf8", "unrecognized", "unclassified"),
            (b"HTTP status code=not-a-number", "bounded-utf8", "unrecognized", "unclassified"),
            (b"HTTP status 401999999999999999999999", "bounded-utf8", "unrecognized", "unclassified"),
            (b"response 401; someURL Code=-1001", "bounded-utf8", "none", "unclassified"),
            (b"prefixHTTP status 401", "bounded-utf8", "none", "unclassified"),
            (b"HTTP status 401\xff", "invalid-utf8", "unrecognized", "unclassified"),
            (b"HTTP" + b" " * 60000 + b"status 401", "bounded-utf8", "single-known", "http-authentication"),
            (b"x" * 65536, "bounded-utf8", "none", "unclassified"))
        for body, form, state, error in cases:
            with self.subTest(form=form, state=state, error=error):
                value = HELPER.notary_submit_diagnostic(body)
                self.assertEqual((value["formatClass"], value["lexicalState"], value["errorClass"]), (form, state, error))
                self.assertEqual(value["stderrSha256"], hashlib.sha256(body).hexdigest())
                self.assertFalse(value["nativeSuccessInferred"])
        for prefix in (b"HTTP status code: 503\n", b"unrecognized error\n", b"\xff"):
            value = HELPER.notary_submit_diagnostic(prefix + PRIVATE)
            self.assertNotIn(PRIVATE.decode(), str(value))
        # Incremental decoder must handle a valid multibyte character crossing a chunk boundary.
        self.assertEqual(HELPER.notary_submit_diagnostic(b"x" * 511 + "€".encode())["formatClass"], "bounded-utf8")
        value = HELPER.notary_submit_diagnostic(b"HTTP status 401\n" * 17)
        self.assertEqual(len(value["matches"]), 16)
        self.assertTrue(value["matchesTruncated"])
        self.assertEqual(value["lexicalState"], "multiple-or-conflicting")
        for body in (b"x" * 65537, PRIVATE.decode()):
            with self.assertRaises(HELPER.Refused):
                HELPER.notary_submit_diagnostic(body)

    def test_actual_call_hook_requires_same_return_and_settled_publications(self):
        argv = ["fixed-notarytool", "submit", "fixed-fixture.zip"]
        for fault in (None, "return-zero", "owner-error", "publish-error"):
            published, invoked = {}, []
            def owned(actual, **kwargs):
                invoked.append(tuple(actual))
                if fault == "owner-error":
                    raise RuntimeError("synthetic-unsettled-original")
                return subprocess.CompletedProcess(actual, 0 if fault == "return-zero" else 1,
                    b"", b"NSURLErrorDomain Code=-1003\n" + PRIVATE)
            def publish(name, body):
                if fault == "publish-error":
                    raise RuntimeError("synthetic-unsettled-output")
                published[name] = body
            op = SimpleNamespace(phase="notarize-payload", credential_known=lambda: True,
                credential_failed=False, credential_active=None, removal_final_active=lambda: False,
                notary_retiring=False, notary_unknown=False, errors=[], stager_io_pending=None,
                calls=[{"role": role, "returned": True, "capturesSettled": True} for role in HELPER.NOTARY_ROLES[:5]],
                notary_mutation_pending=False, notary_clock=lambda: None, android_support=None, store_signing=None,
                app_absence=None, update=None, removal=False, removal_recorded_role=lambda role: role,
                owner=SimpleNamespace(run_owned=owned), work=Path("/synthetic-unopened-work"),
                checkout=Path("/synthetic-unopened-source"), publish=publish)
            if fault == "return-zero":
                HELPER.Operation.call(op, "payload-submit", argv, {}, cwd=op.work, timeout=20, limit=65536)
            else:
                with self.assertRaises(HELPER.Refused if fault is None else RuntimeError) as failure:
                    HELPER.Operation.call(op, "payload-submit", argv, {}, cwd=op.work, timeout=20, limit=65536)
            self.assertEqual(invoked, [tuple(argv)])
            row = op.calls[-1]
            self.assertEqual("notarySubmitDiagnostic" in row, fault is None)
            if fault is None:
                self.assertTrue(row["capturesSettled"])
                self.assertEqual(row["returncode"], 1)
                self.assertEqual(row["notarySubmitDiagnostic"]["errorClass"], "network-dns")
                self.assertNotIn(PRIVATE.decode(), str(row))
                self.assertEqual(len(published), 3)
                self.assertEqual(HELPER.failure_exception(failure.exception)["reason"],
                                 "original-nonzero-payload-submit")

    def test_log_parser_failures_and_invalid_submission_have_finite_distinct_diagnostics(self):
        private = PRIVATE.decode()
        submission_id = "11111111-2222-3333-4444-555555555555"
        log = {"logFormatVersion": 1, "jobId": submission_id, "status": "Accepted",
            "archiveFilename": HELPER.NOTARY_ZIP_NAME, "issues": None, "ticketContents": None}
        encode = lambda value: json.dumps(value).encode("ascii")
        cases = (
            ("Invalid", encode(dict(log, status="Invalid")), "notary-submission-invalid"),
            ("Accepted", encode(dict(log, archiveFilename=private)), "notary-log-binding"),
            ("Accepted", encode(dict(log, statusCode=1)), "notary-log-status-code"),
            ("Accepted", encode(dict(log, ticketContents=[{"path": private, "arch": None,
                "digestAlgorithm": "SHA-256", "cdhash": "a" * 40}])), "notary-log-ticket-shape"),
            ("Accepted", encode(dict(log, issues=[{"severity": "error", "path": private,
                "message": private}])), "notary-log-success-with-errors"),
            ("Accepted", b'{"logFormatVersion":1,"logFormatVersion":1}', "notary-json-format"),
            ("Accepted", b'{' + PRIVATE, "notary-json-format"),
        )
        for status, body, reason in cases:
            with self.subTest(reason=reason):
                submission = HELPER.notary_submit_data(encode({"id": submission_id, "status": status}))
                with self.assertRaises(HELPER.Refused) as failure:
                    HELPER.notary_log_data(body, submission, "a" * 64)
                    # Same terminal Invalid refusal after an otherwise valid
                    # log; this passive fixture grants no owner/finality facts.
                    HELPER.need(submission["status"] != "Invalid", "notary-submission-invalid")
                captured = HELPER.failure_exception(failure.exception)
                self.assertEqual(captured["reason"], reason)
                operation = object.__new__(HELPER.Operation)
                operation.__dict__.update(receipt={"failure": {"stage": "payload-log", "reason": reason},
                    "notarySubmission": submission, "private": private, "passed": False},
                    diagnostic_failure=captured, calls=[{"role": role, "entered": True, "returned": True,
                        "capturesSettled": True, "returncode": 0, "stdout": body, "argv": [private]}
                        for role in HELPER.notary_roles(True)[:8]], credential_calls=[], credential_contexts=[], errors=[])
                before = copy.deepcopy(operation.__dict__)
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    HELPER.emit_failure_diagnostic(HELPER.Refused("helper-package-incomplete"),
                        phase="notarize-payload", target=HELPER.ARM_TARGET,
                        main_stage="operation-execute", operation=operation)
                encoded = output.getvalue()
                value = json.loads(encoded)
                self.assertEqual(value["terminal"]["reason"], "helper-package-incomplete")
                self.assertEqual((value["originalFailure"]["stage"], value["originalFailure"]["reason"]),
                                 ("payload-log", reason))
                self.assertEqual((value["lastRecordedNative"]["role"], value["lastRecordedNative"]["returncode"],
                    value["counts"]["native"]), ("payload-log", 0, 8))
                self.assertTrue(value["diagnosticOnly"])
                self.assertFalse(value["productReady"])
                self.assertLessEqual(len(encoded.encode("ascii")), 4096)
                for forbidden in (private, submission_id, "notarySubmission", "stdout", "argv"):
                    self.assertNotIn(forbidden, encoded)
                self.assertEqual(operation.__dict__, before)
        # No prefix-based admission of a notary-looking private value.
        unknown = "notary-log-" + private
        operation = object.__new__(HELPER.Operation)
        operation.__dict__.update(receipt={"failure": {"stage": unknown, "reason": unknown}},
            diagnostic_failure=HELPER.failure_exception(HELPER.Refused(unknown)), calls=[{"role": unknown}])
        value = HELPER.failure_diagnostic(HELPER.Refused(unknown), operation=operation)
        self.assertEqual(value["terminal"]["reason"], "unclassified")
        self.assertEqual(value["originalFailure"]["stage"], "unclassified")
        self.assertEqual(value["originalFailure"]["reason"], "unclassified")
        self.assertEqual(value["lastRecordedNative"]["role"], "unclassified")
        self.assertNotIn(private, json.dumps(value))

    def test_public_projection_binds_diagnostic_to_failed_original_not_success(self):
        body = b"HTTP status code: 429\n" + PRIVATE
        value = HELPER.notary_submit_diagnostic(body)
        row = {"role": "payload-submit", "entered": True, "returned": True, "capturesSettled": True,
            "returncode": 1, "stdoutSha256": hashlib.sha256(b"").hexdigest(),
            "stderrSha256": hashlib.sha256(body).hexdigest(), "notarySubmitDiagnostic": value}
        actual = PUBLIC.project_calls([row])["calls"][0]
        self.assertEqual(actual["notarySubmitDiagnostic"], value)
        self.assertNotIn(PRIVATE.decode(), str(actual))
        old = {key: item for key, item in row.items() if key != "notarySubmitDiagnostic"}
        self.assertNotIn("notarySubmitDiagnostic", PUBLIC.project_calls([old])["calls"][0])
        corruptions = (("stderrSha256", "a" * 64), ("stderrBytes", True), ("formatClass", "empty"),
            ("errorClass", "http-authentication"), ("matches", [PRIVATE.decode()]),
            ("matchesTruncated", True), ("nativeSuccessInferred", True), ("schemaVersion", True))
        for key, item in corruptions:
            bad = copy.deepcopy(row); bad["notarySubmitDiagnostic"][key] = item
            projected = PUBLIC.project_calls([bad])["calls"][0]
            self.assertEqual(projected["returncode"], 1)
            self.assertEqual(projected["notarySubmitDiagnostic"]["receiptState"], "refused")
            self.assertNotIn(PRIVATE.decode(), str(projected))
        for key, item in (("role", "payload-log"), ("returncode", 0), ("entered", False),
                          ("returned", False), ("capturesSettled", False), ("stderrSha256", "a" * 64)):
            bad = dict(row, **{key: item})
            self.assertEqual(PUBLIC.project_calls([bad])["calls"][0]["notarySubmitDiagnostic"]["receiptState"], "refused")
