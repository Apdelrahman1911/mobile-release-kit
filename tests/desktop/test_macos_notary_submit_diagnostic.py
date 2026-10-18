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


class StagerFailureLocationTests(unittest.TestCase):
    def test_actual_stager_location_is_private_and_not_filename_only(self):
        stager = load("failure_location_stager", "stage_macos_installed.py")
        # Actual first readback guard; no filesystem/native operations entered.
        try:
            stager.observation_command(SimpleNamespace(), expected_previous={"private": PRIVATE})
        except stager.Refused as error:
            location = HELPER.failure_stager_line(error, stager)
            trace = error.__traceback__
            while trace.tb_frame.f_code is not stager.observation_command.__code__:
                trace = trace.tb_next
            self.assertEqual(location, trace.tb_lineno)
            self.assertIsNone(HELPER.failure_stager_line(error, None))
        else:
            self.fail("original readback refusal was not raised")
        # Shared exact-shape guard must locate its schema caller, not the same
        # maintenance_map line for every unrelated installed-record mismatch.
        try:
            stager.maintenance_release_data({}, stager.ARM_TARGET)
        except stager.Refused as error:
            trace = error.__traceback__
            while trace.tb_frame.f_code is not stager.maintenance_release_data.__code__:
                trace = trace.tb_next
            self.assertEqual(HELPER.failure_stager_line(error, stager), trace.tb_lineno)
        else:
            self.fail("original shape refusal was not raised")
        # A matching co_filename alone must not attribute outside code to stager.
        outside = {"Refused": stager.Refused, "private": PRIVATE.decode()}
        try:
            exec(compile("raise Refused(private)", stager.__file__, "exec"), outside)
        except stager.Refused as error:
            self.assertIsNone(HELPER.failure_stager_line(error, stager))
        self.assertIsNone(HELPER.failure_stager_line(ValueError(PRIVATE.decode()), stager))
        op = object.__new__(HELPER.Operation)
        op.__dict__.update(stager_failure_line=location)
        for value in (location, True, 0, 100001, PRIVATE.decode()):
            op.stager_failure_line = value
            projected = HELPER.failure_diagnostic(HELPER.Refused("helper-package-incomplete"), operation=op)
            self.assertEqual(projected["originalFailure"]["stagerLine"], location if value == location else None)
            self.assertNotIn(PRIVATE.decode(), json.dumps(projected))


class NotarySubmitDiagnosticTests(unittest.TestCase):
    def test_final_input_refusals_are_distinct_without_exporting_private_values(self):
        stager = load("notary_final_stager_data", "stage_macos_installed.py")
        for reason in ("applications-launcher-file", "applications-launcher-installed-correspondence",
                       "ticket-input-correspondence", "signed-app-roster", PRIVATE.decode()):
            with self.subTest(public=reason != PRIVATE.decode()):
                error = stager.Refused(reason)
                captured = HELPER.failure_exception(error, stager)
                self.assertEqual(captured["type"], "stager-refused")
                self.assertEqual(captured["reason"], "unclassified" if reason == PRIVATE.decode() else reason)
                self.assertNotIn(PRIVATE.decode(), json.dumps(captured))
        # The same text in an unrelated exception never borrows the stager label.
        self.assertEqual(HELPER.failure_exception(ValueError("applications-launcher-file"), stager)["reason"],
                         "unclassified")

        # A successful Installer is not a successful observation/readback.
        # Keep only the fixed baseline ValueError guard, without rendering it.
        for reason in (
            "app-absence-phase-output-bound", "app-absence-phase-marker-count",
            "app-absence-phase-marker-missing", "app-absence-phase-marker-duplicate",
            "app-absence-phase-marker-shape", "app-absence-phase-canonical-json",
            "app-absence-phase-observation", "app-absence-phase-proof",
            "app-absence-baseline-original", "app-absence-baseline-original-post",
            "app-absence-baseline-binding", "app-absence-baseline-identity",
            "app-absence-baseline-parent-original", "app-absence-baseline-volume",
        ):
            error = ValueError(reason)
            captured = HELPER.failure_exception(error, stager)
            self.assertEqual(captured, {"type": "value-error", "reason": reason, "errno": None})
            op = object.__new__(HELPER.Operation)
            op.__dict__.update(receipt={"failure": {"stage": "owned-directory-admission"},
                "originalClosesKnown": False, "targetRetired": False},
                diagnostic_failure=captured, calls=[{"role": "app-absence-baseline",
                    "returncode": 0, "entered": True, "returned": True, "capturesSettled": True}])
            before = copy.deepcopy(op.__dict__)
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                HELPER.emit_failure_diagnostic(error, operation=op, phase="candidate-baseline", stager=stager)
            value = json.loads(output.getvalue())
            self.assertEqual(value["terminal"], captured)
            self.assertEqual(value["originalFailure"]["reason"], reason)
            self.assertEqual(value["lastRecordedNative"]["returncode"], 0)
            self.assertFalse(value["productReady"])
            self.assertFalse(value["cleanup"]["originalClosesKnown"])
            self.assertFalse(value["cleanup"]["targetRetired"])
            self.assertLessEqual(len(output.getvalue().encode()), 4096)
            self.assertEqual(op.__dict__, before)
            self.assertEqual(error.args, (reason,))
        class PrivateArgument:
            def __str__(self): raise AssertionError("private argument rendered")
        class ForeignValueError(ValueError):
            def __str__(self): raise AssertionError("private exception rendered")
        class TextSubclass(str): pass
        reason = "app-absence-phase-marker-count"
        for error in (ValueError(PRIVATE.decode()), ValueError(reason + PRIVATE.decode()),
                      ValueError(PrivateArgument()), ValueError(reason, PRIVATE.decode()),
                      ValueError(TextSubclass(reason)), ForeignValueError(reason), TypeError(reason)):
            value = HELPER.failure_exception(error, stager)
            self.assertEqual(value["reason"], "unclassified")
            self.assertNotIn(PRIVATE.decode(), json.dumps(value))

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
            ("Accepted", encode(dict(log, ticketContents=[{"path": private, "arch": True,
                "digestAlgorithm": "SHA-256", "cdhash": "a" * 40}])), "notary-log-ticket-architecture"),
            ("Accepted", encode(dict(log, ticketContents=[{"path": private + "\n", "arch": None,
                "digestAlgorithm": "SHA-256", "cdhash": "a" * 40}])), "notary-log-ticket-path"),
            ("Accepted", encode(dict(log, ticketContents=[{"path": private, "arch": None,
                "digestAlgorithm": private, "cdhash": "a" * 40}])), "notary-log-ticket-digest-algorithm"),
            ("Accepted", encode(dict(log, ticketContents=[{"path": private, "arch": None,
                "digestAlgorithm": "SHA-256", "cdhash": private}])), "notary-log-ticket-digest"),
            ("Accepted", encode(dict(log, ticketContents=[{"path": private}])), "notary-log-ticket-shape"),
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

    def test_invalid_log_issue_diagnostic_is_bounded_private_and_never_finality(self):
        op = object.__new__(HELPER.Operation)
        op.__dict__.update(receipt={}, calls=[], credential_calls=[], credential_contexts=[], errors=[])
        private = PRIVATE.decode()
        issues = [{"severity": "error", "message": "The binary is not signed.", "code": None,
            "path": private + "/store/cache/terminal-notifier-2.0.0.gem/terminal-notifier.app/binary"}]
        body = json.dumps({"issues": issues}).encode()
        HELPER.Operation.capture_notary_failure(op, body)
        before = copy.deepcopy(op.__dict__)
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            HELPER.emit_failure_diagnostic(HELPER.Refused("notary-submission-invalid"),
                phase="notarize-payload", target=HELPER.ARM_TARGET, operation=op)
        exported = out.getvalue()
        value = json.loads(exported)
        self.assertEqual(value["terminal"]["reason"], "notary-submission-invalid")
        self.assertFalse(value["productReady"])
        self.assertEqual(value["notaryIssues"]["rows"], [{"severity": "error", "code": None,
            "category": "unsigned-binary", "component": "optional-terminal-notifier-cache", "count": 1}])
        self.assertNotIn(private, exported)
        self.assertLessEqual(len(exported), 4096)
        self.assertEqual(op.__dict__, before)
        for malformed in (b"{", b"x" * (1024 * 1024 + 1),
                json.dumps({"issues": [{"severity": "error", "path": private, "message": private,
                    "code": True}]}).encode()):
            HELPER.Operation.capture_notary_failure(op, malformed)
            self.assertEqual(op.__dict__, before)
        many = [dict(issues[0], code=i) for i in range(9)]
        HELPER.Operation.capture_notary_failure(op, json.dumps({"issues": many}).encode())
        bounded = HELPER.failure_diagnostic(HELPER.Refused("notary-submission-invalid"), operation=op)
        self.assertEqual(len(bounded["notaryIssues"]["rows"]), 8)
        self.assertTrue(bounded["notaryIssues"]["rowsOmitted"])
        good = copy.deepcopy(op.notary_issue_diagnostic)
        for field, bad in (("category", private), ("component", private), ("severity", private),
                ("count", True), ("code", private), ("path", private)):
            op.notary_issue_diagnostic = copy.deepcopy(good)
            op.notary_issue_diagnostic["rows"][0][field] = bad
            output = HELPER.failure_diagnostic(HELPER.Refused("notary-submission-invalid"), operation=op)
            self.assertIsNone(output["notaryIssues"])
            self.assertNotIn(private, json.dumps(output))
        # Unknown strings are never copied into the closed category vocabulary.
        self.assertEqual(HELPER.notary_issue_summary([dict(issues[0], message=private)])[0]["category"],
                         "unclassified")
        for excessive in ([issues[0]] * 2049, [dict(issues[0], code=i) for i in range(65)]):
            with self.assertRaises(HELPER.Refused): HELPER.notary_issue_summary(excessive)

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


class InstallerFailureDiagnosticTests(unittest.TestCase):
    def operation(self, *, code=1, publish_error=False):
        self.publications = {}
        self.invocations = []
        self.capture = (b'MRK_MACOS_POSTINSTALL_PHASE=pre-exec\n'
            b'MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=acl-entry-present;'
            b'result=1;call=0;errno=0;freeCall=0;freeErrno=0\n'
            b'MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + b'a' * 64 +
            b';exit=1;originals=1;native=0;timely=1;unknown=1\n')
        def owned(argv, **kwargs):
            self.invocations.append(tuple(argv))
            return subprocess.CompletedProcess(argv, code, self.capture, PRIVATE)
        def publish(name, body, *, parent=None):
            self.assertIsNone(parent)
            if publish_error and name == 'installer-output.txt':
                raise RuntimeError('synthetic-publication-failure')
            self.publications[name] = body
        op = object.__new__(HELPER.Operation)
        op.__dict__.update(phase='package-install', candidate_removal_context=None, prepared_binding=None, prepared_staging=False, credential_known=lambda: True,
            credential_failed=False, credential_active=None, removal_final_active=lambda: False,
            errors=[], stager_io_pending=None, android_support=None, store_signing=None,
            app_absence=None, update=None, removal=False, setup_verify=False, setup_package=False,
            removal_recorded_role=lambda role: role,
            owner=SimpleNamespace(run_owned=owned), work=Path('/synthetic-unopened-work'),
            checkout=Path('/synthetic-unopened-source'), publish=publish,
            calls=[{'role': role, 'entered': True, 'returned': True, 'capturesSettled': True, 'returncode': 0}
                   for role in HELPER._PACKAGE_DIAGNOSTIC_ROLES[:13]],
            receipt={}, credential_calls=[], credential_contexts=[], installer_entered=False,
            installer_zero=False, installation_readback=False)
        return op

    def invoke(self, op, role='installer'):
        return HELPER.Operation.call(op, role, ['fixed-' + role], {}, cwd=op.work, timeout=20, limit=256*1024)

    def test_remove_producer_reason_requires_original_settled_exit_and_closed_static_data(self):
        from unittest import mock
        marker = b'MRK_MACOS_REMOVE_PRODUCER_REFUSED=private-acl\n'
        original = HELPER.Refused('original-nonzero-producer-emitter')
        def operation(code=78, stdout=b'', stderr=marker, phase='package-remove'):
            op = self.operation(); op.phase = phase; op.calls = []; op.removal = True
            def owned(argv, **kwargs):
                self.invocations.append(tuple(argv))
                return subprocess.CompletedProcess(argv, code, stdout, stderr)
            op.owner.run_owned = owned
            return op
        def projected(op):
            return HELPER.failure_diagnostic(original, phase=op.phase, operation=op)['lastRecordedNative']['removeProducerReason']

        op = operation()
        with self.assertRaisesRegex(HELPER.Refused, '^original-nonzero-producer-emitter$'):
            self.invoke(op, 'producer-emitter')
        self.assertEqual(self.invocations, [('fixed-producer-emitter',)])
        self.assertEqual((op.calls[0]['returned'], op.calls[0]['capturesSettled'], op.calls[0]['returncode']), (True, True, 78))
        self.assertEqual(projected(op), 'private-acl')
        before = copy.deepcopy(op.calls)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            HELPER.emit_failure_diagnostic(original, phase=op.phase, target=HELPER.ARM_TARGET, operation=op)
        self.assertEqual(json.loads(output.getvalue())['lastRecordedNative']['removeProducerReason'], 'private-acl')
        self.assertLessEqual(len(output.getvalue()), 4096)
        self.assertNotIn(PRIVATE.decode(), output.getvalue()); self.assertEqual(op.calls, before)
        for reason in HELPER._REMOVE_PRODUCER_REASONS:
            self.assertEqual(HELPER.remove_producer_refusal(b'', b'MRK_MACOS_REMOVE_PRODUCER_REFUSED=' + reason.encode() + b'\n'), reason)
        for stdout, stderr in ((PRIVATE, marker), (b'', marker + marker), (b'', marker[:-1]),
                (b'', PRIVATE + marker), (b'', marker + PRIVATE), (b'', b'x' * 129),
                (b'', b'MRK_MACOS_REMOVE_PRODUCER_REFUSED=unknown-private-name\n'),
                (b'', b'MRK_MACOS_REMOVE_PRODUCER_REFUSED=Private-acl\n'), (b'', PRIVATE), (b'', ''), ('', marker)):
            self.assertIsNone(HELPER.remove_producer_refusal(stdout, stderr))
        for key, value in (('entered', False), ('returned', False), ('capturesSettled', False),
                ('returncode', 0), ('returncode', 1), ('returncode', True), ('returncode', -9),
                ('role', 'build'), ('removeProducerReason', PRIVATE.decode())):
            self.assertIsNone(HELPER.remove_producer_refusal_data('package-remove', dict(before[0], **{key: value})))
        self.assertIsNone(HELPER.remove_producer_refusal_data('prepare', before[0]))
        op.calls.append(dict(role='distribution-sign', entered=True, returned=True, capturesSettled=True, returncode=0))
        self.assertIsNone(projected(op))  # Earlier diagnostics never label a later original.

        for code, phase, role in ((0, 'package-remove', 'producer-emitter'), (1, 'package-remove', 'producer-emitter'),
                (78, 'package-remove', 'producer-build'), (78, 'package-install', 'producer-emitter')):
            op = operation(code=code, phase=phase)
            if code == 0:
                self.invoke(op, role)
            else:
                with self.assertRaisesRegex(HELPER.Refused, '^original-nonzero-' + role + '$'):
                    self.invoke(op, role)
            self.assertIsNone(projected(op))
        op = operation()
        with mock.patch.object(HELPER, 'remove_producer_refusal', side_effect=KeyboardInterrupt):
            with self.assertRaisesRegex(HELPER.Refused, '^original-nonzero-producer-emitter$'):
                self.invoke(op, 'producer-emitter')
        self.assertTrue(op.calls[0]['capturesSettled']); self.assertIsNone(projected(op))
        for fault in ('publication', 'unknown'):
            op = operation(); primary = RuntimeError(PRIVATE.decode())
            def fail(*args, **kwargs): raise primary
            if fault == 'publication': op.publish = fail
            else: op.owner.run_owned = fail
            with self.assertRaises(RuntimeError) as caught:
                self.invoke(op, 'producer-emitter')
            self.assertIs(caught.exception, primary)
            self.assertFalse(op.calls[0]['capturesSettled']); self.assertIsNone(projected(op))

    def test_fixture_original_capture_is_private_and_later_outcomes_supersede_it(self):
        from unittest import mock
        def fixture_operation(*, code=1):
            op = self.operation(code=code)
            op.phase = 'candidate-baseline'
            op.calls = []
            op.app_absence = {}
            # The real call/capture/diagnostic boundary, with inert native ports.
            op.app_absence_module = SimpleNamespace(dispatch=lambda *_: None,
                cut_role_data=lambda *_: False, cut_return_data=lambda *_: False,
                returned=lambda *_: None)
            return op

        op = fixture_operation()
        with self.assertRaisesRegex(HELPER.Refused, '^original-nonzero-app-absence-baseline$'):
            self.invoke(op, 'app-absence-baseline')
        self.assertEqual(self.invocations, [('fixed-app-absence-baseline',)])
        self.assertTrue(op.calls[0]['capturesSettled'])
        self.assertIn('installerMarkers', op.calls[0])
        projected = HELPER.failure_diagnostic(HELPER.Refused('original-nonzero-app-absence-baseline'), operation=op)
        observed = projected['fixtureInstall']
        self.assertEqual((observed['role'], observed['index'], observed['returncode']), ('app-absence-baseline', 1, 1))
        self.assertEqual(observed['markers']['acl'][0]['phase'], 'acl-entry-present')
        self.assertFalse(observed['systemServiceExitClaimed'])
        self.assertIsNone(projected['packageInstall'])
        self.assertNotIn(PRIVATE.decode(), json.dumps(projected))
        before = copy.deepcopy(op.calls)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            HELPER.emit_failure_diagnostic(HELPER.Refused('original-nonzero-app-absence-baseline'),
                phase=op.phase, target=HELPER.ARM_TARGET, operation=op)
        self.assertEqual(json.loads(output.getvalue())['fixtureInstall'], observed)
        self.assertLessEqual(len(output.getvalue()), 4096)
        self.assertEqual(op.calls, before)

        for changes in ({'returncode': 0}, {'returncode': True}, {'returned': False},
                        {'capturesSettled': False}, {'entered': False}):
            rows = [dict(before[0], role='app-absence-cut-app-write'),
                    dict(before[0], role='app-absence-recovery-cut-1', **changes)]
            self.assertIsNone(HELPER.fixture_installer_diagnostic('app-absence-restore', rows))
        # No role-prefix grant and no raw/malformed nested marker passthrough.
        self.assertIsNone(HELPER.fixture_installer_diagnostic('candidate-baseline',
            [dict(before[0], role='app-absence-build')]))
        bad = copy.deepcopy(before)
        bad[0]['installerMarkers']['acl'][0]['role'] = PRIVATE.decode()
        bad[0]['installerErrors'] = {'raw': PRIVATE.decode()}
        sanitized = HELPER.fixture_installer_diagnostic('candidate-baseline', bad)
        self.assertIsNone(sanitized['markers']); self.assertIsNone(sanitized['errors'])
        self.assertNotIn(PRIVATE.decode(), json.dumps(sanitized))

        op = fixture_operation(code=0)
        self.invoke(op, 'app-absence-baseline')
        self.assertNotIn('installerMarkers', op.calls[0])
        self.assertIsNone(HELPER.fixture_installer_diagnostic(op.phase, op.calls))
        op = fixture_operation()
        with mock.patch.object(HELPER, 'installer_markers', side_effect=KeyboardInterrupt):
            with self.assertRaisesRegex(HELPER.Refused, '^original-nonzero-app-absence-baseline$'):
                self.invoke(op, 'app-absence-baseline')
        self.assertTrue(op.calls[0]['capturesSettled'])
        self.assertNotIn('installerMarkers', op.calls[0])
        op = fixture_operation()
        op.publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError('fixture-publication-failed'))
        with self.assertRaisesRegex(RuntimeError, '^fixture-publication-failed$'):
            self.invoke(op, 'app-absence-baseline')
        self.assertFalse(op.calls[0]['capturesSettled'])
        self.assertNotIn('installerMarkers', op.calls[0])

    def test_fixture_baseline_log_uses_same_owner_finite_interval_and_preserves_failure(self):
        from unittest import mock
        import stat
        stager = load('fixture_interval_stager', 'stage_macos_installed.py')
        fixture = load('fixture_interval_adapter', 'macos_app_absence_fixture.py')
        now = 1_000_000_000
        binding = dict(fixtureSource='a'*40, productSource='b'*40, target=HELPER.ARM_TARGET,
            runId='123', runAttempt='1', inventorySha256='c'*64, runtimeManifestSha256='d'*64)
        context = '\n'.join(('123','1',binding['target'],'app-absence-baseline-attach'))
        mounted = Path('/Volumes') / ('MRK-AppAbsence-' + stager.digest(context.encode())[:32])
        args = SimpleNamespace(command='installer-log-cursor', app_absence=True, fixture=False, xcode_setup=False,
            package=mounted/fixture.PHASE_NAMES[0], fixture_source=binding['fixtureSource'],
            expected_source=binding['productSource'], expected_inventory=binding['inventorySha256'],
            expected_manifest=binding['runtimeManifestSha256'], run_id='123', run_attempt='1', target=binding['target'])
        admitted = stager.installer_log_binding(args)
        self.assertEqual((admitted['fixtureSource'],admitted['productSource']),('a'*40,'b'*40))
        for key,value in (('package',mounted/fixture.PHASE_NAMES[1]),('fixture',True),('xcode_setup',True),
                          ('fixture_source','a'*39),('expected_source',True),('selected_output',Path('/private')),
                          ('run_attempt','2'),('target',HELPER.INTEL_TARGET)):
            bad = copy.copy(args);setattr(bad,key,value)
            with self.subTest(binding=key),self.assertRaises(stager.Refused):stager.installer_log_binding(bad)
        info = SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o644,st_uid=0,st_gid=0,st_nlink=1,st_size=7)
        before = b'before\n'; closed=[]
        @contextlib.contextmanager
        def log_file():
            try:yield 9,8,'install.log',info
            finally:closed.append(True)
        with mock.patch.object(stager,'installer_log_file',log_file), \
             mock.patch.object(stager,'positioned_log_read',return_value=before), \
             mock.patch.object(stager,'log_growth',return_value=0):
            cursor,status=stager.installer_log_diagnostic(args)
        self.assertEqual(status,0);self.assertEqual(closed,[True])
        parent=b'MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256='+b'a'*64+b';exit=1;originals=1;native=1;timely=1;unknown=0\n'
        acl=b'MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=acl-entry-present;result=1;call=0;errno=0;freeCall=0;freeErrno=0\n'
        interval=(PRIVATE+b' '+admitted['packageIdentifier'].encode()+b'\nprivate prefix '+parent+
            b'private prefix '+acl+b'private Error  Domain=PKInstallErrorDomain  Code=112 '+PRIVATE+b'\n'
            +b'private MRK_MACOS_APP_ABSENCE_RESULT='+PRIVATE+b'\n')
        whole=before+interval;info.st_size=len(whole)
        @contextlib.contextmanager
        def cursor_parent(_):yield 8,'cursor.json'
        capture_args=copy.copy(args);capture_args.command='installer-log-capture';capture_args.cursor=Path('/fixed/cursor.json')
        with mock.patch.object(stager,'installer_log_file',log_file), \
             mock.patch.object(stager,'parent',cursor_parent), \
             mock.patch.object(stager,'read_at',return_value=(stager.canonical(cursor),SimpleNamespace(st_uid=stager.os.getuid(),st_mode=stat.S_IFREG|0o600))), \
             mock.patch.object(stager,'positioned_log_read',side_effect=lambda fd,start,size:whole[start:start+size]), \
             mock.patch.object(stager,'log_growth',return_value=0),mock.patch.object(stager,'write_log_selection') as output:
            captured,status=stager.installer_log_diagnostic(capture_args)
        self.assertEqual(status,0);self.assertEqual(closed,[True,True]);output.assert_not_called()
        self.assertNotIn(PRIVATE.decode(),json.dumps(captured));self.assertNotIn('private prefix',json.dumps(captured))
        finite=HELPER.fixture_log_document(captured,0)
        self.assertEqual(finite['markers']['parent'][0]['reasonSha256'],'a'*64)
        self.assertEqual(finite['errors']['rows'],[dict(domain='PKInstallErrorDomain',code=112)])
        self.assertEqual(finite['phaseMarkerCount'],1)
        self.assertEqual(captured['authority'],stager.LOG_AUTHORITY)
        self.assertEqual(captured['scriptOutputFinality'],'unestablished')
        for count in (0,1,2,5,8):
            raw=admitted['packageIdentifier'].encode()+b'\n'+(b'MRK_MACOS_APP_ABSENCE_RESULT='+PRIVATE+b'\n')*count
            projected=stager.select_app_absence_log(raw,admitted)
            self.assertEqual(projected['phaseMarkerCount'],min(count,5))
            self.assertNotIn(PRIVATE.decode(),json.dumps(projected))
        legacy=copy.deepcopy(captured)
        legacy['intervalScope']='before-baseline-through-failed-installer'
        del legacy['projection']['phaseMarkerCount']
        self.assertNotIn('phaseMarkerCount',HELPER.fixture_log_document(legacy,0))
        for count in (True,-1,6,PRIVATE.decode()):
            bad=copy.deepcopy(captured);bad['projection']['phaseMarkerCount']=count
            self.assertIsNone(HELPER.fixture_log_document(bad,0))
            bad=copy.deepcopy(finite);bad['phaseMarkerCount']=count
            self.assertIsNone(HELPER.fixture_log_projection_data(bad))
        bad=copy.deepcopy(captured);del bad['projection']['phaseMarkerCount']
        self.assertIsNone(HELPER.fixture_log_document(bad,0))
        repeated=stager.select_app_absence_log(admitted['packageIdentifier'].encode()+b'\n'+parent*5,admitted)
        self.assertEqual(len(repeated['markerTokens']),4);self.assertTrue(repeated['omitted'])
        for body in (parent,interval[:-1],b'x'*(stager.LOG_INTERVAL_BYTES+1)):
            with self.assertRaises(stager.Refused):stager.select_app_absence_log(body,admitted)
        for key,value in (('markerTokens',[PRIVATE.decode()]),('errorTokens',['Error Domain=private Code=1']),
                          ('omitted',1),('markerTokens',['x'*1025])):
            bad=copy.deepcopy(captured);bad['projection'][key]=value
            self.assertIsNone(HELPER.fixture_log_document(bad,0))
        unknown=dict(authority=stager.LOG_AUTHORITY,state='unknown',reason='log-file-identity')
        self.assertEqual(HELPER.fixture_log_document(unknown,1)['state'],'unknown')
        self.assertIsNone(HELPER.fixture_log_document(unknown,0))
        # The real baseline adapter + Operation.call, with only native/file ports inert.
        for fault in (None,'cursor-one','cursor-publication','native-unknown','capture-unknown','capture-malformed','late','success',
                      'zero-missing','zero-duplicate','zero-other'):
            with self.subTest(fault=fault):
                zero = type(fault) is str and fault.startswith('zero-')
                op=self.operation();op.phase='candidate-baseline';op.target=HELPER.ARM_TARGET
                op.calls=[dict(role=role,entered=True,returned=True,capturesSettled=True,returncode=0)
                          for role in fixture.BASELINE_ROLES[:3]]
                op.app_absence=dict(nativeBinding=binding,pendingRoot=None,pendingCut=None,mount={'known':True})
                op.app_absence_module=fixture;op.app_absence_api=HELPER;op.candidate_fixture_stager=stager
                op.candidate_fixture_checkout=Path('/fixed/current-helper');op.package_endpoint=now+60_000_000_000
                op.package_settled=lambda: op.stager_io_pending is None and not op.errors and all(
                    row['returned'] and row['capturesSettled'] for row in op.calls)
                invoked=[];primary=[]
                publication_error=OSError('private cursor publication failed')
                publish=op.publish
                def publishing(name,body,*,parent=None):
                    if fault=='cursor-publication' and name=='app-absence-log-cursor.json':raise publication_error
                    return publish(name,body,parent=parent)
                op.publish=publishing
                def owned(argv,**kwargs):
                    role=op.calls[-1]['role'];invoked.append(role)
                    if role=='app-absence-log-cursor':
                        self.assertEqual(argv[4],'/fixed/current-helper/desktop/tools/stage_macos_installed.py')
                        self.assertIn('--app-absence',argv);self.assertEqual(kwargs['timeout'],30)
                        document=unknown if fault=='cursor-one' else cursor
                        return subprocess.CompletedProcess(argv,int(fault=='cursor-one'),stager.canonical(document),b'')
                    if role=='app-absence-baseline':
                        if fault=='native-unknown':raise RuntimeError('private unknown native')
                        stdout=(b'MRK_MACOS_APP_ABSENCE_RESULT={}\n'*2 if fault=='zero-duplicate' else
                                b'MRK_MACOS_APP_ABSENCE_RESULT={}\n' if fault=='zero-other' else b'')
                        return subprocess.CompletedProcess(argv,0 if fault=='success' or zero else 1,stdout,PRIVATE)
                    self.assertEqual(role,fixture.LOG_CAPTURE)
                    if fault == 'capture-unknown':raise RuntimeError('private unknown capture')
                    return subprocess.CompletedProcess(argv,0,stager.canonical({'private':PRIVATE.decode()} if fault=='capture-malformed' else captured),b'')
                op.owner.run_owned=owned
                op.package_call=lambda role,argv,**kwargs: HELPER.Operation.call(op,role,argv,kwargs['environment'] if kwargs.get('environment') is not None else {},
                    cwd=op.work,timeout=kwargs['timeout'],limit=kwargs['limit'])
                original_root=fixture.root_call
                def root(owner,phase):
                    try:return original_root(owner,phase)
                    except BaseException as error:primary.append(error);raise
                def clock(owner):return op.package_endpoint-1 if fault == 'late' and len(op.calls)>=5 else now
                original_observation=fixture.phase_observation_data
                missing=FileNotFoundError('fixed completion absent')
                def io_port(owner,label,function,*args):
                    if label=='completion-read':
                        if fault in ('zero-missing','zero-duplicate'):raise missing
                        return b'{}\n'
                    return {'original':'unchanged'}
                with mock.patch.object(fixture,'clock',side_effect=clock),mock.patch.object(fixture,'post'), \
                     mock.patch.object(fixture,'reserve'),mock.patch.object(fixture,'mounted_path',return_value=mounted), \
                     mock.patch.object(fixture,'root_call',side_effect=root), \
                     mock.patch.object(fixture,'phase_observation_data',side_effect=lambda o,r,p: original_observation(o,r,p) if zero else {'baselineSha256':'e'*64}), \
                     mock.patch.object(fixture,'io',side_effect=io_port):
                    if fault=='success':
                        fixture.baseline(op);self.assertEqual(op.app_absence['baselineSha256'],'e'*64)
                        self.assertIsNone(op.app_absence['pendingRoot'])
                    elif fault=='cursor-publication':
                        with self.assertRaises(OSError) as caught:fixture.baseline(op)
                        self.assertIs(caught.exception,publication_error)
                        self.assertEqual(invoked,['app-absence-log-cursor']);self.assertEqual(primary,[])
                        self.assertIsNone(op.app_absence['pendingRoot']);self.assertNotIn('logCursor',op.app_absence)
                    else:
                        with self.assertRaises(BaseException) as caught:fixture.baseline(op)
                        self.assertIs(caught.exception,primary[0]);self.assertEqual(op.app_absence['pendingRoot'],None if zero else 'app-absence-baseline')
                capture_entered=not zero and fault not in ('cursor-one','cursor-publication','native-unknown','late','success')
                self.assertEqual(fixture.LOG_CAPTURE in invoked,capture_entered)
                projected=HELPER.fixture_installer_diagnostic(op.phase,op.calls)
                if fault is None:self.assertEqual(projected['log'],finite)
                elif projected is not None:self.assertIsNone(projected['log'])
                if zero:
                    # A missing/invalid protected export cannot fall back to
                    # either captured frames or the correlated physical log.
                    if fault != 'zero-other':self.assertIs(primary[0],missing)
                    self.assertIsNone(projected)
                    self.assertNotIn('phaseMarkerRefusal',op.calls[4])
                    self.assertNotIn('baselineObservation',op.app_absence)
                self.assertNotIn(PRIVATE.decode(),json.dumps(projected))
                self.assertTrue(op.app_absence['mount']['known'])
                output=io.StringIO()
                with contextlib.redirect_stderr(output):HELPER.emit_failure_diagnostic(primary[0] if primary else HELPER.Refused('original-nonzero-app-absence-baseline'),operation=op)
                self.assertTrue(output.getvalue());self.assertLessEqual(len(output.getvalue()),4096);self.assertNotIn(PRIVATE.decode(),output.getvalue())
                if fault is None:
                    good=copy.deepcopy(op.calls)
                    for mutation in ('wrong-role','duplicate','unsettled','cursor-one'):
                        bad=copy.deepcopy(good)
                        if mutation=='wrong-role':bad[-1]['role']='app-absence-private'
                        elif mutation=='duplicate':bad.append(copy.deepcopy(bad[-1]))
                        elif mutation=='unsettled':bad[-1]['capturesSettled']=False
                        else:bad[3]['returncode']=1
                        self.assertIsNone(HELPER.fixture_installer_diagnostic(op.phase,bad)['log'])

    def test_actual_installer_and_diagnostic_statuses_stay_distinct(self):
        for code in (0, 1):
            with self.subTest(code=code):
                op = self.operation(code=code)
                if code:
                    with self.assertRaises(HELPER.Refused) as failure:
                        self.invoke(op)
                    self.assertEqual(HELPER.failure_exception(failure.exception)['reason'], 'original-nonzero-installer')
                else:
                    self.invoke(op)
                    op.installer_zero = True  # Same assignment as the package owner, not diagnostic inference.
                op.owner.run_owned = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, b'', PRIVATE)
                self.invoke(op, 'installer-log-capture')
                value = HELPER.failure_diagnostic(HELPER.Refused('helper-package-incomplete'),
                    phase='package-install', operation=op)
                slots = value['packageInstall']['calls']
                self.assertEqual(slots['installer']['returncode'], code)
                self.assertEqual(slots['installer']['index'], 14)
                self.assertEqual(slots['installer-log-capture']['returncode'], 1)
                self.assertEqual(value['lastRecordedNative']['role'], 'installer-log-capture')
                self.assertEqual(slots['installer']['capturesSettled'], True)
                self.assertEqual(self.publications['installer-output.status'], str(code).encode() + b'\n')
                if code:
                    self.assertEqual(slots['installer']['markers']['phases'], ['pre-exec'])
                    self.assertEqual(slots['installer']['markers']['acl'][0]['phase'], 'acl-entry-present')
                    self.assertEqual(slots['installer']['markers']['parent'][0]['exit'], 1)
                    self.assertEqual(slots['installer']['markers']['parent'][0]['reasonSha256'], 'a' * 64)
                else:
                    self.assertIsNone(slots['installer']['markers'])
                self.assertFalse(value['packageInstall']['systemServiceExitClaimed'])
                self.assertNotIn(PRIVATE.decode(), json.dumps(value))

    def test_failed_publication_or_parser_does_not_replace_original_failure(self):
        from unittest import mock
        op = self.operation(publish_error=True)
        with self.assertRaisesRegex(RuntimeError, 'synthetic-publication-failure'):
            self.invoke(op)
        self.assertFalse(op.calls[-1]['capturesSettled'])
        self.assertNotIn('installerMarkers', op.calls[-1])
        op = self.operation()
        with mock.patch.object(HELPER, 'installer_markers', side_effect=KeyboardInterrupt):
            with self.assertRaises(HELPER.Refused) as failure:
                self.invoke(op)
        self.assertEqual(str(failure.exception), 'original-nonzero-installer')
        self.assertTrue(op.calls[-1]['capturesSettled'])
        self.assertNotIn('installerMarkers', op.calls[-1])

    def test_revalidation_omits_duplicate_wrong_slot_and_private_fields(self):
        op = self.operation()
        with self.assertRaises(HELPER.Refused): self.invoke(op)
        original = copy.deepcopy(op.calls)
        mutations = (
            lambda: op.calls.append(dict(op.calls[-1])),
            lambda: op.calls.insert(0, {}),
            lambda: op.calls[-1].update(returncode=0),
            lambda: op.calls[-1].update(capturesSettled=False),
            lambda: op.calls[-1]['installerMarkers'].update(path=PRIVATE.decode()),
            lambda: op.calls[-1]['installerMarkers']['acl'][0].update(role=PRIVATE.decode()),
        )
        for mutate in mutations:
            op.calls = copy.deepcopy(original); mutate()
            projected = HELPER.failure_diagnostic(HELPER.Refused('helper-package-incomplete'), operation=op)
            slot = projected['packageInstall']['calls']['installer']
            self.assertTrue(slot is None or slot['markers'] is None)
            self.assertNotIn(PRIVATE.decode(), json.dumps(projected))
        for raw in (b'x' * (256*1024+1), PRIVATE.decode()):
            self.assertIsNone(HELPER.installer_markers(raw, b''))
        malformed = b'MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=acl-entry-present;result=1\n'
        self.assertEqual(HELPER.installer_markers(malformed, b'')['acl'], [])

    def test_existing_log_authority_is_observed_without_raw_selected_output(self):
        stager = load('installer_log_stager_data', 'stage_macos_installed.py')
        op = self.operation()
        op.stager = stager
        op.package_settled = lambda: True
        op.package_clock = lambda: None
        op.target = HELPER.ARM_TARGET
        op.calls = op.calls[:12]
        document = {'authority': stager.LOG_AUTHORITY, 'state': 'unknown',
            'reason': 'log-incomplete-boundary', 'selectedOutputState': 'not-created',
            'binding': PRIVATE.decode(), 'logPath': PRIVATE.decode()}
        op.owner.run_owned = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, json.dumps(document).encode(), b'')
        op.package_call = lambda role, argv, **kwargs: HELPER.Operation.call(op, role, argv, {}, cwd=op.work, **kwargs)
        args = SimpleNamespace(package=Path('/synthetic-unopened-package'), request_id='1'*32,
            expected_source='2'*40, expected_inventory='3'*64, expected_manifest='4'*64, run_id='1', run_attempt='1')
        HELPER.Operation.package_diagnostic(op, args, capture=False)
        value = HELPER.failure_diagnostic(HELPER.Refused('helper-package-incomplete'), operation=op)
        self.assertEqual(value['packageInstall']['calls']['installer-log-cursor']['log'],
            {'state': 'unknown', 'reason': 'log-incomplete-boundary', 'selection': 'not-created'})
        self.assertNotIn(PRIVATE.decode(), json.dumps(value))
        op.calls = op.calls[:12]
        document['authority'] = PRIVATE.decode()
        with self.assertRaisesRegex(HELPER.Refused, 'installer-diagnostic-original-output'):
            HELPER.Operation.package_diagnostic(op, args, capture=False)
        self.assertNotIn('installerLog', op.calls[-1])

    def test_emitted_line_is_bounded_and_does_not_mutate_original_diagnostics(self):
        op = self.operation()
        with self.assertRaises(HELPER.Refused): self.invoke(op)
        op.calls[-1]['installerMarkers'] = HELPER.installer_markers(self.capture*3, PRIVATE)
        self.assertTrue(op.calls[-1]['installerMarkers']['omitted'])
        op.receipt = {'failure': {'stage': 'standard-original-installer', 'reason': 'original-nonzero-installer'}}
        before = copy.deepcopy(op.calls)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            HELPER.emit_failure_diagnostic(HELPER.Refused('helper-package-incomplete'), phase='package-install',
                target=HELPER.ARM_TARGET, main_stage='operation-execute', operation=op)
        encoded = output.getvalue()
        value = json.loads(encoded)
        self.assertLessEqual(len(encoded), 4096)
        self.assertEqual(value['originalFailure']['stage'], 'standard-original-installer')
        self.assertEqual(value['originalFailure']['reason'], 'original-nonzero-installer')
        self.assertEqual(op.calls, before)
        self.assertNotIn(PRIVATE.decode(), encoded)

    def test_parent_reason_categories_keep_unknown_and_composite_causes(self):
        for reason, category in (
            ('deadline', 'deadline'), ('worker-work-deadline', 'worker-work-deadline'),
            ('worker-final-deadline', 'worker-final-deadline'),
            ('deadline-or-unknown', 'deadline-or-ownership-unknown'),
            ('export-deadline-or-unknown', 'deadline-or-ownership-unknown'),
            ('directory-bound', 'directory-policy-or-bound'),
            ('read-bound', 'original-read-bound'),
            ('acl-refused', 'acl-refusal'), ('export-acl-refused', 'acl-refusal'),
            ('worker-self-image', 'worker-image-refusal'), (PRIVATE.decode(), 'unclassified')):
            with self.subTest(category=category):
                reason_hash = hashlib.sha256(reason.encode()).hexdigest()
                capture = ('MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + reason_hash +
                    ';exit=1;originals=1;native=0;timely=1;unknown=1\n').encode()
                value = HELPER.installer_markers(capture, PRIVATE)
                self.assertEqual(value['parent'][0]['category'], category)
                self.assertEqual(value['parent'][0]['reasonSha256'], reason_hash)
                self.assertEqual({k: value['parent'][0][k] for k in ('exit', 'originals', 'native', 'timely', 'unknown')},
                    {'exit': 1, 'originals': True, 'native': False, 'timely': True, 'unknown': True})
                self.assertNotIn(PRIVATE.decode(), json.dumps(value))
                for bad in (None, 123, '', reason_hash[:-1], reason_hash+'0', reason_hash.upper(), PRIVATE.decode()):
                    altered = copy.deepcopy(value)
                    altered['parent'][0]['reasonSha256'] = bad
                    self.assertIsNone(HELPER.installer_markers_data(altered))
                    malformed = capture.replace(reason_hash.encode(), str(bad).encode())
                    self.assertEqual(HELPER.installer_markers(malformed, PRIVATE)['parent'], [])
                value['parent'][0]['category'] = PRIVATE.decode()
                self.assertIsNone(HELPER.installer_markers_data(value))
        # Exercise the real call and final public projection: this diagnostic
        # neither converts the original nonzero result nor mutates its ledger.
        op = self.operation()
        with self.assertRaisesRegex(HELPER.Refused, 'original-nonzero-installer'):
            self.invoke(op)
        before = copy.deepcopy(op.calls)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            HELPER.emit_failure_diagnostic(HELPER.Refused('original-nonzero-installer'),
                phase='package-install', target=HELPER.ARM_TARGET, operation=op)
        emitted = json.loads(output.getvalue())
        slot = emitted['packageInstall']['calls']['installer']
        self.assertEqual(slot['returncode'], 1)
        self.assertTrue(slot['capturesSettled'])
        self.assertEqual(slot['markers']['parent'][0]['reasonSha256'], 'a' * 64)
        self.assertEqual(slot['markers']['parent'][0]['category'], 'unclassified')
        self.assertEqual(emitted['terminal']['reason'], 'original-nonzero-installer')
        self.assertEqual(op.calls, before)
        self.assertNotIn(PRIVATE.decode(), output.getvalue())
        self.assertLessEqual(len(output.getvalue()), 4096)


class PreparedInstallerLogTests(unittest.TestCase):
    def args(self, stager, target):
        env = {'GITHUB_RUN_ID': '38967044255', 'GITHUB_RUN_ATTEMPT': '1'}
        package = HELPER.transport_mount_path_data(env, target, 'package-install') / stager.distribution_request_name('1' * 32)
        return SimpleNamespace(fixture=False, target=target, package=package, request_id='1' * 32,
            expected_source='2' * 40, expected_inventory='3' * 64, expected_manifest='4' * 64,
            run_id=env['GITHUB_RUN_ID'], run_attempt=env['GITHUB_RUN_ATTEMPT'])

    def test_real_transport_paths_bind_both_targets_and_refuse_other_cohorts(self):
        stager = load('prepared_log_binding_data', 'stage_macos_installed.py')
        for target in (HELPER.ARM_TARGET, HELPER.INTEL_TARGET):
            args = self.args(stager, target)
            self.assertEqual(stager.installer_log_binding(args)['packagePath'], str(args.package))
            for key, value in (('target', HELPER.INTEL_TARGET if target == HELPER.ARM_TARGET else HELPER.ARM_TARGET),
                               ('run_id', '38967044256'), ('run_attempt', '2'),
                               ('package', Path('/Volumes/unrelated') / args.package.name),
                               ('package', Path('/tmp/Volumes') / args.package.parent.name / args.package.name)):
                bad = copy.copy(args); setattr(bad, key, value)
                with self.subTest(target=target, key=key), self.assertRaisesRegex(stager.Refused, 'log-input-binding'):
                    stager.installer_log_binding(bad)
            # The old ordinary/fixture diagnostic grammar is not reinterpreted.
            args.package = Path('/tmp/original/package-mount') / args.package.name
            stager.installer_log_binding(args)
            args.fixture = True; args.request_id = None
            args.package = Path('/tmp/original/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg')
            stager.installer_log_binding(args)

    def operation(self, target):
        import tempfile, time
        from unittest import mock
        from desktop.tools import macos_prepared_package as prepared
        from test_macos_prepared_package import fixture
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        current = root / 'current'; old = current / 'prepared-built-source'; work = root / 'work'
        (current / '.git').mkdir(parents=True); (current / 'desktop/tools').mkdir(parents=True)
        old.mkdir(); work.mkdir(mode=0o700)
        values, manifest, service, consumer = fixture(target)
        consumer.update(source='6' * 40, tree='7' * 40)
        binding = prepared.admit_data(values, service, consumer)
        (current / '.git/HEAD').write_text(consumer['source'] + '\n')
        (current / '.git/HEAD').chmod(0o644)
        program = current / 'desktop/tools/stage_macos_installed.py'
        program.write_bytes((ROOT / 'desktop/tools/stage_macos_installed.py').read_bytes()); program.chmod(0o644)
        environment = dict(GITHUB_SHA=consumer['source'], GITHUB_WORKFLOW_SHA=consumer['source'],
            GITHUB_RUN_ID=consumer['runId'], GITHUB_RUN_ATTEMPT=consumer['runAttempt'],
            GITHUB_WORKFLOW_REF=prepared.REPOSITORY + '/' + prepared.WORKFLOW + '@refs/heads/' + prepared.BRANCH,
            MRK_MACOS_PACKAGE_ROLE='ordinary-image')
        stager = load('prepared_actual_log_stager_' + target, 'stage_macos_installed.py')
        self.enterContext(mock.patch.object(HELPER, 'CHECKOUT', current))
        op = HELPER.Operation(SimpleNamespace(run_owned=None), old, work, 'package-install', environment,
            stager, target=target, prepared=binding)
        op.open(); op.package_started = op.package_observed = time.monotonic_ns()
        op.package_endpoint = op.package_started + 180_000_000_000
        op.calls.extend({'role': role, 'entered': True, 'returned': True, 'capturesSettled': True, 'returncode': 0}
            for role in HELPER._PACKAGE_DIAGNOSTIC_ROLES[:12])
        return op, stager, program

    def test_current_diagnostic_parser_and_original_selected_log_do_not_relabel_product(self):
        from unittest import mock
        for target in (HELPER.ARM_TARGET, HELPER.INTEL_TARGET):
            with self.subTest(target=target):
                op, stager, program = self.operation(target)
                args = self.args(stager, target)
                args.run_id = op.environment['GITHUB_RUN_ID']; args.run_attempt = op.environment['GITHUB_RUN_ATTEMPT']
                args.package = HELPER.transport_mount_path_data(op.environment, target, 'package-install') / stager.distribution_request_name(args.request_id)
                selected = (b'PackageKit: MRK_MACOS_POSTINSTALL_PHASE=pre-exec\n'
                    b'PackageKit: MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + b'a' * 64 +
                    b';exit=1;originals=1;native=1;timely=1;unknown=0\n'
                    b'PackageKit: Error Domain=PKInstallErrorDomain Code=112 private message\n' + PRIVATE + b'\n')
                def diagnostic(parsed):
                    # Native log input is inert. Real CLI/parser+binding, owner
                    # call ledger, exclusive outputs/readbacks and closes remain.
                    binding = stager.installer_log_binding(parsed)
                    self.assertEqual(binding['packagePath'], str(args.package))
                    row = dict(authority=stager.LOG_AUTHORITY, state='observed', binding=binding)
                    if parsed.command == 'installer-log-capture':
                        stager.write_log_selection(parsed.selected_output, selected)
                        row.update(state='observed-project-correlated', selectedData=dict(
                            file='installer-log-selected.txt', bytes=len(selected), sha256=HELPER.digest(selected)))
                    return row, 0
                def native(argv, **kwargs):
                    if argv == ['inert-installer']:
                        return subprocess.CompletedProcess(argv, 1, b'Installer failed without marker',
                            b'Error Domain=NSPOSIXErrorDomain Code=13 private message')
                    self.assertEqual(Path(argv[4]), program)
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output): status = stager.main(argv[5:])
                    return subprocess.CompletedProcess(argv, status, output.getvalue().encode(), b'')
                op.owner.run_owned = native
                try:
                    with mock.patch.object(stager, 'installer_log_diagnostic', side_effect=diagnostic):
                        op.package_diagnostic(args, capture=False)
                        with self.assertRaisesRegex(HELPER.Refused, 'original-nonzero-installer'):
                            op.call('installer', ['inert-installer'], {}, cwd=op.work, timeout=20, limit=256*1024)
                        op.package_diagnostic(args, capture=True)
                    self.assertIs(op.stager, stager); self.assertEqual(op.checkout.name, 'prepared-built-source')
                    self.assertEqual(op.environment['GITHUB_SHA'], '6' * 40)
                    self.assertEqual(op.prepared_binding.source, '1' * 40)
                    self.assertEqual(sum(e['role'] == 'diagnostic-source-root' for e in op.entries), 1)
                    value = HELPER.failure_diagnostic(HELPER.Refused('helper-package-incomplete'), operation=op)
                    slots = value['packageInstall']['calls']
                    self.assertEqual(slots['installer']['returncode'], 1)
                    self.assertEqual(slots['installer']['markers']['phases'], [])
                    self.assertEqual(slots['installer-log-capture']['markers']['phases'], ['pre-exec'])
                    self.assertEqual(slots['installer-log-capture']['markers']['parent'][0],
                        dict(reasonSha256='a'*64, category='unclassified', exit=1, originals=True,
                             native=True, timely=True, unknown=False))
                    self.assertEqual(slots['installer']['errors']['rows'], [{'domain':'NSPOSIXErrorDomain','code':13}])
                    self.assertEqual(slots['installer-log-capture']['errors']['rows'], [{'domain':'PKInstallErrorDomain','code':112}])
                    self.assertNotIn(PRIVATE.decode(), json.dumps(value))
                    self.assertFalse(value['packageInstall']['systemServiceExitClaimed'])
                    self.assertTrue(all(e['closed'] for e in op.entries if e['role'] == 'diagnostic-selected-log'))
                    self.assertLess(sum(e['fd'] is not None for e in op.entries) + 40, 256)
                    op.calls[13]['returncode'] = 0
                    self.assertIsNone(HELPER.failure_diagnostic(HELPER.Refused('helper-package-incomplete'), operation=op)
                        ['packageInstall']['calls']['installer-log-capture']['markers'])
                finally:
                    op.finish()
                self.assertTrue(op.receipt['originalClosesKnown'])
                self.assertTrue(all(e['closed'] and e['fd'] is None for e in op.entries))

    def test_changed_current_source_and_unknown_selected_close_refuse_without_reopening(self):
        from unittest import mock
        op, stager, program = self.operation(HELPER.ARM_TARGET)
        try:
            self.assertEqual(op.package_diagnostic_program(), program)
            original = program.read_bytes(); program.write_bytes(original + b'\n')
            with self.assertRaisesRegex(HELPER.Refused, 'file-original-changed'):
                op.package_diagnostic_program()
            self.assertEqual(sum(e['role'] == 'diagnostic-source-root' for e in op.entries), 1)
        finally: op.finish()
        self.assertTrue(all(e['closed'] for e in op.entries))
        # A change during the original child call must fail the current-source
        # POST before its successful JSON can become a diagnostic record.
        op, stager, program = self.operation(HELPER.ARM_TARGET)
        def changed_child(argv, **kwargs):
            program.write_bytes(program.read_bytes() + b'\n')
            return subprocess.CompletedProcess(argv, 0,
                json.dumps({'authority':stager.LOG_AUTHORITY, 'state':'observed'}).encode(), b'')
        op.owner.run_owned = changed_child
        try:
            with self.assertRaisesRegex(HELPER.Refused, 'file-original-changed'):
                op.package_diagnostic(self.args(stager, HELPER.ARM_TARGET), capture=False)
            self.assertEqual(len(op.calls), 13)
            self.assertTrue(op.calls[-1]['returned'] and op.calls[-1]['capturesSettled'])
            self.assertNotIn('installerLog', op.calls[-1])
            self.assertFalse((op.work / 'installer-log-cursor.json').exists())
        finally: op.finish()
        self.assertTrue(all(e['closed'] for e in op.entries))
        op, stager, program = self.operation(HELPER.ARM_TARGET)
        body = b'MRK_MACOS_POSTINSTALL_PHASE=pre-exec\n'
        path = op.work / 'installer-log-selected.txt'; path.write_bytes(body); path.chmod(0o600)
        document = dict(authority=stager.LOG_AUTHORITY, state='observed-project-correlated',
            selectedData=dict(file=path.name, bytes=len(body), sha256=HELPER.digest(body)))
        try:
            wrong = copy.deepcopy(document); wrong['selectedData']['file'] = '../private'
            with self.assertRaisesRegex(HELPER.Refused, 'installer-diagnostic-selected'):
                op.package_log_markers(wrong)
            self.assertFalse(any(e['role'] == 'diagnostic-selected-log' for e in op.entries))
            real_close = HELPER.os.close
            def consuming_unknown(fd):
                real_close(fd)
                raise OSError('synthetic lost close return')
            with mock.patch.object(HELPER.os, 'close', side_effect=consuming_unknown):
                with self.assertRaisesRegex(HELPER.Refused, 'installer-diagnostic-selected-close'):
                    op.package_log_markers(document)
        finally: op.finish()
        self.assertFalse(op.receipt['originalClosesKnown'])
        self.assertEqual(len(op.errors), 1)
        self.assertEqual(sum(e['role'] == 'diagnostic-selected-log' for e in op.entries), 1)

    def test_apple_error_projection_is_closed_bounded_and_never_freeform(self):
        body = (b'Error Domain=PKInstallErrorDomain Code=112 "' + PRIVATE + b'"\n'
            b'Underlying Error Domain=NSPOSIXErrorDomain Code=13\n'
            b'Error Domain=NSOSStatusErrorDomain Code=-67062\n'
            b'Error Domain=NSCocoaErrorDomain Code=513\n'
            b'Error Domain=PKInstallErrorDomain Code=113\n')
        value = HELPER.installer_errors(body, b'')
        self.assertEqual(len(value['rows']), 4); self.assertTrue(value['omitted'])
        self.assertNotIn(PRIVATE.decode(), json.dumps(value))
        for invalid in (b'Error Domain=UnknownDomain Code=4', b'XError Domain=PKInstallErrorDomain Code=3',
                        b'Error Domain=PKInstallErrorDomain Code=2147483648',
                        b'Error Domain=PKInstallErrorDomain Code=-2147483649',
                        b'Error Domain=PKInstallErrorDomain Code=12345678901',
                        b'Error Domain=PKInstallErrorDomain Code=3secret',
                        b'Error Domain=PKInstallErrorDomain Code=3.5'):
            self.assertEqual(HELPER.installer_errors(invalid, b'')['rows'], [])
        self.assertIsNone(HELPER.installer_errors(b'x' * (256*1024+1), b''))
        for row in ({'domain':'NSPOSIXErrorDomain','code':True},
                    {'domain':'NSPOSIXErrorDomain','code':13,'message':PRIVATE.decode()},
                    {'domain':PRIVATE.decode(),'code':13}):
            self.assertIsNone(HELPER.installer_errors_data({'rows':[row], 'omitted':False}))


class SetupInstallerDiagnosticTests(unittest.TestCase):
    def test_hook_and_native_observations_are_distinct_closed_data(self):
        rows = [{"hook": hook, "stage": stage} for hook in HELPER._SETUP_HOOKS
                for stage in HELPER._SETUP_HOOK_STAGES]
        body = b"".join(("installer: MRK_XCODE_HOOK=hook=" + r["hook"] + ";stage=" + r["stage"] + "\r\n").encode()
                        for r in rows)
        value = HELPER.setup_hook_diagnostics(body + body, PRIVATE + b"\n")
        self.assertEqual(value, {"available": True, "observations": rows})
        native_line = b"installer: MRK_XCODE_SETUP_REFUSED=scope=child;stage=source;reason=binding\n"
        native = HELPER.setup_installer_diagnostics(native_line, b"")
        self.assertEqual(HELPER.setup_installer_diagnostics_data(native), native)
        self.assertFalse(HELPER.setup_hook_diagnostics(native_line, b"")["available"])
        self.assertFalse(HELPER.setup_installer_diagnostics(body, b"")["available"])
        good = b"MRK_XCODE_HOOK=hook=preinstall;stage=pre-exec\n"
        self.assertEqual(HELPER.setup_hook_diagnostics(b"\t" + good, b"")["observations"],
                         [{"hook": "preinstall", "stage": "pre-exec"}])
        for bad in (b"X" + good, good.rstrip(b"\n"), good.replace(b"preinstall", b"foreign"),
                    good.replace(b"pre-exec", b"helper-admitted"), good[:-1] + PRIVATE + b"\n",
                    good.replace(b"hook=", b"private="), b"x" * 4096 + b" " + good):
            with self.subTest(length=len(bad)):
                self.assertEqual(HELPER.setup_hook_diagnostics(bad, b""), {"available": False, "observations": []})
        self.assertIsNone(HELPER.setup_hook_diagnostics(b"x" * (256*1024 + 1), b""))
        self.assertIsNone(HELPER.setup_hook_diagnostics("not bytes", b""))
        for parser, original in ((HELPER.setup_hook_diagnostics_data, value),
                                 (HELPER.setup_installer_diagnostics_data, native)):
            before = copy.deepcopy(original)
            parsed = parser(original)
            parsed["observations"][0]["stage"] = "changed-copy"
            self.assertEqual(original, before)
            bad_rows = (original["observations"] + original["observations"],
                        [dict(original["observations"][0], extra=PRIVATE.decode())],
                        [dict(original["observations"][0], stage=PRIVATE.decode())], [None])
            for changed in (None, dict(original, available=1), dict(original, available=False),
                            dict(original, extra=PRIVATE.decode()),
                            *[dict(original, observations=r) for r in bad_rows]):
                self.assertIsNone(parser(changed))
            self.assertEqual(parser({"available": False, "observations": []}),
                             {"available": False, "observations": []})

    def test_actual_setup_call_only_classifies_settled_nonzero_capture(self):
        from unittest import mock
        parsers = (("setupDiagnostic", "setup_installer_diagnostics"),
                   ("setupHooks", "setup_hook_diagnostics"), ("installerErrors", "installer_errors"))
        stdout = b"installer: MRK_XCODE_HOOK=hook=preinstall;stage=pre-exec\n"
        stderr = (b"installer: MRK_XCODE_SETUP_REFUSED=scope=public;stage=source;reason=binding\n"
                  b'Error Domain=PKInstallErrorDomain Code=112 "' + PRIVATE + b'"\n')
        for index in (2, 3):
            role = HELPER.XCODE_SETUP_VERIFY_ROLES[index]
            for fault in (None, "zero", "owner", "publication", *[name for _, name in parsers]):
                with self.subTest(role=role, fault=fault):
                    published, invoked, observed = [], [], []
                    argv = ["inert-original-installer"]
                    def owned(actual, **kwargs):
                        invoked.append(tuple(actual))
                        if fault == "owner": raise RuntimeError("inert unknown original")
                        return subprocess.CompletedProcess(actual, 0 if fault == "zero" else 1, stdout, stderr)
                    def publish(name, body, *, parent=None):
                        self.assertIsNone(parent)
                        if fault == "publication": raise RuntimeError("inert unknown publication")
                        published.append(name)
                    op = SimpleNamespace(phase=HELPER.XCODE_SETUP_VERIFY,
                        credential_known=lambda: True, credential_failed=False, credential_active=None,
                        removal_final_active=lambda: False, android_support=None, store_signing=None,
                        app_absence=None, update=None, removal=False, setup_package=False, setup_verify=True,
                        prepared_staging=False,
                        removal_recorded_role=lambda r:r, setup_verification_post=lambda:None,
                        setup_verification_absent=lambda:None, errors=[], stager_io_pending=None,
                        calls=[dict(role=r, entered=True, returned=True, capturesSettled=True, returncode=0)
                               for r in HELPER.XCODE_SETUP_VERIFY_ROLES[:index]],
                        owner=SimpleNamespace(run_owned=owned), work=Path("/inert-unopened-work"),
                        checkout=Path("/inert-unopened-checkout"), publish=publish)
                    def guarded(name, actual_parser):
                        def invoke(out, err):
                            self.assertEqual((out, err), (stdout, stderr))
                            self.assertEqual(len(published), 3)
                            self.assertTrue(op.calls[-1]["returned"] and op.calls[-1]["capturesSettled"])
                            self.assertEqual(op.calls[-1]["returncode"], 1)
                            observed.append(name)
                            if fault == name: raise RuntimeError(PRIVATE.decode())
                            return actual_parser(out, err)
                        return invoke
                    with contextlib.ExitStack() as stack:
                        for _, name in parsers:
                            stack.enter_context(mock.patch.object(HELPER, name, side_effect=guarded(name, getattr(HELPER, name))))
                        if fault == "zero":
                            HELPER.Operation.call(op, role, argv, {}, cwd=op.work, timeout=20, limit=256*1024)
                        else:
                            exception = RuntimeError if fault in ("owner", "publication") else HELPER.Refused
                            with self.assertRaises(exception) as captured:
                                HELPER.Operation.call(op, role, argv, {}, cwd=op.work, timeout=20, limit=256*1024)
                            if exception is HELPER.Refused:
                                self.assertEqual(str(captured.exception), "original-nonzero-" + role)
                    self.assertEqual(invoked, [tuple(argv)])
                    row = op.calls[-1]
                    available = fault not in ("zero", "owner", "publication")
                    self.assertEqual(observed, [name for _, name in parsers] if available else [])
                    for key, name in parsers:
                        self.assertEqual(key in row, available and fault != name)
                    if available:
                        if fault != "installer_errors":
                            self.assertEqual(row["installerErrors"]["rows"], [{"domain":"PKInstallErrorDomain", "code":112}])
                        self.assertNotIn(PRIVATE.decode(), json.dumps(row))
                    if fault == "publication": self.assertFalse(row["capturesSettled"])
                    if fault == "owner": self.assertFalse(row["returned"])

    def test_setup_failure_projection_is_original_bound_private_and_finite(self):
        hooks = {"available": True, "observations": [{"hook":h,"stage":s}
            for h in HELPER._SETUP_HOOKS for s in HELPER._SETUP_HOOK_STAGES]}
        native = {"available": True, "observations": [{"scope":"child","stage":s,"reason":"binding"}
            for s in ("source", "self", "carrier", "finality")]}
        errors = {"rows":[{"domain":domain,"code":112} for domain in HELPER._INSTALLER_ERROR_DOMAINS], "omitted":False}
        def operation(index):
            op = object.__new__(HELPER.Operation)
            op.__dict__.update(phase=HELPER.XCODE_SETUP_VERIFY, receipt={"passed":False},
                credential_calls=[], credential_contexts=[], errors=[],
                calls=[dict(role=r, entered=True, returned=True, capturesSettled=True, returncode=0,
                            stdout=PRIVATE, argv=[PRIVATE.decode()]) for r in HELPER.XCODE_SETUP_VERIFY_ROLES[:index+1]])
            op.calls[-1].update(returncode=1, setupHooks=copy.deepcopy(hooks),
                                setupDiagnostic=copy.deepcopy(native), installerErrors=copy.deepcopy(errors))
            return op
        for index in (2,3):
            op = operation(index); before=copy.deepcopy(op.__dict__)
            output=io.StringIO()
            with contextlib.redirect_stderr(output):
                HELPER.emit_failure_diagnostic(HELPER.Refused("helper-package-incomplete"),
                    phase=HELPER.XCODE_SETUP_VERIFY, target=HELPER.ARM_TARGET, operation=op)
            encoded=output.getvalue(); value=json.loads(encoded)
            self.assertLessEqual(len(encoded),4096)
            self.assertEqual(value["setupInstall"], {"role":HELPER.XCODE_SETUP_VERIFY_ROLES[index], "index":index+1,
                "returncode":1, "hooks":hooks, "native":native, "errors":errors, "log":None, "systemServiceExitClaimed":False})
            self.assertFalse(value["productReady"])
            self.assertTrue(value["diagnosticOnly"])
            self.assertIsNone(value["packageInstall"])
            self.assertNotIn(PRIVATE.decode(),encoded)
            self.assertEqual(op.__dict__,before)
            # Corrupt saved diagnostic fields are refused independently, not
            # converted into missing native observations or success evidence.
            for key, projected in (("setupHooks","hooks"),("setupDiagnostic","native"),("installerErrors","errors")):
                changed=operation(index); changed.calls[-1][key]={"private":PRIVATE.decode()}
                data=HELPER.failure_diagnostic(HELPER.Refused("helper-package-incomplete"),operation=changed)["setupInstall"]
                self.assertIsNone(data[projected]); self.assertNotIn(PRIVATE.decode(),json.dumps(data))
        for fault in ("phase","zero","bool-status","unentered","unreturned","unsettled","prior-failed",
                      "prior-unsettled","wrong-role","duplicate","extra-call","status-bound"):
            op=operation(2)
            if fault=="phase": op.phase="package-install"
            elif fault=="zero": op.calls[-1]["returncode"]=0
            elif fault=="bool-status": op.calls[-1]["returncode"]=True
            elif fault=="unentered": op.calls[-1]["entered"]=False
            elif fault=="unreturned": op.calls[-1]["returned"]=False
            elif fault=="unsettled": op.calls[-1]["capturesSettled"]=False
            elif fault=="prior-failed": op.calls[0]["returncode"]=1
            elif fault=="prior-unsettled": op.calls[0]["capturesSettled"]=False
            elif fault=="wrong-role": op.calls[-1]["role"]="installer"
            elif fault=="duplicate": op.calls.insert(0,copy.deepcopy(op.calls[0]))
            elif fault=="extra-call": op.calls.append(copy.deepcopy(op.calls[-1]))
            elif fault=="status-bound": op.calls[-1]["returncode"]=65536
            with self.subTest(fault=fault):
                self.assertIsNone(HELPER.failure_diagnostic(HELPER.Refused("helper-package-incomplete"),operation=op)["setupInstall"])


class SetupIntervalLogTests(unittest.TestCase):
    def test_companion_binding_and_finite_interval_never_export_neighbor_text(self):
        stager = load("xcode_interval_binding_data", "stage_macos_installed.py")
        args = SimpleNamespace(xcode_setup=True, fixture=False, target=HELPER.ARM_TARGET,
            package=Path("/work/xcode-setup-final/Prepare Xcode.pkg"), expected_source="a"*40,
            run_id="123", run_attempt="1")
        binding = stager.installer_log_binding(args)
        self.assertEqual(binding["packageKind"], "xcode-setup")
        self.assertFalse({"inventorySha256", "runtimeManifestSha256", "requestId"} & set(binding))
        for changes in ({"fixture":True}, {"request_id":"1"*32}, {"expected_inventory":"b"*64},
                {"expected_manifest":"c"*64}, {"selected_output":Path("/work/raw.txt")},
                {"package":Path("/work/package-mount/Install.pkg")}, {"run_attempt":"0"}):
            with self.subTest(changes=changes), self.assertRaises(stager.Refused):
                stager.installer_log_binding(SimpleNamespace(**{**vars(args), **changes}))
        body = (PRIVATE + b"\nPackageKit: MRK_XCODE_HOOK=hook=preinstall;stage=pre-exec\n"
            b"PackageKit: MRK_XCODE_SETUP_REFUSED=scope=child;stage=self;reason=binding\n"
            b'Error Domain=PKInstallErrorDomain Code=112 "' + PRIVATE + b'"\n'
            b"MRK_XCODE_SETUP_REFUSED=scope=child;stage=arbitrary-private;reason=binding\n"
            b"prefixMRK_XCODE_HOOK=hook=postinstall;stage=pre-exec\n")
        projected = stager.select_xcode_setup_log(body, binding)
        self.assertEqual(projected["hooks"]["observations"], [{"hook":"preinstall","stage":"pre-exec"}])
        self.assertEqual(projected["native"]["observations"], [{"scope":"child","stage":"self","reason":"binding"}])
        self.assertEqual(projected["errors"]["rows"], [{"domain":"PKInstallErrorDomain","code":112}])
        self.assertNotIn(PRIVATE.decode(), json.dumps(projected))
        capped = stager.select_xcode_setup_log(b"".join(
            ("MRK_XCODE_SETUP_REFUSED=scope=child;stage="+stage+";reason=binding\n").encode()
            for stage in ("input","source","self","carrier","selection")),binding)
        self.assertEqual(len(capped["native"]["observations"]),4)
        self.assertTrue(capped["errors"]["omitted"])
        for bad in (b"unrelated\n", b"Error Domain=PKInstallErrorDomain Code=112\n",
                    body[:-1], b"x"*(stager.LOG_INTERVAL_BYTES+1)):
            with self.assertRaises(stager.Refused): stager.select_xcode_setup_log(bad,binding)
        # Genuine bounded file reader/cursor logic reused; only fixed physical
        # APIs are modeled, never a native process or another host log.
        from unittest import mock
        tail = b"existing private log line\n"
        identity = dict(device=1,inode=2,mode=0o100644,uid=0,gid=0,links=1)
        cursor = stager.make_log_cursor(binding, identity, len(tail), tail, 0)
        args.command="installer-log-capture"; args.cursor=Path("/work/cursor.json")
        info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o100644,st_uid=0,st_gid=0,st_nlink=1,st_size=len(tail)+len(body))
        cursor_info=SimpleNamespace(st_uid=stager.os.getuid(),st_mode=0o100600)
        @contextlib.contextmanager
        def original(): yield 9,8,"install.log",info
        with mock.patch.object(stager,"parent") as parent, \
             mock.patch.object(stager,"read_at",return_value=(stager.canonical(cursor),cursor_info)), \
             mock.patch.object(stager,"installer_log_file",side_effect=original), \
             mock.patch.object(stager,"positioned_log_read",side_effect=[tail,body,tail]), \
             mock.patch.object(stager,"log_growth",return_value=0), \
             mock.patch.object(stager,"write_log_selection") as writer:
            parent.return_value.__enter__.return_value=(8,"cursor.json")
            result,status=stager.installer_log_diagnostic(args)
        self.assertEqual(status,0); writer.assert_not_called()
        self.assertEqual(result["projection"],projected)
        self.assertEqual(result["intervalScope"],"before-first-through-failed-installer")
        self.assertEqual(result["scriptOutputFinality"],"unestablished")
        self.assertNotIn("selectedData",result)
        self.assertNotIn(PRIVATE.decode(),json.dumps(result))
        self.assertNotIn(tail.decode().strip(),json.dumps(result))
        cli=["installer-log-cursor","--xcode-setup","--package",str(args.package),
             "--expected-source",args.expected_source,"--run-id",args.run_id,"--run-attempt",args.run_attempt]
        with mock.patch.object(stager,"installer_log_diagnostic",return_value=({"state":"unknown"},1)) as call, \
             mock.patch.object(stager,"print",create=True):
            self.assertEqual(stager.main(cli),1)
            self.assertTrue(call.call_args.args[0].xcode_setup)
            self.assertEqual(stager.installer_log_binding(call.call_args.args[0]),binding)

    def test_terminal_log_never_replaces_installer_or_unknown_owner_custody(self):
        stages = [{"scope":"child","stage":"self","reason":"binding"}]
        projection={"state":"observed-project-correlated","reason":None,
            "intervalScope":"before-first-through-failed-installer",
            "hooks":{"available":True,"observations":[{"hook":"preinstall","stage":"pre-exec"}]},
            "native":{"available":True,"observations":stages},
            "errors":{"rows":[{"domain":"PKInstallErrorDomain","code":112}],"omitted":False},"omitted":False}
        for index in (2,3):
            originals=[dict(role=r,entered=True,returned=True,capturesSettled=True,returncode=0)
                       for r in HELPER.XCODE_SETUP_VERIFY_ROLES[:index+1]]
            originals[-1]["returncode"]=75
            for fault in (None,"unreturned","unsettled","wrongrole","private","cursor-unavailable"):
                rows=copy.deepcopy(originals)
                rows.append(dict(role=HELPER.XCODE_SETUP_LOG_CAPTURE,entered=True,returned=True,
                    capturesSettled=True,returncode=0,setupLog=copy.deepcopy(projection)))
                if fault=="unreturned": rows[-1]["returned"]=False
                if fault=="unsettled": rows[-1]["capturesSettled"]=False
                if fault=="wrongrole": rows[-1]["role"]="unrelated"
                if fault=="private": rows[-1]["setupLog"]["native"]["observations"][0]["reason"]=PRIVATE.decode()
                if fault=="cursor-unavailable": rows[1]["returncode"]=1
                op=object.__new__(HELPER.Operation)
                op.__dict__.update(phase=HELPER.XCODE_SETUP_VERIFY,calls=rows,receipt={},errors=[],
                    credential_calls=[],credential_contexts=[])
                value=HELPER.failure_diagnostic(HELPER.Refused("original-nonzero-"+originals[-1]["role"]),operation=op)
                if fault=="wrongrole": self.assertIsNone(value["setupInstall"]);continue
                self.assertEqual(value["setupInstall"]["returncode"],75)
                self.assertEqual(value["setupInstall"]["role"],originals[-1]["role"])
                self.assertEqual(value["setupInstall"]["log"],projection if fault is None else None)
                self.assertNotIn(PRIVATE.decode(),json.dumps(value))
        # Worst-case finite rows still produce a bounded public line; trimming
        # changes only the projected copy and keeps the original exit/ledger.
        op=object.__new__(HELPER.Operation)
        rows=[dict(role=r,entered=True,returned=True,capturesSettled=True,returncode=0)
              for r in HELPER.XCODE_SETUP_VERIFY_ROLES[:3]]
        rows[-1].update(returncode=75,
            setupHooks={"available":True,"observations":[{"hook":h,"stage":s}
                for h in HELPER._SETUP_HOOKS for s in HELPER._SETUP_HOOK_STAGES]},
            setupDiagnostic={"available":True,"observations":[{"scope":"child","stage":s,"reason":"binding"}
                for s in ("source", "self", "carrier", "finality")]},
            installerErrors={"rows":[{"domain":d,"code":112} for d in HELPER._INSTALLER_ERROR_DOMAINS],"omitted":False})
        maximum=copy.deepcopy(projection)
        maximum.update(hooks=copy.deepcopy(rows[-1]["setupHooks"]),native=copy.deepcopy(rows[-1]["setupDiagnostic"]),
                       errors=copy.deepcopy(rows[-1]["installerErrors"]))
        rows.append(dict(role=HELPER.XCODE_SETUP_LOG_CAPTURE,entered=True,returned=True,capturesSettled=True,
                         returncode=0,setupLog=maximum))
        op.__dict__.update(phase=HELPER.XCODE_SETUP_VERIFY,calls=rows,receipt={},errors=[],credential_calls=[],credential_contexts=[])
        before=copy.deepcopy(op.__dict__); output=io.StringIO()
        with contextlib.redirect_stderr(output):
            HELPER.emit_failure_diagnostic(HELPER.Refused("original-nonzero-setup-installer-first"),
                phase=HELPER.XCODE_SETUP_VERIFY,target=HELPER.ARM_TARGET,operation=op)
        self.assertLessEqual(len(output.getvalue()),4096)
        self.assertEqual(json.loads(output.getvalue())["setupInstall"]["returncode"],75)
        self.assertEqual(op.__dict__,before)
