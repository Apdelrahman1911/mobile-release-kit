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
        op.__dict__.update(phase='package-install', prepared_binding=None, prepared_staging=False, credential_known=lambda: True,
            credential_failed=False, credential_active=None, removal_final_active=lambda: False,
            errors=[], stager_io_pending=None, android_support=None, store_signing=None,
            app_absence=None, update=None, removal=False, removal_recorded_role=lambda role: role,
            owner=SimpleNamespace(run_owned=owned), work=Path('/synthetic-unopened-work'),
            checkout=Path('/synthetic-unopened-source'), publish=publish,
            calls=[{'role': role, 'entered': True, 'returned': True, 'capturesSettled': True, 'returncode': 0}
                   for role in HELPER._PACKAGE_DIAGNOSTIC_ROLES[:13]],
            receipt={}, credential_calls=[], credential_contexts=[], installer_entered=False,
            installer_zero=False, installation_readback=False)
        return op

    def invoke(self, op, role='installer'):
        return HELPER.Operation.call(op, role, ['fixed-' + role], {}, cwd=op.work, timeout=20, limit=256*1024)

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
                else:
                    self.assertIsNone(slots['installer']['markers'])
                self.assertFalse(value['packageInstall']['systemServiceExitClaimed'])
                self.assertNotIn(PRIVATE.decode(), json.dumps(value))
                self.assertNotIn('a' * 64, json.dumps(value))

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
            ('acl-refused', 'acl-refusal'), ('export-acl-refused', 'acl-refusal'),
            ('worker-self-image', 'worker-image-refusal'), (PRIVATE.decode(), 'unclassified')):
            with self.subTest(category=category):
                reason_hash = hashlib.sha256(reason.encode()).hexdigest()
                capture = ('MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + reason_hash +
                    ';exit=1;originals=1;native=0;timely=1;unknown=1\n').encode()
                value = HELPER.installer_markers(capture, PRIVATE)
                self.assertEqual(value['parent'][0]['category'], category)
                self.assertNotIn(reason_hash, json.dumps(value))
                self.assertNotIn(PRIVATE.decode(), json.dumps(value))
                value['parent'][0]['category'] = PRIVATE.decode()
                self.assertIsNone(HELPER.installer_markers_data(value))


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
