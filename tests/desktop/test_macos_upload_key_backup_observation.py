"""Backend-observer DATA/real-FD tests; never a native backup qualification.

All files below are tiny labelled INERT bytes (not keys, codes or ciphertext).
Process/native/provider ports are fake; Popen is prohibited. Tests exercise the
actual fixed parser, Fixtures FD/roster methods and current run_cases boundary.
They do not create native joins, picker receipts, AEAD proof or signing keys.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_macos_identity_current_runtime as current
import test_macos_upload_key_observation as data


A, M, B, U = data.M, current.M, data.M.BACKUP, data.U
BINDING, CASE = data.BINDING, B.SCOPE


def report(*, missing=False):
    if missing:
        return data.report(missing=True)
    source = data.report()
    return {**dict.fromkeys(B.TRUE_FIELDS, True), **dict.fromkeys(B.FALSE_FIELDS, False),
        "mechanism": "generated-upload-key-backup-v1", "execution": "executed", "testResult": "positive",
        "initializeHelper": source["initializeHelper"], "storage": source["storage"],
        "generated": source["generated"], "restoredInitializeHelper": deepcopy(source["initializeHelper"]),
        "restoredStorage": deepcopy(source["storage"]), "originalCount": 13,
        "rowRetirement": "disposable-hosted-account-only"}


def frame(*, missing=False):
    value = A.expected_result(BINDING, CASE)
    value["vaultHelper"] = report(missing=missing)
    return value


class Files(A.Fixtures):
    """Actual existing FD methods, only source/runtime/native ports inert."""
    def __init__(self, directory):
        super().__init__(BINDING, os.getuid(), os.getgid(), CASE)
        self.events = []
        self.runtime_admitted = False
        self.runtime_checks = 0
        self.runtime_failure = None
        self.vault_namespace = self._open(str(directory), directory=True)
        parent = self._mkdir(self.vault_namespace, CASE)
        self.vault_parents[CASE] = parent
        self.base = Path(directory) / CASE
        self.source = self.base / B.APP / "credential-vault-v1"
        self.restored = self.base / "restored" / B.APP / "credential-vault-v1"
        self.backup = self.base / "backup" / ("mrk-backup-" + "c" * 32 + ".mrkbackup")
        self.code = self.base / "recovery" / ("mrk-recovery-" + "c" * 32 + ".mrkcode")
        B.prepare(self)

    def prepare(self):
        self.events.append("inert-source-prepare")

    def _vault_namespace_current(self):
        self._roster(self.vault_namespace, (CASE,), "inert-native-namespace")
        B.namespace_current(self)

    def before_call(self, case):
        if case != CASE:
            raise AssertionError("wrong fixed case")
        self.events.append("before")
        self.case, self.stage = case, "before-invocation"
        B.before_call(self)

    def readback(self, case):
        if case != CASE or self.inflight or not self.last_returned:
            raise AssertionError("readback before original return")
        self.events.append("source-readback")
        return {"inertSourceComparison": True}

    def recovery_runtime_paths(self):
        if not self.runtime_admitted or self.inflight:
            raise AssertionError("runtime check without original return/admission")
        self.runtime_checks += 1
        self.events.append(("runtime-post", self.runtime_checks))
        if self.runtime_failure == self.runtime_checks:
            raise A.Refused("inert-current-runtime-changed")
        return "INERT", "INERT"

    def create_private_data(self, *, missing=False):
        """Fake original port writes labelled regular bytes, no crypto/code."""
        def vault(parent, identifier=None):
            with ExitStack() as stack:
                app = stack.enter_context(self._temporary(self._mkdir(parent, B.APP)))
                store = stack.enter_context(self._temporary(self._mkdir(app, "credential-vault-v1")))
                for name, size in (("vault-lock", 0), ("initialization-reservation", 48), ("vault-header", 104)):
                    self._write(store, name, (b"INERT-NOT-PRIVATE-" * 8)[:size])
                if identifier:
                    self._write(store, "record-" + identifier * 32, b"INERT-RECORD" * 24)
                if identifier == "a":
                    self._write(app, "service-v1.reservation", b"X" * (len(b"MRK service root v1\n") + 16))
                    service = stack.enter_context(self._temporary(self._mkdir(app, "service-v1")))
                    reservation = b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n"
                    for name, body in (("owner.lock", b""), ("reservation", reservation),
                        ("projects.state", b"X" * 53), ("credential-references.state", b"Y" * 53),
                        ("version-allocations.state", b"Z" * 52)):
                        self._write(service, name, body)
        vault(self.vault_parents[CASE], None if missing else "a")
        if not missing:
            self._write(self.upload_backup_parents["backup"], self.backup.name, b"INERT-NOT-ENCRYPTED" * 16)
            self._write(self.upload_backup_parents["recovery"], self.code.name, b"X" * B.CODE_BYTES)
            vault(self.upload_backup_parents["restored"], "b")

    def close(self):
        self.events.append("fixture-close")
        super().close()


class GeneratedBackupTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("process/native execution forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-generated-backup-inert-")
        self.addCleanup(temporary.cleanup)
        fixtures = Files(temporary.name)
        def close_test_ports():
            # No actual child ever ran. This only closes our fake-port test
            # FDs during teardown, never supplies a production return receipt.
            fixtures.inflight = False
            A.Fixtures.close(fixtures)
        self.addCleanup(close_test_ports)
        return fixtures

    def ready(self):
        fixtures = self.fixture()
        fixtures.before_call(CASE)
        fixtures.create_private_data()
        fixtures.last_returned = True  # INERT original caller return.
        return fixtures

    def test_only_explicit_current_singleton_and_fixed_isolated_namespace(self):
        env = {**current.environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}
        self.assertEqual(M.BACKUP_SCOPE, CASE)
        self.assertEqual(M.observation_scope(env, CASE), CASE)
        self.assertEqual(M.arguments(["--target", M.TARGET, "--scope", CASE]), CASE)
        self.assertEqual(A.selected_cases(CASE), (CASE,))
        self.assertEqual(A.case_timeout(CASE), 495)
        self.assertEqual(B.fixture_path(BINDING, "/Users/inert").parts[-3:],
            (f"mrk-macos-aqua-upload-key-{BINDING.source}-123-1-{CASE}", CASE, B.APP))
        self.assertEqual(A.fixture_data(CASE, False), A.fixture_data(CASE, True))
        self.assertEqual(A.fixture_data(CASE, False), A.fixture_data(U.CASES[0], False))
        for scope in ("backup", "../" + CASE, CASE + "/restored", "all", "", None):
            with self.subTest(scope=scope), self.assertRaises(M.Refused):
                M.observation_scope(env, scope)
        for native in (M.SCOPE, CASE, "disabled", None):
            with self.subTest(native=native), self.assertRaises(M.Refused):
                M.observation_scope({**env, "MRK_MACOS_NATIVE_SCOPE": native}, CASE)
        with self.assertRaises(A.Refused):
            A.argument_scope(["--scope", CASE])  # No historical supplier entry.
        for case in U.CASES:
            self.assertEqual(A.selected_cases(case), (case,))
            self.assertNotEqual(B.fixture_path(BINDING, "/Users/inert"), U.fixture_path(BINDING, "/Users/inert", case))
        self.assertEqual(A.selected_cases(A.COLD.SCOPE), A.COLD.CASES)

    def test_actual_runtime_admission_only_exact_unstarted_tuple_before_io(self):
        fixtures = A.Fixtures(BINDING, 501, 20, CASE)
        sentinel = RuntimeError("inert stop before runtime source IO")
        with patch.object(A, "_gate_load_stager", side_effect=sentinel) as load, self.assertRaises(RuntimeError) as raised:
            fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(current.environment()["MRK_MACOS_WORK"]),
                                                  application_source=BINDING.source)
        self.assertIs(raised.exception, sentinel)
        load.assert_called_once()
        self.assertFalse(fixtures.fds)
        for cases, live in (((CASE, U.CASES[0]), False), ((CASE, CASE), False), (("backup",), False), ((CASE,), True)):
            fixtures.cases, fixtures.inflight = cases, live
            with self.subTest(cases=cases, live=live), patch.object(A, "_gate_load_stager") as load, self.assertRaises(A.Refused):
                fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(current.environment()["MRK_MACOS_WORK"]),
                                                      application_source=BINDING.source)
            load.assert_not_called()

    def test_real_complete_report_parser_does_not_invent_native_backup_or_new_receipts(self):
        for missing in (False, True):
            value = frame(missing=missing)
            self.assertEqual(A.parse_result(data.captured(value), b"", BINDING, CASE), value)
        changes = [(key, False) for key in B.TRUE_FIELDS] + [(key, True) for key in B.FALSE_FIELDS]
        changes += [("originalCount", 9), ("originalCount", True), ("path", "/private/fake"),
                    ("recordId", "a" * 32), ("recoveryCode", "INERT"), ("testResult", "not-executed")]
        for key, new in changes:
            value = frame()
            value["vaultHelper"][key] = new
            with self.subTest(key=key), self.assertRaises((ValueError, A.Refused)):
                A.parse_result(data.captured(value), b"", BINDING, CASE)
        for helper in ("initializeHelper", "restoredInitializeHelper"):
            value = frame()
            value["vaultHelper"][helper]["applicationCandidateConstructed"] = False
            with self.subTest(helper=helper), self.assertRaises((ValueError, A.Refused)):
                A.parse_result(data.captured(value), b"", BINDING, CASE)
        for storage in ("storage", "restoredStorage"):
            value = frame()
            value["vaultHelper"][storage]["durability"] = [True, False]
            with self.subTest(storage=storage), self.assertRaises((ValueError, A.Refused)):
                A.parse_result(data.captured(value), b"", BINDING, CASE)
        value = frame()
        value["vaultHelper"]["generated"]["producer"]["tailClosed"] = False
        with self.assertRaises((ValueError, A.Refused)):
            A.parse_result(data.captured(value), b"", BINDING, CASE)

    def test_original_parents_are_exclusive_one_attempt_and_never_adopted(self):
        fixtures = self.fixture()
        before = dict(fixtures.upload_backup_parents)
        with self.assertRaises(ValueError):
            B.prepare(fixtures)
        self.assertEqual(before, fixtures.upload_backup_parents)
        fixtures._write(before["backup"], "foreign", b"inert")
        with self.assertRaises(A.Refused):
            fixtures.before_call(CASE)
        self.assertTrue(fixtures.upload_backup_entered)
        # Even clearing our labelled file cannot rearm a refused attempt.
        (fixtures.base / "backup" / "foreign").unlink()
        with self.assertRaises(ValueError):
            fixtures.before_call(CASE)

    def test_pair_names_require_both_exact_outputs_no_pending_or_extra_adoption(self):
        left = "mrk-backup-" + "a" * 32 + ".mrkbackup"
        right = "mrk-recovery-" + "a" * 32 + ".mrkcode"
        self.assertEqual(B.pair_names((left,), (right,)), (left, right))
        for first, second in (((), (right,)), ((left, "extra"), (right,)),
            ((left + ".pending",), (right,)), ((left,), (right.replace("a" * 32, "b" * 32),)),
            ((left.replace("a" * 32, "0" * 32),), (right.replace("a" * 32, "0" * 32),)),
            ((left,), ("../" + right,)), ([left], (right,))):
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                B.pair_names(first, second)

    def test_real_fd_readback_is_metadata_only_and_leaves_all_private_outputs(self):
        fixtures = self.ready()
        with patch.object(os, "pread", side_effect=AssertionError("no private-body read in fixture")):
            observed = B.readback(fixtures, report(), U)
        facts = observed["uploadKeyGeneratedBackup"]
        self.assertTrue(facts["privatePairMetadataObserved"])
        self.assertTrue(facts["freshEncryptedRecordPresent"])
        self.assertFalse(facts["privateContentsExported"])
        self.assertGreater(facts["retainedPrivateFileBytes"], 0)
        self.assertNotIn("record-", json.dumps(observed))
        self.assertNotIn("mrk-recovery-", json.dumps(observed))
        self.assertEqual(fixtures.vault_completed, {CASE})
        with self.assertRaises(ValueError):
            B.readback(fixtures, report(), U)
        fixtures.close()
        self.assertFalse(fixtures.fds)
        for path in (fixtures.backup, fixtures.code, fixtures.source / ("record-" + "a" * 32),
                     fixtures.restored / ("record-" + "b" * 32)):
            self.assertTrue(path.is_file())

    def test_changed_rosters_sizes_aliases_and_target_identity_refuse_without_completion(self):
        for change in ("pair-id", "pending", "extra", "hardlink", "symlink", "code-size", "mode", "record-id", "target-extra"):
            with self.subTest(change=change):
                fixtures = self.ready()
                if change == "pair-id":
                    fixtures.code.rename(fixtures.code.with_name(fixtures.code.name.replace("c" * 32, "d" * 32)))
                elif change == "pending":
                    fixtures.backup.rename(fixtures.backup.with_name(fixtures.backup.name + ".pending"))
                elif change == "extra":
                    (fixtures.backup.parent / "extra").write_bytes(b"INERT")
                elif change == "hardlink":
                    os.link(fixtures.backup, fixtures.base / "inert-alias")
                elif change == "symlink":
                    fixtures.code.unlink()  # Only the labelled file we made.
                    fixtures.code.symlink_to(fixtures.backup)
                elif change == "code-size":
                    fixtures.code.write_bytes(b"X" * (B.CODE_BYTES + 1))
                elif change == "mode":
                    fixtures.backup.chmod(0o644)
                elif change == "record-id":
                    (fixtures.restored / ("record-" + "b" * 32)).rename(fixtures.restored / ("record-" + "a" * 32))
                else:
                    (fixtures.restored / "extra").write_bytes(b"INERT")
                with self.assertRaises((ValueError, A.Refused, OSError)):
                    B.readback(fixtures, report(), U)
                self.assertFalse(fixtures.vault_completed)

    def test_lost_or_early_readback_and_unknown_close_cannot_mark_completed(self):
        fixtures = self.ready()
        for inflight, returned, close_errors in ((True, False, 0), (False, False, 0), (False, True, 1)):
            fixtures.inflight, fixtures.last_returned, fixtures.close_errors = inflight, returned, close_errors
            with self.subTest(inflight=inflight, returned=returned, close=close_errors), self.assertRaises(ValueError):
                B.readback(fixtures, report(), U)
            self.assertFalse(fixtures.vault_completed)
        fixtures.inflight, fixtures.close_errors = False, 0

    def execute(self, *, behavior="positive", post=None, close_error=None):
        fixtures = self.fixture()
        fixtures.runtime_failure = post
        calls, errors, events = [], [], fixtures.events
        missing = behavior == "missing"
        original_error = RuntimeError("inert original return lost")
        value = frame(missing=missing)
        def admit(*args):
            fixtures.runtime_admitted = True
            M._current(A, fixtures)
        def original(argv, **options):
            self.assertEqual(argv, [A.EXECUTABLE, CASE])
            self.assertTrue(fixtures.inflight)
            self.assertEqual(options["timeout"], 495)
            self.assertEqual(options["output_limit"], A.OUTPUT_LIMIT)
            self.assertEqual(options["cwd"], BINDING.root(upload_key=CASE) / "state" / CASE)
            calls.append(CASE)
            events.append("inert-invocation")
            fixtures.create_private_data(missing=missing)
            if behavior == "lost":
                raise original_error
            if behavior == "foreign":
                return SimpleNamespace(args=argv, returncode=0, stdout=data.captured(value), stderr=b"")
            return subprocess.CompletedProcess(argv, 1 if behavior == "failed" else 0,
                b"malformed\n" if behavior == "malformed" else data.captured(value), b"")
        def diagnose(error, owner, held):
            self.assertIs(held, fixtures)
            errors.append(error)
            return {"inertOnly": True, "unknown": fixtures.inflight}
        actual_emit = A.emit_record
        def emit(value, output):
            events.append(("emit", value.get("case", value.get("type"))))
            actual_emit(value, output)
        with ExitStack() as stack:
            stack.enter_context(patch.object(A, "Fixtures", return_value=fixtures))
            stack.enter_context(patch.object(M, "_admit_runtime", side_effect=admit))
            stack.enter_context(patch.object(A, "_gate_recheck", return_value=None))
            stack.enter_context(patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=original)))
            stack.enter_context(patch.object(A, "diagnostic", side_effect=diagnose))
            stack.enter_context(patch.object(A, "emit_record", side_effect=emit))
            if close_error is not None:
                real_close = fixtures.close
                def fail_close():
                    real_close()
                    raise close_error
                stack.enter_context(patch.object(fixtures, "close", side_effect=fail_close))
            stdout = stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            # Environment DATA is the existing hosted-user fixture; only our
            # temporary FD ownership above uses the actual local test uid.
            status = M._run(A, BINDING, 501, 20, "runner", Path("/unused"),
                {**current.environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}, scope=CASE)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        return status, fixtures, calls, errors, rows, original_error

    def test_current_original_return_readback_post_and_close_precede_only_completion(self):
        status, fixtures, calls, errors, rows, _ = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(calls, [CASE])
        self.assertFalse(errors)
        self.assertEqual(rows[-1]["type"], "macos-upload-key-backup-current-complete")
        self.assertTrue(rows[-1]["backupRoundtrip"])
        self.assertFalse(rows[-1]["cleanProcessRestart"])
        self.assertFalse(rows[-1]["physicalPickerQualified"])
        events = fixtures.events
        self.assertLess(events.index("inert-invocation"), events.index("source-readback"))
        self.assertLess(events.index("source-readback"), events.index(("emit", CASE)))
        self.assertLess(events.index("fixture-close"), events.index(("emit", rows[-1]["type"])))
        self.assertFalse(fixtures.fds)

    def test_missing_is_78_only_after_real_parser_readback_and_close_not_unknown(self):
        status, fixtures, calls, errors, rows, _ = self.execute(behavior="missing")
        self.assertEqual(status, 78)
        self.assertEqual(calls, [CASE])
        self.assertFalse(errors)
        self.assertEqual(rows[-1]["type"], "macos-upload-key-current-unexecuted")
        self.assertFalse(any(row.get("type", "").endswith("complete") for row in rows))
        self.assertFalse(fixtures.fds)
        self.assertFalse(fixtures.backup.exists())
        for behavior in ("lost", "foreign", "failed", "malformed"):
            with self.subTest(behavior=behavior):
                status, fixtures, calls, errors, rows, original = self.execute(behavior=behavior)
                self.assertEqual(status, 1)
                self.assertEqual(calls, [CASE])
                self.assertTrue(errors)
                self.assertFalse(any(row.get("type", "").endswith(("complete", "unexecuted")) for row in rows))
                if behavior in ("lost", "foreign"):
                    self.assertTrue(fixtures.inflight)
                    self.assertNotIn("fixture-close", fixtures.events)
                if behavior == "lost":
                    self.assertIs(errors[0], original)

    def test_current_runtime_or_close_failure_preserves_primary_and_no_completion(self):
        late = OSError("inert original fixture close error")
        # Checks: admission1, pre-call2, run_cases3, emit4, final5.
        for options in ({"post": 2}, {"post": 4}, {"post": 5}, {"close_error": late},
                        {"behavior": "failed", "close_error": late}):
            with self.subTest(options=options):
                status, fixtures, calls, errors, rows, _ = self.execute(**options)
                self.assertEqual(status, 1)
                self.assertEqual(calls, [] if options.get("post") == 2 else [CASE])
                self.assertTrue(errors)
                self.assertFalse(any(row.get("type", "").endswith("complete") for row in rows))
                self.assertIn("fixture-close", fixtures.events)
                if options.get("behavior") == "failed":
                    self.assertIsNot(errors[0], late)
                    self.assertEqual(str(errors[0]), "app-return")
                elif "close_error" in options:
                    self.assertIs(errors[0], late)


if __name__ == "__main__":
    unittest.main()
