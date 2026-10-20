"""Cold-restart orchestration and real bounded FD tests with INERT process ports.

No JKS, Keychain, native app, subprocess, network or Store is used. Small regular
files contain labelled synthetic bytes, not credentials. CompletedProcess and
all native report bodies are explicitly DATA fixtures: passing these tests does
not prove a native quit, generation, lookup, assessment, Bind or cold restart.
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


A, M, C = data.M, current.M, data.M.COLD
BINDING = data.BINDING


def reopen_report():
    return {"mechanism": "fresh-process-upload-key-reuse-v1", "normalGenerationEnabled": False,
        "execution": "executed", "testResult": "positive", "openedExisting": True, "initialized": False,
        "generationAttempted": False, "lookupHelper": A._expected_vault_original("lookup"),
        "inventoryRows": 1, "authenticatedStoredRead": True, "explicitlyBoundSavedKey": True,
        "originalCount": 6, "allOriginalsSettled": True, "finalDocumentEmpty": True,
        "automaticallyAssigned": False, "backupCreated": False, "releaseSigningQualified": False,
        "physicalMacEvidence": False, "privateContentsExported": False,
        "rowRetirement": "disposable-hosted-account-only"}


def frame(case, *, missing=False):
    value = A.expected_result(BINDING, case)
    value["vaultHelper"] = data.report(missing=missing) if case == C.PRODUCE else reopen_report()
    return value


class Files(A.Fixtures):
    """Real same Fixtures FD methods; source/process/provider ports are inert."""
    def __init__(self, directory):
        super().__init__(BINDING, os.getuid(), os.getgid(), C.SCOPE)
        self.events = []
        self.runtime_admitted = False
        self.runtime_failure = None
        self.vault_namespace = self._open(str(directory), directory=True)
        parent = self._mkdir(self.vault_namespace, C.PROJECT)
        self.vault_parents = dict.fromkeys(C.CASES, parent)
        self.private_directory = Path(directory) / C.PROJECT / C.APP
        self.record_path = self.private_directory / "credential-vault-v1" / ("record-" + "a" * 32)

    def prepare(self):
        self.events.append("prepare-inert-source")

    def _vault_namespace_current(self):
        self._roster(self.vault_namespace, (C.PROJECT,), "inert-native-namespace")
        for case in C.CASES:
            self._named(self.vault_namespace, C.PROJECT, self.vault_parents[case], 0o700)
            self._roster(self.vault_parents[case], (C.APP,) if C.PRODUCE in self.vault_completed else (),
                         "inert-native-parent")

    def before_call(self, case):
        self.events.append(("before", case))
        self.case, self.stage = case, "before-invocation"
        self.upload_cold.before_call(self, case)

    def readback(self, case):
        if self.inflight or not self.last_returned:
            raise AssertionError("inert source read before original return")
        self.events.append(("source-readback", case))
        return {"inertSourceComparison": True}

    def recovery_runtime_paths(self):
        if not self.runtime_admitted or self.inflight:
            raise AssertionError("inert runtime check without admission/return")
        pair = self.upload_cold
        cut = (pair.entered, pair.readbacks, pair.emitted)
        self.events.append(("runtime-post", cut))
        if self.runtime_failure == cut:
            raise A.Refused("inert-runtime-post-changed")
        return "INERT", "INERT"

    def create_private_data(self):
        """Labelled fake bytes only, written by the inert original-call port."""
        with ExitStack() as stack:
            app = stack.enter_context(self._temporary(self._mkdir(self.vault_parents[C.PRODUCE], C.APP)))
            vault = stack.enter_context(self._temporary(self._mkdir(app, "credential-vault-v1")))
            for name, size in (("vault-lock", 0), ("initialization-reservation", 48),
                               ("vault-header", 104), ("record-" + "a" * 32, 257)):
                self._write(vault, name, (b"inert-not-a-key-" * (size // 16 + 1))[:size])
            self._write(app, "service-v1.reservation", b"X" * (len(b"MRK service root v1\n") + 16))
            service = stack.enter_context(self._temporary(self._mkdir(app, "service-v1")))
            reservation = b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n"
            for name, body in (("owner.lock", b""), ("reservation", reservation),
                               ("projects.state", b"X" * 53), ("credential-references.state", b"Y" * 53),
                               ("version-allocations.state", b"Z" * 52)):
                self._write(service, name, body)

    def close(self):
        self.events.append("original-fixture-close")
        super().close()


class ColdRestartTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("native/process execution forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-cold-inert-")
        self.addCleanup(temporary.cleanup)
        fixtures = Files(temporary.name)
        def release_test_data():
            # There was NO process in these tests. Teardown of our inert port
            # isn't returned to production as a join or cancellation receipt.
            fixtures.inflight = False
            try:
                A.Fixtures.close(fixtures)
            except BaseException:
                if fixtures.fds:
                    raise
        self.addCleanup(release_test_data)
        return fixtures

    def first_readback(self, fixtures):
        fixtures.before_call(C.PRODUCE)
        fixtures.create_private_data()
        fixtures.last_returned = True  # INERT caller contract, not native proof.
        return fixtures.upload_cold.readback(fixtures, C.PRODUCE, data.report())

    def test_exact_current_pair_and_same_private_namespace_no_historical_entry(self):
        env = {**current.environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}
        self.assertEqual(M.COLD_SCOPE, C.SCOPE)
        self.assertEqual(M.arguments(["--target", M.TARGET, "--scope", C.SCOPE]), C.SCOPE)
        self.assertEqual(M.observation_scope(env, C.SCOPE), C.SCOPE)
        self.assertEqual(A.selected_cases(C.SCOPE), C.CASES)
        self.assertEqual([A.case_timeout(case) for case in C.CASES], [495, 495])
        self.assertEqual(C.OBSERVER_SECONDS, 480)
        self.assertEqual(C.fixture_path(BINDING, "/Users/inert", C.PRODUCE),
                         C.fixture_path(BINDING, "/Users/inert", C.REOPEN))
        self.assertEqual(C.fixture_path(BINDING, "/Users/inert", C.PRODUCE).parts[-3:],
                         (f"mrk-macos-aqua-upload-key-{BINDING.source}-123-1-{C.SCOPE}", C.PROJECT, C.APP))
        self.assertEqual(A.fixture_data(C.PRODUCE, False), A.fixture_data(C.REOPEN, True))
        for scope in (*C.CASES, "upload-key-cold", "../" + C.SCOPE, "", None):
            with self.subTest(scope=scope), self.assertRaises(M.Refused):
                M.observation_scope(env, scope)
        for native in (M.SCOPE, C.SCOPE, "disabled", None):
            with self.subTest(native=native), self.assertRaises(M.Refused):
                M.observation_scope({**env, "MRK_MACOS_NATIVE_SCOPE": native}, C.SCOPE)
        with self.assertRaises(A.Refused):
            A.argument_scope(["--scope", C.SCOPE])  # Not the historical supplier/main.
        for case in A.UPLOAD.CASES:
            self.assertEqual(A.selected_cases(case), (case,))
            self.assertEqual(A.case_timeout(case), 495)
            self.assertNotEqual(A.UPLOAD.fixture_path(BINDING, "/Users/inert", case),
                                C.fixture_path(BINDING, "/Users/inert", C.PRODUCE))

    def test_actual_normal_runtime_tuple_gate_rejects_reversed_partial_or_live_pair(self):
        sentinel = RuntimeError("inert stop before runtime source IO")
        fixtures = A.Fixtures(BINDING, 501, 20, C.SCOPE)
        with patch.object(A, "_gate_load_stager", side_effect=sentinel) as load, self.assertRaises(RuntimeError) as raised:
            fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(current.environment()["MRK_MACOS_WORK"]),
                                                  application_source=BINDING.source)
        self.assertIs(raised.exception, sentinel)
        load.assert_called_once()
        self.assertFalse(fixtures.fds)
        for cases, live in ((C.CASES[::-1], False), ((C.PRODUCE,), False), ((C.REOPEN,), False), (C.CASES, True)):
            fixtures.cases, fixtures.inflight = cases, live
            with self.subTest(cases=cases, live=live), patch.object(A, "_gate_load_stager") as load, self.assertRaises(A.Refused):
                fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(current.environment()["MRK_MACOS_WORK"]),
                                                      application_source=BINDING.source)
            load.assert_not_called()

    def test_complete_native_report_parser_never_substitutes_missing_lookup_or_private_authority(self):
        for case in C.CASES:
            value = frame(case)
            self.assertEqual(A.parse_result(data.captured(value), b"", BINDING, case), value)
        for key, value in (("initialized", True), ("generationAttempted", True), ("allOriginalsSettled", False),
                           ("authenticatedStoredRead", False), ("explicitlyBoundSavedKey", False),
                           ("inventoryRows", True), ("originalCount", 9), ("recordId", "a" * 32)):
            body = frame(C.REOPEN)
            body["vaultHelper"][key] = value
            with self.subTest(key=key), self.assertRaises((ValueError, A.Refused)):
                A.parse_result(data.captured(body), b"", BINDING, C.REOPEN)
        body = frame(C.REOPEN)
        body["vaultHelper"]["lookupHelper"]["applicationCandidateConstructed"] = False
        with self.assertRaises((ValueError, A.Refused)):
            A.parse_result(data.captured(body), b"", BINDING, C.REOPEN)
        with self.assertRaises((ValueError, A.Refused)):
            A.parse_result(data.captured(frame(C.PRODUCE, missing=True)), b"", BINDING, C.PRODUCE)
        body = frame(C.PRODUCE)
        body["vaultHelper"]["generated"]["producer"]["inspectorJoined"] = False
        with self.assertRaises((ValueError, A.Refused)):
            A.parse_result(data.captured(body), b"", BINDING, C.PRODUCE)

    def test_readback_alone_does_not_release_second_call_and_original_book_cannot_be_replaced(self):
        fixtures = self.fixture()
        result = self.first_readback(fixtures)
        pair = fixtures.upload_cold
        self.assertEqual((pair.entered, pair.readbacks, pair.emitted), (1, 1, 0))
        with self.assertRaises(ValueError):
            pair.before_call(fixtures, C.REOPEN)
        with self.assertRaises(ValueError):
            C.Pair().after_emit(fixtures, C.PRODUCE)
        with self.assertRaises(ValueError):
            pair.finished(fixtures)
        self.assertNotIn("record-", json.dumps(result))
        pair.after_emit(fixtures, C.PRODUCE)
        with self.assertRaises(ValueError):
            pair.after_emit(fixtures, C.PRODUCE)
        pair.before_call(fixtures, C.REOPEN)
        second = pair.readback(fixtures, C.REOPEN, reopen_report())
        self.assertTrue(second["uploadKeyColdRestart"]["ciphertextAndHeaderUnchanged"])
        pair.after_emit(fixtures, C.REOPEN)
        pair.finished(fixtures)
        self.assertEqual((len(pair.directories), len(pair.files)), (3, 10))
        with self.assertRaises(ValueError):
            pair.before_call(fixtures, C.REOPEN)
        fixtures.close()
        self.assertFalse(fixtures.fds)
        self.assertTrue(fixtures.record_path.is_file())  # Production keeps the key/intent.

    def test_retained_ciphertext_header_control_and_complete_roster_drift_refuse_reopen(self):
        for change in ("record-body", "header-body", "state-body", "extra-record", "replace", "symlink"):
            with self.subTest(change=change):
                fixtures = self.fixture()
                self.first_readback(fixtures)
                fixtures.upload_cold.after_emit(fixtures, C.PRODUCE)
                vault = fixtures.record_path.parent
                if change == "record-body":
                    fixtures.record_path.write_bytes(b"B" * 257)
                elif change == "header-body":
                    (vault / "vault-header").write_bytes(b"B" * 104)
                elif change == "state-body":
                    (fixtures.private_directory / "service-v1" / "credential-references.state").write_bytes(b"B" * 53)
                elif change == "extra-record":
                    (vault / ("record-" + "b" * 32)).write_bytes(b"B" * 257)
                elif change == "replace":
                    swap = vault / "inert-swap"
                    swap.write_bytes(fixtures.record_path.read_bytes())
                    os.chmod(swap, 0o600)
                    os.replace(swap, fixtures.record_path)
                else:
                    fixtures.record_path.unlink()  # Only our known synthetic test file.
                    fixtures.record_path.symlink_to(vault / "vault-header")
                with self.assertRaises((ValueError, A.Refused)):
                    fixtures.upload_cold.before_call(fixtures, C.REOPEN)
                # Attempt remains spent; exact late restoration cannot rearm it.
                self.assertEqual(fixtures.upload_cold.entered, 2)

    def test_private_byte_limit_precedes_first_read_and_hash_reads_have_fixed_chunks(self):
        fixtures = self.fixture()
        fixtures.before_call(C.PRODUCE)
        fixtures.create_private_data()
        record = fixtures._open(str(fixtures.record_path))
        parent = fixtures._open(str(fixtures.record_path.parent), directory=True)
        original = fixtures._upload_signature(record)
        with patch.object(C.os, "pread", wraps=os.pread) as read:
            self.assertEqual(len(C._hash(fixtures, parent, fixtures.record_path.name, record, original, 257, C.RECORD_LIMIT)), 32)
            self.assertTrue(all(call.args[1] <= 65536 for call in read.call_args_list))
        for low, high, original_override in ((258, C.RECORD_LIMIT, original), (0, 256, original),
                                             (0, C.RECORD_LIMIT, (*original[:6], C.RECORD_LIMIT + 1, *original[7:]))):
            with self.subTest(low=low, high=high), patch.object(C.os, "pread") as read, self.assertRaises(ValueError):
                C._hash(fixtures, parent, fixtures.record_path.name, record, original_override, low, high)
            read.assert_not_called()

    def execute(self, *, first="positive", second="positive", post=None, drift=False, emit_error=False, close_error=None):
        fixtures = self.fixture()
        fixtures.runtime_failure = post
        events, errors = fixtures.events, []
        frames = {case: frame(case, missing=(case == C.PRODUCE and first == "missing")) for case in C.CASES}
        first_error = RuntimeError("inert original command return lost")
        calls = []

        def admit(*args):
            events.append("admit-current-runtime")
            fixtures.runtime_admitted = True
            M._current(A, fixtures)

        def original(argv, **options):
            case = argv[1]
            if argv != [A.EXECUTABLE, C.CASES[len(calls)]] or not fixtures.inflight:
                raise AssertionError("wrong original invocation")
            self.assertEqual(options["timeout"], 495)
            self.assertEqual(options["output_limit"], A.OUTPUT_LIMIT)
            self.assertEqual(options["cwd"], BINDING.root(upload_key=C.SCOPE) / "state" / case)
            calls.append(case)
            events.append(("inert-original", case))
            if case == C.PRODUCE:
                fixtures.create_private_data()
            behavior = first if case == C.PRODUCE else second
            if behavior == "lost":
                raise first_error
            if behavior == "foreign":
                return SimpleNamespace(args=argv, returncode=0, stdout=data.captured(frames[case]), stderr=b"")
            return subprocess.CompletedProcess(argv, 1 if behavior == "failed" else 0,
                b"malformed\n" if behavior == "malformed" else data.captured(frames[case]), b"")

        real_emit = A.emit_record
        def emit(value, output):
            events.append(("emit", value.get("case", value.get("type"))))
            if value.get("case") == C.PRODUCE:
                if drift:
                    fixtures.record_path.write_bytes(b"B" * 257)
                if emit_error:
                    raise OSError("inert report output not returned")
            real_emit(value, output)

        def diagnose(error, owner, original_fixtures):
            self.assertIs(original_fixtures, fixtures)
            errors.append(error)
            return {"inertOnly": True, "unknown": fixtures.inflight}

        with ExitStack() as stack:
            stack.enter_context(patch.object(A, "Fixtures", return_value=fixtures))
            stack.enter_context(patch.object(M, "_admit_runtime", side_effect=admit))
            stack.enter_context(patch.object(A, "_gate_recheck", side_effect=lambda _: None))
            stack.enter_context(patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=original)))
            stack.enter_context(patch.object(A, "emit_record", side_effect=emit))
            stack.enter_context(patch.object(A, "diagnostic", side_effect=diagnose))
            if close_error is not None:
                original_close = fixtures.close
                def close_with_error():
                    original_close()
                    raise close_error
                stack.enter_context(patch.object(fixtures, "close", side_effect=close_with_error))
            out, err = io.StringIO(), io.StringIO()
            stack.enter_context(redirect_stdout(out))
            stack.enter_context(redirect_stderr(err))
            # The command environment is inert hosted-user DATA. Actual test
            # files above still check their real local uid/gid via Fixtures.
            status = M._run(A, BINDING, 501, 20, "runner",
                Path(current.environment()["MRK_MACOS_WORK"]),
                {**current.environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}, scope=C.SCOPE)
        records = [json.loads(line) for line in out.getvalue().splitlines()]
        return status, fixtures, calls, events, errors, records, first_error

    def test_actual_run_cases_and_current_wrapper_release_one_fresh_call_only_after_returned_post(self):
        status, fixtures, calls, events, errors, records, _ = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(calls, list(C.CASES))
        self.assertFalse(errors)
        self.assertLess(events.index(("source-readback", C.PRODUCE)), events.index(("runtime-post", (1, 1, 0))))
        self.assertLess(events.index(("runtime-post", (1, 1, 0))), events.index(("before", C.REOPEN)))
        self.assertLess(events.index(("emit", C.PRODUCE)), events.index(("inert-original", C.REOPEN)))
        self.assertLess(events.index(("runtime-post", (2, 2, 2))), events.index("original-fixture-close"))
        self.assertEqual(records[-1]["type"], "macos-upload-key-cold-restart-complete")
        self.assertTrue(records[-1]["fixtureHandlesClosed"])
        self.assertTrue(records[-1]["cleanProcessRestart"])
        self.assertFalse(records[-1]["processLossEvidence"])
        self.assertFalse(records[-1]["backupRoundtrip"])
        self.assertFalse(fixtures.fds)

    def test_first_missing_failed_malformed_foreign_or_lost_never_launches_second(self):
        for first in ("missing", "failed", "malformed", "foreign", "lost"):
            with self.subTest(first=first):
                status, fixtures, calls, events, errors, records, original = self.execute(first=first)
                self.assertEqual(status, 1)  # Missing cannot append-and-continue or become pair78.
                self.assertEqual(calls, [C.PRODUCE])
                self.assertEqual(fixtures.upload_cold.emitted, 0)
                self.assertFalse(any(record.get("type", "").endswith("complete") for record in records))
                self.assertEqual(fixtures.inflight, first in ("foreign", "lost"))
                self.assertEqual("original-fixture-close" in events, first not in ("foreign", "lost"))
                self.assertTrue(fixtures.record_path.exists())
                if first == "lost":
                    self.assertIs(errors[0], original)

    def test_post_output_or_private_drift_never_releases_the_second_command(self):
        for options in ({"post": (1, 1, 0)}, {"emit_error": True}, {"drift": True}):
            with self.subTest(options=options):
                status, fixtures, calls, events, errors, records, _ = self.execute(**options)
                self.assertEqual(status, 1)
                self.assertEqual(calls, [C.PRODUCE])
                self.assertEqual(fixtures.upload_cold.emitted, int(bool(options.get("drift"))))
                self.assertFalse(any(record.get("type", "").endswith("complete") for record in records))
                self.assertIn("original-fixture-close", events)
                self.assertTrue(errors)

    def test_second_loss_final_post_or_close_failure_cannot_publish_pair_completion(self):
        close_error = OSError("inert final fixture close error")
        for options in ({"second": "lost"}, {"second": "failed"}, {"post": (2, 2, 1)},
                        {"post": (2, 2, 2)}, {"close_error": close_error}):
            with self.subTest(options=options):
                status, fixtures, calls, events, errors, records, original = self.execute(**options)
                self.assertEqual(status, 1)
                self.assertEqual(calls, list(C.CASES))
                self.assertFalse(any(record.get("type", "").endswith("complete") for record in records))
                self.assertEqual(fixtures.inflight, options.get("second") == "lost")
                if options.get("second") == "lost":
                    self.assertIs(errors[0], original)
                    self.assertNotIn("original-fixture-close", events)
                if "close_error" in options:
                    self.assertIs(errors[0], close_error)

    def test_first_error_remains_first_even_when_actual_fixture_close_also_fails(self):
        late = OSError("inert late close error")
        status, _, calls, _, errors, _, _ = self.execute(first="failed", close_error=late)
        self.assertEqual(status, 1)
        self.assertEqual(calls, [C.PRODUCE])
        self.assertIsNot(errors[0], late)
        self.assertEqual(str(errors[0]), "app-return")


if __name__ == "__main__":
    unittest.main()
