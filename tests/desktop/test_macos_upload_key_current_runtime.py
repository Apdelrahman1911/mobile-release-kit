"""Current-route DATA tests, not native generation, recovery or backup proof.

Reuse the actual current wrapper, run_cases, complete report parser and existing
synthetic metadata port. The only process return is explicitly inert; Popen is
forbidden. No fixture directory, private key or provider is touched.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_macos_identity_current_runtime as current
import test_macos_upload_key_observation as data
import test_macos_upload_key_cancel_observation as cancellation


M, A, U = current.M, data.M, data.U
BINDING = data.BINDING
ROUNDTRIP, BEFORE, AFTER = U.CASES


def environment():
    return {**current.environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}


class UploadCurrentRuntimeTests(unittest.TestCase):
    def setUp(self):
        no_process = patch("subprocess.Popen", side_effect=AssertionError("native execution forbidden"))
        no_process.start()
        self.addCleanup(no_process.stop)

    def test_exact_single_cases_require_the_existing_source_owned_tool_package(self):
        self.assertEqual(M.UPLOAD_SCOPES, U.CASES)
        for case in U.CASES:
            self.assertEqual(M.arguments(["--target", M.TARGET, "--scope", case]), case)
            self.assertEqual(M.observation_scope(environment(), case), case)
            self.assertEqual(A.selected_cases(case), (case,))
            for native in (M.SCOPE, M.SERVICE_SCOPE, case, "disabled", "all", None):
                with self.subTest(case=case, native=native), self.assertRaises(M.Refused):
                    M.observation_scope({**environment(), "MRK_MACOS_NATIVE_SCOPE": native}, case)
        for scope in ("upload-key-all", "upload-key-stop", "../upload-key-roundtrip", "", None, [ROUNDTRIP]):
            with self.subTest(scope=scope), self.assertRaises(M.Refused):
                M.observation_scope(environment(), scope)
        for argv in (["--scope", ROUNDTRIP], ["--target", A.INTEL_TARGET, "--scope", ROUNDTRIP],
                     ["--target", M.TARGET, "--scope", ROUNDTRIP, BEFORE],
                     ["--target", M.TARGET, "--scope", ROUNDTRIP, "--timeout", "999"]):
            with self.subTest(argv=argv), self.assertRaises(M.Refused):
                M.arguments(argv)
        self.assertEqual(M.arguments(["--target", M.TARGET]), M.SCOPE)
        for scope in (M.SCOPE, M.SERVICE_SCOPE, M.TOOLS_SCOPE):
            self.assertEqual(M.observation_scope(environment(), scope), scope)
        # No new package role or source-owned scope is introduced by arguments.
        self.assertEqual(M.package_role(environment(), "package-install", M.TARGET), M.ROLE)
        ordinary = {**environment(), "MRK_MACOS_NATIVE_SCOPE": "disabled"}
        self.assertIsNone(M.package_role(ordinary, "any-old-role", A.INTEL_TARGET))

    def test_bad_current_source_or_package_refuses_before_native_or_owner_loading(self):
        for key, value in (("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                           ("GITHUB_REF", "refs/heads/verify/desktop-macos-aqua"),
                           ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image"),
                           ("MRK_MACOS_STORE_RUNTIME", "historical"),
                           ("MRK_MACOS_AQUA_SCOPE", ROUNDTRIP)):
            with self.subTest(key=key), \
                 patch.dict(os.environ, {**environment(), key: value}, clear=True), \
                 patch.object(sys, "argv", ["entry", "--target", M.TARGET, "--scope", ROUNDTRIP]), \
                 patch.object(M, "_native_user") as native, patch.object(M, "_load_observer") as load, \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(M.main(), 1)
                native.assert_not_called()
                load.assert_not_called()

    def test_normal_runtime_admission_adds_only_exact_unstarted_singleton_tuples(self):
        sentinel = RuntimeError("inert stop BEFORE installed source/IO admission")
        for case in U.CASES:
            fixtures = A.Fixtures(BINDING, 501, 20, case)
            with patch.object(A, "_gate_load_stager", side_effect=sentinel) as loader, \
                 self.assertRaises(RuntimeError) as raised:
                fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(environment()["MRK_MACOS_WORK"]),
                                                      application_source=BINDING.source)
            self.assertIs(raised.exception, sentinel)
            loader.assert_called_once()
            self.assertFalse(fixtures.fds)  # The sentinel stopped before any IO.
        for cases, inflight, retained in ((U.CASES, False, None), ((ROUNDTRIP, BEFORE), False, None),
                                          (("upload-key-all",), False, None), ((), False, None),
                                          ((ROUNDTRIP,), True, None), ((ROUNDTRIP,), False, ("inert", "inert"))):
            fixtures = A.Fixtures(BINDING, 501, 20, ROUNDTRIP)
            fixtures.cases, fixtures.inflight, fixtures.recovery_runtime = cases, inflight, retained
            with self.subTest(cases=cases, inflight=inflight, retained=retained), \
                 patch.object(A, "_gate_load_stager") as loader, self.assertRaises(A.Refused):
                fixtures.admit_normal_account_runtime(M.CHECKOUT, Path(environment()["MRK_MACOS_WORK"]),
                                                      application_source=BINDING.source)
            loader.assert_not_called()

    def execute(self, case, *, missing=False, original_error=None, admission_error=None,
                close_error=None, post_error_at=None, foreign_return=False, returncode=0,
                report=None, run_cases=None):
        events, errors = [], []
        fixtures = data.MetadataPort(case=case, generated=not missing and case != BEFORE,
                                     host_started=not missing)
        # The existing metadata port has integers, not OS handles. These empty
        # runtime rosters are inert; real held-source readers are tested by the
        # unchanged current-runtime reader suite, not fabricated here.
        fixtures.gate_files, fixtures.gate_directories = [], []
        fixtures.runtime_admitted = False
        fixtures.runtime_checks = 0
        fixtures.prepare = lambda: events.append("prepare")
        value = deepcopy(report if report is not None else data.report(missing=True) if missing
                         else data.report() if case == ROUNDTRIP else cancellation.report(case))
        frame = A.expected_result(BINDING, case)
        frame["vaultHelper"] = value

        def admit(*args):
            events.append("admit-current-runtime")
            if admission_error is not None:
                raise admission_error
            fixtures.runtime_admitted = True

        def runtime_paths():
            self.assertTrue(fixtures.runtime_admitted)
            self.assertFalse(fixtures.inflight)
            fixtures.runtime_checks += 1
            events.append(("runtime-post", fixtures.runtime_checks))
            if fixtures.runtime_checks == post_error_at:
                raise A.Refused("inert original runtime changed")
            return "INERT", "INERT"

        fixtures.recovery_runtime_paths = runtime_paths
        original_before = fixtures.before_call
        def before(selected):
            events.append(("before", selected))
            original_before(selected)
        fixtures.before_call = before

        def original(argv, **options):
            self.assertTrue(fixtures.inflight)
            self.assertTrue(fixtures.runtime_admitted)
            self.assertGreaterEqual(fixtures.runtime_checks, 1)
            self.assertEqual(argv, [A.EXECUTABLE, case])
            state = BINDING.root(upload_key=case) / "state" / case
            self.assertEqual(options["cwd"], state)
            self.assertEqual(options["environ"], A.app_environment(state, 501, "runner"))
            self.assertEqual(options["timeout"], 495)
            events.append(("inert-original", case))
            if original_error is not None:
                raise original_error
            if foreign_return:
                return SimpleNamespace(args=argv, returncode=0, stdout=data.captured(frame), stderr=b"")
            return subprocess.CompletedProcess(argv, returncode, data.captured(frame), b"")

        def close():
            self.assertFalse(fixtures.inflight)
            self.assertFalse(fixtures.active)
            events.append("close")
            if close_error is not None:
                raise close_error

        fixtures.close = close
        def diagnose(error, owner, original_fixtures):
            self.assertIs(original_fixtures, fixtures)
            errors.append(error)
            return {"inertOnly": True, "unknown": fixtures.inflight}

        with ExitStack() as stack:
            stack.enter_context(patch.object(A, "Fixtures", return_value=fixtures))
            stack.enter_context(patch.object(M, "_admit_runtime", side_effect=admit))
            load = stack.enter_context(patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=original)))
            stack.enter_context(patch.object(A, "diagnostic", side_effect=diagnose))
            if run_cases is not None:
                stack.enter_context(patch.object(A, "run_cases", side_effect=run_cases))
            out, err = io.StringIO(), io.StringIO()
            stack.enter_context(redirect_stdout(out))
            stack.enter_context(redirect_stderr(err))
            status = M._run(A, BINDING, 501, 20, "runner", Path(environment()["MRK_MACOS_WORK"]),
                            environment(), scope=case)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        return status, events, rows, errors, fixtures, load, value

    def test_each_case_uses_one_real_control_flow_and_keeps_cancelled_recovery_distinct(self):
        for case in U.CASES:
            with self.subTest(case=case):
                status, events, rows, errors, fixtures, load, report = self.execute(case)
                self.assertEqual(status, 0)
                self.assertEqual(errors, [])
                load.assert_called_once()
                self.assertEqual(events[:2], ["prepare", "admit-current-runtime"])
                self.assertEqual([e for e in events if type(e) is tuple and e[0] == "inert-original"],
                                 [("inert-original", case)])
                self.assertEqual(fixtures.reads, [case])
                self.assertEqual(events[-1], "close")
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]["observer"]["vaultHelper"], report)
                self.assertEqual(report["testResult"], "positive" if case == ROUNDTRIP else "cancelled-cleanup")
                self.assertEqual(report["originalCount"], 11 if case == AFTER else 9)
                self.assertEqual(rows[-1]["type"], "macos-upload-key-current-complete")
                self.assertEqual(rows[-1]["cases"], [case])
                self.assertFalse(rows[-1]["processLossEvidence"])
                self.assertFalse(rows[-1]["shippingBinaryQualified"])
                self.assertFalse(report["backupCreated"])
                self.assertFalse(report["automaticallyAssigned"])
                self.assertEqual(report["stoppedIntentAcknowledged"], case == BEFORE)
                if case == AFTER:
                    self.assertTrue(report["explicitlyBoundSavedKey"] and report["rememberedBoundSavedKey"])

    def test_parsed_known_unexecuted_is_78_after_readback_and_close_not_a_pass(self):
        for case in U.CASES:
            with self.subTest(case=case):
                status, events, rows, errors, fixtures, _, _ = self.execute(case, missing=True)
                self.assertEqual(status, 78)
                self.assertEqual(errors, [])
                self.assertEqual(events[-1], "close")
                self.assertEqual(fixtures.reads, [case])
                self.assertEqual(rows[-1]["type"], "macos-upload-key-current-unexecuted")
                self.assertEqual(rows[-1]["notExecuted"], [case])
                self.assertFalse(rows[0]["independentReadback"]["uploadKeyOutput"]["newEncryptedRecordPresent"])
                self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "inert-original"]), 1)

    def test_lost_or_foreign_original_never_reads_closes_completes_or_retries(self):
        first = TimeoutError("INERT lost original")
        for kwargs in ({"original_error": first}, {"foreign_return": True}):
            status, events, rows, errors, fixtures, _, _ = self.execute(BEFORE, **kwargs)
            self.assertEqual(status, 1)
            self.assertEqual(rows, [])
            self.assertTrue(fixtures.inflight)
            self.assertFalse(fixtures.last_returned)
            self.assertEqual(fixtures.reads, [])
            self.assertEqual(fixtures.opened, [])
            self.assertNotIn("close", events)
            self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "inert-original"]), 1)
            if "original_error" in kwargs:
                self.assertEqual(errors, [first])

    def test_nonzero_original_is_failure_not_unexecuted_even_with_a_missing_report(self):
        status, events, rows, errors, fixtures, _, _ = self.execute(ROUNDTRIP, missing=True, returncode=1)
        self.assertEqual(status, 1)
        self.assertTrue(errors)
        self.assertFalse(fixtures.inflight)
        self.assertTrue(fixtures.last_returned)
        self.assertEqual(fixtures.reads, [])
        self.assertEqual(rows, [])
        self.assertEqual(events[-1], "close")

    def test_intermediate_retention_or_old_after_new_report_never_becomes_completion(self):
        retained = cancellation.report(BEFORE)
        retained["generated"] = data.stopped(BEFORE)["sample"]
        old_after = cancellation.report(AFTER)
        old_after.pop("explicitlyBoundSavedKey")
        old_after.pop("rememberedBoundSavedKey")
        old_after["originalCount"] = 9
        for case, report in ((BEFORE, retained), (AFTER, old_after)):
            status, events, rows, errors, fixtures, _, _ = self.execute(case, report=report)
            self.assertEqual(status, 1)
            self.assertTrue(errors)
            self.assertEqual(rows, [])
            self.assertEqual(fixtures.reads, [])
            self.assertEqual(events[-1], "close")

    def test_runtime_admission_failure_never_loads_owner_and_retains_first_error(self):
        first = RuntimeError("INERT installed runtime refused")
        status, events, rows, errors, fixtures, load, _ = self.execute(
            ROUNDTRIP, admission_error=first, close_error=OSError("INERT close"))
        self.assertEqual(status, 1)
        self.assertEqual(errors, [first])
        self.assertEqual(events, ["prepare", "admit-current-runtime", "close"])
        self.assertEqual(rows, [])
        self.assertEqual(fixtures.reads, [])
        load.assert_not_called()

    def test_runtime_post_or_close_failure_suppresses_completion_without_another_case(self):
        for kwargs in ({"post_error_at": 2}, {"post_error_at": 3}, {"close_error": OSError("INERT close failed")}):
            status, events, rows, errors, fixtures, _, _ = self.execute(AFTER, **kwargs)
            self.assertEqual(status, 1)
            self.assertTrue(errors)
            self.assertEqual(fixtures.reads, [AFTER])
            self.assertEqual(events[-1], "close")
            self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "inert-original"]), 1)
            self.assertFalse(any(row.get("type") == "macos-upload-key-current-complete" for row in rows))

    def test_missing_or_foreign_case_publication_is_not_a_zero_case_success(self):
        def foreign(binding, fixtures, owner, uid, username, emit, scope):
            emit({"case": BEFORE})
            return ()
        for cases in (lambda *args, **kwargs: (), foreign):
            status, events, rows, errors, fixtures, _, _ = self.execute(ROUNDTRIP, run_cases=cases)
            self.assertEqual(status, 1)
            self.assertTrue(errors)
            self.assertEqual(rows, [])
            self.assertEqual(fixtures.reads, [])
            self.assertEqual(events[-1], "close")


if __name__ == "__main__":
    unittest.main()
