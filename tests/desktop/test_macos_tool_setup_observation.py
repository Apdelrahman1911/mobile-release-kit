"""Passive report/runner contract tests. No native/process/vendor/file effects."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mrk_tool_setup_passive_parent", ROOT / "desktop/tools/macos_aqua_qualification.py")
PARENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PARENT
SPEC.loader.exec_module(PARENT)
TOOLS = PARENT.TOOLS
BINDING = PARENT.Binding("a" * 40, "123", "1")


def sample(phase):
    value = dict.fromkeys(TOOLS.BOOLS, False)
    value.update(action="acquire" if phase in ("acquire", "cancel", "drift") else "inspect",
                 outcome="complete", reason="none", sourceInspected=phase != "reuse", sourceFailure=None)
    for key in ("sameActive", "allJoined", "sourceClosed", "cacheClosed", "runtimeClosed"):
        value[key] = True
    if phase in ("initial", "acquire", "reuse"):
        for key in ("accepted", "terminal", "current", "transferAttempted", "childAttempted", "childWaited", "ioJoined"):
            value[key] = True
        value.update(cacheAttempted=phase == "acquire", caArmed=phase == "acquire",
                     completeSdkLocation=phase == "acquire", reuseSelected=phase == "reuse")
    else:
        value.update(firstFailure=True, outcome="cancelled" if phase == "cancel" else "refused",
                     reason="cancelled" if phase == "cancel" else "existing-tools-incompatible")
        if phase == "cancel":
            value.update(cacheAttempted=True, caArmed=True)
        else:
            value["sourceFailure"] = value["reason"]
    return value


def report(case, executed=True):
    """Literal comparison fixture, never passed to a native authority API."""
    positive = case == TOOLS.CASES[0]
    return {"mechanism": "same-original-tool-setup-v1", "normalAcquisitionEnabled": False,
        "execution": "executed" if executed else "not-executed-prerequisite",
        "testResult": ("registered-reused" if positive else "cancelled-before-transfer" if case == TOOLS.CASES[1] else "source-refused-before-effects") if executed else "not-executed",
        "initial": sample("initial") if executed else None,
        "acquire": sample("acquire" if positive else "cancel" if case == TOOLS.CASES[1] else "drift") if executed else None,
        "reuse": sample("reuse") if executed and positive else None,
        "selectedSources": ([True] * 4 if positive else [True, True, True, False]) if executed else [False] * 4,
        "protectedCopyRegistered": executed and positive, "selectedCatalogVerified": executed and positive,
        "normalQuitOriginal": (6 if positive else 5) if executed else 2,
        "allOriginalsSettled": True, "projectSentinelPreserved": True, "automaticRegistration": False,
        "privilegedInstallRequested": False, "productionQualified": False, "pendingCaseReused": False,
        "retirement": "retain-task-owned-cache-and-source-until-original-host-retirement"}


def complete_output(case, executed=True):
    value = PARENT.expected_result(BINDING, case)
    value["toolSetup"] = report(case, executed)
    return PARENT.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n"


class ToolSetupPassive(unittest.TestCase):
    def test_three_distinct_returned_cases_parse_without_changing_qualification(self):
        for case in TOOLS.CASES:
            with self.subTest(case=case):
                value = PARENT.parse_result(complete_output(case), b"", BINDING, case)
                self.assertEqual(value["toolSetup"], report(case))
                self.assertFalse(value["shippingBinaryQualified"])
                self.assertIsNone(PARENT.expected_result(BINDING, case)["toolSetup"])

    def test_positive_requires_each_original_and_all_three_samples(self):
        for phase in ("initial", "acquire", "reuse"):
            for key in ("sameActive", "allJoined", "sourceClosed", "cacheClosed", "runtimeClosed", "accepted", "terminal", "current", "childWaited", "ioJoined"):
                value = report(TOOLS.CASES[0])
                value[phase][key] = False
                with self.subTest(phase=phase, key=key), self.assertRaises(PARENT.Refused):
                    TOOLS.report(value, TOOLS.CASES[0], PARENT.need)
            value = report(TOOLS.CASES[0]); value[phase] = None
            with self.assertRaises(PARENT.Refused):
                TOOLS.report(value, TOOLS.CASES[0], PARENT.need)

    def test_first_failure_or_redundant_effect_cannot_be_reuse_success(self):
        for phase, key in (("initial", "firstFailure"), ("reuse", "firstFailure"), ("initial", "cacheAttempted"),
                           ("reuse", "cacheAttempted"), ("initial", "caArmed"), ("reuse", "caArmed")):
            value = report(TOOLS.CASES[0]); value[phase][key] = True
            with self.subTest(phase=phase, key=key), self.assertRaises(PARENT.Refused):
                TOOLS.report(value, TOOLS.CASES[0], PARENT.need)

    def test_negative_cuts_are_not_interchangeable_or_unknown_settlement(self):
        for case in TOOLS.CASES[1:]:
            for key in ("transferAttempted", "childAttempted", "childWaited", "ioJoined", "completeSdkLocation"):
                value = report(case); value["acquire"][key] = True
                with self.subTest(case=case, key=key), self.assertRaises(PARENT.Refused):
                    TOOLS.report(value, case, PARENT.need)
            for reason in ("cleanup-unknown", "unknown", "timed-out"):
                value = report(case); value["acquire"]["reason"] = reason
                with self.assertRaises(PARENT.Refused):
                    TOOLS.report(value, case, PARENT.need)
        value = report(TOOLS.CASES[2]); value["acquire"] = sample("cancel")
        with self.assertRaises(PARENT.Refused):
            TOOLS.report(value, TOOLS.CASES[2], PARENT.need)

    def test_closed_fields_no_path_or_integer_truth_and_no_autoregistration(self):
        mutations = (lambda v: v.update(path="/foreign"), lambda v: v["acquire"].update(path="/foreign"),
                     lambda v: v.update(privilegedInstallRequested=True), lambda v: v.update(automaticRegistration=True),
                     lambda v: v.update(productionQualified=True), lambda v: v.update(pendingCaseReused=True),
                     lambda v: v.update(normalQuitOriginal=True), lambda v: v["initial"].update(allJoined=1))
        for mutate in mutations:
            value = report(TOOLS.CASES[0]); mutate(value)
            with self.assertRaises(PARENT.Refused):
                TOOLS.report(value, TOOLS.CASES[0], PARENT.need)

    def test_source_drift_requires_retained_source_and_same_first_classification(self):
        case = TOOLS.CASES[2]
        for reason in ("existing-tools-incompatible", "stale"):
            value = report(case)
            value["acquire"].update(reason=reason, sourceFailure=reason)
            self.assertIs(TOOLS.report(value, case, PARENT.need), value)
        changes = [dict(reason=reason, sourceFailure=reason) for reason in (
            "runtime-unavailable", "protocol-error", "input", "unsupported", "stale-intent", "existing-tools-unreadable")]
        changes += [dict(sourceInspected=False), dict(sourceFailure=None), dict(sourceFailure="stale")]
        for change in changes:
            value = report(case); value["acquire"].update(change)
            with self.subTest(change=change), self.assertRaises(PARENT.Refused):
                TOOLS.report(value, case, PARENT.need)

    def test_missing_service_is_explicit_unexecuted_not_a_positive_result(self):
        for case in TOOLS.CASES:
            value = PARENT.parse_result(complete_output(case, False), b"", BINDING, case)
            self.assertEqual(value["toolSetup"]["testResult"], "not-executed")
            for key, field in (("testResult", "registered-reused"), ("protectedCopyRegistered", True),
                               ("initial", sample("initial")), ("normalQuitOriginal", 6)):
                changed = copy.deepcopy(value["toolSetup"]); changed[key] = field
                with self.assertRaises(PARENT.Refused):
                    TOOLS.report(changed, case, PARENT.need)

    def test_fixed_scope_timeout_and_fixture_no_generated_or_wrapper_executable(self):
        self.assertEqual(PARENT.selected_cases(TOOLS.SCOPE), TOOLS.CASES)
        self.assertEqual(PARENT.argument_scope(["--scope", "tool-setup"]), TOOLS.SCOPE)
        self.assertEqual(BINDING.root(tool_setup=True).name, "mrk-macos-aqua-" + "a" * 40 + "-123-1-tool-setup")
        with self.assertRaises(PARENT.Refused):
            BINDING.root(tool_setup=True, vault_helper=True)
        for case in TOOLS.CASES:
            self.assertEqual(PARENT.case_timeout(case), 2415)
            files, dirs = PARENT.fixture_data(case, False)
            self.assertEqual((files, dirs), PARENT.fixture_data(case, True))
            self.assertEqual(len(files), 7); self.assertEqual(len(dirs), 5)
            self.assertEqual(files["keep.txt"], PARENT.KEEP)
            self.assertEqual(files["app/build.gradle.kts"], TOOLS.APP)
            self.assertEqual(files["release/mobile-release.json"], PARENT.CONFIG)
            self.assertNotIn("gradlew", files)
            self.assertTrue(all(mode == 0o700 for mode, _ in dirs.values()))

    def test_fixed_native_account_namespace_never_ambient_home_or_report_path(self):
        with patch.dict("os.environ", {"HOME": "/untrusted", "TMPDIR": "/untrusted"}):
            paths = [TOOLS.application_path(BINDING, "/Users/example", case, PARENT.need) for case in TOOLS.CASES]
        self.assertEqual(len(set(paths)), 3)
        self.assertTrue(all(str(p).startswith("/Users/example/Library/Application Support/mrk-macos-aqua-tools-") for p in paths))
        for home in ("/", "relative", "/Users/../foreign", "/Users//foreign", "/Users/foreign/"):
            with self.assertRaises(PARENT.Refused):
                TOOLS.application_path(BINDING, home, TOOLS.CASES[0], PARENT.need)

    def test_same_runner_returns_unexecuted_cases_without_new_installer_invocation(self):
        calls, outputs = [], []
        class InertFixtures:
            cases = TOOLS.CASES
            inflight = False
            last_returned = False
            def recovery_runtime_paths(self):
                return ("inert-only",)
            def before_call(self, case):
                self.case = case
        fixture = InertFixtures()
        def inert_owner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, complete_output(args[1], False), b"")
        with patch.object(TOOLS, "readback", side_effect=lambda *args: {"inertReadback": True}) as readback:
            refused = PARENT.run_cases(BINDING, fixture, inert_owner, 501, "example", outputs.append, TOOLS.SCOPE)
        self.assertEqual(refused, TOOLS.RUN_ORDER)
        self.assertEqual(readback.call_count, 3)
        self.assertEqual([call[0] for call in calls], [[PARENT.EXECUTABLE, case] for case in TOOLS.RUN_ORDER])
        self.assertEqual(calls[-1][0][1], "tool-setup-missing-sdk")
        self.assertTrue(all(call[1]["timeout"] == 2415 for call in calls))
        self.assertEqual(len(outputs), 3)
        self.assertFalse(fixture.inflight)

    def test_original_invoke_error_retained_without_readback_or_next_case(self):
        class InertFixtures:
            cases = TOOLS.CASES
            inflight = False
            last_returned = False
            def recovery_runtime_paths(self): return ("inert-only",)
            def before_call(self, case): self.case = case
        fixture = InertFixtures(); failure = RuntimeError("synthetic-unknown")
        def inert_owner(*args, **kwargs): raise failure
        with patch.object(TOOLS, "readback") as readback:
            with self.assertRaises(RuntimeError) as caught:
                PARENT.run_cases(BINDING, fixture, inert_owner, 501, "example", lambda _: None, TOOLS.SCOPE)
        self.assertIs(caught.exception, failure)
        self.assertTrue(fixture.inflight)
        self.assertFalse(fixture.last_returned)
        readback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
