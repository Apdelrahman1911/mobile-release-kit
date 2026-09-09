from __future__ import annotations

import io
import itertools
import os
import subprocess
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from . import run_native_profile_checks
from .test_ci_verification import controller_module, coordinator_shell, fixture_paths
from .workflow_harness import evaluate_condition, load_workflow


class NativeProfileCITests(unittest.TestCase):
    def test_macos_upload_process_contracts_require_all_suites_and_pinned_ruby(self):
        workflow = load_workflow(Path(__file__).parents[2] / ".github/workflows/ci.yml")
        native = workflow["jobs"]["test-native-profiles"]
        linux_ruby = next(step for step in workflow["jobs"]["test-linux"]["steps"]
                          if step.get("uses", "").startswith("ruby/setup-ruby@"))
        ruby = next(step for step in native["steps"]
                    if step.get("uses", "").startswith("ruby/setup-ruby@"))
        self.assertEqual(ruby["uses"], linux_ruby["uses"])
        self.assertEqual(ruby["with"], {"ruby-version": "3.3.12", "bundler": "none", "bundler-cache": False})
        step = native["steps"][-1]
        self.assertEqual(step["run"], coordinator_shell("macos"))
        self.assertLess(native["steps"].index(ruby), native["steps"].index(step))
        for required in (ruby, step):
            self.assertNotIn("if", required)
            self.assertNotIn("continue-on-error", required)
        controller = controller_module()
        paths = fixture_paths(controller)
        steps = controller.catalog(paths, "macos", deadline=12345.0)
        suites = {
            "ruby-native-capture": ("test_native_upload_validation.rb", 13),
            "ruby-ios_upload_validation": ("test_ios_upload_validation.rb", 26),
            "ruby-android_upload_validation": ("test_android_upload_validation.rb", 26),
        }
        actual = [item for item in steps if item.id in suites]
        self.assertEqual([item.id for item in actual], list(suites))
        for item in actual:
            filename, count = suites[item.id]
            self.assertEqual(item.argv, (*paths.bundle, "exec", str(paths.ruby),
                                       str(paths.source / "tests/workflow" / filename), "--verbose"))
            self.assertEqual(item.parser, "minitest")
            self.assertEqual(item.expected_tests, count)
        ids = [item.id for item in steps]
        # Exercise the actual dispatcher with an inert result producer. A
        # filename in YAML cannot prove execution or first-failure behavior.
        for failed in (None, *suites):
            with self.subTest(failed=failed):
                calls = []

                def perform(item):
                    calls.append(item.id)
                    return controller.CheckResult(item.id != failed)

                report = controller.execute_pipeline(steps, perform, platform="macos")
                self.assertEqual(report.ok, failed is None)
                expected_calls = ids if failed is None else ids[:ids.index(failed) + 1]
                self.assertEqual(calls, expected_calls)
                if failed is not None:
                    self.assertTrue(all(row["status"] == "UNEXECUTED" for row in report.rows[len(calls):]))

    def test_protected_aggregate_always_runs_and_fails_for_any_unsuccessful_predecessor(self):
        workflow = load_workflow(Path(__file__).parents[2] / ".github/workflows/ci.yml")
        aggregate = workflow["jobs"]["test"]
        self.assertEqual(set(aggregate["needs"]), {"test-linux", "test-native-profiles"})
        self.assertEqual(aggregate["permissions"], {})
        self.assertNotIn("continue-on-error", aggregate)
        self.assertEqual(len(aggregate["steps"]), 1)
        step = aggregate["steps"][0]
        self.assertNotIn("if", step)
        self.assertNotIn("continue-on-error", step)
        self.assertEqual(step["env"], {"LINUX_RESULT": "${{ needs.test-linux.result }}", "NATIVE_RESULT": "${{ needs.test-native-profiles.result }}"})
        self.assertEqual(step["run"], 'set -euo pipefail\n[[ "$LINUX_RESULT" == success && "$NATIVE_RESULT" == success ]]\n')
        for linux, native in itertools.product(("success", "failure", "cancelled", "skipped", ""), repeat=2):
            with self.subTest(linux=linux, native=native):
                expected = linux == native == "success"
                self.assertTrue(evaluate_condition(aggregate.get("if"), {}, success=expected,
                                                   cancelled="cancelled" in (linux, native)))
                result = subprocess.run(["bash", "-c", step["run"]], capture_output=True, timeout=5,
                                        env={"PATH": os.environ["PATH"], "LINUX_RESULT": linux, "NATIVE_RESULT": native})
                self.assertEqual(result.returncode == 0, expected)
        native_job = workflow["jobs"]["test-native-profiles"]
        self.assertEqual(native_job["runs-on"], "macos-26")
        self.assertEqual(native_job["permissions"], {"contents": "read"})
        self.assertNotIn("if", native_job)
        self.assertNotIn("continue-on-error", native_job)
        self.assertNotIn("environment", native_job)
        self.assertEqual(native_job["steps"][-1]["run"], coordinator_shell("macos"))
        controller = controller_module()
        paths = fixture_paths(controller)
        catalog = controller.catalog(paths, "macos", deadline=12345.0)
        checks = [item for item in catalog if item.id in {"native-profile-source", "native-profile-wheel"}]
        self.assertEqual([item.id for item in checks], ["native-profile-source", "native-profile-wheel"])
        gate = str(paths.source / "tests/workflow/run_native_profile_checks.py")
        self.assertEqual(checks[0].argv, (str(paths.source_python), "-I", "-B", gate))
        self.assertEqual(checks[1].argv, (str(paths.wheel_python), "-I", "-B", gate, "--installed-wheel"))
        self.assertTrue(all(item.parser == "native" for item in checks))
        self.assertTrue(all(item.cwd == paths.work and not item.cwd.is_relative_to(paths.source) for item in checks))
        ids = [item.id for item in catalog]
        self.assertLess(ids.index("wheel-inspect"), ids.index("native-profile-wheel"))
        self.assertLess(ids.index("wheel-install"), ids.index("native-profile-wheel"))

    def test_native_gate_rejects_unavailable_platform_missing_tooling_empty_suite_and_skips(self):
        gate = run_native_profile_checks
        with patch.object(gate, "sys", SimpleNamespace(platform="linux", stderr=io.StringIO())), redirect_stderr(io.StringIO()):
            self.assertEqual(gate.run(), 1)
        with patch.object(gate, "sys", SimpleNamespace(platform="darwin", stderr=io.StringIO())), patch.object(gate.subprocess, "run", side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
            gate.run()
        with patch.object(gate, "sys", SimpleNamespace(platform="darwin", stderr=io.StringIO())), patch.object(gate.subprocess, "run"), patch.object(gate.unittest.TestLoader, "discover", return_value=unittest.TestSuite()), self.assertRaisesRegex(AssertionError, "empty"):
            gate.run()
        class Skipped(unittest.TestCase):
            def runTest(self): self.skipTest("unavailable native tool")
        with patch.object(gate, "sys", SimpleNamespace(platform="darwin", stderr=io.StringIO())), patch.object(gate.subprocess, "run"), patch.object(gate.unittest.TestLoader, "discover", side_effect=lambda *args, **kwargs: unittest.TestSuite([Skipped()])), redirect_stderr(io.StringIO()):
            self.assertEqual(gate.run(), 1)


if __name__ == "__main__":
    unittest.main()
