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
from .workflow_harness import evaluate_condition, load_workflow


class NativeProfileCITests(unittest.TestCase):
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
        checks = [step for step in native_job["steps"] if "run_native_profile_checks.py" in step.get("run", "")]
        self.assertEqual(len(checks), 2)
        for check in checks:
            self.assertNotIn("if", check)
            self.assertNotIn("continue-on-error", check)

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
