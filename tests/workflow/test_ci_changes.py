"""Regression coverage for required-status-safe CI change selection."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "ci_changes", Path(__file__).resolve().parents[2] / ".github/scripts/ci_changes.py")
changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changes)


class ChangesTests(unittest.TestCase):
    def test_core_inputs_include_deletions_and_dependency_configuration(self):
        for path in (b"src/mobile_release/config.py", b"fastlane/Fastfile", b"schemas/a.json",
                     b"templates/workflows/mobile-candidate.yml", b"tests/unit/test_config.py",
                     b"tests/workflow/test_ci_changes.py", b".github/scripts/verify_ci.py",
                     b".github/workflows/ci.yml", b".github/workflows/reusable-preflight.yml",
                     b".github/verification-tools.json", b"README.md", b"LICENSE",
                     b"pyproject.toml", b"MANIFEST.in", b"Gemfile.lock"):
            with self.subTest(path=path):
                self.assertTrue(changes.affects_core(path))

    def test_desktop_and_documentation_changes_do_not_repeat_core_matrix(self):
        for path in (b"desktop/src/App.tsx", b"tests/desktop/test_api.py",
                     b"tests/native_desktop.py", b"docs/desktop-ci.md",
                     b".github/workflows/desktop-ci.yml"):
            self.assertFalse(changes.affects_core(path), path)

    def run_selection(self, *, event="pull_request", base="a" * 40, paths=b"docs/desktop-ci.md\0", error=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(os.environ, {"CI_EVENT": event, "CI_BASE": base,
                                         "CI_HEAD": "b" * 40, "GITHUB_OUTPUT": str(output)}, clear=True), \
                 patch.object(changes.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                 patch.object(changes.subprocess, "check_output", return_value=paths, side_effect=error) as diff:
                if error:
                    with self.assertRaises(type(error)):
                        changes.main()
                    self.assertFalse(output.exists(), "failure must never produce a skip result")
                else:
                    changes.main()
                    return output.read_text(), diff

    def test_no_core_change_reports_explicit_false(self):
        value, _ = self.run_selection()
        self.assertEqual(value, "core=false\n")

    def test_rename_out_of_core_and_newline_filenames_cannot_hide_a_change(self):
        value, diff = self.run_selection(paths=b"docs/moved.py\0src/old.py\0desktop/line\nbreak.ts\0")
        self.assertEqual(value, "core=true\n")
        self.assertIn("--no-renames", diff.call_args.args[0])
        self.assertIn("-z", diff.call_args.args[0])

    def test_manual_and_new_branch_run_full_checks(self):
        for arguments in ({"event": "workflow_dispatch"}, {"event": "push", "base": "0" * 40}):
            value, diff = self.run_selection(**arguments)
            self.assertEqual(value, "core=true\n")
            diff.assert_not_called()

    def test_diff_failure_never_authorizes_skipping_tests(self):
        self.run_selection(error=subprocess.CalledProcessError(128, ["git", "diff"]))


if __name__ == "__main__":
    unittest.main()
