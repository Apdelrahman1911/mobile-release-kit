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

    def run_selection(self, *, event="pull_request", base="a" * 40, paths=b"docs/desktop-ci.md\0", error=None, scope="core"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(os.environ, {"CI_EVENT": event, "CI_BASE": base,
                                         "CI_HEAD": "b" * 40, "GITHUB_OUTPUT": str(output), "CI_SCOPE": scope}, clear=True), \
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

    def test_desktop_skips_only_known_non_product_inputs(self):
        for path in (b"docs/desktop-ci.md", b"tests/desktop/test_api.py",
                     b"tests/workflow/test_ci_changes.py", b"desktop/tests/ios-archive.test.mjs",
                     b"desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift",
                     b"README.md"):
            self.assertFalse(changes.affects_desktop_native(path), path)
        for path in (b"desktop/src/App.tsx", b"desktop/src-tauri/src/lib.rs",
                     b"desktop/src-tauri/tests/native.rs", b"desktop/package-lock.json",
                     b"desktop/tests/fixtures/candidate-evidence.json", b"desktop/tests/new-fixture.json",
                     b"tests/native_desktop_config.py", b"tests/native_desktop_installed_windows_probe.py",
                     b"desktop/native/macos-installed-native/src/lib.rs", b"src/mobile_release/config.py",
                     b".github/workflows/desktop-ci.yml", b".github/scripts/ci_changes.py",
                     b"desktop/new-input", b"unknown-input", b"schemas/config.json"):
            self.assertTrue(changes.affects_desktop_native(path), path)

    def test_desktop_selection_does_not_relabel_core_or_hide_moved_inputs(self):
        value, _ = self.run_selection(scope="desktop", paths=b"desktop/tests/config-edit.test.mjs\0")
        self.assertEqual(value, "native=false\n")
        for paths in (b"docs/moved.rs\0desktop/src-tauri/src/old.rs\0",
                      b"docs/note.md\0desktop/new\ninput\0"):
            value, _ = self.run_selection(scope="desktop", paths=paths)
            self.assertEqual(value, "native=true\n")

    def test_desktop_manual_unknown_base_and_diff_errors_never_skip_native(self):
        for arguments in ({"event": "workflow_dispatch"}, {"event": "push", "base": "0" * 40}, {"base": ""}):
            value, diff = self.run_selection(scope="desktop", **arguments)
            self.assertEqual(value, "native=true\n")
            diff.assert_not_called()
        self.run_selection(scope="desktop", error=subprocess.CalledProcessError(128, ["git", "diff"]))
        self.run_selection(scope="invalid", error=ValueError("unsupported scope"))


if __name__ == "__main__":
    unittest.main()
