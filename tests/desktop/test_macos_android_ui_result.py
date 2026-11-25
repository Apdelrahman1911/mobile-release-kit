"""Passive Android result-reader checks; no native tools or signed inputs."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "android_ui_result", ROOT / "desktop/tools/macos_android_ui_result.py")
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class AndroidUIResultTests(unittest.TestCase):
    def environment(self):
        return {
            "MRK_MACOS_TARGET": "aarch64-apple-darwin",
            "MRK_MACOS_WORK": "/Users/runner/work/_temp/mrk-macos-installed.Abc12345",
            "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
            "MRK_EXPECTED_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKSPACE": str(result.SOURCE),
            "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/verify/desktop-macos-installed",
            "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/"
                "desktop-macos-installed.yml@refs/heads/verify/desktop-macos-installed",
            "MRK_MACOS_ANDROID_UI_SCOPE": "android-signed-build",
        }

    def test_json_rejects_duplicate_nonfinite_and_nonobject_data(self):
        self.assertEqual(result.document(b'{"count":1,"duration":0.5}'),
                         {"count": 1, "duration": 0.5})
        for body in (b'{"count":1,"count":0}', b'{"x":NaN}', b'{"x":Infinity}',
                     b'{"x":1e999}', b'[]', b'{'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                result.document(body)

    def test_original_calls_require_correct_roles_statuses_and_closes(self):
        row = {"role": "installer", "entered": True, "returned": True,
               "capturesSettled": True, "returncode": 0}
        result.package_originals([row], ("installer",))
        result.package_originals([dict(row, role="installer-log-cursor", returncode=1)],
                                 ("installer-log-cursor",))
        credential = {"role": "producer-adhoc", "entered": True, "returned": True,
                      "settled": True, "status": 0}
        result.package_originals([credential], ("producer-adhoc",), credentials=True)
        for bad in (dict(row, returned=False), dict(row, capturesSettled=False),
                    dict(row, returncode=1), dict(row, returncode=False), dict(row, role="other")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                result.package_originals([bad], ("installer",))
        with self.assertRaises(ValueError):
            result.package_originals([], ("installer",))
        with self.assertRaises(ValueError):
            result.package_originals([dict(credential, settled=False)],
                                     ("producer-adhoc",), credentials=True)

    def test_checkout_imports_are_fixed_and_checked_against_original_deadline(self):
        names = ("mrk_android_ui_normal", "mrk_android_ui_stager", "mrk_android_ui_package")
        leaves = ("macos_normal_ui_runner.py", "stage_macos_installed.py", "macos_android_helper_package.py")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            tools = source / "desktop/tools"
            tools.mkdir(parents=True)
            for index, leaf in enumerate(leaves):
                (tools / leaf).write_text(f"value = {index}\n", encoding="utf-8")
            with patch.object(result, "SOURCE", source), patch.dict(sys.modules):
                for name in names:
                    sys.modules.pop(name, None)
                clock = Mock()
                modules = result.load_checkout_modules(clock)
                self.assertEqual(tuple(module.value for module in modules), (0, 1, 2))
                self.assertEqual(clock.call_count, 6)
                with self.assertRaisesRegex(ValueError, "ui-source-module-collision"):
                    result.load_checkout_modules(clock)
            with patch.object(result, "SOURCE", source), patch.dict(sys.modules):
                for name in names:
                    sys.modules.pop(name, None)
                with self.assertRaisesRegex(ValueError, "expired"):
                    result.load_checkout_modules(Mock(side_effect=[None, ValueError("expired")]))
                self.assertIn(names[0], sys.modules)
                self.assertNotIn(names[1], sys.modules)

    def test_entry_deadline_is_not_renewed_after_imports_or_on_clock_rollback(self):
        for now in (10 + 60 * 10**9, 9):
            with self.subTest(now=now), patch.dict(os.environ, self.environment(), clear=True), \
                 patch.object(result, "_STARTED_NS", 10), \
                 patch.object(result.time, "monotonic_ns", return_value=now), \
                 patch.object(result.os, "open") as opened, \
                 patch.object(result, "load_checkout_modules") as loaded:
                with self.assertRaisesRegex(ValueError, "ui-data-deadline"):
                    result.main()
                opened.assert_not_called()
                loaded.assert_not_called()

    def test_acquired_descriptor_closes_without_masking_original_failure(self):
        original_error = OSError("synthetic-fstat-failure")
        for close_error in (None, OSError("synthetic-close-failure")):
            with self.subTest(close_error=close_error), \
                 patch.dict(os.environ, self.environment(), clear=True), \
                 patch.object(result, "_STARTED_NS", 10), \
                 patch.object(result.time, "monotonic_ns", return_value=20), \
                 patch.object(result.Path, "cwd", return_value=result.SOURCE), \
                 patch.object(result.os, "getuid", return_value=501), \
                 patch.object(result.os, "open", return_value=97) as opened, \
                 patch.object(result.os, "fstat", side_effect=original_error), \
                 patch.object(result.os, "close", side_effect=close_error) as closed:
                with self.assertRaises(OSError) as caught:
                    result.main()
                self.assertIs(caught.exception, original_error)
                self.assertEqual(opened.call_count, 1)
                closed.assert_called_once_with(97)


if __name__ == "__main__":
    unittest.main()
