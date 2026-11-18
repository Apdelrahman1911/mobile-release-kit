"""Unit checks for the hosted in-place update check (#49); no Installer runs."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macos_update_check", ROOT / "desktop/tools/macos_update_check.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

VALID = {"schemaVersion": 1,
         "previous": {"runId": "42930321870", "artifactId": "13821079751", "carrierArtifactId": "13822869472", "packageSha256": "e" * 64,
                      "packageVersion": "0.1.4", "release": "macos26-arm64-desktop-04"},
         "next": {"runId": "43900000000", "artifactId": "14200000000", "carrierArtifactId": "14200000001", "packageSha256": "f" * 64,
                  "packageVersion": "0.1.5", "release": "macos26-arm64-desktop-05"}}


def write(value):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, handle)
    handle.close()
    return handle.name


class UpdateCheckSelectionTests(unittest.TestCase):
    def test_valid_upgrade_selection(self):
        self.assertEqual(M.load_selection(write(VALID))["next"]["release"], "macos26-arm64-desktop-05")

    def test_refuses_non_upgrade_and_malformed_rows(self):
        cases = []
        same = copy.deepcopy(VALID); same["next"]["packageVersion"] = "0.1.4"; cases.append(same)
        down = copy.deepcopy(VALID); down["next"]["packageVersion"] = "0.1.3"; cases.append(down)
        extra = copy.deepcopy(VALID); extra["next"]["url"] = "https://example.invalid"; cases.append(extra)
        bad_sha = copy.deepcopy(VALID); bad_sha["previous"]["packageSha256"] = "E" * 64; cases.append(bad_sha)
        bad_release = copy.deepcopy(VALID); bad_release["next"]["release"] = "macos26-x86_64-desktop-05"; cases.append(bad_release)
        bad_run = copy.deepcopy(VALID); bad_run["next"]["runId"] = "0"; cases.append(bad_run)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(M.Failed):
                M.load_selection(write(case))

    def test_committed_selection_is_the_installed_ac506_predecessor(self):
        path = ROOT / "desktop/macos-installed-inputs/update-check-selection.json"
        selection = M.load_selection(path)
        previous = selection["previous"]
        self.assertEqual((previous["packageVersion"], previous["release"], previous["packageSha256"]),
                         ("0.1.4", "macos26-arm64-desktop-04",
                          "ed44a41a0b286ce831fe18c36e5178afbab492ce12e77aff294ce3dfaa0a4f15"))
        history = json.loads((ROOT / "desktop/macos-installed-inputs/producer-history.json").read_text())
        accepted = history["targets"]["aarch64-apple-darwin"]["acceptedPredecessors"]
        self.assertIn(previous["packageSha256"], [row["packageSha256"] for row in accepted])
        build = json.loads((ROOT / "desktop/macos-installed-inputs/build-release.json").read_text())
        self.assertEqual((selection["next"]["packageVersion"], selection["next"]["release"]),
                         (build["packageVersion"], build["release"]))


class LaunchSmokeSourceTests(unittest.TestCase):
    def test_window_query_uses_no_apple_events_or_privacy_prompts(self):
        self.assertIn("CGWindowListCopyWindowInfo", M.WINDOWS_JXA)
        for forbidden in ("tell application", "System Events", "Application(", "doShellScript"):
            self.assertNotIn(forbidden, M.WINDOWS_JXA)

    def test_both_modes_are_wired_in_the_workflow(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-update-check.yml").read_text()
        self.assertIn("mode: [update, fresh]", workflow)
        self.assertIn('--mode "${{ matrix.mode }}"', workflow)
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        self.assertIn('choices=("update", "fresh", "remove")', source)
        # The launch smoke runs only after every user-data comparison in update mode.
        update = source.split("def main():", 1)[1]
        self.assertLess(update.index('"user-data-changed-by-downgrade-attempt"'), update.index('launch_smoke("after-update"'))

    def test_remove_mode_confirms_only_the_exact_sheet_and_checks_before_reinstall(self):
        self.assertIn("'Continue and Quit'", M.SHEET_JXA)
        self.assertIn("'Quit and prepare to remove Mobile Release Kit?'", M.SHEET_JXA)
        self.assertIn("names.length !== 2", M.SHEET_JXA)
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text().split("def remove_check(", 1)[1]
        order = [source.index(marker) for marker in ('"removal-sheet-not-confirmed"', '"remove-returned-nonzero"',
                 '"removal-left-app-objects"', '"user-data-changed-by-removal"', 'install("reinstall"',
                 '"user-data-changed-by-reinstall"', 'launch_smoke("after-reinstall"')]
        self.assertEqual(order, sorted(order))

    def test_removal_selection_is_optional_and_strict(self):
        import tempfile
        base = json.loads((ROOT / "desktop/macos-installed-inputs/update-check-selection.json").read_text())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "selection.json"
            for removal, ok in ((None, True), ({"runId": "1", "artifactId": "2", "imageSha256": "a" * 64}, True),
                                ({"runId": "1", "artifactId": "2"}, False)):
                value = dict(base) if removal is None else dict(base, removal=removal)
                path.write_text(json.dumps(value))
                if ok:
                    M.load_selection(path)
                else:
                    with self.assertRaises(M.Failed):
                        M.load_selection(path)


if __name__ == "__main__":
    unittest.main()
