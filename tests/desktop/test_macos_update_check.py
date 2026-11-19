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
        self.assertIn("mode: [update, fresh, remove]", workflow)
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
        text = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        live = text.split("def live_remove(", 1)[1].split("\ndef ", 1)[0]
        order = [live.index(marker) for marker in ('"removal-sheet-not-confirmed"', '"remove-returned-nonzero"',
                 '"removal-left-app-objects"')]
        self.assertEqual(order, sorted(order))
        source = text.split("def remove_check(", 1)[1].split("\ndef ", 1)[0]
        order = [source.index(marker) for marker in ('live_remove(mount, work, evidence, steps, "remove")',
                 '"user-data-changed-by-removal"', 'install("reinstall"',
                 '"user-data-changed-by-reinstall"', 'launch_smoke("after-reinstall"', "uninstaller_check(", '"detach"')]
        self.assertEqual(order, sorted(order))

    def test_uninstaller_check_covers_cancel_recovery_refusal_and_scoped_deletion(self):
        self.assertEqual(M.REMOVAL_SIDECARS, ("Remove.pkg", "remove-producer.json", "remove-producer.sig"))
        self.assertEqual(M.UNINSTALLER, "Uninstall Mobile Release Kit.app")
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        image = source.split("def removal_image(", 1)[1].split("\ndef ", 1)[0]
        for marker in ('"removal-image-hidden-sidecars"', '"uninstaller-codesign"', '"uninstaller-gatekeeper"',
                       '"Notarized Developer ID"', "stat.UF_HIDDEN"):
            self.assertIn(marker, image)
        check = source.split("def uninstaller_check(", 1)[1].split("\ndef ", 1)[0]
        order = [check.index(marker) for marker in ('"uninstall-cancel-delete"', '"uninstall-cancel-keep"',
                 '"uninstall-installer-quit"', "p.returncode == 65", 'live_remove(mount, work, evidence, steps, "remove-again")',
                 '"user-data-changed-by-second-removal"', '"uninstall-delete"', '"delete-all-data-left-app-data"',
                 '"delete-all-data-removed-decoy-keychain-item"', '"delete-all-data-touched-other-files"')]
        self.assertEqual(order, sorted(order))
        # Cancels are pinned to the exact dialog, never the first "Cancel" seen.
        self.assertIn('("Cancel", "Delete All Data")', check)
        self.assertIn('("Cancel", "Continue")', check)
        # Decoys include a look-alike sibling, a project, gh config and link targets.
        self.assertTrue(any("desktop.decoy" in d for d in M.DECOY_FILES))
        self.assertTrue(any(d.startswith("Projects/") for d in M.DECOY_FILES))
        self.assertTrue(any(d.startswith(".config/gh/") for d in M.DECOY_FILES))
        self.assertNotIn(M.DECOY_SERVICE, M.KEYCHAIN_SERVICES)

    def test_fresh_mode_adds_interruption_resources_and_signature_after_existing_checks(self):
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        fresh = source.split("def fresh_check(", 1)[1].split("\ndef ", 1)[0].split("\nSHEET_JXA", 1)[0]
        order = [fresh.index(m) for m in ('launch_smoke("reopen"', 'kill_and_relaunch("kill-startup"',
                 'kill_and_relaunch("kill-idle"', "installed_signature_check(", '"installed-app-codesign"',
                 '"installed-app-gatekeeper"', '"installed-app-not-hardened-runtime"')]
        self.assertEqual(order, sorted(order))
        kill = source.split("def kill_and_relaunch(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("signal.SIGKILL", kill)
        for marker in ('-partial-app-data"', '-idle-kill-changed-app-data"', '-app-survived-sigkill"', "launch_smoke(label + \"-relaunch\""):
            self.assertIn(marker, kill)
        smoke = source.split("def launch_smoke(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('"resources": resource_summary(samples)', smoke)
        # Resources are recorded, never a pass/fail budget (owner decision, #66).
        self.assertNotIn("Rss", smoke.split("need(", 1)[1] if "need(" in smoke else "")
        summary = M.resource_summary([{"t": 1, "phase": "startup", "processes": 2, "rssKiB": 10, "cpuPercent": 50.0, "appRssKiB": 8},
                                      {"t": 2, "phase": "idle", "processes": 3, "rssKiB": 30, "cpuPercent": 2.0, "appRssKiB": 20},
                                      {"t": 3, "phase": "idle", "processes": 3, "rssKiB": 25, "cpuPercent": 4.0, "appRssKiB": 18}])
        self.assertEqual((summary["peakRssKiB"], summary["idleRssKiB"], summary["idleAppRssKiB"], summary["idleMeanCpuPercent"],
                          summary["peakProcesses"]), (30, 25, 18, 3.0, 3))

    def test_uninstaller_sources_match_the_harness(self):
        folder = ROOT / "desktop/macos-installed-inputs/uninstaller"
        script = (folder / "delete-data.sh").read_text()
        applet = (folder / "main.applescript").read_text()
        for service in M.KEYCHAIN_SERVICES:
            self.assertIn(f"'{service}'", script)
        for app_id in M.APP_IDS:
            self.assertIn(app_id, script)
        self.assertIn("exit 65", script)
        self.assertIn("rm -r -f -x --", script)
        self.assertNotIn("sudo", script)
        for label in (M.KEEP_LABEL, M.DELETE_LABEL, "Delete All Data", "still installed, so none of your data was deleted",
                      "was removed, but some data was kept"):
            self.assertIn(label, applet)
        self.assertIn("default button keepLabel", applet)
        self.assertIn('default button "Cancel" cancel button "Cancel"', applet)
        # No top-level state an applet would save into its signed bundle.
        self.assertNotRegex(applet, r"(?m)^\s*(property|global)\s")

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



class FirstLaunchObservationTests(unittest.TestCase):
    """#45/#46/#50 first-launch evidence; no app, osascript or CLI runs."""

    def test_ui_script_only_reads_or_clicks_a_named_element(self):
        for forbidden in ("keystroke", "doShellScript", "setValue", "value =", ".value(", "delete", "privilege"):
            if forbidden == ".value(":
                self.assertEqual(M.UI_JXA.count(".value("), 1)  # the single static-text read
                continue
            self.assertNotIn(forbidden, M.UI_JXA)
        self.assertIn("e.click()", M.UI_JXA)
        self.assertIn("AXStaticText", M.UI_JXA)

    def observe(self, overview, tools, cli_rc=3, cli_text="... CLI / AI access ..."):
        from unittest import mock
        replies = iter([overview, {"clicked": "Build tools", "role": "AXLink"}, tools])
        cli = mock.Mock(returncode=cli_rc, stdout=cli_text, stderr="")
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(M, "ui_query", side_effect=lambda *a, **k: next(replies)), \
             mock.patch.object(M.time, "sleep"), \
             mock.patch.object(M.subprocess, "run", return_value=cli):
            return M.first_launch_observe(123, Path(folder), Path(folder), "first-launch")

    def test_runtime_card_classification(self):
        ok = self.observe({"texts": ["Get your app ready."]}, {"texts": ["CORE RUNTIME", "Bundled runtime", "available"]})
        self.assertEqual((ok["runtimeCard"], ok["workspaceErrorMarkers"], ok["cliStatus"]),
                         ("bundled", [], {"returncode": 3, "guidance": True}))
        bad = self.observe({"texts": []}, {"texts": ["CORE RUNTIME", "Runtime unavailable"]})
        self.assertEqual(bad["runtimeCard"], "unavailable")
        unseen = self.observe({"error": "timeout"}, {"error": "no-window"})
        self.assertEqual((unseen["runtimeCard"], unseen["overviewError"]), ("not-observed", "timeout"))

    def test_workspace_error_and_cli_guidance_are_recorded(self):
        value = self.observe({"texts": ["Minified React error #185"]}, {"texts": ["Bundled runtime"]},
                             cli_rc=0, cli_text="{}")
        self.assertEqual(value["workspaceErrorMarkers"], ["Minified React error"])
        self.assertEqual(value["cliStatus"], {"returncode": 0, "guidance": False})

    def test_fresh_check_enforces_only_definite_failures(self):
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        fresh = source[source.index("def fresh_check"):source.index("SHEET_JXA = ")]
        for reason in ('"fresh-first-launch-runtime-unavailable"', '"fresh-first-launch-workspace-error"',
                       '"fresh-cli-status-guidance"'):
            self.assertIn(reason, fresh)
        self.assertIn('observe=first_launch_observe', fresh)
        self.assertIn('!= "unavailable"', fresh)


if __name__ == "__main__":
    unittest.main()
