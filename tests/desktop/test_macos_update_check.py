"""Unit checks for the hosted in-place update check (#49); no Installer runs."""
import copy
import importlib.util
import json
import plistlib
import subprocess
import sys
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

    def test_two_upgrade_hops_require_strict_versions_and_full_artifact_references(self):
        path_data = copy.deepcopy(VALID)
        path_data["initial"] = dict(path_data["previous"], packageVersion="0.1.3",
                                    release="macos26-arm64-desktop-03", packageSha256="a" * 64)
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "selection.json"
            path.write_text(json.dumps(path_data))
            self.assertEqual(M.load_selection(path), path_data)
            for field, invalid in (("packageVersion", "0.1.4"), ("packageSha256", ""),
                                   ("carrierArtifactId", "0")):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(M.Failed):
                    broken = copy.deepcopy(path_data)
                    broken["initial"][field] = invalid
                    path.write_text(json.dumps(broken))
                    M.load_selection(path)

    def test_three_upgrade_hops_validate_the_intermediate_artifact_in_order(self):
        selection = copy.deepcopy(VALID)
        selection["initial"] = dict(selection["previous"], packageVersion="0.1.2")
        selection["intermediate"] = dict(selection["previous"], packageVersion="0.1.3")
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "selection.json"
            path.write_text(json.dumps(selection))
            self.assertEqual(M.selected_release_roles(M.load_selection(path)),
                             ["initial", "intermediate", "previous", "next"])
            ambiguous = dict(selection, intermediate=selection["previous"])
            without_initial = {key: value for key, value in selection.items() if key != "initial"}
            for invalid in (ambiguous, without_initial):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(M.Failed):
                    M.load_selection(path)

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
        previous = selection.get("initial", selection["previous"])
        self.assertEqual((previous["packageVersion"], previous["release"], previous["packageSha256"]),
                         ("0.1.4", "macos26-arm64-desktop-04",
                          "ed44a41a0b286ce831fe18c36e5178afbab492ce12e77aff294ce3dfaa0a4f15"))
        history = json.loads((ROOT / "desktop/macos-installed-inputs/producer-history.json").read_text())
        accepted = history["targets"]["aarch64-apple-darwin"]["acceptedPredecessors"]
        self.assertIn(previous["packageSha256"], [row["packageSha256"] for row in accepted])
        if "initial" in selection:
            installed_020 = selection.get("intermediate", selection["previous"])
            self.assertEqual((installed_020["packageVersion"], installed_020["release"],
                              installed_020["packageSha256"]),
                             ("0.2.0", "macos26-arm64-desktop-06",
                              "db9d76b1b3c137ba398cda6fb234ddf702219fbb89cff3d2d1c1bf0ef6926111"))
            if "intermediate" in selection:
                installed_021 = selection["previous"]
                self.assertEqual((installed_021["packageVersion"], installed_021["release"],
                                  installed_021["packageSha256"]),
                                 ("0.2.1", "macos26-arm64-desktop-07",
                                  "3cc29dda7841022c993bea447ec1090a105caa43cfd647da66d3a586ff8bac8b"))
                self.assertEqual((selection["next"]["packageVersion"], selection["next"]["release"]),
                                 ("0.2.3", "macos26-arm64-desktop-09"))
                return
            self.assertEqual((selection["next"]["packageVersion"], selection["next"]["release"]),
                             ("0.2.1", "macos26-arm64-desktop-07"))
            return
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
        self.assertIn('fromJSON(\'["update","fresh","remove","uninstaller"]\')', workflow)
        self.assertIn("'[macos-remove-diagnostic]') && fromJSON('[\"remove\"]')", workflow)
        self.assertIn("'[macos-fresh-upgrade-check]') && fromJSON('[\"update\",\"fresh\"]')", workflow)
        self.assertIn("'[macos-delete-data-check]') && fromJSON('[\"delete-data\"]')", workflow)
        self.assertIn("'[macos-repeat-removal-check]') && fromJSON('[\"repeat\",\"repeat-after-dialogs\"]')", workflow)
        self.assertIn('--mode "${{ matrix.mode }}"', workflow)
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        self.assertIn('"repeat", "repeat-after-dialogs")', source)
        # The installed-only uninstaller mode never runs or claims a live removal.
        installed = source.split("def uninstaller_installed_check(", 1)[1].split("\ndef ", 1)[0]
        self.assertNotIn("live_remove(", installed)
        self.assertIn("uninstaller_while_installed(", installed)
        # The launch smoke runs only after every user-data comparison in update mode.
        update = source.split("def main():", 1)[1]
        self.assertLess(update.index('"user-data-changed-by-downgrade-attempt"'), update.index('launch_smoke("after-update"'))

    def test_remove_mode_confirms_only_the_exact_sheet_and_checks_before_reinstall(self):
        self.assertIn("'Continue and Quit'", M.SHEET_JXA)
        self.assertIn("'Quit and prepare to remove Mobile Release Kit?'", M.SHEET_JXA)
        self.assertIn("'Quit and discard unsaved drafts?'", M.SHEET_JXA)
        self.assertIn("names.length !== 2", M.SHEET_JXA)
        text = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        live = text.split("def live_remove(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('phase = "quit" if clicked else "removal"', live)
        self.assertIn("pids[0] in live and not quit_clicked", live)
        order = [live.index(marker) for marker in ('"removal-sheet-not-confirmed"', '"remove-returned-nonzero"',
                 '"removal-quit-sheet-not-confirmed"', '"removal-left-app-objects"')]
        self.assertEqual(order, sorted(order))

        source = text.split("def remove_check(", 1)[1].split("\ndef ", 1)[0]
        order = [source.index(marker) for marker in ('live_remove(mount, work, evidence, steps, "remove",',
                 '"user-data-changed-by-removal"', 'install("reinstall"',
                 '"user-data-changed-by-reinstall"', 'launch_smoke("after-reinstall"', "uninstaller_check(", '"detach"')]
        self.assertEqual(order, sorted(order))

    def test_removal_metadata_changes_records_fields_without_paths_or_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-name"
            path.write_bytes(b"x")
            paths = {"producer": path}
            first, changes = M.removal_metadata_changes(paths, {})
            self.assertEqual(changes, {})
            path.chmod(0o444)
            second, changes = M.removal_metadata_changes(paths, first)
            self.assertIn("st_mode", changes["producer"])
            self.assertNotIn(str(path), json.dumps(changes))
            path.unlink()
            self.assertEqual(M.removal_metadata_changes(paths, second)[1], {"producer": ["availability"]})

    def test_remove_result_retains_installer_status_when_acceptance_raises(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest import mock

        for installer_status, failure in ((1, "remove-returned-nonzero"), (None, "remove-app-not-running")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)

                def refuse(_selection, _work, _evidence, steps, _result):
                    steps.append({"role": "remove-launch", "returncode": 0})
                    if installer_status is not None:
                        steps.append({"role": "remove", "returncode": installer_status})
                    raise M.Failed(failure)

                argv = ["check", "--selection", "unused", "--work", directory, "--mode", "remove"]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(M, "load_selection", return_value=VALID), \
                     mock.patch.object(M, "STATE", work / "state"), mock.patch.object(M, "USER_DATA", work / "user"), \
                     mock.patch.object(M, "remove_check", side_effect=refuse), mock.patch.object(M, "install_log_excerpt"), \
                     redirect_stdout(StringIO()) as stdout:
                    self.assertEqual(M.main(), 1)
                result = json.loads((work / "evidence" / "RESULT.json").read_text())
                for row in (result, json.loads(stdout.getvalue())):
                    self.assertFalse(row["passed"])
                    self.assertEqual(row["failure"], failure)
                    self.assertEqual(row["removeReturn"], installer_status)

    def test_removal_file_summary_keeps_only_fixed_categories(self):
        root = str(M.STATE)
        trace = [f"open {root}-RemovalRequests/r-private/request.json", f"stat {root}/installation-v2.json",
                 f"open {root}/installation-v2.json", "open /Users/runner/private.txt",
                 f"open {root}/versions/release/runtime/private"]
        self.assertEqual(M.removal_file_summary(trace), "request -> transaction-state -> runtime")

    def test_uninstaller_check_covers_cancel_recovery_refusal_and_scoped_deletion(self):
        self.assertEqual(M.REMOVAL_SIDECARS, ("Remove.pkg", "remove-producer.json", "remove-producer.sig"))
        self.assertEqual(M.UNINSTALLER, "Uninstall Mobile Release Kit.app")
        source = (ROOT / "desktop/tools/macos_update_check.py").read_text()
        image = source.split("def removal_image(", 1)[1].split("\ndef ", 1)[0]
        for marker in ('"removal-image-hidden-sidecars"', '"uninstaller-codesign"', '"uninstaller-gatekeeper"',
                       '"Notarized Developer ID"', "stat.UF_HIDDEN"):
            self.assertIn(marker, image)
        installed = source.split("def uninstaller_while_installed(", 1)[1].split("\ndef ", 1)[0]
        confirmed = source.split("def uninstaller_check(", 1)[1].split("\ndef ", 1)[0]
        # The confirmed path first runs every installed-app path, then removes.
        self.assertLess(confirmed.index("uninstaller_while_installed("),
                        confirmed.index('live_remove(mount, work, evidence, steps, "remove-again")'))
        deletion = source.split("def confirmed_data_deletion(", 1)[1]
        check = installed + confirmed + deletion
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

    def test_quarantined_remove_media_binds_read_only_mount_to_the_opened_image(self):
        from unittest import mock

        image = Path("/private/tmp/staged/MobileReleaseKit-Remove.dmg")
        mount = "/Volumes/MobileReleaseKit"
        original = {"image-path": str(image), "writeable": False, "system-entities": [{"mount-point": mount}]}
        other = {**original, "image-path": "/private/tmp/foreign.dmg", "system-entities": [{"mount-point": "/Volumes/Foreign"}]}
        opened = subprocess.CompletedProcess([], 0)

        for writable in (False, True):
            with self.subTest(writable=writable):
                info = plistlib.dumps({"images": [other, {**original, "writeable": writable}]})
                with mock.patch.object(M, "run", return_value=(opened, {})) as launch, \
                     mock.patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, info)) as inspect:
                    steps = []
                    if writable:
                        with self.assertRaisesRegex(M.Failed, "removal-image-writable"):
                            M.open_quarantined_removal_image(image, steps)
                    else:
                        self.assertEqual(M.open_quarantined_removal_image(image, steps), Path(mount))
                    launch.assert_called_once_with(["/usr/bin/open", str(image)], 60)
                    inspect.assert_called_once_with(["/usr/bin/hdiutil", "info", "-plist"], capture_output=True, timeout=20)
                    self.assertEqual(steps, [{"role": "removal-image-launch-services"}])

    def test_delete_data_can_run_after_the_first_confirmed_removal(self):
        from unittest import mock

        row = VALID["next"]
        selection = {"next": row, "removal": {}}
        result = {"mode": "delete-data"}
        state = {"sheet": ["clicked"], "quitSheet": ["clicked"], "returncode": 0,
                 "remaining": {"app": False, "launcher": False, "process": False}}
        seeded = {"settings.json": "fixture"}
        with mock.patch.object(M, "fetch"), mock.patch.object(M, "removal_image", return_value=("mounted", [])), \
             mock.patch.object(M, "install", return_value=0) as install, mock.patch.object(M, "installed_state", return_value=row), \
             mock.patch.object(M, "seed_user_data", return_value=seeded), mock.patch.object(M, "manifest", return_value=seeded), \
             mock.patch.object(M, "live_remove", return_value=state) as removal, mock.patch.object(M, "plant_decoys", return_value={}), \
             mock.patch.object(M, "confirmed_data_deletion") as deletion, mock.patch.object(M.subprocess, "run"):
            M.remove_check(selection, "work", "evidence", [], result)
        self.assertEqual(install.call_count, 1)
        self.assertEqual(removal.call_count, 1)
        deletion.assert_called_once_with("mounted", "work", "evidence", result, {})
        self.assertEqual(result["removeReturn"], 0)
        self.assertTrue(result["userDataPreservedByRemoval"])

    @unittest.skipUnless(sys.platform == "darwin", "uses macOS stat and rm")
    def test_uninstaller_file_cleanup_preserves_linked_ancestors_and_decoys(self):
        script = (ROOT / "desktop/macos-installed-inputs/uninstaller/delete-data.sh").read_text()
        actual_cleanup = script[script.index("library_device="):script.index("# The app's own login-keychain items")]
        fixture_command = 'uid=$(id -u)\nlib=$1\n' + actual_cleanup + '\nexit "$status"\n'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            library = root / "Library"
            library.mkdir()
            app_id = "dev.mobile-release-kit.desktop"
            project = root / "Projects" / app_id
            project.mkdir(parents=True)
            decoy = project / "keep.txt"
            decoy.write_text("project data")
            linked_parent = library / "Application Support"
            linked_parent.symlink_to(project.parent)
            cache = library / "Caches" / app_id
            cache.mkdir(parents=True)
            (cache / "link-out").symlink_to(project)
            linked_leaf = library / "Caches" / f"{app_id}.entry"
            linked_leaf.symlink_to(project)
            receipt = subprocess.run(["/bin/sh", "-c", fixture_command, "file-cleanup", str(library)],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(receipt.returncode, 1, receipt.stdout + receipt.stderr)
            self.assertIn(f"kept (link, not followed): {linked_parent}", receipt.stdout)
            self.assertTrue(linked_leaf.is_symlink())
            self.assertFalse(cache.exists())
            self.assertEqual(decoy.read_text(), "project data")

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

    def test_crash_facts_bind_to_the_observed_process_without_including_report_content(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "synthetic.ips"
            report.write_text('{}\n{"procName":"mobile-release-kit-desktop","pid":17,'
                              '"exception":{"type":"EXC_BAD_ACCESS"},"termination":{"namespace":"SIGNAL"},'
                              '"path":"unpublished fixture path"}')
            self.assertEqual(M.crash_report_facts(report, {17}), {"read": True, "role": "payload",
                             "pidSeenThisLaunch": True, "exception": "EXC_BAD_ACCESS", "termination": "SIGNAL"})
            self.assertFalse(M.crash_report_facts(report, {18})["pidSeenThisLaunch"])
            report.write_text("truncated")
            self.assertEqual(M.crash_report_facts(report, {17}), {"read": False})

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



class RetainedRemovalTests(unittest.TestCase):
    def test_keep_data_checks_credential_before_reinstall_and_never_deletes_it(self):
        from unittest import mock

        row = VALID["next"]
        selection = {"next": row, "removal": {}}
        work = Path("unused-fixture")
        seeded = {"fixture": "file-digest"}
        archive = {".remove-fixture": (1, 2)}
        credential = b"keychain-fixture"
        for preserved in (True, False):
            with self.subTest(preserved=preserved):
                result = {"mode": "retained-transition"}
                install = mock.Mock(return_value=0)
                uninstaller = mock.Mock()
                check_credential = mock.Mock(return_value=preserved)
                order = mock.Mock()
                order.attach_mock(check_credential, "credential")
                order.attach_mock(install, "install")
                with mock.patch.multiple(
                    M, removal_image=mock.Mock(return_value=(work, [])), installed_state=mock.Mock(return_value=row),
                    live_remove=mock.Mock(return_value={"sheet": [], "quitSheet": [], "returncode": 0, "remaining": {}}),
                    manifest=mock.Mock(return_value=seeded), install=install, update_credential_matches=check_credential,
                    removal_archive_identities=mock.Mock(return_value=archive), uninstaller_check=uninstaller,
                    launch_smoke=mock.Mock(return_value={"ui": {"runtimeCard": "bundled"}}),
                ), mock.patch.object(M.subprocess, "run"):
                    if preserved:
                        M.remove_check(selection, work, work, [], result, folder=work, seeded=seeded, credential=credential)
                        install.assert_called_once()
                        self.assertEqual(result["reinstallReturn"], 0)
                    else:
                        with self.assertRaisesRegex(M.Failed, "retained-credential-changed-by-removal"):
                            M.remove_check(selection, work, work, [], result, folder=work, seeded=seeded, credential=credential)
                        install.assert_not_called()
                self.assertEqual(order.mock_calls[0], mock.call.credential(credential))
                uninstaller.assert_not_called()
                self.assertEqual(result["credentialPreservedAfterRemoval"], preserved)


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

    def observe(self, overview, tools, cli_rc=3, cli_text="... CLI / AI access ...", details=()):
        from unittest import mock
        replies = iter([overview, {"clicked": "Build tools", "role": "AXLink"}, tools, *details])
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

    def test_opens_collapsed_runtime_card(self):
        opened = {"clicked": M.RUNTIME_DETAILS_LABEL, "role": "AXDisclosureTriangle"}
        result = self.observe({"texts": []}, {"texts": [M.RUNTIME_DETAILS_LABEL]},
                              details=(opened, {"texts": [M.RUNTIME_AVAILABLE_TEXT]}))
        self.assertEqual((result["runtimeCard"], result["runtimeDetails"]), ("bundled", opened))

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
