"""Inert diagnostic contracts only. These tests never launch a Mac application."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mrk_entry_diagnostic_contract", ROOT / "desktop/tools/macos_installed_entry_diagnostic.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE = "a" * 40


def normal_observation():
    value = {key: False for key in MODULE.BOOLS}
    value.update({key: None for key in MODULE.NULLABLE_BOOLS})
    value.update({key: 1 for key in MODULE.COUNTS})
    value.update({key: "entry" for key in MODULE.IDENTITIES})
    value.update(schemaVersion=1, scope="ordinary-installed-entry-launch-diagnostic-v1", diagnosticSource=SOURCE,
        applicationSource=MODULE.APPLICATION_SOURCE, launchRequested=True, launchReferenceReturned=True,
        normalTerminateRequested=True, normalTerminateReturned=True, terminationObserved=True,
        ancestorCloseReturned=True, probeClosesReturned=True, finalDeadlineMet=True, observationComplete=True,
        referenceTerminatedAtObservation=False, referenceFinishedLaunching=True, referenceActive=True,
        gateBefore="free", gateWhileOriginalLive="busy", gateAfterTermination="free", launchErrorDomain="none",
        launchErrorCode=None, originalAppExitStatus=None, allWorkerFinality="not-established", firstFailure="none")
    return value


def frame(value):
    return MODULE.PREFIX + json.dumps(value, separators=(",", ":")).encode() + b"\n"


class InstalledEntryDiagnosticContracts(unittest.TestCase):
    def test_outer_only_original_is_valid_diagnostic_not_payload_or_product_qualification(self):
        value = normal_observation()
        self.assertEqual(MODULE.native_result(frame(value), SOURCE), value)
        self.assertTrue(value["observationComplete"])
        self.assertIsNone(value["originalAppExitStatus"])
        for key in ("normalQuitQualified", "fullUIQualified", "fullM2Qualified", "productReady"):
            self.assertFalse(value[key])
        payload = copy.deepcopy(value)
        for key in MODULE.IDENTITIES:
            payload[key] = "payload"
        self.assertEqual(MODULE.native_result(frame(payload), SOURCE), payload)
        # A cached outer finishedLaunching=false is a useful observation, not
        # a reason to turn this diagnostic into an inevitable UI timeout.
        value["referenceFinishedLaunching"] = False
        self.assertEqual(MODULE.native_result(frame(value), SOURCE), value)

    def test_refusal_and_late_cleanup_remain_noncomplete_diagnostics(self):
        value = normal_observation()
        value.update(observationComplete=False, workDeadlineFailed=True, firstFailure="observation-deadline",
                     referenceTerminatedAtObservation=None, referenceFinishedLaunching=None, referenceActive=None,
                     gateWhileOriginalLive="unobserved", forceTerminateRequested=True, forceTerminateReturned=True)
        for key in MODULE.IDENTITIES:
            value[key] = "unavailable"
        self.assertEqual(MODULE.native_result(frame(value), SOURCE), value)
        value["observationComplete"] = True
        with self.assertRaises(MODULE.Refused):
            MODULE.native_result(frame(value), SOURCE)

    def test_result_mutations_cannot_mint_finality_or_hide_bad_counts(self):
        mutations = [
            ("schemaVersion", True), ("launchRequested", 1), ("completionCount", True),
            ("completionCount", 2), ("completionBodyDoneCount", 0), ("completionHandoffCount", 2),
            ("diagnosticSource", "b" * 40), ("applicationSource", SOURCE), ("originalAppExitStatus", 0),
            ("allWorkerFinality", "settled"), ("productReady", True), ("firstFailure", "none-but-ignore-error"),
            ("terminationObserved", False), ("probeClosesReturned", False), ("finalDeadlineMet", False),
            ("referenceTerminatedAtObservation", True), ("referenceFinishedLaunching", None),
            ("gateWhileOriginalLive", "free"), ("launchErrorDomain", "posix"), ("launchErrorCode", 2**31),
        ]
        for key, changed in mutations:
            with self.subTest(key=key, changed=changed):
                value = normal_observation(); value[key] = changed
                with self.assertRaises(MODULE.Refused):
                    MODULE.native_result(frame(value), SOURCE)
        raw = frame(normal_observation())
        for bad in (raw + b"unreviewed\n", b"other=" + raw, raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1')):
            with self.assertRaises(MODULE.Refused):
                MODULE.native_result(bad, SOURCE)

    def test_direct_status_requires_same_returned_command_not_synthetic_timeout_success(self):
        for code, outcome in ((0, "returned-zero"), (68, "returned-entry-refusal"),
                              (1, "returned-payload-generic-one"), (12, "returned-other")):
            result = subprocess.CompletedProcess([MODULE.ENTRY], code, b"", b"")
            self.assertEqual(MODULE.direct_outcome(result), outcome)
        for result in (subprocess.CompletedProcess([MODULE.ENTRY], -15, b"", b""),
                       subprocess.CompletedProcess([MODULE.ENTRY, "extra"], 64, b"", b""),
                       subprocess.CompletedProcess([MODULE.ENTRY], 0, "", ""),
                       subprocess.CompletedProcess([MODULE.ENTRY], True, b"", b""),
                       SimpleNamespace(args=[MODULE.ENTRY], returncode=0, stdout=b"", stderr=b"")):
            with self.assertRaises(MODULE.Refused):
                MODULE.direct_outcome(result)

    def test_artifact_bound_and_roster_precede_any_materialization(self):
        def archive(names):
            target = io.BytesIO()
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as stream:
                for name in names:
                    stream.writestr(name, b"inert fixture, never executable")
            return target.getvalue()
        for names in (("MobileReleaseKit.pkg", "README.md", "../PREVIEW.json"),
                      ("MobileReleaseKit.pkg", "README.md", "PREVIEW.json", "extra")):
            body = archive(names)
            with patch.object(MODULE, "ARCHIVE_BYTES", len(body)), patch.object(MODULE, "ARCHIVE_SHA", MODULE.digest(body)):
                with self.assertRaises(MODULE.Refused):
                    MODULE.archive_members(body)
        with self.assertRaises(MODULE.Refused):
            MODULE.archive_members(b"unbound bytes")

    def test_complete_scripts_and_preview_image_correspondence_are_required(self):
        def directories(names):
            result = set()
            for name in names:
                parts = name.split("/")
                for count in range(1, len(parts)):
                    result.add("/".join(parts[:count]))
            return result
        rows = {"app/entry": {"size": 1, "sha256": MODULE.digest(b"E"), "executable": True},
                "app/payload": {"size": 1, "sha256": MODULE.digest(b"P"), "executable": True}}
        original = {"postinstall": (b"fixed inert hook", 0o555), "mrk-macos-install": (b"inert Mach-O stand-in", 0o555),
                    "input/install-inventory.json": (b"{}", 0o444), "input/app/entry": (b"E", 0o555),
                    "input/app/payload": (b"P", 0o555), "input": (None, 0o555), "input/app": (None, 0o555)}
        selected = {"installerInventorySha256": MODULE.digest(b"{}"), "runtimeManifestSha256": "0" * 64,
                    "signedEntryBinarySha256": MODULE.digest(b"E"), "signedAppBinarySha256": MODULE.digest(b"P")}
        # Existing stager parser tests own the actual CPIO/Mach-O parsing risk.
        # This inert seam tests the new complete correspondence wrapper only.
        def stage(entries):
            return SimpleNamespace(xar_members=lambda _: {"PackageInfo": b"info", "Scripts": b"cpio"},
                package_info=lambda _: None, cpio_members=lambda _: entries, macho=lambda _: None,
                observation_inventory_bytes=lambda *_: rows, directories=directories,
                ENTRY_BINARY="entry", APP_BINARY="payload")
        inventory, facts = MODULE.package_inventory(stage(original), b"fixed", selected, b"fixed inert hook")
        self.assertEqual(inventory, b"{}")
        self.assertEqual(facts["fileCount"], 2)
        for name, replacement in (("extra", (b"foreign", 0o555)), ("input/app/entry", (b"X", 0o555)),
                                  ("input/app", (None, 0o755)), ("postinstall", (b"fixed inert hook", 0o444))):
            changed = copy.deepcopy(original); changed[name] = replacement
            with self.subTest(name=name), self.assertRaises(MODULE.Refused):
                MODULE.package_inventory(stage(changed), b"fixed", selected, b"fixed inert hook")
        changed_preview = {**selected, "signedEntryBinarySha256": "f" * 64}
        with self.assertRaises(MODULE.Refused):
            MODULE.package_inventory(stage(original), b"fixed", changed_preview, b"fixed inert hook")

    @unittest.skipUnless(os.name == "posix", "POSIX no-clobber fixture; native Mac behavior remains separate")
    def test_no_clobber_and_unknown_owner_retains_its_build(self):
        with tempfile.TemporaryDirectory(prefix="mrk-entry-diagnostic-contract-") as selected:
            root = Path(selected)
            marker = root / "launch-attempted"
            MODULE.write_new(marker, b"original\n", 0o400)
            with self.assertRaises(FileExistsError):
                MODULE.write_new(marker, b"replacement\n", 0o400)
            self.assertEqual(marker.read_bytes(), b"original\n")
            build = root / "build"; build.mkdir()
            retained = build / "observe"; retained.write_bytes(b"inert fixture")
            context = MODULE.Context.__new__(MODULE.Context)
            context.inflight = True
            context.work = root
            context.report = {"cleanup": {"unknownStateRetained": False}}
            context.cleanup()
            self.assertTrue(context.report["cleanup"]["unknownStateRetained"])
            self.assertEqual(retained.read_bytes(), b"inert fixture")

    @unittest.skipUnless(os.name == "posix", "POSIX installer-channel contract; no native application execution")
    def test_protected_work_root_uses_same_installer_status_channel(self):
        # Execute the unchanged stager's actual status caller, but with its os
        # namespace replaced by an inert dictionary model; no app/Installer call.
        spec = importlib.util.spec_from_file_location("mrk_entry_channel_contract", ROOT / MODULE.STAGER)
        stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stage)
        fixed = MODULE.work_path(SOURCE, "12", "1", "launchservices")
        self.assertEqual(fixed.parent, Path("/Users/runner"))
        self.assertEqual(fixed.name, "mrk-macos-entry-diagnostic-" + SOURCE + "-12-1-launchservices")
        for work, allowed in ((fixed, True), (Path("/private/tmp") / fixed.name, False)):
            context = MODULE.Context.__new__(MODULE.Context)
            context.work = work
            args = context.observation_args({"installerInventorySha256": "0" * 64,
                                             "runtimeManifestSha256": "1" * 64})
            self.assertEqual(args.input, work / "input")
            self.assertEqual(args.installer_status, work / "installer-output.status")
            rows, opened, offsets = {}, {}, {}
            chain = list(reversed(work.parents)) + [work]
            for index, path in enumerate(chain + [args.installer_status]):
                leaf = path == args.installer_status
                mode = (stat.S_IFREG | 0o600) if leaf else stat.S_IFDIR | (0o700 if path == work else 0o755)
                if path == Path("/private/tmp"):
                    mode = stat.S_IFDIR | 0o1777
                rows[path] = SimpleNamespace(st_dev=1, st_ino=index + 1, st_mode=mode,
                    st_uid=65534 if path == work or leaf or path == Path("/Users/runner") else 0,
                    st_gid=65534, st_nlink=1 if leaf else 2, st_size=2 if leaf else 0,
                    st_mtime_ns=1, st_ctime_ns=1)
            next_fd = [10]
            def selected(name, dir_fd=None):
                return Path(name) if dir_fd is None else opened[dir_fd] / name
            def fake_stat(name, *, dir_fd=None, follow_symlinks=False):
                self.assertFalse(follow_symlinks)
                return rows[selected(name, dir_fd)]
            def fake_open(name, flags, *, dir_fd=None):
                fd = next_fd[0]; next_fd[0] += 1
                path = selected(name, dir_fd)
                self.assertIn(path, rows)
                opened[fd], offsets[fd] = path, 0
                return fd
            def fake_read(fd, count):
                self.assertEqual(opened[fd], args.installer_status)
                start = offsets[fd]; chunk = b"0\n"[start:start + count]
                offsets[fd] += len(chunk)
                return chunk
            def fake_close(fd):
                del opened[fd]; del offsets[fd]
            inert = SimpleNamespace(O_DIRECTORY=os.O_DIRECTORY, fspath=os.fspath, fsencode=os.fsencode,
                getuid=lambda: 65534, geteuid=lambda: 65534, getgid=lambda: 65534, getegid=lambda: 65534,
                stat=fake_stat, open=fake_open, fstat=lambda fd: rows[opened[fd]], read=fake_read,
                close=fake_close, listxattr=lambda fd: [])
            with patch.object(stage, "os", inert), patch.object(stage, "no_xattrs", lambda fd: self.assertIn(fd, opened)):
                if allowed:
                    stage.installer_success_status(args)
                else:
                    with self.assertRaisesRegex(stage.Refused, "installer-channel-parent-protection"):
                        stage.installer_success_status(args)
            self.assertEqual(opened, {})
            self.assertEqual(offsets, {})


    def ui_alias_fixture(self, root, alias=True):
        spec = importlib.util.spec_from_file_location("mrk_ui_alias_original_helper", ROOT / MODULE.UI_HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        applications = root / "Applications"
        developer = applications / ("Xcode_26.6.app" if alias else "Xcode.app") / "Contents/Developer"
        sdk = developer / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk"
        sdk.mkdir(parents=True)
        application = applications / "Xcode.app"
        if alias:
            application.symlink_to("Xcode_26.6.app", target_is_directory=True)
        return helper, application / "Contents/Developer", developer, sdk

    @unittest.skipUnless(os.name == "posix", "No-follow directory fixture, not native toolchain evidence")
    def test_selected_xcode_and_terminal_sdk_alias_bind_same_originals(self):
        for spelling in ("literal", "canonical", "logical", "sdk-alias"):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory(prefix="mrk-ui-alias-") as temporary:
                root = Path(temporary).resolve()
                helper, logical, physical, sdk = self.ui_alias_fixture(root, spelling != "literal")
                candidate = sdk
                if spelling == "logical":
                    candidate = logical / sdk.relative_to(physical)
                elif spelling == "sdk-alias":
                    candidate = sdk.with_name("MacOSX.sdk")
                    candidate.symlink_to(sdk.name, target_is_directory=True)
                report = {}
                with patch.object(MODULE, "UI_DEVELOPER", str(logical)):
                    with MODULE.SelectedUIToolchain(helper, report) as authority:
                        authority.admit_sdk(str(candidate), "26.5")
                        self.assertEqual(len(authority.bindings), 3)
                        self.assertFalse(report["toolchainAdmission"]["admitted"])
                self.assertEqual(authority.held, {"developer": None, "sdk-parent": None, "sdk": None})
                self.assertEqual(report["toolchainAdmission"], {"admitted": True, "check": "admitted",
                                 "originalClosesCompleted": True, "closeFailures": []})

    @unittest.skipUnless(os.name == "posix", "Task-owned alias refusal fixture, no native execution")
    def test_selected_xcode_refuses_other_installation_redirect_missing_and_cycle(self):
        for scenario in ("other-xcode", "prefix-lookalike", "dot-traversal", "application-escape",
                         "developer-redirect", "sdk-parent-redirect", "sdk-leaf-escape", "sdk-missing",
                         "sdk-cycle", "missing", "cycle"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix="mrk-ui-alias-refuse-") as temporary:
                root = Path(temporary).resolve()
                helper, logical, physical, sdk = self.ui_alias_fixture(root)
                candidate = str(sdk)
                application = logical.parent.parent
                if scenario in {"other-xcode", "prefix-lookalike"}:
                    name = "Xcode_26.4.app" if scenario == "other-xcode" else "Xcode_26.6.app-extra"
                    candidate = str(application.parent / name / "Contents/Developer" / sdk.relative_to(physical))
                    Path(candidate).mkdir(parents=True)
                elif scenario == "dot-traversal":
                    candidate = str(sdk.parent) + "/../SDKs/" + sdk.name
                elif scenario == "application-escape":
                    external = root / "Elsewhere/Xcode_26.6.app"
                    external.parent.mkdir()
                    physical.parent.parent.rename(external)
                    application.unlink()
                    application.symlink_to(external, target_is_directory=True)
                elif scenario == "developer-redirect":
                    external = root / "other-developer"
                    physical.rename(external)
                    physical.symlink_to(external, target_is_directory=True)
                elif scenario == "sdk-parent-redirect":
                    external = root / "other-sdks"
                    sdk.parent.rename(external)
                    sdk.parent.symlink_to(external, target_is_directory=True)
                elif scenario == "sdk-leaf-escape":
                    external = root / sdk.name
                    sdk.rename(external)
                    sdk.symlink_to(external, target_is_directory=True)
                elif scenario in {"sdk-missing", "sdk-cycle"}:
                    sdk.rmdir()
                    if scenario == "sdk-cycle":
                        sdk.symlink_to(sdk.name, target_is_directory=True)
                else:
                    application.unlink()
                    if scenario == "cycle":
                        application.symlink_to(application.name, target_is_directory=True)
                report = {}
                authority = MODULE.SelectedUIToolchain(helper, report)
                with patch.object(MODULE, "UI_DEVELOPER", str(logical)):
                    with self.assertRaises((MODULE.Refused, OSError, RuntimeError)):
                        with authority:
                            authority.admit_sdk(candidate, "26.5")
                self.assertFalse(report["toolchainAdmission"]["admitted"])
                self.assertTrue(report["toolchainAdmission"]["originalClosesCompleted"])
                self.assertTrue(all(fd is None for fd in authority.held.values()))

    @unittest.skipUnless(os.name == "posix", "Owned directory/CompletedProcess seams only, no build/test process")
    def test_ui_build_requires_query_original_binding_and_final_closes_keeps_safe_diagnostics(self):
        for scenario in ("accepted", "query-retarget", "close-uncertain", "unsafe-values", "wrong-major"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix="mrk-ui-build-seam-") as temporary:
                root = Path(temporary).resolve()
                helper, logical, physical, sdk = self.ui_alias_fixture(root)
                alternative = logical.parent.parent.parent / "Xcode_26.7.app/Contents/Developer"
                alternative.mkdir(parents=True)
                pending, acquired, consumed, queries, builds = set(), [], [], [], []
                def open_original(path):
                    fd = helper.open_directory(path)
                    pending.add(fd); acquired.append(fd)
                    return fd
                def close_original(fd):
                    owned = fd in pending
                    if owned:
                        pending.remove(fd); consumed.append(fd)
                    os.close(fd)  # Always really consume the fixture FD before simulating uncertainty.
                    if owned and scenario == "close-uncertain" and len(consumed) == 1:
                        raise OSError("fixture consuming-close uncertainty")
                local_os = SimpleNamespace(**vars(os))
                local_os.close = close_original  # Replace only the subject's namespace, never global os.
                context = MODULE.Context.__new__(MODULE.Context)
                context.root = ROOT
                context.work = root / "work"; context.work.mkdir()
                context.environment = {}
                context.report = {"commands": [], "diagnosticValid": False, "diagnosticComplete": False}
                context.ui_file_budget = lambda phase: self.assertEqual(phase, "build")
                context.ui_prior = lambda phase: {"freshInstallerOriginalZero": phase == "readback"}
                context.selected = lambda: {"packageSize": MODULE.PACKAGE_BYTES, "packageSha256": MODULE.PACKAGE_SHA}
                context.readback = lambda: None
                context.ui_tools = lambda: None
                context.check = lambda: None
                context.ui_helper = SimpleNamespace(PROJECT=helper.PROJECT, open_directory=open_original)
                outputs = {
                    ("/usr/bin/xcodebuild", "-version"): b"Xcode 26.6\nBuild version 17F113\n",
                    ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"): (str(sdk) + "\n").encode(),
                    ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"): b"26.5\n",
                    # This is an explicit synthetic fixture token, not native sdkBuild evidence.
                    ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"): b"FIXTURE26\n",
                }
                if scenario == "unsafe-values":
                    outputs[("/usr/bin/xcodebuild", "-version")] = b"private-token /home/private/input\n"
                    outputs[("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path")] = b"/home/private/SDK.sdk\n"
                elif scenario == "wrong-major":
                    outputs[("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version")] = b"27.0\n"
                def run_owned(argv, **options):
                    self.assertEqual(options["cwd"], context.work)
                    self.assertEqual(options["output_limit"], MODULE.LIMIT)
                    if tuple(argv) in outputs:
                        self.assertEqual(len(pending), 1)  # The original predates the first query.
                        self.assertEqual(consumed, [])
                        queries.append(tuple(argv))
                        if scenario == "query-retarget" and len(queries) == 2:
                            application = logical.parent.parent
                            application.unlink()
                            application.symlink_to(alternative.parent.parent.name, target_is_directory=True)
                        return subprocess.CompletedProcess(argv, 0, outputs[tuple(argv)], b"")
                    self.assertEqual(argv[:2], ["/usr/bin/xcodebuild", "build-for-testing"])
                    self.assertEqual(pending, set())
                    self.assertEqual(consumed, acquired)
                    self.assertEqual(len(consumed), 3)
                    self.assertTrue(context.report["toolchainAdmission"]["admitted"])
                    builds.append(argv)
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                context.owner = SimpleNamespace(run_owned=run_owned)
                with patch.object(MODULE, "UI_DEVELOPER", str(logical)), patch.object(MODULE, "os", local_os):
                    if scenario == "accepted":
                        context.ui_build()
                    else:
                        with self.assertRaises(MODULE.Refused):
                            context.ui_build()
                self.assertEqual(len(queries), 4)
                self.assertEqual(pending, set())
                self.assertEqual(consumed, acquired)
                self.assertEqual(len(builds), int(scenario == "accepted"))
                self.assertEqual(context.report["diagnosticComplete"], scenario == "accepted")
                self.assertEqual(context.report["toolchainAdmission"]["admitted"], scenario == "accepted")
                self.assertEqual(context.report["toolchain"]["sdkBuild"], "FIXTURE26")
                self.assertEqual(len(context.report["commands"]), 4 + len(builds))
                if scenario == "close-uncertain":
                    self.assertEqual(len(consumed), 3)
                    self.assertEqual(context.report["toolchainAdmission"]["closeFailures"], ["developer"])
                    self.assertFalse(context.report["toolchainAdmission"]["originalClosesCompleted"])
                if scenario == "unsafe-values":
                    self.assertNotIn("xcode", context.report["toolchain"])
                    self.assertNotIn("sdkPath", context.report["toolchain"])
                    self.assertNotIn("private-token", json.dumps(context.report))
                    self.assertNotIn("/home/private", json.dumps(context.report))
                else:
                    self.assertEqual(context.report["toolchain"]["sdkPath"], str(sdk))

    def test_fixed_two_host_workflow_and_original_only_native_route(self):
        workflow = (ROOT / MODULE.WORKFLOW).read_text()
        native = (ROOT / MODULE.NATIVE).read_text()
        self.assertEqual(workflow.count("runs-on: macos-26"), 3)
        self.assertIn("  launchservices:", workflow)
        self.assertIn("  direct_entry:", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 3)
        # The service rejects runner context at jobs.<id>.env before allocating
        # any runner. Each consumer gets its value at the permitted step scope;
        # prepare/readback/observe must retain Context's same hosted-runner check.
        self.assertEqual(workflow.count("${{ runner.environment }}"), 13)
        jobs = (
            workflow.split("\n  launchservices:\n", 1)[1].split("\n  direct_entry:\n", 1)[0],
            workflow.split("\n  direct_entry:\n", 1)[1].split("\n  packaged_ui:\n", 1)[0],
        )
        ui = workflow.split("\n  packaged_ui:\n", 1)[1]
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-packaged-ui'", ui)
        self.assertNotIn("needs:", ui)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("macos_installed_entry_diagnostic.py observe", ui)
        self.assertIn("DEVELOPER_DIR: /Applications/Xcode.app/Contents/Developer", ui)
        for phase in ("ui-build", "ui-test"):
            self.assertEqual(ui.count("macos_installed_entry_diagnostic.py " + phase + " >"), 1)
        for job in jobs:
            self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-entry-diagnostic'", job)
            self.assertIn("DEVELOPER_DIR: /Library/Developer/CommandLineTools", job)
            self.assertNotIn("ui-build", job)
            header, steps = job.split("    steps:\n", 1)
            self.assertNotIn("${{ runner.", header)
            for selected in ("work", "prepare", "readback", "observe"):
                matches = [step for step in steps.split("      - name: ")
                           if f"\n        id: {selected}\n" in step]
                self.assertEqual(len(matches), 1)
                step_header = matches[0].split("\n        run: |", 1)[0]
                self.assertIn("\n        env:\n", step_header)
                self.assertIn("\n          RUNNER_ENVIRONMENT: ${{ runner.environment }}", step_header)
        self.assertEqual(workflow.count('root="/Users/runner/mrk-macos-entry-diagnostic-'), 3)
        self.assertNotIn('root="/private/tmp/mrk-macos-entry-diagnostic-', workflow)
        adapter = (ROOT / "desktop/tools/macos_installed_entry_diagnostic.py").read_text()
        self.assertIn("self.work = work_path(self.source, self.run, self.attempt, self.job)", adapter)
        self.assertIn('with self.stage.installer_channel_parent(self.work / "installer-output.status", private=self.work):', adapter)
        self.assertNotIn("write-all", workflow)
        self.assertNotIn("contents: write", workflow)
        for unused in ("cargo ", "rustup ", "npm ", "xcodebuild ", "store upload", "--deep"):
            self.assertNotIn(unused, workflow)
        self.assertEqual(native.count("openApplicationAtURL:"), 1)
        self.assertEqual(native.count("[original_app terminate]"), 1)
        self.assertEqual(native.count("[original_app forceTerminate]"), 1)
        for prohibited in ("runningApplicationsWithBundleIdentifier", "runningApplicationWithProcessIdentifier", "kill(", "proc_pidpath", "LOCK_UN"):
            self.assertNotIn(prohibited, native)
        self.assertIn("return complete && before(final_end) ? 0 : 1;", native)
        self.assertIn("work_expired || !before(deadline)", native)


if __name__ == "__main__":
    unittest.main()
