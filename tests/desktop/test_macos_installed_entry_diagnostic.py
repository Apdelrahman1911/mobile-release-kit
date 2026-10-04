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
UI_FAILURE_CASE = b"-[MRKNormalAppUITests.NormalAppUITests testPackagedEntryLaunchCancelAndQuit]"


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
        # Immutable genuine8b preview; synthetic archive cases below never
        # substitute for these public source/run/archive/package bindings.
        self.assertEqual(
            (MODULE.APPLICATION_SOURCE, MODULE.SOURCE_RUN, MODULE.SOURCE_ATTEMPT,
             MODULE.ARTIFACT_ID, MODULE.ARCHIVE_BYTES, MODULE.ARCHIVE_SHA,
             MODULE.PACKAGE_BYTES, MODULE.PACKAGE_SHA),
            ("8b67300f92d2e92cf909a0da12850a678bc2812f", "37195548745", "1",
             "11301302356", 56256693, "a4dd135994251b3663da354650c7aa3e158134f12c236752f610af6baf75d64b",
             56247938, "024523ce33675ecdad8e678b3fe5981f2824ccc26b4477e0bb1f5a6c196ee0ea"))
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

    def test_ui_failure_projection_keeps_typed_findings_not_private_tails(self):
        private = "fixture-secret token=SYNTHETIC https://invalid.example/秘密".encode()
        stdout = (b"Test Case '" + UI_FAILURE_CASE + b"' started.\n"
                  b'Error Domain=NSPOSIXErrorDomain Code=13 "' + private + b'"\n'
                  b"/Users/fixture-secret/NormalAppUITests.swift:321:7: error: "
                  + UI_FAILURE_CASE + b" : XCTAssertTrue failed - " + private + b"\x00\xff\n"
                  b"Test Case '" + UI_FAILURE_CASE + b"' failed (1.234 seconds).\n")
        stderr = (b'Error Domain=com.apple.dt.xctest.error Code=-2147483648 "' + private + b'"\n'
                  b'{Error Domain=NSCocoaErrorDomain Code=2147483647 "' + private + b'"}\n'
                  b"/Users/fixture-secret/NormalAppUITests.swift:65535: error: "
                  + UI_FAILURE_CASE + b": " + private + b"\n"
                  b"** TEST EXECUTE FAILED **\nTesting failed:\n" + private
                  + b"\nxcodebuild: error: " + private + b"\n")
        value = MODULE.ui_failure_diagnostics(stdout, stderr)
        expected = MODULE.ui_failure_unavailable()
        expected.update(status="classified", errorCodes=[
            {"stream": "stdout", "domain": "NSPOSIXErrorDomain", "code": 13},
            {"stream": "stderr", "domain": "com.apple.dt.xctest.error", "code": -2147483648},
            {"stream": "stderr", "domain": "NSCocoaErrorDomain", "code": 2147483647}], sourceFailures=[
            {"stream": stream, "source": "NormalAppUITests.swift", "test": "testPackagedEntryLaunchCancelAndQuit",
             "line": line, "column": column} for stream, line, column in (("stdout", 321, 7), ("stderr", 65535, None))])
        expected["markers"] = {key: True for key in expected["markers"]}
        self.assertEqual(value, expected)
        serialized = MODULE.encoded(value, MODULE.UI_FAILURE_LIMIT)
        for forbidden in (b"fixture-secret", b"SYNTHETIC", b"/Users/", b"https://", b"XCTAssertTrue", b"\\u79d8"):
            self.assertNotIn(forbidden, serialized)

    def test_ui_failure_projection_rejects_lookalikes_and_noncanonical_tokens(self):
        for token in (b"", b"-", b"+1", b"-0", b"01", b"-01", b"1.0", b"1e3", b"1token", b"1_2",
                      b"1/2", b"1\xff", b"2147483648", b"-2147483649", b"21474836470"):
            with self.subTest(code=token):
                value = MODULE.ui_failure_diagnostics(b"Error Domain=NSPOSIXErrorDomain Code=" + token + b"\n", b"")
                self.assertEqual(value["errorCodes"], [])
                self.assertEqual(value["status"], "unclassified")
        unknown = (b"Error Domain=PrivateDomain Code=1\nError Domain=prefixNSPOSIXErrorDomain Code=1\n"
                   b"Error Domain=NSPOSIXErrorDomain.suffix Code=1\nprefixError Domain=NSPOSIXErrorDomain Code=1\n")
        for source in (b"OtherNormalAppUITests.swift", b"NormalAppUITests.swiftExtra", b"\xffNormalAppUITests.swift"):
            unknown += b"/fixture/" + source + b":1: error: " + UI_FAILURE_CASE + b" : fixture-secret\n"
        for location in (b"0", b"01", b"65536", b"655350", b"-1", b"+1", b"1.0", b"1:0", b"1:01",
                         b"1:4097", b"1:40960", b"1:-1", b"1:1tail"):
            unknown += b"NormalAppUITests.swift:" + location + b": error: " + UI_FAILURE_CASE + b" : fixture-secret\n"
        for case in (UI_FAILURE_CASE.replace(b"Quit]", b"QuitExtra]"), UI_FAILURE_CASE + b"Extra",
                     UI_FAILURE_CASE.replace(b"MRKNormalAppUITests.", b"OtherTests.")):
            unknown += b"NormalAppUITests.swift:1: error: " + case + b" : fixture-secret\n"
            unknown += b"Test Case '" + case + b"' started.\nTest Case '" + case + b"' failed (1.0 seconds).\n"
        value = MODULE.ui_failure_diagnostics(unknown, b"")
        self.assertEqual(value["errorCodes"], [])
        self.assertEqual(value["sourceFailures"], [])
        self.assertFalse(any(value["markers"].values()))
        self.assertEqual(value["status"], "unclassified")
        markers_only = MODULE.ui_failure_diagnostics(b"Testing failed:\n", b"")
        self.assertTrue(markers_only["markers"]["testingFailed"])
        self.assertEqual(markers_only["status"], "unclassified")

    def test_ui_failure_projection_bounds_dedup_and_truncation(self):
        row = b"Error Domain=NSPOSIXErrorDomain Code=1\n"
        full = (row * (MODULE.LIMIT // len(row))).ljust(MODULE.LIMIT, b"x")
        value = MODULE.ui_failure_diagnostics(full, b"")
        self.assertEqual(value["errorCodes"], [{"stream": "stdout", "domain": "NSPOSIXErrorDomain", "code": 1}])
        self.assertFalse(value["findingsTruncated"])
        def rows(codes, locations):
            return (b"".join(f"Error Domain=NSPOSIXErrorDomain Code={code}\n".encode() for code in range(codes))
                    + b"".join(b"NormalAppUITests.swift:" + str(line).encode() + b":4096: error: "
                               + UI_FAILURE_CASE + b" : fixture-secret\n" for line in range(1, locations + 1)))
        value = MODULE.ui_failure_diagnostics(rows(5, 2) + row, rows(6, 5))
        self.assertEqual([(item["stream"], item["code"]) for item in value["errorCodes"]],
                         [("stdout", code) for code in range(5)] + [("stderr", code) for code in range(3)])
        self.assertEqual([(item["stream"], item["line"]) for item in value["sourceFailures"]],
                         [("stdout", 1), ("stdout", 2), ("stderr", 1), ("stderr", 2)])
        self.assertTrue(value["findingsTruncated"])
        self.assertLessEqual(len(MODULE.encoded(value, MODULE.UI_FAILURE_LIMIT)), 4096)
        self.assertEqual(value, MODULE.ui_failure_diagnostics(rows(5, 2) + row, rows(6, 5)))
        incomplete = b"\nError Domain=NSPOSIXErrorDomain Code=-"
        self.assertEqual(MODULE.ui_failure_diagnostics(b"x" * (MODULE.LIMIT - len(incomplete)) + incomplete,
                                                     b"")["status"], "unclassified")
        for stdout, stderr in ((None, b""), (b"", ""), (bytearray(), b""),
                               (b"x" * (MODULE.LIMIT + 1), b""), (b"x" * MODULE.LIMIT, b"x")):
            self.assertEqual(MODULE.ui_failure_diagnostics(stdout, stderr), MODULE.ui_failure_unavailable())

    def test_ui_failure_require_marker_has_one_canonical_first_site(self):
        prefix = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE="
        for stream, line, check, ending in (("stdout", 1, "condition", b"\n"),
                                           ("stderr", 591, "singleton", b"\r\n"),
                                           ("stderr", 65535, "actionable", b"\n")):
            with self.subTest(stream=stream, line=line, check=check):
                record = prefix + f"v1;line={line};check={check}".encode() + ending
                value = MODULE.ui_failure_diagnostics(record if stream == "stdout" else b"",
                                                      record if stream == "stderr" else b"")
                self.assertEqual(value["requireFailure"], {"status": "observed", "site": {
                    "stream": stream, "line": line, "check": check}})
                self.assertEqual(value["status"], "classified")
                self.assertEqual(value["errorCodes"], [])
                self.assertEqual(value["sourceFailures"], [])
                self.assertEqual(value["queryObservations"], [])
                self.assertEqual(value["contextObservations"], [])
                self.assertFalse(any(value["markers"].values()))  # Marker does not manufacture XCTest outcome.

    def test_ui_failure_fixed_context_and_queries_preserve_bounded_observations(self):
        host = (b"MRK_MACOS_UI_HOST_FACTS=os=26.0.1;nonroot=true;sameUid=true;sameGid=true;"
                b"runnerName=true;fixedHome=false\n")
        environment = (b"MRK_MACOS_UI_HOST_ENV_FACTS=homeIsRunner=true;userIsRunner=true;lognameIsRunner=true;"
                       b"fixedHomePresent=false;versionCompatPresent=false\r\n")
        account = (b"MRK_MACOS_UI_ACCOUNT_FACTS=lookupSucceeded=true;originalRecord=true;uidMatches=true;"
                   b"gidMatches=true;nameMatches=false;homeMatches=true\n")
        cleanup = (b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true;normalReturned=null;forceRequested=false;"
                   b"forceReturned=false;originalTerminated=false;unknownStateRetained=true\n")
        renderer = b"MRK_MACOS_NORMAL_RENDERER_QUERY=observation=initial;matches=0;exceedsFour=0;nonAtomic=1\n"
        dashboard = b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=initial;matches=2;exceedsFour=0;nonAtomic=1\n"
        property_row = b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=identifier;matches=1;exceedsFour=0;nonAtomic=1\n"
        value = MODULE.ui_failure_diagnostics(host + environment + account + renderer + dashboard + property_row,
                                              cleanup + property_row)
        self.assertEqual(value["contextObservations"], [
            {"stream": "stdout", "kind": "host", "os": [26, 0, 1], "nonroot": True, "sameUid": True,
             "sameGid": True, "runnerName": True, "fixedHome": False},
            {"stream": "stdout", "kind": "environment", "homeIsRunner": True, "userIsRunner": True,
             "lognameIsRunner": True, "fixedHomePresent": False, "versionCompatPresent": False},
            {"stream": "stdout", "kind": "account", "lookupSucceeded": True, "originalRecord": True,
             "uidMatches": True, "gidMatches": True, "nameMatches": False, "homeMatches": True},
            {"stream": "stderr", "kind": "failureCleanup", "normalRequested": True, "normalReturned": None,
             "forceRequested": False, "forceReturned": False, "originalTerminated": False, "unknownStateRetained": True}])
        self.assertEqual([(row["stream"], row["kind"], row["observation"], row["matches"]) for row in value["queryObservations"]],
                         [("stdout", "renderer", "initial", 0), ("stdout", "dashboard", "initial", 2),
                          ("stdout", "dashboard", "identifier", 1), ("stderr", "dashboard", "identifier", 1)])
        self.assertTrue(all(row["nonAtomic"] for row in value["queryObservations"]))
        self.assertFalse(any(row["exceedsFour"] for row in value["queryObservations"]))
        self.assertEqual(value["requireFailure"], {"status": "unobserved", "site": None})
        self.assertEqual(value["status"], "unclassified")  # Context is not a causal failure classification.
        repeated = MODULE.ui_failure_diagnostics(property_row * 9 + cleanup * 5, b"")
        self.assertEqual(len(repeated["queryObservations"]), 8)
        self.assertEqual(len(repeated["contextObservations"]), 4)
        self.assertEqual(repeated["queryObservations"], [repeated["queryObservations"][0]] * 8)
        self.assertEqual(repeated["contextObservations"], [repeated["contextObservations"][0]] * 4)
        self.assertTrue(repeated["findingsTruncated"])
        # Simultaneously fill every retained category, with maximal closed scalar widths.
        longest_query = (b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=containingSameStaticText;"
                         b"matches=4;exceedsFour=0;nonAtomic=1\n")
        widest_cleanup = (b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=false;normalReturned=false;forceRequested=false;"
                          b"forceReturned=false;originalTerminated=false;unknownStateRetained=false\n")
        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=65535;check=actionable\n"
        codes = b"".join(f"Error Domain=IDETestOperationsObserverErrorDomain Code={-2147483648 + i}\n".encode() for i in range(8))
        sites = b"".join(b"NormalAppUITests.swift:" + str(line).encode() + b":4096: error: " + UI_FAILURE_CASE
                         + b" : fixture-secret\n" for line in range(65532, 65536))
        maximum = MODULE.ui_failure_diagnostics(b"", require + codes + sites + longest_query * 8 + widest_cleanup * 4)
        self.assertEqual([len(maximum[key]) for key in ("errorCodes", "sourceFailures", "queryObservations", "contextObservations")],
                         [8, 4, 8, 4])
        self.assertEqual(maximum["requireFailure"]["status"], "observed")
        self.assertFalse(maximum["findingsTruncated"])
        encoded = MODULE.encoded(maximum, MODULE.UI_FAILURE_LIMIT)
        self.assertLessEqual(len(encoded), 4096)
        self.assertNotIn(b"fixture-secret", encoded)
        # Upper count bucket remains explicitly non-atomic and distinct from4.
        high = MODULE.ui_failure_diagnostics(longest_query.replace(b"matches=4;exceedsFour=0", b"matches=5;exceedsFour=1"), b"")
        self.assertEqual(high["queryObservations"][0]["matches"], 5)
        self.assertIs(high["queryObservations"][0]["exceedsFour"], True)

    def test_ui_failure_marker_lookalikes_partial_and_conflicting_records_stay_closed(self):
        prefix = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE="
        valid = prefix + b"v1;line=591;check=actionable\n"
        malformed = [prefix + b"v1;line=" + line + b";check=condition\n" for line in
                     (b"0", b"01", b"+1", b"65536", b"999999", b"-1", b"1.0", b"1\xff")]
        malformed += [prefix, prefix + b"v1;line=1;check=condition", prefix + b"v2;line=1;check=condition\n",
                      prefix + b"v1;line=1;check=fixture-secret\n", valid[:-1] + b";extra=fixture-secret\n",
                      valid[:-1] + b"\r\r\n", valid[:-1] + b"\x00\n"]
        for record in malformed:
            with self.subTest(malformed=record[:90]):
                value = MODULE.ui_failure_diagnostics(record, b"")
                self.assertEqual(value["requireFailure"], {"status": "malformed", "site": None})
                self.assertEqual(value["status"], "unclassified")
                self.assertNotIn(b"fixture-secret", MODULE.encoded(value))
        for record in (b"prefix" + valid, b" " + valid, b"fixture-secret " + valid,
                       valid.replace(prefix, b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE_EXTRA="), prefix[:-1]):
            self.assertEqual(MODULE.ui_failure_diagnostics(record, b"")["requireFailure"],
                             {"status": "unobserved", "site": None})
        other = prefix + b"v1;line=433;check=condition\n"
        bad = prefix + b"v2;line=433;check=condition\n"
        for stdout, stderr in ((valid + valid, b""), (valid + other, b""), (valid, valid),
                               (bad + valid, b""), (valid, bad), (prefix, valid)):
            with self.subTest(stdout=stdout[:90], stderr=stderr[:90]):
                value = MODULE.ui_failure_diagnostics(stdout, stderr)
                self.assertEqual(value["requireFailure"], {"status": "ambiguous", "site": None})
                self.assertEqual(value["status"], "unclassified")
        query = b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=initial;matches=2;exceedsFour=0;nonAtomic=1\n"
        host = (b"MRK_MACOS_UI_HOST_FACTS=os=26.0.1;nonroot=true;sameUid=true;sameGid=true;"
                b"runnerName=true;fixedHome=false\n")
        context = (b"MRK_MACOS_UI_ACCOUNT_FACTS=lookupSucceeded=true;originalRecord=true;uidMatches=true;"
                   b"gidMatches=true;nameMatches=false;homeMatches=true\n")
        unknown = [query.replace(b"matches=2", b"matches=1"), query.replace(b"matches=2", b"matches=02"),
                   query.replace(b"matches=2", b"matches=5"), query.replace(b"exceedsFour=0", b"exceedsFour=1"),
                   query.replace(b"nonAtomic=1", b"nonAtomic=0"), query.replace(b"initial", b"fixture-secret"),
                   query.replace(b"DASHBOARD", b"RENDERER").replace(b"initial", b"identifier"),
                   query[:-1], query[:-1] + b";private=fixture-secret\n",
                   host.replace(b"26.0.1", b"026.0.1"), host.replace(b"26.0.1", b"26.65536.1"),
                   host.replace(b"true", b"TRUE", 1), host[:-1], context.replace(b"true", b"null", 1),
                   context.replace(b"homeMatches=true", b"homeMatches=fixture-secret"),
                   context[:-1] + b";private=fixture-secret\n"]
        for record in unknown:
            with self.subTest(unknown=record[:90]):
                value = MODULE.ui_failure_diagnostics(record, b"")
                self.assertEqual(value["queryObservations"], [])
                self.assertEqual(value["contextObservations"], [])
                self.assertEqual(value["status"], "unclassified")
                self.assertNotIn(b"fixture-secret", MODULE.encoded(value))

    def ui_failure_context(self, original):
        context = MODULE.Context.__new__(MODULE.Context)
        context.work, context.source, context.environment = Path("/synthetic-packaged-ui"), SOURCE, {}
        context.owner, context.inflight, context.last_returned = None, False, False
        context.report = {"commands": [], "error": None, "originalCallReturned": False,
            "diagnosticValid": False, "diagnosticComplete": False, "uiScenarioObserved": False,
            "normalQuitQualified": False, "fullUIQualified": False, "fullM2Qualified": False, "productReady": False,
            "allWorkerFinality": "not-established", "cleanup": {"unknownStateRetained": False}}
        context.ui_file_budget = lambda phase: self.assertEqual(phase, "test")
        context.ui_prior = lambda phase: {"buildOriginalZero": True, "applicationRebuilt": False, "toolchain": {}}
        context.selected = lambda: {"packageSize": MODULE.PACKAGE_BYTES, "packageSha256": MODULE.PACKAGE_SHA}
        context.readback = context.ui_tools = lambda: None
        def forbidden(*args, **kwargs):
            self.fail("No command, result query or post-observation is allowed in this failure fixture")
        context.call = context.zero = forbidden
        context.stage = SimpleNamespace(Refused=MODULE.Refused, observation_command=forbidden)
        runner, events = {"syntheticAdmittedRunner": True, "originalClosesCompleted": True}, []
        def admitted(call, derived, result, methods, timeout, budget):
            self.assertIs(call, context.call)
            self.assertEqual((derived, result), (context.work / "normal-ui/DerivedData", context.work / "normal-ui/test.xcresult"))
            self.assertEqual((methods, timeout, budget), ((context.ui_helper.PACKAGED_METHOD,), 60, 180))
            self.assertNotIn("uiFailureDiagnostics", context.report)
            events.append("helper-return")
            context.last_returned = True
            return original, runner
        context.ui_helper = SimpleNamespace(Refused=MODULE.Refused, run_admitted_test=admitted,
            PACKAGED_METHOD="MRKNormalAppUITests/NormalAppUITests/testPackagedEntryLaunchCancelAndQuit",
            packaged_ui_result=forbidden)
        return context, runner, events

    def test_ui_failure_nonzero_keeps_original_refusal_and_skips_success_queries(self):
        original = subprocess.CompletedProcess([], 65, b"Error Domain=NSPOSIXErrorDomain Code=13\n"
            b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=591;check=actionable\n"
            b"MRK_MACOS_UI_ACCOUNT_FACTS=lookupSucceeded=true;originalRecord=true;uidMatches=true;"
            b"gidMatches=true;nameMatches=false;homeMatches=true\n", b"fixture-secret")
        context, runner, events = self.ui_failure_context(original)
        formatter = MODULE.ui_failure_diagnostics
        def project(stdout, stderr):
            self.assertEqual(events, ["helper-return"])
            self.assertIs(context.report["generatedRunner"], runner)
            self.assertEqual(context.report["originalTestReturncode"], 65)
            self.assertIs(stdout, original.stdout); self.assertIs(stderr, original.stderr)
            events.append("format")
            return formatter(stdout, stderr)
        with patch.object(MODULE, "read", return_value=(b"synthetic-build-report", None)), \
                patch.object(MODULE, "write_new"), patch.object(MODULE, "ui_failure_diagnostics", side_effect=project):
            with self.assertRaisesRegex(MODULE.Refused, "^original-ui-test-nonzero$") as caught:
                context.ui_test()
        context.failure(caught.exception)
        self.assertEqual(events, ["helper-return", "format"])
        self.assertEqual(context.report["uiFailureDiagnostics"], formatter(original.stdout, original.stderr))
        self.assertEqual(context.report["uiFailureDiagnostics"]["requireFailure"], {"status": "observed", "site": {
            "stream": "stdout", "line": 591, "check": "actionable"}})
        self.assertFalse(context.report["uiFailureDiagnostics"]["contextObservations"][0]["nameMatches"])
        self.assertEqual(context.report["originalTestReturncode"], 65)
        self.assertEqual(context.report["error"], "original-ui-test-nonzero")
        self.assertTrue(context.report["originalCallReturned"])
        self.assertTrue(context.report["cleanup"]["unknownStateRetained"])
        self.assertEqual(context.report["allWorkerFinality"], "not-established")
        for key in ("diagnosticValid", "diagnosticComplete", "uiScenarioObserved", "normalQuitQualified",
                    "fullUIQualified", "fullM2Qualified", "productReady"):
            self.assertFalse(context.report[key])

    def test_ui_failure_formatter_exception_or_oversize_cannot_replace_original_nonzero(self):
        for scenario in ("exception", "oversize"):
            with self.subTest(scenario=scenario):
                original = subprocess.CompletedProcess([], 65, b"", b"fixture-secret")
                context, runner, events = self.ui_failure_context(original)
                with patch.object(MODULE, "read", return_value=(b"synthetic-build-report", None)), \
                        patch.object(MODULE, "write_new"), patch.object(MODULE, "ui_failure_diagnostics") as formatter:
                    if scenario == "exception":
                        formatter.side_effect = RuntimeError("fixture-secret /Users/private/assertion")
                    else:
                        formatter.return_value = {"unsafe": "fixture-secret" * MODULE.UI_FAILURE_LIMIT}
                    with self.assertRaisesRegex(MODULE.Refused, "^original-ui-test-nonzero$") as caught:
                        context.ui_test()
                    formatter.assert_called_once_with(original.stdout, original.stderr)
                context.failure(caught.exception)
                self.assertEqual(events, ["helper-return"])
                self.assertIs(context.report["generatedRunner"], runner)
                self.assertEqual(context.report["uiFailureDiagnostics"], MODULE.ui_failure_unavailable())
                self.assertEqual(context.report["originalTestReturncode"], 65)
                self.assertEqual(context.report["error"], "original-ui-test-nonzero")
                self.assertNotIn("fixture-secret", json.dumps(context.report))
                self.assertFalse(context.report["diagnosticComplete"])
                self.assertEqual(context.report["allWorkerFinality"], "not-established")

    def test_ui_failure_success_or_unreturned_helper_never_formats_or_publishes(self):
        for scenario in ("zero", "admission-refused", "original-close-uncertain"):
            with self.subTest(scenario=scenario):
                original = subprocess.CompletedProcess([], 0, b"synthetic-success", b"")
                context, runner, events = self.ui_failure_context(original)
                if scenario == "zero":
                    def zero(role, argv, timeout):
                        self.assertIn(role, ("original-ui-summary", "original-ui-tests"))
                        self.assertEqual(timeout, 15)
                        events.append(role)
                        return subprocess.CompletedProcess(argv, 0, role.encode(), b"")
                    def accepted(stdout, summary, tests):
                        self.assertEqual((stdout, summary, tests), (original.stdout, b"original-ui-summary", b"original-ui-tests"))
                        events.append("success-parser")
                        return {"syntheticAccepted": True}
                    context.zero = zero
                    context.ui_helper.packaged_ui_result = accepted
                    context.observation_args = lambda selected: None
                    context.stage.observation_command = lambda options: events.append("post-observation") or {"syntheticObserved": True}
                else:
                    def refused(*args):
                        raise MODULE.Refused(scenario)
                    context.ui_helper.run_admitted_test = refused
                with patch.object(MODULE, "read", return_value=(b"synthetic-build-report", None)), \
                        patch.object(MODULE, "write_new"), patch.object(MODULE, "ui_failure_diagnostics") as formatter:
                    if scenario == "zero":
                        context.ui_test()
                    else:
                        with self.assertRaisesRegex(MODULE.Refused, "^" + scenario + "$"):
                            context.ui_test()
                    formatter.assert_not_called()
                self.assertNotIn("uiFailureDiagnostics", context.report)
                self.assertEqual(context.report["allWorkerFinality"], "not-established")
                self.assertFalse(context.report["productReady"])
                if scenario == "zero":
                    self.assertEqual(events, ["helper-return", "original-ui-summary", "original-ui-tests", "success-parser", "post-observation"])
                    self.assertIs(context.report["generatedRunner"], runner)
                    self.assertEqual(context.report["originalTestReturncode"], 0)
                    self.assertTrue(context.report["diagnosticComplete"])
                    self.assertTrue(context.report["uiScenarioObserved"])
                else:
                    self.assertEqual(events, [])
                    self.assertNotIn("originalTestReturncode", context.report)
                    self.assertNotIn("generatedRunner", context.report)
                    self.assertFalse(context.report["diagnosticComplete"])

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
        # All fixed acquisition copies agree with the one owner authority.
        # The existing per-branch guards still select only packaged_ui here.
        for selected_job in (*jobs, ui):
            for endpoint in (
                "actions/artifacts/" + MODULE.ARTIFACT_ID,
                "actions/artifacts/" + MODULE.ARTIFACT_ID + "/zip",
                "actions/runs/" + MODULE.SOURCE_RUN + "/attempts/" + MODULE.SOURCE_ATTEMPT,
            ):
                self.assertEqual(selected_job.count('gh api "repos/' + MODULE.REPO + "/" + endpoint + '"'), 1)
            self.assertEqual(selected_job.count("# Exact" + str(MODULE.ARCHIVE_BYTES) + "B"), 1)
        self.assertEqual(native.count("openApplicationAtURL:"), 1)
        self.assertEqual(native.count("[original_app terminate]"), 1)
        self.assertEqual(native.count("[original_app forceTerminate]"), 1)
        for prohibited in ("runningApplicationsWithBundleIdentifier", "runningApplicationWithProcessIdentifier", "kill(", "proc_pidpath", "LOCK_UN"):
            self.assertNotIn(prohibited, native)
        self.assertIn("return complete && before(final_end) ? 0 : 1;", native)
        self.assertIn("work_expired || !before(deadline)", native)


if __name__ == "__main__":
    unittest.main()
