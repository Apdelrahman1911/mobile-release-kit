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

    def test_fixed_two_host_workflow_and_original_only_native_route(self):
        workflow = (ROOT / MODULE.WORKFLOW).read_text()
        native = (ROOT / MODULE.NATIVE).read_text()
        self.assertEqual(workflow.count("runs-on: macos-26"), 2)
        self.assertIn("  launchservices:", workflow)
        self.assertIn("  direct_entry:", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        self.assertEqual(workflow.count('root="/Users/runner/mrk-macos-entry-diagnostic-'), 2)
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
