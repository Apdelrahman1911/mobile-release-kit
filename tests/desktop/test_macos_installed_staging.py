"""Focused DATA parser definitions; never a native install/GUI qualification.

These tests do not import the core, stage/extract M, launch Python/app children,
write an installation, construct a panel, or fabricate an operation permit.
"""
import importlib.util
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

TOOL = None
if sys.platform in ("darwin", "linux"):
    path = Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py"
    spec = importlib.util.spec_from_file_location("macos_installed_staging_data", path)
    TOOL = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(TOOL)


def odc(name, mode, body=b"", *, uid=0, gid=0, links=1):
    encoded = name.encode("ascii") + b"\0"
    header = b"070707" + ("%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" %
        (0, 1, mode, uid, gid, links, 0, 0, len(encoded), len(body))).encode("ascii")
    return header + encoded + body


def package_data(*, uid=0, gid=0, root=".", file_owner=None):
    # Small inert parser input, not a native tar/xar or Installer observation.
    files = {"input/readonly.txt": (b"DATA\n", 0o444), "postinstall": (b"exit 97\n", 0o555)}
    info = (b'<?xml version="1.0"?>\n<pkg-info identifier="dev.mobile-release-kit.desktop.installed" '
            b'version="0.1.0" install-location="/" auth="root"><payload numberOfFiles="0"/>'
            b'<scripts><postinstall file="./postinstall"/></scripts></pkg-info>\n')
    archive = odc(root, stat.S_IFDIR | 0o755, uid=uid, gid=gid)
    archive += odc("./input", stat.S_IFDIR | 0o555, uid=uid, gid=gid)
    for name, (body, mode) in files.items():
        owner = file_owner if file_owner is not None and name == "postinstall" else (uid, gid)
        archive += odc("./" + name, stat.S_IFREG | mode, body, uid=owner[0], gid=owner[1])
    return files, {"PackageInfo": info, "Scripts": archive + odc("TRAILER!!!", 0)}


def original_result(expected, *, stage=".install-" + "d" * 32):
    reason, runtime, app, state, verified, _exit = expected
    return {"schemaVersion": 1, "state": state, "reason": reason, "release": TOOL.RELEASE,
            "runtimePublication": runtime, "appPublication": app, "staging": stage, "payloadVerified": verified,
            "payloadWritersSettled": True, "originalsSettled": True, "deadlineMetAfterFinalCloses": True, "createdAncestors": [],
            "cleanup": "original-closes-only-no-deletion", "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64}


def reported_fixture_data():
    # Inert serialized DATA, never a native observation or root test runner.
    rows = []
    for name, expected in TOOL.FIXTURE_CASES.items():
        stage = None if name in ("occupied-app", "occupied-release") else ".install-" + "d" * 32
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        identity = {"device": 1, "inode": 42, "mode": 0o444, "uid": 0, "gid": 0, "links": 1, "size": len(TOOL.FIXTURE_MARKER),
                    "mtimeSeconds": 1, "mtimeNanoseconds": 0, "ctimeSeconds": 1, "ctimeNanoseconds": 0}
        witness = {"visibleRelativePath": TOOL.visible_occupant(name), "sha256": TOOL.digest(TOOL.FIXTURE_MARKER),
                   "before": dict(identity), "after": dict(identity), "verifiedByOriginalInstaller": True}
        persistence = {"point": point, "actualNativeSucceeded": True, "actualNativeErrno": None, "injectedReportedFailure": True}
        rows.append({"case": name, "passed": True, "proofError": None, "originalResult": original_result(expected, stage=stage), "originalExit": expected[-1],
                     "occupant": witness if point is None else None, "persistence": persistence if point is not None else None,
                     "absenceObservedBeforeCollision": name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal"),
                     "stagingOpenErrno": 17 if name == "staging-file-collision" else None})
    return {"schemaVersion": 1, "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64,
            "fixtureBase": TOOL.FIXTURE_PREFIX + "a" * 12 + "-" + "e" * 32, "setupError": None, "setupOriginalsSettled": True,
            "setupDeadlineMet": True, "inertCloseDeadlinePolicyTable": True, "fixedCasesComplete": True, "passed": True, "cases": rows,
            "genuineConcurrentRaceObserved": False, "nativeCloseFailureInjected": False, "applicationLaunched": False, "guiSaveQualified": False,
            "qualification": "native-installer-collisions-and-injected-policy-only"}


def log_args(command="installer-log-cursor", *, fixture=False):
    package = "/work/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg" if fixture else "/work/package-final/MobileReleaseKit.pkg"
    return SimpleNamespace(command=command, fixture=fixture, package=Path(package), expected_source="a" * 40,
                           expected_inventory="b" * 64, expected_manifest="c" * 64, run_id="123", run_attempt="1",
                           cursor=Path("/work/cursor.json"), selected_output=Path("/work/selected.txt"))


def log_info(size=0, **changes):
    values = dict(st_dev=1, st_ino=42, st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=80,
                  st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    values.update(changes)
    return SimpleNamespace(**values)


@unittest.skipUnless(TOOL is not None, "Darwin/POSIX DATA tool only")
class MacInstalledData(unittest.TestCase):
    def test_portable_names_and_complete_directory_identity(self):
        for name in ("python/lib/python3.14/encodings/utf_8.py", "app/Contents/_CodeSignature/CodeResources"):
            self.assertTrue(TOOL.safe_path(name))
        for name in ("../x", "a//b", "a/./b", "/root", "a\\b", "NUL.txt", "CON", "x.", "x ", "é.py"):
            self.assertFalse(TOOL.safe_path(name))
        self.assertEqual(TOOL.directories({"a/b": None}), {"a"})
        for files in ({"a": None, "a/b": None}, {"a/B": None, "a/b": None}):
            with self.assertRaises(TOOL.Refused):
                TOOL.directories(files)

    def test_json_rejects_duplicates_and_nonfinite_constants(self):
        self.assertEqual(TOOL.decode(b'{"a":[1,true,null]}'), {"a": [1, True, None]})
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(TOOL.Refused):
                TOOL.decode(body)

    def test_manifest_digest_and_original_roster_are_separate_checks(self):
        files = [{"path": name, "sha256": "1" * 64, "size": 1} for name in sorted(TOOL.BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"})]
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "DATA-only", "target": "aarch64-apple-darwin",
                    "coreSha256": "1" * 64, "protocolSha256": TOOL.PROTOCOL,
                    "inventorySha256": TOOL.digest(TOOL.canonical(files)), "files": files}
        encoded = TOOL.canonical(manifest) + b"\n"
        value, rows = TOOL.manifest_files(encoded, TOOL.digest(encoded))
        self.assertEqual(set(rows), {row["path"] for row in files})
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, "0" * 64)
        manifest["files"] = list(reversed(files))
        manifest["inventorySha256"] = TOOL.digest(TOOL.canonical(manifest["files"]))
        encoded = TOOL.canonical(manifest)
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, TOOL.digest(encoded))

    def test_scripts_cpio_is_root_owned_exact_data_not_extracted(self):
        end = odc("TRAILER!!!", 0)
        body = odc(".", stat.S_IFDIR | 0o755) + odc("./input", stat.S_IFDIR | 0o555)
        body += odc("./input/manifest.json", stat.S_IFREG | 0o444, b"{}") + end
        self.assertEqual(TOOL.cpio_members(body), {"input": (None, 0o555), "input/manifest.json": (b"{}", 0o444)})
        bad = [odc("x", stat.S_IFREG | 0o444, b"x", uid=501), odc("x", stat.S_IFREG | 0o444, b"x", links=2),
               odc("x", stat.S_IFLNK | 0o777, b"target"), odc("../x", stat.S_IFREG | 0o444), odc("x", stat.S_IFREG | 0o644)]
        for entry in bad:
            with self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(odc(".", stat.S_IFDIR | 0o755) + entry + end)
        with self.assertRaises(TOOL.Refused):
            TOOL.cpio_members(odc(".", stat.S_IFDIR | 0o755) + odc("x", stat.S_IFREG | 0o444) * 2 + end)

    def test_scripts_root_is_exact_unique_and_owner_bound(self):
        for root in (".", "./"):
            files, members = package_data(root=root)
            self.assertEqual(TOOL.cpio_members(members["Scripts"]), {**files, "input": (None, 0o555)})
        end = odc("TRAILER!!!", 0)
        root = odc(".", stat.S_IFDIR | 0o755)
        bad = [end, root + odc("./", stat.S_IFDIR | 0o755) + end,
               odc(".", stat.S_IFDIR | 0o755, uid=501) + end,
               odc("./", stat.S_IFDIR | 0o755, gid=20) + end,
               odc(".", stat.S_IFDIR | 0o555) + end,
               odc(".", stat.S_IFDIR | 0o755, b"x") + end,
               odc(".", stat.S_IFREG | 0o755) + end]
        bad.extend(root + odc(name, stat.S_IFDIR | 0o555) + end for name in ("", "././", "/", "../x", "./input/", "./input/../x"))
        for archive in bad:
            with self.subTest(archive=archive[:6]), self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(archive)

    def test_original_package_preparation_cannot_substitute_for_root_audit(self):
        files, members = package_data(uid=501, gid=20)
        info = SimpleNamespace(st_uid=501, st_gid=20)
        with (mock.patch.object(TOOL, "packager_ids", return_value=(501, 20)),
              mock.patch.object(TOOL, "tree", return_value=files) as scan,
              mock.patch.object(TOOL, "parent") as parent,
              mock.patch.object(TOOL, "read_at", return_value=(b"original-package", info)),
              mock.patch.object(TOOL, "xar_members", return_value=members) as read_members):
            parent.return_value.__enter__.return_value = (9, "original.pkg")
            result = TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            self.assertEqual(result, (files, b"original-package", members, TOOL.PACKAGE_ID, (501, 20)))
            scan.assert_called_once_with(Path("/scripts"), packager=True)
            with self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(members["Scripts"])
            wrong_archives = [package_data(uid=0, gid=0)[1]["Scripts"],
                              package_data(uid=501, gid=21)[1]["Scripts"],
                              package_data(uid=501, gid=20, file_owner=(502, 20))[1]["Scripts"],
                              members["Scripts"].replace(b"DATA\n", b"DIFF\n"),
                              members["Scripts"].replace(b"./input/readonly.txt", b"./input/anotherx.txt")]
            for archive in wrong_archives:
                read_members.return_value = {**members, "Scripts": archive}
                with self.assertRaises(TOOL.Refused):
                    TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            read_members.return_value = {**members, "Bom": b"extra"}
            with self.assertRaises(TOOL.Refused):
                TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            read_members.return_value = members
            info.st_uid = 0
            with self.assertRaises(TOOL.Refused):
                TOOL.original_package(Path("/scripts"), Path("/original.pkg"))

    def test_package_commands_preserve_original_bytes_and_require_final_root_audit(self):
        files, original_members = package_data(uid=501, gid=20)
        final_members = package_data()[1]
        args = SimpleNamespace(scripts=Path("/scripts"), package=Path("/final.pkg"), original_package=Path("/original.pkg"),
                               output=Path("/fresh-parts"), fixture=False)
        with (mock.patch.object(TOOL, "original_package", return_value=(files, b"original", original_members, TOOL.PACKAGE_ID, (501, 20))) as original,
              mock.patch.object(TOOL, "write_tree") as writer,
              mock.patch.object(TOOL, "read", return_value=b"final"),
              mock.patch.object(TOOL, "xar_members", return_value=final_members) as read_members):
            prepared = TOOL.prepare_package_command(args)
            writer.assert_called_once_with(Path("/fresh-parts"), {"PackageInfo": (original_members["PackageInfo"], 0o444)}, root_mode=0o700)
            self.assertEqual(prepared["qualification"], "caller-owned-original-prepared-not-root-audited-or-installed")
            audited = TOOL.audit_command(args)
            original.assert_called_with(Path("/scripts"), Path("/original.pkg"), fixture=False)
            self.assertEqual(audited["originalPackageSha256"], TOOL.digest(b"original"))
            self.assertEqual(audited["packageInfoSha256"], TOOL.digest(original_members["PackageInfo"]))
            for mutation in (original_members, {**final_members, "PackageInfo": final_members["PackageInfo"] + b"\n"},
                             {**final_members, "Payload": b"extra"}, {"PackageInfo": final_members["PackageInfo"]},
                             {**final_members, "Scripts": final_members["Scripts"].replace(b"DATA\n", b"DIFF\n")}):
                read_members.return_value = mutation
                with self.assertRaises(TOOL.Refused):
                    TOOL.audit_command(args)
            writer.reset_mock()
            original.side_effect = TOOL.Refused("original-package-owner")
            with self.assertRaises(TOOL.Refused):
                TOOL.prepare_package_command(args)
            writer.assert_not_called()
            TOOL.package_format_input_command(args)
            call = writer.call_args
            self.assertEqual(call.args[0], Path("/fresh-parts"))
            self.assertEqual(call.kwargs, {"root_mode": 0o755})
            self.assertEqual(set(call.args[1]), {"input/readonly.txt", "postinstall"})
            self.assertEqual(call.args[1]["input/readonly.txt"][1], 0o444)
            self.assertEqual(call.args[1]["postinstall"][1], 0o555)
            self.assertTrue(call.args[1]["postinstall"][0].endswith(b"exit 97\n"))

    def test_package_workflow_fails_fast_and_gates_every_installer(self):
        # I intentionally has no Aqua workflow: that separately-based source
        # delta is independently composed/reviewed, not fictitiously exercised.
        path = Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-installed.yml"
        workflow = path.read_text(encoding="utf-8")
        probe = workflow.index("- name: Fail fast on native Scripts ownership and package format")
        sdk = workflow.index("- name: Fail fast on the selected SDK public native API")
        self.assertLess(probe, sdk)
        self.assertLess(sdk, workflow.index("cargo build --locked --release"))
        self.assertNotIn("/usr/sbin/installer", workflow[probe:sdk])
        for label, scripts, basename in (("package-format", "package-format-scripts", "PackageFormat"),
                                         ("package-fixture", "scripts-fixture", "MobileReleaseKit-InstallerFixture"),
                                         ("package", "scripts", "MobileReleaseKit")):
            start = workflow.index('/usr/bin/pkgbuild --nopayload --scripts "$MRK_MACOS_WORK/' + scripts + '"')
            audit = workflow.index('> "$MRK_MACOS_WORK/' + label + '-audit.json"', start)
            block = workflow[start:audit]
            self.assertIn('cd "$MRK_MACOS_WORK/' + scripts + '" || exit', block)
            target = '"$MRK_MACOS_WORK/' + label + '-parts/Scripts"'
            guard = '[[ ! -e ' + target + ' && ! -L ' + target + ' ]]'
            command = '/usr/bin/tar -c -z -f ' + target + ' --format=odc --uid=0 --gid=0'
            self.assertIn(guard, block)
            self.assertIn(command, block)
            self.assertLess(block.index(guard), block.index(command))
            self.assertNotIn('/usr/bin/tar -c -z -f - ', block)
            self.assertIn('--no-acls --no-xattrs --no-fflags --no-mac-metadata .', block)
            self.assertNotIn(') > ' + target, block)
            self.assertIn('/bin/mkdir -m 700 "$MRK_MACOS_WORK/' + label + '-final"', block)
            self.assertIn('cd "$MRK_MACOS_WORK/' + label + '-parts" || exit', block)
            final = '$MRK_MACOS_WORK/' + label + '-final/' + basename + '.pkg'
            self.assertIn('/usr/bin/xar -c -f "' + final + '"', block)
            self.assertIn('--compression=none PackageInfo Scripts', block)
            self.assertEqual(block.count('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC COPYFILE_DISABLE=1'), 2)
            self.assertIn('[[ $tar_status == 0 ]]', block)
            self.assertIn('[[ $xar_status == 0 ]]', block)
            self.assertIn('--original-package "$MRK_MACOS_WORK/' + basename + '-original.pkg"', block)
            self.assertNotIn('sudo', block)
            if label != "package-format":
                self.assertLess(audit, workflow.index('/usr/sbin/installer -pkg "' + final + '"'))

    def test_package_refusals_are_closed_literals_without_exception_reflection(self):
        class NoReflection:
            def __str__(self):
                raise AssertionError("arbitrary value must not be reflected")
        for reason, literal in TOOL.PACKAGE_REFUSALS.items():
            self.assertTrue(literal.isascii())
            self.assertLessEqual(len(literal), 128)
            self.assertEqual(TOOL.package_refusal_message(TOOL.Refused(reason)), literal + "\n" + TOOL.GENERIC_REFUSAL)
        for error in (TOOL.Refused(), TOOL.Refused("/private/credential=value"), TOOL.Refused(NoReflection()),
                      TOOL.Refused("scripts-root-owner-mode", "/private/extra"), ValueError("scripts-root-owner-mode")):
            self.assertEqual(TOOL.package_refusal_message(error), TOOL.GENERIC_REFUSAL)

    def test_postinstall_accepts_only_fixed_entry_and_preserves_exec_boundary(self):
        stub = (Path(__file__).absolute().parents[2] / "desktop/macos-installed-inputs/postinstall").read_text(encoding="utf-8")
        self.assertTrue(stub.startswith("#!/bin/sh\n"))
        self.assertIn('if [ "${3:-}" != / ]; then', stub)
        self.assertIn('./postinstall)\n        scripts=.', stub)
        self.assertIn('/*/postinstall)\n        scripts=${0%/*}', stub)
        self.assertIn('if ! cd -P "$scripts" 2>/dev/null; then', stub)
        self.assertTrue(stub.endswith('exec ./mrk-macos-install "$PWD/input"\n'))
        self.assertEqual(stub.count("\nexec "), 1)
        phases = {"entry", "target-ok", "relative-entry", "absolute-entry", "cwd-ok", "pre-exec"}
        refusals = {"target", "entry", "cwd"}
        markers = TOOL.re.findall(r"'(MRK_MACOS_POSTINSTALL_[A-Z]+=[a-z-]+)'", stub)
        self.assertEqual(set(markers), {"MRK_MACOS_POSTINSTALL_PHASE=" + value for value in phases}
                         | {"MRK_MACOS_POSTINSTALL_REFUSED=" + value for value in refusals})
        self.assertEqual(len(markers), len(phases) + len(refusals))
        self.assertLess(stub.index("MRK_MACOS_POSTINSTALL_REFUSED=target"), stub.index("MRK_MACOS_POSTINSTALL_PHASE=target-ok"))
        self.assertLess(stub.index("MRK_MACOS_POSTINSTALL_REFUSED=cwd"), stub.index("MRK_MACOS_POSTINSTALL_PHASE=pre-exec"))
        for forbidden in ("PATH=", "eval ", "sh -c", "sudo ", 'printf "$', "post-exec", "../postinstall)", "    postinstall)"):
            self.assertNotIn(forbidden, stub)

    def test_installer_log_cursor_identity_binding_and_append_boundaries(self):
        binding = TOOL.installer_log_binding(log_args())
        tail, body = b"old log text\n", b"one new line\n"
        identity = TOOL.installer_log_identity(log_info())
        cursor = TOOL.make_log_cursor(binding, identity, len(tail), tail, 0)
        self.assertEqual(TOOL.validate_log_cursor(cursor, binding), cursor)
        self.assertNotIn("old log text", TOOL.canonical(cursor).decode())
        self.assertEqual(cursor["precedingTailSha256"], TOOL.digest(tail))
        self.assertEqual(TOOL.make_log_cursor(binding, identity, 0, b"", 0)["precedingTailBytes"], 0)
        end = len(tail) + len(body)
        TOOL.validate_log_window(cursor, identity, end, tail, body)
        with mock.patch.object(TOOL, "os", mock.Mock(wraps=TOOL.os)) as api:
            api.fstat.return_value = log_info(end + 3)
            api.stat.return_value = log_info(end + 5)
            self.assertEqual(TOOL.log_growth(9, 8, "install.log", identity, end), 5)
        for changed in ({**cursor, "schemaVersion": True}, {**cursor, "offsetBytes": True}, {**cursor, "precedingTailBytes": 0},
                        {**cursor, "growthBeyondSnapshotBytes": True}, {**cursor, "logPath": "/var/log/install.log"},
                        {**cursor, "extra": 1}, {**cursor, "binding": {**binding, "runAttempt": "2"}}):
            with self.assertRaises(TOOL.Refused):
                TOOL.validate_log_cursor(changed, binding)
        for key, value in (("device", 2), ("inode", 43), ("mode", stat.S_IFREG | 0o600), ("uid", 501), ("gid", 20), ("links", 2)):
            with self.subTest(identity=key), self.assertRaises(TOOL.Refused):
                TOOL.validate_log_window(cursor, {**identity, key: value}, end, tail, body)
        for changes in ({"st_uid": 501}, {"st_nlink": 2}, {"st_mode": stat.S_IFREG | 0o666}, {"st_mode": stat.S_IFLNK | 0o777}):
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_log_identity(log_info(**changes))
        for observed_end, anchor, interval in ((len(tail) - 1, tail, b""), (end, b"changed text\n", body),
                                               (end, tail, body[:-1]), (end - 1, tail, body[:-1]),
                                               (len(tail) + TOOL.LOG_INTERVAL_BYTES + 1, tail, b"")):
            with self.assertRaises(TOOL.Refused):
                TOOL.validate_log_window(cursor, identity, observed_end, anchor, interval)
        with self.assertRaises(TOOL.Refused):
            TOOL.make_log_cursor(binding, identity, 7, b"partial", 0)
        for args in (log_args(fixture=True), log_args()):
            args.package = Path("/work/package-final/another.pkg")
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_log_binding(args)

    def test_installer_log_selection_is_bounded_raw_and_never_result_authority(self):
        binding = TOOL.installer_log_binding(log_args())
        result_line = b'PackageKit: MRK_MACOS_INSTALL_RESULT={"not":"acceptance"}\n'
        lines = [b"unrelated private neighboring text\n", b"dev.mobile-release-kit.desktop.installed-fixture-suffix\n",
                 b"prefixMRK_MACOS_INSTALL_RESULT={}\n", b"mrk-macos-install-helper\n",
                 b"PackageKit: /work/package-final/MobileReleaseKit.pkg\n", b"MRK_MACOS_POSTINSTALL_PHASE=relative-entry\r\n",
                 b"./mrk-macos-install: original loader bytes \xff\n", result_line]
        selected, detail = TOOL.select_installer_log(b"".join(lines), binding)
        self.assertEqual(selected, b"".join(lines[4:]))
        self.assertEqual(detail["linesUnselected"], 4)
        self.assertEqual(detail["resultMarkerState"], "unbound")
        self.assertEqual(detail["selectedLines"][0]["relativeOffsetBytes"], len(b"".join(lines[:4])))
        self.assertEqual(detail["selectedLines"][-1]["sha256"], TOOL.digest(result_line))
        self.assertNotIn("private neighboring", TOOL.canonical(detail).decode())
        opposite = b"MRK_MACOS_INSTALL_FIXTURE_RESULT={}\n"
        raw, mixed = TOOL.select_installer_log(result_line + opposite, binding)
        self.assertEqual(raw, result_line + opposite)
        self.assertEqual(mixed["resultMarkerState"], "mixed")
        self.assertEqual(TOOL.select_installer_log(result_line * 2, binding)[1]["resultMarkerState"], "duplicate")
        self.assertEqual(TOOL.select_installer_log(lines[4], binding)[1]["resultMarkerState"], "missing")
        header = b"mrk-macos-install "
        limit_line = header + b"x" * (TOOL.LOG_LINE_BYTES - len(header) - 1) + b"\n"
        for bad in (b"", b"unrelated\n", b"MRK_MACOS_POSTINSTALL_PHASE=unknown-value\n", result_line[:-1],
                    b"x" * (TOOL.LOG_INTERVAL_BYTES + 1), limit_line[:-1] + b"x\n", limit_line * 3):
            with self.assertRaises(TOOL.Refused):
                TOOL.select_installer_log(bad, binding)

    def test_installer_log_failures_and_cli_never_manufacture_settlement(self):
        args = log_args()
        tail = b"before\n"
        @TOOL.contextlib.contextmanager
        def failed_close():
            yield 9, 8, "install.log", log_info(len(tail))
            raise TOOL.Refused("original-close-unknown")
        with (mock.patch.object(TOOL, "installer_log_file", side_effect=failed_close),
              mock.patch.object(TOOL, "positioned_log_read", return_value=tail),
              mock.patch.object(TOOL, "log_growth", return_value=0),
              mock.patch.object(TOOL, "write_log_selection") as writer):
            result, status = TOOL.installer_log_diagnostic(args)
            self.assertEqual((result["state"], result["reason"], status), ("unknown", "original-close-unknown", 1))
            writer.assert_not_called()
        with (mock.patch.object(TOOL, "installer_log_file", side_effect=PermissionError("private path must not be reflected")),
              mock.patch.object(TOOL, "write_log_selection") as writer):
            result, status = TOOL.installer_log_diagnostic(args)
            self.assertEqual((result["state"], status, result["selectedOutputState"]), ("unknown", 1, "not-created"))
            self.assertNotIn("private path", TOOL.canonical(result).decode())
            writer.assert_not_called()
        args = log_args("installer-log-capture")
        binding = TOOL.installer_log_binding(args)
        cursor = TOOL.make_log_cursor(binding, TOOL.installer_log_identity(log_info()), len(tail), tail, 0)
        encoded = TOOL.canonical(cursor) + b"\n"
        body = b"MRK_MACOS_INSTALL_RESULT={}\n"
        @TOOL.contextlib.contextmanager
        def log_file():
            yield 9, 8, "install.log", log_info(len(tail) + len(body))
        for write_error in (None, OSError("private exception text must not be reflected")):
            with (mock.patch.object(TOOL, "parent") as parent,
                  mock.patch.object(TOOL, "read_at", return_value=(encoded, log_info(st_uid=TOOL.os.getuid(), st_mode=stat.S_IFREG | 0o600))),
                  mock.patch.object(TOOL, "installer_log_file", side_effect=log_file),
                  mock.patch.object(TOOL, "positioned_log_read", side_effect=[tail, body, tail]),
                  mock.patch.object(TOOL, "log_growth", return_value=7),
                  mock.patch.object(TOOL, "write_log_selection", side_effect=write_error)):
                parent.return_value.__enter__.return_value = (8, "cursor.json")
                result, status = TOOL.installer_log_diagnostic(args)
                self.assertEqual(result["scriptOutputFinality"], "unestablished")
                self.assertEqual(result["authority"], TOOL.LOG_AUTHORITY)
                if write_error is None:
                    self.assertEqual(status, 0)
                    self.assertEqual(result["resultMarkerState"], "unbound")
                    self.assertEqual(result["growthBeyondSnapshotBytes"], 7)
                    self.assertEqual(result["intervalSha256"], TOOL.digest(body))
                    self.assertEqual(result["selectedData"]["sha256"], TOOL.digest(body))
                else:
                    self.assertEqual((status, result["state"], result["reason"]), (1, "unknown", "log-output-unavailable"))
                    self.assertEqual(result["selectedOutputState"], "write-or-close-unknown-preserve-original")
                    self.assertEqual(result["plannedSelectedData"]["sha256"], TOOL.digest(body))
                    self.assertNotIn("private exception", TOOL.canonical(result).decode())
        argv = ["installer-log-cursor", "--package", str(args.package),
                "--expected-source", args.expected_source, "--expected-inventory", args.expected_inventory,
                "--expected-manifest", args.expected_manifest, "--run-id", args.run_id, "--run-attempt", args.run_attempt]
        with (mock.patch.object(TOOL, "os", mock.Mock(wraps=TOOL.os)) as api,
              mock.patch.object(TOOL, "installer_log_diagnostic", return_value=({"state": "unknown"}, 1)) as diagnostic,
              mock.patch.object(TOOL, "print", create=True)):
            api.getuid.return_value = api.geteuid.return_value = 501
            self.assertEqual(TOOL.main(argv), 1)
            diagnostic.reset_mock()
            api.getuid.return_value = 0
            with self.assertRaises(TOOL.Refused):
                TOOL.main(argv)
            diagnostic.assert_not_called()

    def test_installer_workflows_preserve_original_status_and_separate_diagnostics(self):
        root = Path(__file__).absolute().parents[2] / ".github/workflows"
        paths = [root / "desktop-macos-installed.yml"]
        aqua = root / "desktop-macos-aqua.yml"
        if aqua.is_file():
            paths.append(aqua)  # A validates both; I does not pretend it includes A.
        for path in paths:
            workflow = path.read_text(encoding="utf-8")
            names = [("Standard Installer only is privileged; never execute the app or Python as root", "installer")]
            if path.name == "desktop-macos-installed.yml":
                names.insert(0, ("Standard Installer runs the one fixed fixture, never root libtest or a scenario selector", "installer-fixture"))
            for name, stem in names:
                block = workflow.split("      - name: " + name + "\n", 1)[1].split("      - name: ", 1)[0]
                self.assertIn("set -o noclobber", block)
                self.assertIn("umask 077", block)
                self.assertEqual(block.count("sudo -- /usr/sbin/installer -pkg "), 1)
                self.assertEqual(block.count("installer-log-cursor "), 1)
                self.assertEqual(block.count("installer-log-capture "), 1)
                positions = [block.index(value) for value in (
                    "set +e", "installer-log-cursor ", "cursor_status=$?", "cursor_status_saved=$?",
                    "sudo -- /usr/sbin/installer -pkg ", "installer_status=$?", '"$installer_status" >',
                    "installer_status_saved=$?", "installer-log-capture ", "capture_status=$?", "capture_status_saved=$?",
                    "set -e\n", 'if [[ "$installer_status" != 0 ]]; then exit "$installer_status"; fi',
                    '[[ "$installer_status_saved" == 0 && "$cursor_status_saved" == 0 && "$capture_status_saved" == 0 ]]')]
                self.assertEqual(positions, sorted(positions))
                for filename in (stem + "-output.status", stem + "-log-cursor.json", stem + "-log-cursor.status",
                                 stem + "-log-capture.json", stem + "-log-capture.status", stem + "-log-selected.txt"):
                    self.assertIn('${{ steps.work.outputs.root }}/' + filename, workflow)
                self.assertIn('--installer-output "$MRK_MACOS_WORK/' + stem + '-output.txt"', workflow)
                self.assertNotIn("ulimit", block)
                self.assertNotIn('[[ "$capture_status" == 0 ]]', block)
                self.assertNotIn('--installer-output "$MRK_MACOS_WORK/' + stem + '-log-', workflow)

    def test_macho_header_data_refuses_an_unreviewed_target_or_minimum(self):
        header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
        build = struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
        TOOL.macho(header + build)
        for body in (b"\0" * 56, header + struct.pack("<6I", 0x32, 24, 1, 25 << 16, 26 << 16, 0), header + build[:-1]):
            with self.assertRaises(TOOL.Refused):
                TOOL.macho(body)

    def test_archive_pins_are_the_existing_M_not_new_interpreter_inputs(self):
        self.assertEqual(TOOL.ZIP_SHA, "42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be")
        self.assertEqual(TOOL.TAR_SHA, "c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a")
        self.assertEqual(TOOL.ORIGINAL_MANIFEST, "7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44")
        self.assertEqual(set(TOOL.NOTICES), {"21-LLVM-header-license.txt", "22-macOS-SDK-libffi-header-notices.txt"})

    def test_fixed_package_kind_rejects_wrong_identifier_payload_or_extra_hook(self):
        for fixture in (False, True):
            identifier = "dev.mobile-release-kit.desktop.installed" + ("-fixture" if fixture else "")
            body = (f'<pkg-info identifier="{identifier}" version="0.1.0" install-location="/" auth="root">'
                    '<payload numberOfFiles="0"/><scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()
            self.assertEqual(TOOL.package_info(body, fixture=fixture), identifier)
            with self.assertRaises(TOOL.Refused):
                TOOL.package_info(body, fixture=not fixture)
            for changed in (body.replace(identifier.encode(), b"arbitrary.package"), body.replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                            body.replace(b'</scripts>', b'<preinstall file="other"/></scripts>')):
                with self.assertRaises(TOOL.Refused):
                    TOOL.package_info(changed, fixture=fixture)
        with self.assertRaises(TOOL.Refused):
            TOOL.package_info(body, fixture="arbitrary")

    def test_original_result_requires_bound_timely_final_closes(self):
        expected = (None, "confirmed", "confirmed", "installed", True, 0)
        result = original_result(expected)
        TOOL.bound_original_result(result, expected, "a" * 40, "b" * 64, "c" * 64)
        for key, value in (("deadlineMetAfterFinalCloses", False), ("originalsSettled", False), ("payloadWritersSettled", False),
                           ("reason", "deadline"), ("state", "unknown-retained"), ("sourceCommit", "f" * 40), ("schemaVersion", True), ("extra", True)):
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result({**result, key: value}, expected, "a" * 40, "b" * 64, "c" * 64)

    def test_fixture_result_exact_seven_cases_never_promotes_actual_uncertainty(self):
        self.assertEqual(tuple(TOOL.FIXTURE_CASES), ("occupied-app", "occupied-release", "runtime-publication-collision", "staging-file-collision",
                         "first-publication-second-refusal", "prepublication-persistence-report", "postruntime-persistence-report"))
        marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
        good = reported_fixture_data()
        log = marker + TOOL.canonical(good) + b"\n"
        self.assertEqual(TOOL.fixture_record(log, "a" * 40, "b" * 64, "c" * 64), good)
        mutations = [(("sourceCommit",), "f" * 40), (("fixtureBase",), "/tmp/arbitrary"),
                     (("fixtureBase",), TOOL.FIXTURE_PREFIX + "f" * 12 + "-" + "e" * 32),
                     (("cases",), good["cases"][:-1]), (("cases",), list(reversed(good["cases"]))),
                     (("nativeCloseFailureInjected",), True), (("genuineConcurrentRaceObserved",), True),
                     (("cases", 2, "originalResult", "runtimePublication"), "unknown"), (("cases", 3, "stagingOpenErrno"), 5),
                     (("cases", 5, "persistence", "actualNativeSucceeded"), False), (("cases", 6, "persistence", "actualNativeErrno"), 5),
                     (("cases", 6, "persistence", "injectedReportedFailure"), False), (("cases", 4, "originalResult", "originalsSettled"), False),
                     (("cases", 4, "originalResult", "deadlineMetAfterFinalCloses"), False), (("cases", 0, "occupant", "after", "inode"), 43),
                     (("cases", 0, "occupant", "visibleRelativePath"), "../../arbitrary"), (("cases", 0, "occupant", "after", "links"), True), (("extra",), True)]
        for path, value in mutations:
            changed = TOOL.decode(TOOL.canonical(good))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(marker + TOOL.canonical(changed), "a" * 40, "b" * 64, "c" * 64)
        for changed in (log + log, b"MRK_MACOS_INSTALL_RESULT={}\n" + log):
            with self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(changed, "a" * 40, "b" * 64, "c" * 64)


if __name__ == "__main__":
    unittest.main()
