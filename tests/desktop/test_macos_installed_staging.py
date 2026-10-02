"""Focused DATA parser definitions; never a native install/GUI qualification.

These tests do not import the core, stage/extract M, launch Python/app children,
write an installation, construct a panel, or fabricate an operation permit.
"""
import ast
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

TOOL = None
if sys.platform in ("darwin", "linux"):
    path = Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py"
    spec = importlib.util.spec_from_file_location("macos_installed_staging_data", path)
    TOOL = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(TOOL)


def workflow_step(workflow, name):
    """Select one reviewed named step, without consuming unrelated later steps."""
    marker = "      - name: " + name + "\n"
    if workflow.count(marker) != 1:
        raise AssertionError("expected exactly one workflow step: " + name)
    return workflow.split(marker, 1)[1].split("      - name: ", 1)[0]


def normal_app_steps(workflow):
    return tuple(workflow_step(workflow, name) for name in (
        "Build only the normal ARM64 bundled-asset shell",
        "Assemble and ad-hoc sign the app only (never --deep or the runtime)",
        "Bind this completed signed app and current-source runtime into fresh Installer DATA"))


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
    recorded = state == "installed" or (runtime == "confirmed" and app == "occupied-refused")
    partial = reason == "open-refused" and runtime == "confirmed"
    metadata = {"state": "recorded" if recorded else "incomplete" if partial else "not-attempted",
                "attemptedFiles": 2 if recorded or partial else 0, "openedFiles": 2 if recorded else 1 if partial else 0,
                "plannedBytes": 10 if recorded or partial else 0, "writtenBytes": 10 if recorded else 6 if partial else 0,
                "writersSettled": True}
    return {"schemaVersion": 1, "state": state, "reason": reason, "release": TOOL.RELEASE,
            "runtimePublication": runtime, "appPublication": app, "staging": stage, "payloadVerified": verified,
            "payloadWritersSettled": True, "originalsSettled": True, "deadlineMetAfterFinalCloses": True, "createdAncestors": [],
            "cleanup": "original-closes-only-no-deletion", "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64, "installationMetadata": metadata}


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
                     "absenceObservedBeforeCollision": name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal", "metadata-descriptor-collision"),
                     "stagingOpenErrno": 17 if name in ("staging-file-collision", "metadata-descriptor-collision") else None})
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


def result_args(*, fixture=False):
    return SimpleNamespace(input=Path("/work/input"), fixture=fixture, expected_source="a" * 40,
                           expected_inventory="b" * 64, expected_manifest="c" * 64,
                           installer_status=Path("/work/installer-fixture-output.status" if fixture else "/work/installer-output.status"))


def export_document(*, fixture=False, result=None):
    return {"schemaVersion": 1, "kind": "fixture" if fixture else "ordinary", "sourceCommit": "a" * 40,
            "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64,
            "transportState": "pending-original-export-finalization", "result": {} if result is None else result}


@contextlib.contextmanager
def channel_data(path, body=None, *, private=False):
    # Finite DATA model for the existing original-FD reader. Every OS operation
    # that could touch these numeric tokens is replaced; no fake FD reaches the
    # host, no file is created, and no native ownership/ACL/finality is claimed.
    names, objects, events, opened, closed = {}, {}, [], [], []
    outer = None
    for index, name in enumerate(path.parts[:-1]):
        fd = 40 + index
        task_parent = private and index == len(path.parts) - 2
        names[(outer, name)] = fd
        objects[fd] = log_info(st_ino=fd, st_mode=stat.S_IFDIR | (0o700 if task_parent else 0o755),
                               st_uid=501 if task_parent else 0, st_gid=80, st_nlink=3)
        outer = fd
    leaf = 40 + len(path.parts) - 1
    if body is not None:
        names[(outer, path.name)] = leaf
        objects[leaf] = log_info(len(body), st_ino=leaf, st_mode=stat.S_IFREG | (0o600 if private else 0o444),
                                 st_uid=501 if private else 0, st_gid=80 if private else 0)
    model = SimpleNamespace(names=names, objects=objects, events=events, opened=opened, closed=closed,
                            parent=outer, leaf=leaf, offset=0)
    def named(name, *, dir_fd=None, follow_symlinks=True):
        assert follow_symlinks is False
        fd = names.get((dir_fd, name))
        if fd is None:
            raise FileNotFoundError(TOOL.errno.ENOENT, "inert expected-name absence")
        return objects[fd]
    def acquire(name, flags, *, dir_fd=None):
        fd = names[(dir_fd, name)]
        expected = TOOL.READ_FLAGS | (TOOL.os.O_DIRECTORY if stat.S_ISDIR(objects[fd].st_mode) else 0)
        assert flags == expected and fd not in opened
        opened.append(fd); events.append(("open", fd))
        return fd
    def read(fd, size):
        assert fd == leaf and fd in opened and fd not in closed and size >= 0
        block = body[model.offset:model.offset + size]
        model.offset += len(block); events.append(("read", fd))
        return block
    def close(fd):
        assert fd in opened and fd not in closed
        closed.append(fd); events.append(("close", fd))
    api = mock.Mock(wraps=TOOL.os)
    api.O_DIRECTORY = TOOL.os.O_DIRECTORY
    api.getuid.return_value = api.geteuid.return_value = 501
    api.getgid.return_value = api.getegid.return_value = 20
    api.stat.side_effect = named
    api.open.side_effect = acquire
    api.fstat.side_effect = objects.__getitem__
    api.read.side_effect = read
    api.close.side_effect = close
    model.api, model.named, model.read, model.close = api, named, read, close
    with (mock.patch.object(TOOL, "os", api), mock.patch.object(TOOL, "no_xattrs") as attributes):
        model.attributes = attributes
        yield model


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
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'{"a":-1e999}'):
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
        self.assertNotIn("project_recovery_bootstrap.py", rows)  # Historical supplier roster is unchanged.
        current_only = {"project_recovery_bootstrap.py", "github_preflight_bootstrap.py",
                        "ios_archive_bootstrap.py", "github_release_bootstrap.py"}
        self.assertEqual(TOOL.CURRENT_BOOTSTRAPS, TOOL.BOOTSTRAPS | current_only)
        self.assertEqual(len(TOOL.BOOTSTRAPS), 6)
        self.assertEqual(TOOL.PROTOCOL, "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e")
        checkout = Path(__file__).absolute().parents[2]
        self.assertEqual(TOOL.CURRENT_PROTOCOL, TOOL.digest((checkout / "src/mobile_release/_desktop_engine.py").read_bytes()))
        self.assertIn('pub const PROTOCOL_SHA: &str = "' + TOOL.CURRENT_PROTOCOL + '";',
                      (checkout / "desktop/src-tauri/src/macos_install_paths.rs").read_text())
        self.assertNotEqual(TOOL.PROTOCOL, TOOL.CURRENT_PROTOCOL)
        with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-shape"):
            TOOL.manifest_files(encoded, TOOL.digest(encoded), current=True)
        for invalid in (None, 0, 1, "current"):
            with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-profile"):
                TOOL.manifest_files(encoded, TOOL.digest(encoded), current=invalid)
        current_files = sorted([*files, *({"path": name, "sha256": "1" * 64, "size": 1}
                                         for name in current_only)], key=lambda row: row["path"])
        current_manifest = {**manifest, "protocolSha256": TOOL.CURRENT_PROTOCOL,
                            "files": current_files, "inventorySha256": TOOL.digest(TOOL.canonical(current_files))}
        current_body = TOOL.canonical(current_manifest) + b"\n"
        self.assertEqual(set(TOOL.manifest_files(current_body, TOOL.digest(current_body), current=True)[1]),
                         TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"})
        with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-shape"):
            TOOL.manifest_files(current_body, TOOL.digest(current_body))
        for missing in current_only:
            incomplete = [row for row in current_files if row["path"] != missing]
            body = TOOL.canonical({**current_manifest, "files": incomplete,
                                   "inventorySha256": TOOL.digest(TOOL.canonical(incomplete))})
            with self.assertRaisesRegex(TOOL.Refused, "runtime-required-members"):
                TOOL.manifest_files(body, TOOL.digest(body), current=True)
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
        sdk = workflow.index("- name: Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive")
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
        for reason, expected in (("output-mode", "MRK_MACOS_PACKAGE_REFUSED=output-mode\n" + TOOL.GENERIC_REFUSAL),
                                 ("/private/credential=value", TOOL.GENERIC_REFUSAL)):
            stderr = io.StringIO()
            with self.subTest(reason=reason), mock.patch.object(TOOL, "app_command", side_effect=TOOL.Refused(reason)), \
                    contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                TOOL.main(["app", "--binary", "/inert/app", "--vault-helper", "/inert/helper",
                           "--expected-vault-helper", "a" * 64, "--output", "/inert/output"])
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(stderr.getvalue(), expected + "\n")

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

    def test_acl_failure_diagnostic_is_finite_and_cannot_be_a_result(self):
        binding = TOOL.installer_log_binding(log_args())
        marker = b"MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=acl-entry-present;result=1;call=0;errno=0;freeCall=0;freeErrno=0\n"
        selected, detail = TOOL.select_installer_log(b"PackageKit: " + marker, binding)
        self.assertEqual(selected, b"PackageKit: " + marker)
        self.assertEqual(detail["markerCounts"]["acl-diagnostic"], 1)
        self.assertEqual(detail["resultMarkerState"], "missing")
        self.assertEqual(detail["markerCounts"]["ordinary-result"], 0)
        with self.assertRaises(TOOL.Refused):
            TOOL.installer_record(selected)
        for bad in (b"prefix" + marker, marker.replace(b"input-directory", b"arbitrary-path"),
                    marker.replace(b"acl-entry-present", b"unknown-api"), marker.replace(b"errno=0;", b"errno=private;"),
                    marker.replace(b"result=1;", b"result=123456789012;"), marker[:-1] + b";extra=private\n"):
            with self.subTest(marker=bad), self.assertRaises(TOOL.Refused):
                TOOL.select_installer_log(bad, binding)
        native = (Path(__file__).absolute().parents[2] / "desktop/native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        installer = (Path(__file__).absolute().parents[2] / "desktop/src-tauri/src/bin/macos_install.rs").read_text(encoding="utf-8")
        phases = TOOL.re.findall(r'\d+ => "([a-z-]+)"', native.split("let name = match phase {", 1)[1].split("};", 1)[0]) + ["ffi-output"]
        roles = TOOL.re.findall(r'=> "([a-z-]+)"', installer.split("impl AclRole {", 1)[1].split("fn acl_diagnostic", 1)[0])
        for role in roles:
            for phase in phases:
                row = marker.replace(b"input-directory", role.encode()).replace(b"acl-entry-present", phase.encode())
                self.assertLessEqual(len(row), 512)
                self.assertEqual(TOOL.select_installer_log(row, binding)[1]["markerCounts"]["acl-diagnostic"], 1)
        self.assertEqual((len(roles), len(phases)), (6, 13))
        self.assertIn("if line.len() <= 512", installer)
        self.assertIn("let _ = std::io::Write::write_all", installer)

    def test_acl_probe_gate_is_early_nonroot_and_keeps_original_statuses(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        marker = "      - name: Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive"
        gate = workflow_step(workflow, "Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive")
        self.assertLess(workflow.index(marker), workflow.index("      - name: Build only the normal ARM64 bundled-asset shell"))
        self.assertIn("desktop/native/macos-installed-native/src/native.m desktop/native/macos-installed-native/tests/acl_probe.m", gate)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC "$MRK_MACOS_WORK/acl-probe"', gate)
        self.assertIn('[[ "$(/usr/bin/id -u)" != 0', gate)
        self.assertEqual(gate.count('=("${PIPESTATUS[@]}")'), 2)
        self.assertIn('if [[ ${probe_status[0]} != 0 ]]; then exit "${probe_status[0]}"; fi', gate)
        self.assertIn('compile_status_saved=$?', gate)
        self.assertLess(gate.index('if [[ ${compile_status[0]} != 0 ]]; then exit "${compile_status[0]}"; fi'),
                        gate.index('[[ ${compile_status[1]} == 0 && $compile_status_saved == 0 ]]'))
        self.assertIn("binary_identity=$(/usr/bin/stat -f '%d:%i:%u:%g:%p:%l:%z:%m:%c'", gate)
        self.assertIn("directory_identity=$(/usr/bin/stat -f '%d:%i:%u:%g:%p'", gate)
        self.assertLess(gate.index('== "$binary_identity"'), gate.index('/bin/rm -- "$MRK_MACOS_WORK/acl-probe"'))
        self.assertLess(gate.index('== "$directory_identity"'), gate.index('/bin/rmdir -- "$MRK_MACOS_WORK/acl-probe-data"'))
        self.assertLess(gate.index('> "$MRK_MACOS_WORK/native-acl-probe.status"'), gate.index('/bin/rm -- "$MRK_MACOS_WORK/acl-probe"'))
        self.assertIn('/bin/rmdir -- "$MRK_MACOS_WORK/acl-probe-data"', gate)
        self.assertEqual(gate.count("/usr/bin/tail -c 131072"), 2)
        self.assertNotIn("sudo", gate)
        self.assertNotIn("native-api-link.dylib", workflow)
        probe = (root / "desktop/native/macos-installed-native/tests/acl_probe.m").read_text(encoding="utf-8")
        for value in ("fresh-file-no-acl", "fresh-directory-no-acl", "explicit-empty-no-ace", "real-ace-refused", "invalid-fd-refused"):
            self.assertIn(value, probe)
        self.assertIn("completed == 6 && cleaned && timely()", probe)
        self.assertLess(probe.index("fflush(stdout)"), probe.index("return ok && timely() ? 0 : 1;"))

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
            installer_name = ("Application installation uses only standard privileged Installer; app and Python stay nonroot"
                              if path.name == "desktop-macos-aqua.yml"
                              else "Standard Installer only is privileged; never execute the app or Python as root")
            names = [(installer_name, "installer")]
            if path.name == "desktop-macos-installed.yml":
                names.insert(0, ("Standard Installer runs the one fixed fixture, never root libtest or a scenario selector", "installer-fixture"))
            for name, stem in names:
                block = workflow.split("      - name: " + name + "\n", 1)[1].split("      - name: ", 1)[0]
                self.assertIn("set -o noclobber", block)
                self.assertIn("umask 077", block)
                self.assertEqual(block.count("sudo -- /usr/sbin/installer -pkg "), 1)
                self.assertEqual(block.count("installer-log-cursor "), 1)
                self.assertEqual(block.count("installer-log-capture "), 1)
                self.assertEqual(block.count("check-installer-result-absent "), 1)
                precheck = block.split("check-installer-result-absent ", 1)[1].split("          set +e", 1)[0]
                self.assertEqual("--fixture" in precheck, stem == "installer-fixture")
                for option in ("--expected-source", "--expected-inventory", "--expected-manifest"):
                    self.assertIn(option, precheck)
                positions = [block.index(value) for value in (
                    "check-installer-result-absent ", "set +e", "installer-log-cursor ", "cursor_status=$?", "cursor_status_saved=$?",
                    "sudo -- /usr/sbin/installer -pkg ", "installer_status=$?", '"$installer_status" >',
                    "installer_status_saved=$?", "installer-log-capture ", "capture_status=$?", "capture_status_saved=$?",
                    "set -e\n", 'if [[ "$installer_status" != 0 ]]; then exit "$installer_status"; fi',
                    '[[ "$installer_status_saved" == 0 && "$cursor_status_saved" == 0 && "$capture_status_saved" == 0 ]]')]
                self.assertEqual(positions, sorted(positions))
                for filename in (stem + "-output.status", stem + "-log-cursor.json", stem + "-log-cursor.status",
                                 stem + "-log-capture.json", stem + "-log-capture.status", stem + "-log-selected.txt"):
                    self.assertIn('${{ steps.work.outputs.root }}/' + filename, workflow)
                self.assertIn('--installer-status "$MRK_MACOS_WORK/' + stem + '-output.status"', workflow)
                self.assertNotIn("--installer-output", workflow)
                self.assertNotIn("ulimit", block)
                self.assertNotIn('[[ "$capture_status" == 0 ]]', block)
                self.assertNotIn('--installer-output "$MRK_MACOS_WORK/' + stem + '-log-', workflow)

    def test_installer_export_name_closed_wrapper_and_utf8_bound(self):
        source, inventory, manifest = "a" * 40, "b" * 64, "c" * 64
        for fixture in (False, True):
            document = export_document(fixture=fixture)
            body = TOOL.canonical(document) + b"\n"
            path = TOOL.installer_result_path(source, inventory, manifest, fixture=fixture)
            kind = "fixture" if fixture else "ordinary"
            self.assertEqual(path.parent, Path("/Library/Application Support"))
            self.assertEqual(path.name, f"MobileReleaseKit-InstallerResult-v1-{kind}-{source}-{inventory}-{manifest}.json")
            self.assertLessEqual(len(path.name.encode("ascii")), 255)
            self.assertEqual(TOOL.installer_result_document(body, source, inventory, manifest, fixture=fixture), {})
            for key, value in (("schemaVersion", True), ("kind", "other"), ("sourceCommit", "f" * 40),
                               ("inventorySha256", "f" * 64), ("runtimeManifestSha256", "f" * 64),
                               ("transportState", "complete"), ("result", []), ("extra", True)):
                with self.subTest(key=key, fixture=fixture), self.assertRaises(TOOL.Refused):
                    TOOL.installer_result_document(TOOL.canonical({**document, key: value}) + b"\n", source, inventory, manifest, fixture=fixture)
            for bad in (body[:-1], b"x" * 65536 + b"\n", b"{}\n", b"[]\n", b"\xff\n",
                        body.decode("utf-8").encode("utf-16-be"), body.decode("utf-8").encode("utf-32-be"),
                        body.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                        body.replace(b'"result":{}', b'"result":{"bad":NaN}'),
                        body.replace(b'"result":{}', b'"result":{"bad":1e999}')):
                with self.subTest(body=bad[:24]), self.assertRaises((TOOL.Refused, ValueError)):
                    TOOL.installer_result_document(bad, source, inventory, manifest, fixture=fixture)
        for args in (("A" * 40, inventory, manifest), (source, "b" * 63, manifest), (source, inventory, "../other")):
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_result_path(*args)
        with self.assertRaises(TOOL.Refused):
            TOOL.installer_result_path(source, inventory, manifest, fixture=1)

    def test_installer_export_absence_accepts_only_enoent_and_settled_parents(self):
        args = result_args()
        path = TOOL.installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest)
        with channel_data(path) as model:
            self.assertEqual(TOOL.installer_result_absent_command(args)["state"], "expected-result-name-absent")
            self.assertEqual(model.closed, list(reversed(model.opened)))
            model.attributes.assert_not_called()
        # A perfectly bound old document is still an occupied name, not adoptable.
        with channel_data(path, TOOL.canonical(export_document()) + b"\n") as model:
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_result_absent_command(args)
            self.assertNotIn(model.leaf, model.opened)
            self.assertEqual(model.closed, list(reversed(model.opened)))
        for error in (TOOL.errno.EACCES, TOOL.errno.EIO, TOOL.errno.ENOTDIR):
            with channel_data(path) as model:
                def named(name, **kwargs):
                    if name == path.name:
                        raise OSError(error, "inert metadata refusal")
                    return model.named(name, **kwargs)
                model.api.stat.side_effect = named
                with self.assertRaisesRegex(TOOL.Refused, "installer-export-absence-unknown"):
                    TOOL.installer_result_absent_command(args)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        with channel_data(path) as model:
            def close(fd):
                model.close(fd)
                if fd == model.parent:
                    raise OSError("inert ambiguous parent close")
            model.api.close.side_effect = close
            with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-close-unknown"):
                TOOL.installer_result_absent_command(args)
            self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_channel_parent_binds_protection_not_unrelated_child_times(self):
        path = TOOL.installer_result_path("a" * 40, "b" * 64, "c" * 64)
        with channel_data(path) as model:
            with TOOL.installer_channel_parent(path) as (fd, name):
                self.assertEqual((fd, name), (model.parent, path.name))
                # Protected existing group80 is allowed and never normalized.
                self.assertEqual(model.objects[fd].st_gid, 80)
                model.objects[fd] = SimpleNamespace(**{**model.objects[fd].__dict__, "st_mtime_ns": 99, "st_ctime_ns": 99, "st_nlink": 4})
            self.assertEqual(model.closed, list(reversed(model.opened)))
            model.api.chown.assert_not_called()
            model.api.chmod.assert_not_called()
        for change in ({"st_gid": 81}, {"st_ino": 999}, {"st_uid": 501}, {"st_mode": stat.S_IFDIR | 0o775}):
            with channel_data(path) as model:
                with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-changed"):
                    with TOOL.installer_channel_parent(path) as (fd, _name):
                        model.objects[fd] = SimpleNamespace(**{**model.objects[fd].__dict__, **change})
                self.assertEqual(model.closed, list(reversed(model.opened)))
        for mode in (stat.S_IFDIR | 0o775, stat.S_IFDIR | 0o1777, stat.S_IFLNK | 0o755):
            with channel_data(path) as model:
                model.objects[model.parent] = SimpleNamespace(**{**model.objects[model.parent].__dict__, "st_mode": mode})
                with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-protection"):
                    with TOOL.installer_channel_parent(path):
                        self.fail("unprotected parent admitted")
                self.assertNotIn(model.parent, model.opened)
                self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_saved_status_is_exact_private_original_zero(self):
        for fixture in (False, True):
            args = result_args(fixture=fixture)
            with channel_data(args.installer_status, b"0\n", private=True) as model:
                self.assertIsNone(TOOL.installer_success_status(args, fixture=fixture))
                self.assertEqual(model.closed, list(reversed(model.opened)))
                model.attributes.assert_called_once_with(model.leaf)
            for body in (b"1\n", b"00\n", b"0", b"0\r\n"):
                with channel_data(args.installer_status, body, private=True) as model:
                    with self.assertRaises(TOOL.Refused):
                        TOOL.installer_result_readback(args, fixture=fixture)
                    self.assertEqual(model.closed, list(reversed(model.opened)))
            for change in ({"st_uid": 0}, {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}):
                with channel_data(args.installer_status, b"0\n", private=True) as model:
                    model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, **change})
                    with self.assertRaisesRegex(TOOL.Refused, "installer-status-private-original"):
                        TOOL.installer_success_status(args, fixture=fixture)
                    self.assertNotIn(model.leaf, model.opened)
            args.installer_status = Path("/work/other.status")
            with self.assertRaisesRegex(TOOL.Refused, "installer-status-original-path"):
                TOOL.installer_success_status(args, fixture=fixture)
        args = result_args()
        with channel_data(args.installer_status, b"0\n", private=True) as model:
            model.objects[model.parent] = SimpleNamespace(**{**model.objects[model.parent].__dict__, "st_mode": stat.S_IFDIR | 0o755})
            with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-protection"):
                TOOL.installer_success_status(args)

    def test_installer_export_reader_checks_original_leaf_and_all_closes(self):
        args = result_args()
        path = TOOL.installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest)
        body = TOOL.canonical(export_document()) + b"\n"
        with (mock.patch.object(TOOL, "installer_success_status") as status, channel_data(path, body) as model):
            result, summary = TOOL.installer_result_readback(args)
            status.assert_called_once_with(args, fixture=False)
            self.assertEqual(result, {})
            self.assertEqual(summary, {"bytes": len(body), "sha256": TOOL.digest(body), "identity": list(TOOL.signature(model.objects[model.leaf])),
                                      "finalityBasis": "original-successful-Installer-return-and-checked-readback"})
            model.attributes.assert_called_once_with(model.leaf)
            self.assertEqual(model.closed, list(reversed(model.opened)))
        for change in ({"st_uid": 501}, {"st_gid": 80}, {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}, {"st_size": 65537}):
            with mock.patch.object(TOOL, "installer_success_status"), channel_data(path, body) as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, **change})
                with self.assertRaisesRegex(TOOL.Refused, "installer-export-file-policy"):
                    TOOL.installer_result_readback(args)
                self.assertNotIn(model.leaf, model.opened)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        for fault in ("growth", "named-change", "attributes", "leaf-close", "parent-close"):
            with mock.patch.object(TOOL, "installer_success_status"), channel_data(path, body) as model:
                if fault == "growth":
                    model.api.read.side_effect = [body + b"x", b""]
                elif fault == "named-change":
                    def named(name, **kwargs):
                        info = model.named(name, **kwargs)
                        if name == path.name and model.offset:
                            return SimpleNamespace(**{**info.__dict__, "st_ino": 999})
                        return info
                    model.api.stat.side_effect = named
                elif fault == "attributes":
                    model.attributes.side_effect = TOOL.Refused("inert file attributes")
                else:
                    def close(fd):
                        model.close(fd)
                        if fd == (model.leaf if fault == "leaf-close" else model.parent):
                            raise OSError("inert original-close refusal")
                    model.api.close.side_effect = close
                with self.subTest(fault=fault), self.assertRaises(TOOL.Refused):
                    TOOL.installer_result_readback(args)
                self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_observation_cli_requires_status_without_legacy_fallback(self):
        args = result_args()
        options = ["--input", str(args.input), "--expected-source", args.expected_source,
                   "--expected-inventory", args.expected_inventory, "--expected-manifest", args.expected_manifest]
        api = mock.Mock(wraps=TOOL.os)
        api.getuid.return_value = api.geteuid.return_value = 501
        for command, action in (("observe-installation", "observation_command"), ("observe-installer-fixture", "fixture_observation_command")):
            with (mock.patch.object(TOOL, "os", api), mock.patch.object(TOOL, action, return_value={}) as call,
                  mock.patch.object(TOOL, "print", create=True), mock.patch.object(TOOL.sys, "stderr", TOOL.io.StringIO())):
                TOOL.main([command, *options, "--installer-status", str(args.installer_status)])
                self.assertEqual(call.call_args.args[0].installer_status, args.installer_status)
                call.reset_mock()
                with self.assertRaises(SystemExit):
                    TOOL.main([command, *options, "--installer-output", "/work/old-output.txt"])
                call.assert_not_called()
        source = (Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py").read_text(encoding="utf-8")
        ordinary = source.split("def observation_command(args):", 1)[1].split("def visible_occupant", 1)[0]
        fixture = source.split("def fixture_observation_command(args):", 1)[1].split("def main", 1)[0]
        for block in (ordinary, fixture):
            self.assertIn("installer_result_readback(args", block)
            self.assertNotIn("installer_record(", block)
            self.assertNotIn("fixture_record(", block)
            self.assertNotIn("installer_output", block)
        self.assertIn("bound_original_result(result,", ordinary)
        self.assertIn("bound_fixture_result(result,", fixture)

    def test_installer_export_source_keeps_dedicated_custody_original_clocks_and_finality(self):
        source = (Path(__file__).absolute().parents[2] / "desktop/src-tauri/src/bin/macos_install.rs").read_text(encoding="utf-8")
        exporter = source.split("struct Export {", 1)[1].split("    impl Install {", 1)[0]
        self.assertIn("Vec::with_capacity(4)", exporter)
        self.assertIn('check(self.originals.len() < 4, "export-original-bound")', exporter)
        self.assertNotIn("Install::new", exporter)
        self.assertNotIn("Duration::", exporter)
        writer = exporter.split("fn write(&mut self, name: &str, bytes: &[u8])", 1)[1].split("fn finish", 1)[0]
        for flag in ("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            self.assertIn("OFlag::" + flag, writer)
        self.assertNotIn("create_file", writer)
        self.assertIn("original.mode == 0o100600 && original.uid == 0 && original.links == 1 && original.size == 0", writer)
        self.assertNotIn("original.gid == 0", writer)
        self.assertIn("sealed.size == bytes.len() as i64", writer)
        phases = [writer.index(value) for value in ("let original =", "while written <", "let before_seal =", "unistd::fchown",
                  "stat::fchmod", "let sealed =", "self.persist(n, true)", "self.close(n)", "self.persist(support, false)",
                  "self.named(n)? == sealed", "for (n, role)")]
        self.assertEqual(phases, sorted(phases))
        self.assertIn("for n in (0..self.originals.len()).rev()", exporter)
        self.assertIn("export_final(result, settled, self.unknown, self.end, Instant::now())", exporter)
        self.assertIn("finish_transport(&install.result_record(&final_result), final_result.exit, install.end)", source)
        self.assertLess(source.index("let export_end = Instant::now() + Duration::from_secs(10);"),
                        source.index('let record = serde_json::json!({"schemaVersion":1,"sourceCommit":source_commit'))
        finish = exporter.split("fn finish_transport", 1)[1]
        self.assertIn('if original_exit == 0 { export_result(record, end) } else { Err("original-installation-failed") }', finish)
        self.assertLess(finish.index("if exit != 0 {"), finish.index("std::io::stdout"))
        self.assertIn("pending-original-export-finalization", exporter)
        self.assertNotIn("remove_file", exporter)
        self.assertNotIn("unlink", exporter)
        directory = source.split("fn directory(&mut self, parent: usize, name: &str, fresh: bool, mode: u32)", 1)[1].split("        fn close", 1)[0]
        self.assertIn('Err(Errno::EEXIST) if !fresh => self.creations[effect].state = "existing-not-modified"', directory)
        created = directory.split('if self.creations[effect].state == "created" {', 1)[1]
        phases = [created.index(value) for value in ("self.protected(n, true, None)", "created_directory_private(before)",
                  "self.check_name(n, true)?; self.clock()?;", "unistd::fchown", 'map_err(|_| "created-directory-owner")?;',
                  "self.clock()?; // A failed/late", "stat::fchmod", "let actual =", "let named =", "created_directory_normalized(before, actual, named, mode)",
                  "self.originals[n].identity = Some(actual)", "self.creations[effect].identity = Some(actual)")]
        self.assertEqual(phases, sorted(phases))
        self.assertEqual(directory.count("unistd::fchown"), 1)
        private = source.split("fn created_directory_private", 1)[1].split("fn created_directory_normalized", 1)[0]
        self.assertNotIn("gid", private)
        self.assertIn("id.uid == 0 && id.mode & 0o7077 == 0", private)
        normalized = source.split("fn created_directory_normalized", 1)[1].split("// Consumes only", 1)[0]
        self.assertIn("actual == named && before.dev == actual.dev && before.ino == actual.ino", normalized)
        self.assertIn("actual.uid == 0 && actual.gid == 0", normalized)
        create_file = source.split("fn create_file", 1)[1].split("fn check_name", 1)[0]
        self.assertIn("self.protected(n, false, Some(0o600))?", create_file)

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

    def test_fixture_result_exact_eight_cases_never_promotes_actual_uncertainty(self):
        self.assertEqual(tuple(TOOL.FIXTURE_CASES), ("occupied-app", "occupied-release", "runtime-publication-collision", "staging-file-collision",
                         "first-publication-second-refusal", "prepublication-persistence-report", "postruntime-persistence-report", "metadata-descriptor-collision"))
        marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
        good = reported_fixture_data()
        log = marker + TOOL.canonical(good) + b"\n"
        self.assertEqual(TOOL.fixture_record(log, "a" * 40, "b" * 64, "c" * 64), good)
        self.assertIs(TOOL.bound_fixture_result(good, "a" * 40, "b" * 64, "c" * 64), good)
        mutations = [(("sourceCommit",), "f" * 40), (("fixtureBase",), "/tmp/arbitrary"),
                     (("fixtureBase",), TOOL.FIXTURE_PREFIX + "f" * 12 + "-" + "e" * 32),
                     (("cases",), good["cases"][:-1]), (("cases",), list(reversed(good["cases"]))),
                     (("nativeCloseFailureInjected",), True), (("genuineConcurrentRaceObserved",), True),
                     (("cases", 2, "originalResult", "runtimePublication"), "unknown"), (("cases", 3, "stagingOpenErrno"), 5),
                     (("cases", 5, "persistence", "actualNativeSucceeded"), False), (("cases", 6, "persistence", "actualNativeErrno"), 5),
                     (("cases", 7, "stagingOpenErrno"), 5), (("cases", 7, "originalResult", "installationMetadata", "openedFiles"), 2),
                     (("cases", 7, "occupant", "visibleRelativePath"), "versions/" + TOOL.RELEASE + "/unrelated"),
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
            with self.subTest(direct_path=path), self.assertRaises(TOOL.Refused):
                TOOL.bound_fixture_result(changed, "a" * 40, "b" * 64, "c" * 64)
        for changed in (log + log, b"MRK_MACOS_INSTALL_RESULT={}\n" + log):
            with self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(changed, "a" * 40, "b" * 64, "c" * 64)


def installation_record_fixture():
    # Closed DATA only, not a root-owned installation or original receipt.
    names = ["app/" + TOOL.VAULT_HELPER, "app/Contents/Info.plist",
             "app/" + TOOL.APP_BINARY, "runtime/manifest.json", "runtime/python/bin/python3"]
    rows = [{"path": name, "size": 1, "sha256": ("c" if name == "runtime/manifest.json" else "b") * 64,
             "executable": name in ("app/" + TOOL.VAULT_HELPER, "app/" + TOOL.APP_BINARY, "runtime/python/bin/python3")}
            for name in sorted(names)]
    inventory = TOOL.canonical({"schemaVersion": 1, "release": TOOL.RELEASE,
                                "runtimeManifestSha256": "c" * 64, "files": rows})
    identity = {"device": 1, "inode": 9007199254740993, "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0, "flags": 0}
    release = {**identity, "inode": identity["inode"] + 1}
    record = {"schemaVersion": 1, "basis": "protected-recorded-installation-inventory", "phase": "inventory-recorded",
              "kind": "ordinary", "instance": "d" * 32, "packageIdentifier": TOOL.PACKAGE_ID,
              "packageVersion": TOOL.PACKAGE_VERSION, "bundleIdentifier": TOOL.BUNDLE_ID, "release": TOOL.RELEASE,
              "sourceCommit": "a" * 40, "protocolSha256": TOOL.CURRENT_PROTOCOL, "runtimeManifestSha256": "c" * 64,
              "inventory": {"name": TOOL.INSTALLATION_INVENTORY_NAME, "bytes": len(inventory), "sha256": TOOL.digest(inventory)},
              "policy": "fixed-root-wheel-readonly-v1", "installRoot": identity, "releaseDirectory": release}
    return record, inventory, identity, release


@unittest.skipUnless(TOOL is not None, "POSIX inert DATA definitions only")
class MacInstallationMetadataData(unittest.TestCase):
    def test_closed_record_matches_exact_inventory_tuple_and_full_integer_directory_identity(self):
        record, inventory, root, release = installation_record_fixture()
        def parse(body, payload=inventory):
            return TOOL.installation_record_data(body, payload, "a" * 40, "c" * 64, root, release, "d" * 32)
        self.assertEqual(parse(TOOL.canonical(record)), record)
        for path, value in [(("schemaVersion",), True), (("phase",), "installed"), (("kind",), "fixture"),
                            (("sourceCommit",), "e" * 40), (("protocolSha256",), "e" * 64),
                            (("instance",), "0" * 32), (("installRoot", "inode"), 9007199254740992),
                            (("releaseDirectory", "flags"), 1), (("installRoot", "mtime"), 1),
                            (("installRoot", "uid"), False), (("inventory", "bytes"), True), (("extra",), True)]:
            changed = TOOL.decode(TOOL.canonical(record))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                parse(TOOL.canonical(changed))
        for body in (b'{"schemaVersion":1,' + TOOL.canonical(record)[1:], b" " * (TOOL.INSTALLATION_RECORD_LIMIT + 1)):
            with self.assertRaises(TOOL.Refused):
                parse(body)
        with self.assertRaises(TOOL.Refused):
            parse(TOOL.canonical(record), inventory + b" ")
        # Even a self-consistent descriptor digest cannot bless an invalid roster.
        malformed = TOOL.decode(inventory)
        malformed["files"][0]["path"] = "runtime/../unrelated"
        malformed = TOOL.canonical(malformed)
        changed = {**record, "inventory": {**record["inventory"], "bytes": len(malformed), "sha256": TOOL.digest(malformed)}}
        with self.assertRaises(TOOL.Refused):
            parse(TOOL.canonical(changed), malformed)

    def test_metadata_return_accounting_is_required_and_partial_is_not_success(self):
        expected = (None, "confirmed", "confirmed", "installed", True, 0)
        result = original_result(expected)
        TOOL.bound_original_result(result, expected, "a" * 40, "b" * 64, "c" * 64)
        for field, value in (("writersSettled", False), ("openedFiles", 1), ("attemptedFiles", True),
                             ("writtenBytes", 9), ("state", "incomplete"), ("extra", 0)):
            changed = {**result, "installationMetadata": {**result["installationMetadata"], field: value}}
            with self.subTest(field=field), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result(changed, expected, "a" * 40, "b" * 64, "c" * 64)
        missing = dict(result)
        del missing["installationMetadata"]
        with self.assertRaises(TOOL.Refused):
            TOOL.bound_original_result(missing, expected, "a" * 40, "b" * 64, "c" * 64)
        partial = TOOL.FIXTURE_CASES["metadata-descriptor-collision"]
        value = original_result(partial)
        TOOL.bound_original_result(value, partial, "a" * 40, "b" * 64, "c" * 64)
        self.assertEqual(value["installationMetadata"]["openedFiles"], 1)
        with self.assertRaises(TOOL.Refused):
            TOOL.installation_metadata_result(result["installationMetadata"], partial)

    def test_metadata_leaf_requires_flags_through_original_read_and_positive_close(self):
        # Every numerical FD here is an inert token; all consumers are replaced.
        good = log_info(3, st_mode=stat.S_IFREG | 0o444, st_gid=0, st_flags=0)
        changed = log_info(3, st_mode=stat.S_IFREG | 0o444, st_gid=0, st_flags=1)
        for cause in ("none", "flags", "close"):
            with (mock.patch.object(TOOL.os, "stat", side_effect=[good, good]),
                  mock.patch.object(TOOL.os, "open", return_value=91),
                  mock.patch.object(TOOL.os, "fstat", side_effect=[good, changed if cause == "flags" else good]),
                  mock.patch.object(TOOL.os, "read", side_effect=[b"abc", b""]),
                  mock.patch.object(TOOL, "no_xattrs"),
                  mock.patch.object(TOOL, "close_once", side_effect=TOOL.Refused("synthetic-close-unknown") if cause == "close" else None) as close):
                if cause == "none":
                    self.assertEqual(TOOL.installation_metadata_leaf(90, TOOL.INSTALLATION_RECORD_NAME, 10)[0], b"abc")
                else:
                    with self.subTest(cause=cause), self.assertRaises(TOOL.Refused):
                        TOOL.installation_metadata_leaf(90, TOOL.INSTALLATION_RECORD_NAME, 10)
                close.assert_called_once_with(91)

    def test_metadata_parent_cleanup_consumes_all_originals_and_gates_result(self):
        names = {"runtime", TOOL.INSTALLATION_INVENTORY_NAME, TOOL.INSTALLATION_RECORD_NAME}
        entries = ("MobileReleaseKit", "versions", TOOL.RELEASE)
        info = {entry: log_info(st_ino=index + 101, st_mode=stat.S_IFDIR | 0o755, st_gid=0, st_nlink=3, st_flags=0)
                for index, entry in enumerate(entries)}
        @contextlib.contextmanager
        def parent(_path):
            yield 100, entries[0]
        for cause in ("none", "close", "drift"):
            stats = [info[name] for name in entries] * 2
            if cause == "drift":
                stats[-1] = SimpleNamespace(**{**vars(stats[-1]), "st_ino": 999})
            with (mock.patch.object(TOOL, "parent", side_effect=parent),
                  mock.patch.object(TOOL.os, "stat", side_effect=stats),
                  mock.patch.object(TOOL.os, "open", side_effect=[101, 102, 103]),
                  mock.patch.object(TOOL.os, "fstat", side_effect=lambda fd: info[entries[fd - 101]]),
                  mock.patch.object(TOOL.os, "listdir", return_value=list(names)),
                  mock.patch.object(TOOL, "no_xattrs"),
                  mock.patch.object(TOOL, "close_once", side_effect=[TOOL.Refused("synthetic-close-unknown"), None, None] if cause == "close" else None) as close):
                def observe():
                    with TOOL.installation_metadata_directory(TOOL.INSTALL_ROOT, names) as (_root, _release, fd):
                        self.assertEqual(fd, 103)
                    return "after-real-context-closes"
                if cause == "none":
                    self.assertEqual(observe(), "after-real-context-closes")
                else:
                    with self.subTest(cause=cause), self.assertRaises(TOOL.Refused):
                        observe()
                self.assertEqual(close.call_args_list, [mock.call(103), mock.call(102), mock.call(101)])

    def test_record_identifiers_match_existing_package_and_bundle_source(self):
        source = Path(__file__).absolute().parents[2]
        info = TOOL.plistlib.loads((source / "desktop/macos-installed-inputs/Info.plist").read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], TOOL.BUNDLE_ID)
        self.assertEqual(info["CFBundleVersion"], TOOL.PACKAGE_VERSION)
        self.assertEqual(info["CFBundleShortVersionString"], TOOL.PACKAGE_VERSION)
        paths = (source / "desktop/src-tauri/src/macos_install_paths.rs").read_text(encoding="utf-8")
        for key, value in (("PACKAGE_ID", TOOL.PACKAGE_ID), ("FIXTURE_PACKAGE_ID", TOOL.PACKAGE_ID + "-fixture"),
                           ("PACKAGE_VERSION", TOOL.PACKAGE_VERSION), ("BUNDLE_ID", TOOL.BUNDLE_ID)):
            self.assertIn(f'pub const {key}: &str = "{value}";', paths)



@contextlib.contextmanager
def current_data_fixture():
    """Fresh synthetic DATA only; no real supplier archive or executable core."""
    helper = (Path(__file__).absolute().parents[2] / "desktop/tools/prepare_runtime.py").read_bytes()
    with tempfile.TemporaryDirectory(prefix="mrk-macos-current-data-") as directory:
        root = Path(directory)
        checkout = root / "checkout"
        engine = b"# Inert protocol DATA, never imported.\n"
        inputs = {"src/mobile_release/__init__.py": b'__version__ = "0.1.0"\n',
                  "src/mobile_release/_desktop_engine.py": engine,
                  TOOL.CURRENT_CA_SOURCE: b"SYNTHETIC CA DATA, not a trust store\n",
                  TOOL.CURRENT_HELPER_SOURCE: helper}
        inputs.update({"desktop/" + name: ("# current inert " + name + "\n").encode() for name in TOOL.CURRENT_BOOTSTRAPS})
        for name, body in inputs.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(body)
        archive = root / "supplier.zip"
        archive.write_bytes(b"No actual archive; supplier decoder is mocked.\n")
        supplier = {"python/bin/python3": b"INERT SUPPLIER DATA; NEVER EXECUTED\n",
                    "python/licenses/notice.txt": b"synthetic supplier notice\n"}
        historical = {**supplier, "core.zip": b"historical core, not used", "github-ca.pem": b"historical CA",
                      "manifest.json": b"historical manifest"}
        historical.update({name: b"historical bootstrap" for name in TOOL.BOOTSTRAPS})
        provenance = {"acceptedArchiveSha256": "1" * 64, "acceptedTarSha256": "2" * 64,
                      "originalManifestSha256": "3" * 64, "addedNotices": ["synthetic notice only"]}
        with (mock.patch.object(TOOL, "DESKTOP", checkout / "desktop"),
              mock.patch.object(TOOL, "CURRENT_PROTOCOL", TOOL.digest(engine)),
              mock.patch.object(TOOL, "reused_runtime", return_value=(historical, provenance))):
            yield SimpleNamespace(root=root, checkout=checkout, archive=archive, supplier=supplier, inputs=inputs)


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX DATA stager")
class MacCurrentRuntimeData(unittest.TestCase):
    def args(self, fixture, command="describe-current-runtime", suffix="description"):
        return SimpleNamespace(command=command, archive=fixture.archive, work=fixture.root / ("work-" + suffix),
                               output=fixture.root / ("output-" + suffix), expected_source="0" * 64,
                               expected_manifest="0" * 64)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_current_projection_and_final_payload_preserve_only_supplier(self):
        with current_data_fixture() as fixture:
            captured, projection, source_digest = TOOL.current_source()
            self.assertEqual(set(captured), set(fixture.inputs))
            self.assertEqual(len(projection) + 1, len(captured))
            self.assertNotIn(TOOL.CURRENT_HELPER_SOURCE, projection)
            self.assertNotIn(TOOL.CURRENT_CA_SOURCE, projection)
            self.assertEqual(projection["desktop/github-ca.pem"], (fixture.inputs[TOOL.CURRENT_CA_SOURCE], 0o444))
            description = TOOL.current_runtime_command(self.args(fixture))
            args = self.args(fixture, "current-runtime", "final")
            args.expected_source = source_digest
            args.expected_manifest = description["successorManifestSha256"]
            result = TOOL.current_runtime_command(args)
            self.assertEqual(result["qualification"], "current-source-staged-no-native-execution")
            self.assertTrue(result["supplierOnlyReuse"])
            self.assertEqual(result["sourceInputCount"], len(fixture.inputs))
            self.assertEqual(result["currentCoreFileCount"], 2)
            self.assertEqual(result["supplierInventorySha256"], description["supplierInventorySha256"])
            final = TOOL.tree(args.output, current_root_mode=0o555)
            self.assertEqual(set(final), set(fixture.supplier) | TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "manifest.json", "github-ca.pem"})
            for name, body in fixture.supplier.items():
                self.assertEqual(final[name], (body, 0o555 if name == "python/bin/python3" else 0o444))
            for name in TOOL.CURRENT_BOOTSTRAPS | {"github-ca.pem"}:
                self.assertEqual(final[name], projection["desktop/" + name])
            TOOL.current_core_matches(final["core.zip"][0], projection)
            self.assertEqual(TOOL.tree(args.work / "source", current_root_mode=0o555), projection)
            self.assertEqual(TOOL.current_source(), (captured, projection, source_digest))

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_source_pin_and_output_conflicts_fail_before_helper_or_writes(self):
        with current_data_fixture() as fixture, mock.patch.object(TOOL, "current_preparer") as prepare:
            args = self.args(fixture, "current-runtime", "stale")
            with mock.patch.object(TOOL, "CURRENT_PROTOCOL", "f" * 64):
                with self.assertRaisesRegex(TOOL.Refused, "current-protocol-source"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.work.exists())
            self.assertFalse(args.output.exists())
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-source-mismatch"):
                TOOL.current_runtime_command(args)
            self.assertFalse(args.work.exists())
            self.assertFalse(args.output.exists())
            args.expected_source = TOOL.current_source()[2]
            extra = fixture.checkout / "src/mobile_release/extra.py"
            extra.write_bytes(b"# extra current source must change S\n")
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-source-mismatch"):
                TOOL.current_runtime_command(args)
            extra.unlink()
            for output in (args.work, args.work / "nested", fixture.checkout / "new-output"):
                args.output = output
                with self.assertRaisesRegex(TOOL.Refused, "current-path-overlap"):
                    TOOL.current_runtime_command(args)
            args = self.args(fixture, "current-runtime", "occupied")
            args.work.mkdir(mode=0o700)
            with self.assertRaisesRegex(TOOL.Refused, "current-output-occupied"):
                TOOL.current_runtime_command(args)
            self.assertTrue(args.work.is_dir())
            args = self.args(fixture, "current-runtime", "parent-mode")
            fixture.root.chmod(0o755)
            try:
                with self.assertRaisesRegex(TOOL.Refused, "current-output-parent-owner-mode"):
                    TOOL.current_runtime_command(args)
            finally:
                fixture.root.chmod(0o700)
            prepare.assert_not_called()

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_current_source_rejects_missing_unknown_or_linked_inputs(self):
        with current_data_fixture() as fixture:
            invalid = fixture.checkout / "src/mobile_release/generated.pyc"
            invalid.write_bytes(b"not source")
            with self.assertRaisesRegex(TOOL.Refused, "current-core-inputs"):
                TOOL.current_source()
            invalid.unlink()
            ca = fixture.checkout / TOOL.CURRENT_CA_SOURCE
            original = fixture.root / "original-ca"
            ca.rename(original)
            with self.assertRaises(FileNotFoundError):
                TOOL.current_source()
            ca.symlink_to(original)
            with self.assertRaisesRegex(TOOL.Refused, "ordinary-file-bound"):
                TOOL.current_source()
            ca.unlink()
            original.rename(ca)
            captured = TOOL.current_source()[0]
            helper = fixture.checkout / TOOL.CURRENT_HELPER_SOURCE
            helper.write_bytes(b"# changed helper DATA must not be evaluated\n")
            with mock.patch.object(TOOL.importlib.util, "spec_from_file_location") as loader:
                with self.assertRaisesRegex(TOOL.Refused, "current-helper-changed"):
                    TOOL.current_preparer(captured)
                loader.assert_not_called()

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_complete_runtime_and_core_correspondence_reject_mutations(self):
        with current_data_fixture() as fixture:
            args = self.args(fixture)
            TOOL.current_runtime_command(args)
            _, projection, _ = TOOL.current_source()
            supplier = {name: (body, 0o555 if name == "python/bin/python3" else 0o444)
                        for name, body in fixture.supplier.items()}
            files = TOOL.tree(args.work / "runtime")
            changed = []
            missing = dict(files)
            del missing["python/licenses/notice.txt"]
            changed.append(missing)
            changed.append({**files, "unexpected.py": (b"extra", 0o600)})
            changed.append({**files, "python/bin/python3": (b"changed supplier", 0o555)})
            changed.append({**files, "python/bin/python3": (fixture.supplier["python/bin/python3"], 0o644)})
            changed.append({**files, "github-ca.pem": (b"stale CA", 0o600)})
            changed.append({**files, "core.zip": (files["core.zip"][0], 0o644)})
            for field, value in (("target", "x86_64-unknown-linux-gnu"), ("protocolSha256", "f" * 64)):
                manifest = TOOL.decode(files["manifest.json"][0])
                manifest[field] = value
                changed.append({**files, "manifest.json": (TOOL.canonical(manifest) + b"\n", 0o600)})
            for candidate in changed:
                with mock.patch.object(TOOL, "tree", return_value=candidate), self.assertRaises(TOOL.Refused):
                    TOOL.current_runtime_files(args.work / "runtime", projection, supplier)
            python_directory = args.work / "runtime/python"
            python_directory.chmod(0o700)
            try:
                with self.assertRaisesRegex(TOOL.Refused, "current-directory-mode-owner"):
                    TOOL.current_runtime_files(args.work / "runtime", projection, supplier)
            finally:
                python_directory.chmod(0o555)
            for candidate in ({name: value for name, value in projection.items() if not name.endswith("_desktop_engine.py")},
                              {**projection, "src/mobile_release/extra.py": (b"extra", 0o444)},
                              {**projection, "src/mobile_release/_desktop_engine.py":
                               (b"x" * len(projection["src/mobile_release/_desktop_engine.py"][0]), 0o444)}):
                with self.assertRaises(TOOL.Refused):
                    TOOL.current_core_matches(files["core.zip"][0], candidate)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_manifest_mismatch_preserves_preparation_but_never_creates_final(self):
        with current_data_fixture() as fixture:
            args = self.args(fixture, "current-runtime", "wrong-manifest")
            args.expected_source = TOOL.current_source()[2]
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-manifest-mismatch"):
                TOOL.current_runtime_command(args)
            self.assertTrue((args.work / "runtime/manifest.json").is_file())
            self.assertTrue((args.work / "source/desktop/github-ca.pem").is_file())
            self.assertFalse(args.output.exists())

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_preparation_source_post_and_final_write_failures_stay_failed(self):
        with current_data_fixture() as fixture:
            captured, projection, source_digest = TOOL.current_source()
            preparer = TOOL.current_preparer(captured)
            args = self.args(fixture, "current-runtime", "prepare-failure")
            args.expected_source = source_digest
            def incomplete(source, runtime, target):
                (runtime / "partial-data").write_bytes(b"retained")
                raise ValueError("injected preparation failure")
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=incomplete)):
                with self.assertRaises(ValueError):
                    TOOL.current_runtime_command(args)
            self.assertEqual((args.work / "runtime/partial-data").read_bytes(), b"retained")
            self.assertFalse(args.output.exists())
            self.assertEqual(TOOL.current_source(), (captured, projection, source_digest))
            args = self.args(fixture, "current-runtime", "projection-mode")
            args.expected_source = source_digest
            def writable_projection(source, runtime, target):
                result = preparer.prepare_current(source, runtime, target)
                (source / "desktop").chmod(0o700)
                return result
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=writable_projection)):
                with self.assertRaisesRegex(TOOL.Refused, "current-directory-mode-owner"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.output.exists())
            args = self.args(fixture, "current-runtime", "source-post")
            args.expected_source = source_digest
            original = fixture.checkout / "desktop/engine_bootstrap.py"
            def changed_source(source, runtime, target):
                result = preparer.prepare_current(source, runtime, target)
                original.write_bytes(b"# changed after captured source\n")
                return result
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=changed_source)):
                with self.assertRaisesRegex(TOOL.Refused, "current-source-post-changed"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.output.exists())
            original.write_bytes(fixture.inputs["desktop/engine_bootstrap.py"])
            description = TOOL.current_runtime_command(self.args(fixture))
            args = self.args(fixture, "current-runtime", "final-write")
            args.expected_source = source_digest
            args.expected_manifest = description["successorManifestSha256"]
            writer = TOOL.write_tree
            def incomplete_final(output, files, **options):
                if output == args.output:
                    output.mkdir(mode=0o700)
                    (output / "partial-data").write_bytes(b"retained final output")
                    raise OSError("injected final publication failure")
                return writer(output, files, **options)
            with mock.patch.object(TOOL, "write_tree", side_effect=incomplete_final):
                with self.assertRaises(OSError):
                    TOOL.current_runtime_command(args)
            self.assertEqual((args.output / "partial-data").read_bytes(), b"retained final output")
            self.assertTrue((args.work / "runtime/manifest.json").is_file())

    def test_new_cli_is_nonroot_and_does_not_change_historical_runtime_route(self):
        with mock.patch.object(TOOL.os, "getuid", return_value=0), mock.patch.object(TOOL, "current_runtime_command") as action:
            with self.assertRaisesRegex(TOOL.Refused, "only-installer-is-privileged"):
                TOOL.main(["describe-current-runtime", "--archive", "/a", "--work", "/w"])
            action.assert_not_called()
        with (mock.patch.object(TOOL.os, "getuid", return_value=501),
              mock.patch.object(TOOL.os, "geteuid", return_value=501),
              mock.patch.object(TOOL, "current_runtime_command", return_value={"data": True}) as current,
              mock.patch.object(TOOL, "runtime_command", return_value={"historical": True}) as historical,
              mock.patch.object(TOOL, "input_command", return_value={"input": True}) as inputs,
              contextlib.redirect_stdout(io.StringIO())):
            TOOL.main(["current-runtime", "--archive", "/a", "--work", "/w", "--expected-source", "a" * 64,
                       "--expected-manifest", "b" * 64, "--output", "/o"])
            args = current.call_args.args[0]
            self.assertEqual((args.archive, args.work, args.output), (Path("/a"), Path("/w"), Path("/o")))
            self.assertEqual((args.expected_source, args.expected_manifest), ("a" * 64, "b" * 64))
            historical.assert_not_called()
            TOOL.main(["runtime", "--archive", "/a", "--expected-manifest", "c" * 64, "--output", "/o"])
            historical.assert_called_once()
            current.assert_called_once()
            for current_profile, flags in ((False, []), (True, ["--current-runtime"])):
                TOOL.main(["input", "--app", "/app", "--runtime", "/runtime", "--expected-manifest", "d" * 64,
                           "--expected-vault-helper", "f" * 64, "--output", "/input", *flags])
                self.assertIs(inputs.call_args.args[0].current_runtime, current_profile)
                self.assertEqual(inputs.call_args.args[0].expected_vault_helper, "f" * 64)
        for current_profile in (False, True):
            args = SimpleNamespace(runtime=Path("/inert-runtime"), expected_manifest="e" * 64,
                                   current_runtime=current_profile)
            with mock.patch.object(TOOL, "runtime_tree", side_effect=RuntimeError("inert tree boundary")) as tree:
                with self.assertRaisesRegex(RuntimeError, "inert tree boundary"):
                    TOOL.input_command(args)
                tree.assert_called_once_with(args.runtime, args.expected_manifest, current=current_profile)

    def test_aqua_uses_reviewed_current_source_data_before_compilation(self):
        workflow = (Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        runtime_name = "Reuse accepted Mac supplier and prepare only the current source payload"
        build_name = "Compile the fixed debug actual-main observer and normal embedded frontend once"
        runtime = workflow_step(workflow, runtime_name)
        build = workflow_step(workflow, build_name)
        self.assertEqual(runtime.count("desktop/tools/stage_macos_installed.py current-runtime"), 1)
        self.assertLess(workflow.index("      - name: " + runtime_name + "\n"),
                        workflow.index("      - name: " + build_name + "\n"))
        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn("npm run build", build)
        self.assertIn("cargo test --locked --no-default-features --features desktop-shell,custom-protocol,macos-installed-observation", build)
        self.assertIn("--test installed-shell-observation --no-run --message-format=json", build)
        self.assertIn('--work "$MRK_MACOS_WORK/current-runtime-preparation"', workflow)
        self.assertIn('--expected-source "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256"', workflow)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', workflow)
        for variable in ("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256"):
            literal = TOOL.re.search(r"^      " + variable + r": ([a-z0-9-]+)$", workflow, TOOL.re.M).group(1)
            self.assertTrue(TOOL.sha(literal) or literal.startswith("pending-independent-current-"))
            self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{64}$', workflow)
            self.assertIn('"$' + variable + '" == ' + literal, workflow)
        self.assertIn('actions/artifacts/10639324707/zip', workflow)
        self.assertIn('"reusedSupplierOnly": True', workflow)
        # This workflow now selects explicit current scopes; it does not run or
        # qualify the historical four merely by staging the current payload.
        binding = workflow_step(workflow, "Record exact source and actual tool bindings only after route admission")
        self.assertIn('"scopes": selected_scopes, "caseNames": case_names', binding)
        self.assertIn('"unselectedScopes": [scope for scope in native_scopes if scope not in selected_scopes]', binding)
        self.assertIn('"actualAquaSaveGate": "not-yet-executed"', binding)
        for scope, name in (
                ("project-fields", "One project-field Aqua journey through the reviewed original invocation owner"),
                ("android-inputs", "One Android-input Aqua journey through the reviewed original invocation owner"),
                ("ios-current-synthetic", "Nine serial current-iOS Aqua cases through the reviewed original invocation owner")):
            journey = workflow_step(workflow, name)
            self.assertEqual(journey.count("desktop/tools/macos_aqua_qualification.py --scope " + scope + " "), 1)
            self.assertIn("env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'", journey)
            self.assertIn("[[ $status == 0 ]]", journey)
        aqua_owner = (Path(__file__).absolute().parents[2] / "desktop/tools/macos_aqua_qualification.py").read_text(encoding="utf-8")
        self.assertIn('CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")', aqua_owner)
        self.assertIn('return IOS_CASES if scope == "ios-unsigned-archive" else CASES', aqua_owner)

    def test_ordinary_workflow_binds_reviewed_current_payload_before_normal_release(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        anchors = {}
        for variable in ("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256",
                         "MRK_BUNDLED_PROTOCOL_SHA256"):
            configured = TOOL.re.findall(r"^      " + variable + r": ([0-9a-f]{64})$", workflow, TOOL.re.M)
            self.assertEqual(len(configured), 1, variable)
            anchors[variable] = configured[0]
            self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{64}$', workflow)
            self.assertIn('"$' + variable + '" == ' + configured[0], workflow)
        # Read the actual bounded source DATA used by the stager, not a copy of
        # its historical pin. No core import, supplier extraction or execution.
        self.assertEqual(anchors["MRK_BUNDLED_RUNTIME_SOURCE_SHA256"], TOOL.current_source()[2])
        # The manifest pin still needs independent runtime-regeneration evidence.
        # Its format, guards and CLI binding here do not establish its authority.
        self.assertEqual(TOOL.CURRENT_PROTOCOL, anchors["MRK_BUNDLED_PROTOCOL_SHA256"])
        self.assertNotEqual(TOOL.PROTOCOL, anchors["MRK_BUNDLED_PROTOCOL_SHA256"])
        for field, variable in (("runtimeManifestSha256", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
                                ("runtimeSourceInputsSha256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256"),
                                ("protocolSha256", "MRK_BUNDLED_PROTOCOL_SHA256")):
            self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
        self.assertIn('"reusedSupplierOnly": True', workflow)
        self.assertIn('"reusedRun": "35602474108/1", "reusedArtifactId": "10639324707"', workflow)
        self.assertEqual(workflow.count('actions/artifacts/10639324707/zip'), 1)
        command = "desktop/tools/stage_macos_installed.py current-runtime"
        self.assertEqual(workflow.count(command), 1)
        runtime_name = "Reuse accepted Mac supplier and prepare only the current ordinary payload"
        build_name = "Build only the normal ARM64 bundled-asset shell"
        block = workflow_step(workflow, runtime_name)
        build = workflow_step(workflow, build_name)
        self.assertEqual(block.count(command), 1)
        self.assertLess(workflow.index("      - name: " + runtime_name + "\n"),
                        workflow.index("      - name: " + build_name + "\n"))
        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn("cargo build --locked --release --no-default-features --features desktop-shell,custom-protocol", build)
        for fragment in ("timeout-minutes: 3", "set -o noclobber", "umask 077",
                         '--archive "$MRK_MACOS_WORK/accepted-native-evidence.zip"',
                         '--work "$MRK_MACOS_WORK/current-runtime-preparation"',
                         '--expected-source "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256"',
                         '--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"',
                         '--output "$MRK_MACOS_WORK/runtime" > "$MRK_MACOS_WORK/runtime-result.json"'):
            self.assertEqual(block.count(fragment), 1, fragment)
        for subcommand in ("runtime ", "describe-runtime", "describe-current-runtime"):
            self.assertNotIn("desktop/tools/stage_macos_installed.py " + subcommand, workflow)
        command = "desktop/tools/stage_macos_installed.py input"
        self.assertEqual(workflow.count(command), 1)
        inputs = workflow.split(command, 1)[1].split('inventory=$', 1)[0]
        self.assertEqual(inputs.count("--current-runtime"), 1)
        self.assertIn('--runtime "$MRK_MACOS_WORK/runtime"', inputs)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', inputs)
        self.assertIn('--output "$MRK_MACOS_WORK/input"', inputs)

    def test_native_action_roster_and_independent_publisher_bindings(self):
        root = Path(__file__).absolute().parents[2]
        publisher = "b4cb582837a244f67e4c926f2ce2bb42ad8cfe37"
        fields = (("githubPreflightToolingSha", "MRK_GITHUB_PREFLIGHT_TOOLING_SHA"),
                  ("githubReleaseToolingSha", "MRK_GITHUB_RELEASE_TOOLING_SHA"))
        for filename in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            workflow = (root / ".github/workflows" / filename).read_text()
            admission = workflow_step(workflow, "Admit only this exact disposable-hosted source route")
            for field, variable in fields:
                self.assertEqual(TOOL.re.findall(r"^      " + variable + r": ([0-9a-f]{40})$", workflow, TOOL.re.M), [publisher])
                self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{40}$', admission)
                self.assertIn('"$' + variable + '" == ' + publisher, admission)
                self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
            # Digests must be generated from the actual templates, not provided
            # by CI alongside a different source/application commit.
            for generated in ("MRK_GITHUB_PREFLIGHT_CALLER_SHA256", "MRK_GITHUB_RELEASE_CANDIDATE_SHA256",
                              "MRK_GITHUB_RELEASE_EXTERNAL_SHA256", "MRK_GITHUB_RELEASE_PRODUCTION_SHA256"):
                self.assertNotIn(generated + ":", workflow)
        build = (root / "desktop/src-tauri/build.rs").read_text()
        for _, selector in fields:
            self.assertIn('const SELECTOR: &str = "' + selector + '";', build)
        self.assertEqual(build.count("Sha256::digest(caller.as_bytes())"), 2)
        for template in ("mobile-preflight.yml", "mobile-candidate.yml", "mobile-external-testing.yml", "mobile-production-submit.yml"):
            self.assertIn('include_str!("../../templates/workflows/' + template + '")', build)

        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text()
        data = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        names = ast.literal_eval(TOOL.re.search(r"          names = (\[\n.*?\n          \])\n", data, TOOL.re.S).group(1))
        digest = lambda selected: TOOL.digest(TOOL.json.dumps(selected, separators=(",", ":")).encode())
        self.assertEqual(len(names), 79)
        self.assertEqual(len(set(names)), 79)
        self.assertEqual(digest(names[:57]), "4a5c62f00838d17f54e0970c209fc44a2b5708314e39437dbb156a25ac42ffa6")
        self.assertEqual(digest(names[57:]), "f14c3263aadbdaeb0e7d21c821784902289552eb431ce3448726c6631064bfd5")
        self.assertEqual(digest(names), "81ca0c9325763f3aaf2a181e521d7b6adde06b7c0321eecacfc2b93a78c3c051")
        self.assertEqual(data.count(digest(names)), 2)
        sources = ast.literal_eval(TOOL.re.search(r"          source_names = (\(\n.*?\n          \))\n", data, TOOL.re.S).group(1))
        self.assertEqual(len(sources), len(set(sources)))
        for name in names[57:]:
            module, cls, method = name.split(".")
            path = "tests/desktop/" + module + ".py"
            self.assertIn(path, sources)
            definitions = ast.parse((root / path).read_text())
            owner = next(node for node in definitions.body if isinstance(node, ast.ClassDef) and node.name == cls)
            self.assertIn(method, [node.name for node in owner.body if isinstance(node, ast.FunctionDef)])
        for fragment in ('len(names) != 79 or len(set(names)) != 79', 'suite.countTestCases() != 79',
                         'facts["testsRun"] == 79', 'counts.get("testsRun") != 79', '"pythonExpectedCount": 79',
                         '"workflowFilesystemCount": 2', '"imageFilesystemCount": 18', '"evidenceReaderCount": 37',
                         '"githubActionCount": 22', '"test_github_preflight_frames", "test_github_preflight", "test_github_release"'):
            self.assertIn(fragment, data)
        for path in ("desktop/github_preflight_bootstrap.py", "desktop/github_release_bootstrap.py",
                     "src/mobile_release/github_preflight.py", "src/mobile_release/github_release.py",
                     "src/mobile_release/_github_action_family.py", "src/mobile_release/_desktop_github_preflight_engine.py"):
            self.assertIn(path, sources)

    def test_ordinary_current_route_preserves_separate_installer_and_aqua_obligations(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        normal = "cargo build --locked --release --no-default-features --features desktop-shell,custom-protocol"
        build, assembly, inputs = normal_app_steps(workflow)
        self.assertEqual(workflow.count(normal), 1)
        self.assertEqual(build.count(normal + " \\\n"), 1)
        self.assertIn('--binary "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/mobile-release-kit-desktop"', assembly)
        self.assertIn('--normal-cargo-messages "$MRK_MACOS_WORK/normal-build.jsonl"', assembly)
        self.assertIn('--app "$MRK_MACOS_WORK/app/Mobile Release Kit.app"', inputs)
        # The preview's separate debug DATA contract is not the shipped binary.
        data = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        self.assertEqual(workflow.count("macos-installed-observation"), data.count("macos-installed-observation"))
        self.assertEqual(data.count("macos-installed-observation"), 1)
        self.assertIn('"--features", "desktop-shell,custom-protocol,macos-installed-observation"', data)
        self.assertIn('"--test", "installed-shell-observation", "--no-run", "--message-format=json"', data)
        self.assertIn('argv = [str(artifact), "data-contracts"]', data)
        self.assertIn('artifact.parent != root / "cargo-target/aarch64-apple-darwin/debug/deps"', data)
        for block in (build, assembly, inputs):
            for forbidden in ("macos-installed-observation", "installed_shell_observation", "development-runtime"):
                self.assertFalse(forbidden in block, "normal shipping step: " + forbidden)
        for forbidden in ("development-runtime", "macos_aqua_qualification.py", "--scope "):
            self.assertFalse(forbidden in workflow, forbidden)
        self.assertIn("refs/heads/verify/desktop-macos-installed", workflow)
        self.assertIn("$GITHUB_REPOSITORY/.github/workflows/desktop-macos-installed.yml@$GITHUB_REF", workflow)
        self.assertIn('"fixedFixtureCases": 8', workflow)
        self.assertIn('"aclPrimitiveCases": 6', workflow)
        self.assertIn('"selectedRegressionGroups": [2, 1, 2]', workflow)
        self.assertIn('"actualAquaSaveGate": "pending"', workflow)
        self.assertIn("Engineering installation only. Actual installed runtime, Aqua project/Quit, and Save gates remain unverified.", workflow)
        fixture = workflow.index('sudo -- /usr/sbin/installer -pkg "$MRK_MACOS_WORK/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg"')
        fixture_readback = workflow.index("desktop/tools/stage_macos_installed.py observe-installer-fixture")
        ordinary = workflow.index('sudo -- /usr/sbin/installer -pkg "$MRK_MACOS_WORK/package-final/MobileReleaseKit.pkg"')
        ordinary_readback = workflow.index("desktop/tools/stage_macos_installed.py observe-installation")
        fixture_build = workflow.index(
            "cargo build --locked --release --no-default-features --features macos-installed-installer-fixture ")
        ordinary_build = workflow.index(
            "cargo build --locked --release --no-default-features --features macos-installed-installer ")
        self.assertLess(fixture_build, fixture)
        self.assertLess(fixture, fixture_readback)
        self.assertLess(fixture_readback, ordinary_build)
        self.assertLess(ordinary_build, ordinary)
        self.assertLess(ordinary, ordinary_readback)
        self.assertEqual(workflow.count("sudo -- /usr/sbin/installer -pkg "), 2)
        for stem in ("installer-fixture", "installer"):
            self.assertIn('--installer-status "$MRK_MACOS_WORK/' + stem + '-output.status"', workflow)
        for path in ("runtime-result.json", "input-result.json", "installer-fixture-observation.json", "installation-observation.json"):
            self.assertIn("$" + "{{ steps.work.outputs.root }}/" + path, workflow)
        guide = (root / "desktop/packaging/macos-installed.md").read_text(encoding="utf-8")
        self.assertIn("ordinary4 remains a separate later obligation", guide)
        self.assertIn("No normal P2/project-picker qualification bit is enabled", guide)



def normal_cargo_fixture(target=None):
    target = target or Path("/synthetic-mrk-preview/cargo-target")
    binary = target / "aarch64-apple-darwin/release/mobile-release-kit-desktop"
    cargo_root = TOOL.DESKTOP / "src-tauri"
    artifact = {"reason": "compiler-artifact", "package_id": "path+" + cargo_root.as_uri() + "#mobile-release-kit-desktop@0.1.0",
        "manifest_path": str(cargo_root / "Cargo.toml"),
        "target": {"name": "mobile-release-kit-desktop", "kind": ["bin"], "crate_types": ["bin"],
                   "src_path": str(cargo_root / "src/main.rs")},
        "profile": {"opt_level": "3", "debug_assertions": False, "test": False},
        "features": ["custom-protocol", "desktop-shell"], "filenames": [str(binary)],
        "executable": str(binary), "fresh": False}
    body = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0) + struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
    return target, binary, artifact, body


def cargo_lines(*items):
    return b"".join(TOOL.canonical(item) + b"\n" for item in items)


@unittest.skipUnless(TOOL is not None, "POSIX DATA definitions only")
class MacNormalPreviewData(unittest.TestCase):
    def test_real_app_copy_preserves_signed_helper_mode_bytes_and_normal_binding(self):
        # Real isolated filesystem copy; the bounded synthetic Mach-O is DATA,
        # never executable signing/launch/Keychain qualification.
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(strict=True)
            target, binary, item, body = normal_cargo_fixture(work / "cargo-target")
            binary.parent.mkdir(parents=True, mode=0o700)
            binary.write_bytes(body)
            helper = work / "signed-helper-data"
            helper.write_bytes(body)
            helper.chmod(0o555)
            messages = cargo_lines(item, {"reason": "build-finished", "success": True})
            cargo = work / "cargo.jsonl"
            cargo.write_bytes(messages)
            originals = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                         for path in (binary, helper, cargo)}
            output = work / "Mobile Release Kit.app"
            result = TOOL.app_command(SimpleNamespace(binary=binary, output=output,
                normal_cargo_messages=cargo, normal_cargo_target_dir=target,
                vault_helper=helper, expected_vault_helper=TOOL.digest(body)))
            expected = {TOOL.APP_BINARY: (body, 0o755), TOOL.VAULT_HELPER: (body, 0o555),
                        "Contents/Info.plist": ((TOOL.DESKTOP / "macos-installed-inputs/Info.plist").read_bytes(), 0o644),
                        "Contents/PkgInfo": (b"APPL????", 0o644),
                        "Contents/Resources/icon.png": ((TOOL.DESKTOP / "src-tauri/icons/icon.png").read_bytes(), 0o644)}
            self.assertEqual(TOOL.tree(output), expected)
            self.assertEqual(result["vaultHelperSha256"], TOOL.digest(body))
            self.assertEqual(result["normalCargoArtifact"], TOOL.normal_cargo_artifact(messages, binary, target, body))
            for path, original in originals.items():
                self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), original)
            for path in (output, output / "Contents", output / "Contents/Helpers", output / "Contents/MacOS"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_app_copy_mode_exception_is_only_the_fixed_readonly_helper(self):
        cases = ((TOOL.VAULT_HELPER, 0o755), (TOOL.VAULT_HELPER, 0o644),
                 (TOOL.VAULT_HELPER, 0o444), ("Contents/Helpers/other", 0o555))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(strict=True)
            for number, (name, mode) in enumerate(cases):
                output = work / ("refused-" + str(number))
                with self.subTest(name=name, mode=mode), self.assertRaisesRegex(TOOL.Refused, "^output-mode$"):
                    TOOL.write_tree(output, {name: (b"inert-copy-data", mode)}, root_mode=0o755, app_signing=True)
                self.assertFalse((output / name).exists())

    def test_only_complete_normal_main_bin_receives_original_byte_binding(self):
        target, binary, item, body = normal_cargo_fixture()
        messages = cargo_lines(item, {"reason": "build-finished", "success": True})
        result = TOOL.normal_cargo_artifact(messages, binary, target, body)
        self.assertEqual(result["binarySha256"], TOOL.digest(body))
        self.assertEqual(result["cargoMessagesSha256"], TOOL.digest(messages))
        self.assertEqual(result["entrypoint"], "src/main.rs")
        self.assertFalse(result["profileTest"])
        self.assertFalse(result["instrumented"])
        self.assertEqual(result["qualification"], "ordinary-bin-data-not-launched")
        info = TOOL.plistlib.dumps({"CFBundleExecutable": binary.name, "LSMinimumSystemVersion": "26.0",
                                   "CFBundleIdentifier": TOOL.BUNDLE_ID, "CFBundleShortVersionString": TOOL.PACKAGE_VERSION,
                                   "CFBundleVersion": TOOL.PACKAGE_VERSION})
        values = {binary: body, Path("/synthetic-mrk-preview/helper"): body,
                  Path("/synthetic-mrk-preview/cargo.jsonl"): messages,
                  TOOL.DESKTOP / "macos-installed-inputs/Info.plist": info,
                  TOOL.DESKTOP / "src-tauri/icons/icon.png": b"synthetic-icon"}
        args = SimpleNamespace(binary=binary, output=Path("/synthetic-mrk-preview/app"),
            normal_cargo_messages=Path("/synthetic-mrk-preview/cargo.jsonl"), normal_cargo_target_dir=target,
            vault_helper=Path("/synthetic-mrk-preview/helper"), expected_vault_helper=TOOL.digest(body))
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                mock.patch.object(TOOL, "write_tree") as output:
            staged = TOOL.app_command(args)
        self.assertEqual(staged["normalCargoArtifact"], result)
        self.assertEqual(output.call_args.args[1][TOOL.APP_BINARY], (body, 0o755))
        self.assertEqual(output.call_args.args[1][TOOL.VAULT_HELPER], (body, 0o555))
        self.assertEqual(staged["vaultHelperSha256"], TOOL.digest(body))

    def test_test_targets_feature_drift_and_foreign_artifacts_never_stage(self):
        target, binary, original, body = normal_cargo_fixture()
        mutations = [
            ("target", "kind", ["test"]), ("target", "crate_types", ["lib"]),
            ("target", "src_path", str(TOOL.DESKTOP / "src-tauri/tests/installed_shell_observation.rs")),
            ("profile", "test", True), ("profile", "test", 0), ("profile", "debug_assertions", True),
            ("profile", "opt_level", "0"), (None, "features", ["desktop-shell"]),
            (None, "features", ["desktop-shell", "custom-protocol", "macos-installed-observation"]),
            (None, "features", ["custom-protocol", "desktop-shell", "desktop-shell"]),
            (None, "executable", str(target / "debug/mobile-release-kit-desktop")),
            (None, "filenames", [str(binary), str(target / "foreign")]),
            (None, "manifest_path", "/foreign/Cargo.toml"), (None, "package_id", "registry+foreign"),
            (None, "fresh", 1),
        ]
        for section, field, value in mutations:
            item = TOOL.decode(TOOL.canonical(original))
            (item if section is None else item[section])[field] = value
            messages = cargo_lines(item, {"reason": "build-finished", "success": True})
            with self.subTest(section=section, field=field, value=value), \
                    self.assertRaises(TOOL.Refused):
                TOOL.normal_cargo_artifact(messages, binary, target, body)

    def test_original_terminal_success_is_unique_and_not_a_log_hint(self):
        target, binary, item, body = normal_cargo_fixture()
        end = {"reason": "build-finished", "success": True}
        bad = [cargo_lines(item), cargo_lines(item, {"reason": "build-finished", "success": False}),
               cargo_lines(item, end, end), cargo_lines(item, item, end), cargo_lines(end),
               cargo_lines(item, end) + b"trailing\n", cargo_lines(item, end) + b"\n",
               cargo_lines(item) + b'{"reason":"build-finished","success":false,"success":true}\n',
               cargo_lines(item, {"reason": "build-finished", "success": 1})]
        for messages in bad:
            with self.subTest(messages=messages[-80:]), self.assertRaises((TOOL.Refused, ValueError)):
                TOOL.normal_cargo_artifact(messages, binary, target, body)
        with self.assertRaises(TOOL.Refused):
            TOOL.normal_cargo_artifact(cargo_lines(item, end), target / "debug" / binary.name, target, body)
        with self.assertRaises(TOOL.Refused):
            TOOL.normal_cargo_artifact(cargo_lines(item, end), binary, Path("relative"), body)

    def test_optional_gate_is_paired_and_failure_precedes_any_app_write(self):
        target, binary, item, body = normal_cargo_fixture()
        args = SimpleNamespace(binary=binary, output=Path("/synthetic-mrk-preview/app"),
            normal_cargo_messages=Path("/synthetic-mrk-preview/cargo.jsonl"), normal_cargo_target_dir=None,
            vault_helper=Path("/synthetic-mrk-preview/helper"), expected_vault_helper=TOOL.digest(body))
        with mock.patch.object(TOOL, "read", return_value=body), mock.patch.object(TOOL, "write_tree") as output:
            with self.assertRaises(TOOL.Refused):
                TOOL.app_command(args)
            output.assert_not_called()
        args.normal_cargo_target_dir = target
        item["profile"]["test"] = True
        messages = cargo_lines(item, {"reason": "build-finished", "success": True})
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: body if path in (binary, args.vault_helper) else messages), \
                mock.patch.object(TOOL, "write_tree") as output:
            with self.assertRaises(TOOL.Refused):
                TOOL.app_command(args)
            output.assert_not_called()


    def test_helper_loader_paths_are_closed_to_apple_systems_without_environment_or_rpath(self):
        # Bounded Mach-O DATA. This neither signs code nor substitutes for a
        # native dyld/installed-caller/Keychain admission result.
        build = struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
        def named(command, name, *, dylib=True):
            prefix = 24 if dylib else 12
            data = name + b"\0"
            length = (prefix + len(data) + 7) // 8 * 8
            header = struct.pack("<III", command, length, prefix)
            return header + b"\0" * (prefix - len(header)) + data + b"\0" * (length - prefix - len(data))
        def image(*commands):
            commands = (build, *commands)
            return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, len(commands),
                               sum(map(len, commands)), 0, 0) + b"".join(commands)
        good = named(0xC, b"/usr/lib/libSystem.B.dylib")
        TOOL.macho(image(good, named(0xE, b"/usr/lib/dyld", dylib=False)), system_only=True)
        refused = [named(0xC, b"@rpath/foreign.dylib"),
                   named(0xC, b"/Users/shared/foreign.dylib"),
                   named(0xC, b"/usr/lib/../foreign.dylib"),
                   named(0x8000001C, b"/usr/lib", dylib=False),
                   named(0x27, b"DYLD_LIBRARY_PATH=/tmp", dylib=False),
                   named(0xE, b"/tmp/dyld", dylib=False)]
        for command in refused:
            with self.subTest(command=command[:12]), self.assertRaises(TOOL.Refused):
                TOOL.macho(image(command), system_only=True)

    def test_changed_signed_helper_fails_before_any_app_write(self):
        target, binary, item, body = normal_cargo_fixture()
        args = SimpleNamespace(binary=binary, vault_helper=Path("/inert/helper"),
            expected_vault_helper="f" * 64, output=Path("/inert/output"))
        with mock.patch.object(TOOL, "read", return_value=body), mock.patch.object(TOOL, "write_tree") as output:
            with self.assertRaisesRegex(TOOL.Refused, "helper-final-signed-digest"):
                TOOL.app_command(args)
            output.assert_not_called()

    def test_installer_input_requires_the_same_helper_and_rejects_other_executables(self):
        _, _, _, body = normal_cargo_fixture()
        info = b"inert-info-data"
        args = SimpleNamespace(runtime=Path("/inert/runtime"), expected_manifest="c" * 64,
            current_runtime=True, app=Path("/inert/app"), expected_vault_helper=TOOL.digest(body),
            output=Path("/inert/output"))
        app = {TOOL.APP_BINARY: (body, 0o755), TOOL.VAULT_HELPER: (body, 0o555),
               "Contents/Info.plist": (info, 0o644), "Contents/_CodeSignature/CodeResources": (b"signature-data", 0o644)}
        runtime = {"python/bin/python3": (b"interpreter-data", 0o755)}
        with (mock.patch.object(TOOL, "runtime_tree", return_value=runtime),
              mock.patch.object(TOOL, "tree", return_value=app) as tree,
              mock.patch.object(TOOL, "read", return_value=info),
              mock.patch.object(TOOL, "write_tree") as output):
            TOOL.input_command(args)
            files = output.call_args.args[1]
            self.assertEqual(files["app/" + TOOL.VAULT_HELPER], (body, 0o555))
            for mutation, reason in (
                ({name: value for name, value in app.items() if name != TOOL.VAULT_HELPER}, "signed-app-roster"),
                ({**app, TOOL.VAULT_HELPER: (body + b"changed", 0o555)}, "nested-helper-signature-bytes-changed"),
                ({**app, "Contents/Helpers/foreign": (body, 0o555)}, "input-executable-scope"),
            ):
                output.reset_mock(); tree.return_value = mutation
                with self.subTest(reason=reason), self.assertRaisesRegex(TOOL.Refused, reason):
                    TOOL.input_command(args)
                output.assert_not_called()

    def test_helper_is_separate_signed_before_digest_bound_app_and_not_a_qualification(self):
        root = Path(__file__).absolute().parents[2]
        helper = (root / "desktop/helpers/macos-vault-helper/Cargo.toml").read_text()
        self.assertIn("[workspace]", helper)
        self.assertIn('features = ["vault-helper"]', helper)
        self.assertNotIn("tauri", helper.split("[dependencies]", 1)[1].lower())
        native = (root / "desktop/native/macos-installed-native/build.rs").read_text()
        self.assertIn("release: 1.98.1", native)
        self.assertIn("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985", native)
        library = (root / "desktop/src-tauri/src/lib.rs").read_text()
        self.assertIn("!mrk_macos_installed_native::VAULT_HELPER_BUILD", library)
        for name in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            workflow = (root / ".github/workflows" / name).read_text()
            build = workflow.index("--manifest-path desktop/helpers/macos-vault-helper/Cargo.toml")
            helper_sign = workflow.index('--timestamp=none "$helper"', build)
            digest = workflow.index('output.write("MRK_MACOS_VAULT_HELPER_SHA256=', helper_sign)
            stage = workflow.index("stage_macos_installed.py app", digest)
            app_sign = workflow.index('--timestamp=none "$MRK_MACOS_WORK/app/Mobile Release Kit.app"', stage)
            self.assertLess(build, helper_sign); self.assertLess(helper_sign, digest)
            self.assertLess(digest, stage); self.assertLess(stage, app_sign)
            self.assertIn('RUSTUP_TOOLCHAIN: "1.98.1"', workflow)
            self.assertEqual(workflow.count("--options runtime"), 2)
            self.assertEqual(workflow.count("--entitlements desktop/packaging/macos-empty-entitlements.plist"), 2)
            self.assertEqual(workflow.count('--expected-vault-helper "$MRK_MACOS_VAULT_HELPER_SHA256"'), 2)
            # Prohibition text may mention --deep. Inspect only the real shell
            #signing commands, folding their continued arguments without execution.
            commands = workflow.replace('\\\n', " ").splitlines()
            signing = [shlex.split(line, comments=True) for line in commands
                       if line.lstrip().startswith("/usr/bin/codesign ") and "--sign " in line]
            self.assertTrue(signing)
            for command in signing:
                self.assertNotIn("--deep", command)
        self.assertIn("DURABLE_QUALIFIED: bool = false",
                      (root / "desktop/src-tauri/src/asset_session_vault.rs").read_text())

    def preview_fixture(self):
        work = Path("/synthetic-mrk-preview")
        target, binary, item, body = normal_cargo_fixture(work / "cargo-target")
        messages = cargo_lines(item, {"reason": "build-finished", "success": True})
        normal = TOOL.normal_cargo_artifact(messages, binary, target, body)
        binding = {"source": "a" * 40, "workflowSource": "a" * 40, "tree": "b" * 40,
            "scope": "normal-macos-early-preview", "instrumented": False, "runId": "123", "runAttempt": "1",
            "runtimeManifestSha256": "c" * 64}
        observed = {"sourceCommit": "a" * 40, "installerDeadlineMetAfterFinalCloses": True,
            "installerReportedOriginalsSettled": True, "applicationLaunched": False, "guiSaveQualified": False,
            "runtimeManifestSha256": "c" * 64, "inventorySha256": "d" * 64, "nonrootReadbackFileCount": 1,
             "originalInstallerResult": original_result((None, "confirmed", "confirmed", "installed", True, 0)),
            "installationMetadata": {"state": "recorded-current-data-correspondence", "instance": "d" * 32,
                "inventoryBytes": 6, "descriptorBytes": 4, "originalFinality": "separate-Installer-status"}}
        package = b"synthetic-package-DATA-not-native-Installer-evidence"
        values = {work / "normal-build.jsonl": messages, binary: body,
            work / "normal-build.status": b"0\n", work / "installer-output.status": b"0\n",
            work / "package-final/MobileReleaseKit.pkg": package,
            TOOL.DESKTOP / "packaging/macos-preview.md": b"# Synthetic preview guide\n"}
        documents = {"source-binding.json": binding, "source-inventory.json": {"source": "a" * 40, "tree": "b" * 40},
            "app-result.json": {"normalCargoArtifact": normal, "appBinarySha256BeforeSigning": TOOL.digest(body)},
            "installation-observation.json": observed,
            "package-audit.json": {"packageSha256": TOOL.digest(package), "packageSize": len(package),
                "packageIdentifier": "dev.mobile-release-kit.desktop.installed",
                "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}}
        values.update({work / name: TOOL.canonical(value) for name, value in documents.items()})
        expected = {"app/" + TOOL.APP_BINARY: {"sha256": "e" * 64}}
        return work, values, documents, expected

    def test_preview_roster_has_no_raw_evidence_and_keeps_open_and_quit_unexecuted(self):
        work, values, documents, expected = self.preview_fixture()
        args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40)
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                mock.patch.object(TOOL, "bound_original_result") as original, \
                mock.patch.object(TOOL, "observation_inventory", return_value=expected), \
                mock.patch.object(TOOL, "write_tree") as output:
            result = TOOL.preview_command(args)
        original.assert_called_once_with(documents["installation-observation.json"]["originalInstallerResult"],
            (None, "confirmed", "confirmed", "installed", True, 0), "a" * 40, "d" * 64, "c" * 64)
        files = output.call_args.args[1]
        self.assertEqual(set(files), {"MobileReleaseKit.pkg", "README.md", "PREVIEW.json"})
        self.assertEqual(files["MobileReleaseKit.pkg"], (values[work / "package-final/MobileReleaseKit.pkg"], 0o444))
        summary = TOOL.decode(files["PREVIEW.json"][0])
        self.assertEqual(summary["automaticWindowOpen"], "unexecuted")
        self.assertEqual(summary["normalQuit"], "unexecuted")
        self.assertEqual(summary["manualUIAcceptance"], "pending")
        self.assertFalse(summary["fullUIQualified"])
        self.assertFalse(summary["distributionQualified"])
        self.assertFalse(summary["productReady"])
        self.assertEqual(result["fileCount"], 3)

    def test_failed_original_status_changed_package_or_unsettled_readback_cannot_publish(self):
        failures = [
            ("normal-build.status", None, b"1\n"), ("installer-output.status", None, b"20\n"),
            ("source-binding.json", "instrumented", True), ("source-inventory.json", "tree", "f" * 40),
            ("app-result.json", "appBinarySha256BeforeSigning", "f" * 64),
            ("installation-observation.json", "installerDeadlineMetAfterFinalCloses", False),
            ("installation-observation.json", "installationMetadata", None),
            ("installation-observation.json", "installationMetadata", {"state": "incomplete"}),
            ("installation-observation.json", "installerReportedOriginalsSettled", False),
            ("installation-observation.json", "runtimeManifestSha256", "f" * 64),
            ("installation-observation.json", "nonrootReadbackFileCount", 2),
            ("package-audit.json", "packageSha256", "f" * 64),
        ]
        for name, field, value in failures:
            work, values, documents, expected = self.preview_fixture()
            if field is None:
                values[work / name] = value
            else:
                documents[name][field] = value
                values[work / name] = TOOL.canonical(documents[name])
            args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40)
            with self.subTest(name=name, field=field), \
                    mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                    mock.patch.object(TOOL, "bound_original_result"), \
                    mock.patch.object(TOOL, "observation_inventory", return_value=expected), \
                    mock.patch.object(TOOL, "write_tree") as output:
                with self.assertRaises(TOOL.Refused):
                    TOOL.preview_command(args)
                output.assert_not_called()

    def test_same_xctrunner_diagnostic_keeps_account_policy_and_cannot_launch_product(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-ui-host.yml").read_text()
        swift = (root / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        project = (root / "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj/project.pbxproj").read_text()
        self.assertIn("branches: [verify/desktop-macos-ui-host]", workflow)
        for required in ("runs-on: macos-26", "contents: read", "persist-credentials: false",
                         '"$RUNNER_ENVIRONMENT" == github-hosted', '"$RUNNER_ARCH" == ARM64',
                         '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"', "-project desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj",
                         "-configuration Debug -destination 'platform=macOS,arch=arm64'", "/usr/bin/env -i",
                         "-parallel-testing-enabled NO", "-maximum-test-execution-time-allowance 60",
                         "--display --entitlements :-", '"productQualified": False',
                         'counts["totalTestCount"] != 1', 'counts["skippedTests"] != 0',
                         "exit \"$status\"", "!cancelled() && steps.native_test.outputs.returned == 'true'"):
            self.assertIn(required, workflow)
        self.assertEqual(workflow.count("-only-testing:"), 1)
        self.assertIn("-only-testing:MRKNormalAppUITests/NormalAppUITests/testHostedAccountAdmissionOnly", workflow)
        for forbidden in ("testLaunchCancelAndQuit", "testProject", "cargo ", "npm ", "installer ",
                          "continue-on-error:", "-retry-tests-on-failure", "-test-iterations", "workflow_dispatch:",
                          "tccutil", "killall", "pkill", "sudo "):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("ENABLE_APP_SANDBOX = NO;", project)  # Existing policy, not a new workaround.
        admission = swift.split("private func admitHostedAccount() throws -> HostedAccount {", 1)[1].split("// SAME generated", 1)[0]
        for required in ('context["MRK_NORMAL_UI_HOSTED_JOB"] == "github-hosted-macos26-arm64"',
                         "require(nonroot && sameUid && sameGid", "version.majorVersion == 26",
                         'NSUserName() == "runner"', 'NSHomeDirectory() == "/Users/runner"',
                         "applicationSource.utf8.count == 40", "applicationSource == harnessSource",
                         "require(runnerName,", "try hostedAccountRecord()", "MRK_MACOS_UI_HOST_FACTS="):
            self.assertIn(required, admission)
        self.assertNotIn("require(fixedHome,", admission)
        account = swift.split("private func hostedAccountRecord() throws -> HostedAccount {", 1)[1].split(
            "private func admitHostedAccount()", 1)[0]
        for required in ("count: 64 * 1024", "getpwuid_r(uid, entry, buffer.baseAddress!, buffer.count, &result)",
                         "lookupSucceeded && result == entry", "guard originalRecord else { return }",
                         "entry.pointee.pw_uid == uid", "entry.pointee.pw_gid == gid",
                         'accountFieldMatches(entry.pointee.pw_name, "runner", buffer: buffer)',
                         'accountFieldMatches(entry.pointee.pw_dir, "/Users/runner", buffer: buffer)',
                         "lookupSucceeded && originalRecord && uidMatches && gidMatches && nameMatches && homeMatches",
                         'HostedAccount(name: "runner", home: "/Users/runner")'):
            self.assertIn(required, account)
        for forbidden in ("pw_passwd", "pw_gecos", "String(cString:", "setenv(", "unsetenv("):
            self.assertNotIn(forbidden, account)
        field = swift.split("private func accountFieldMatches(", 1)[1].split("private func hostedAccountRecord()", 1)[0]
        self.assertIn("UInt(bytes.count) < UInt(buffer.count) - (address - start)", field)
        self.assertIn("buffer[offset + bytes.count] == 0", field)
        environments = [block.split("\n        ]", 1)[0] for block in swift.split("app.launchEnvironment = [\n")[1:]]
        self.assertEqual(len(environments), 2)
        for environment in environments:
            self.assertIn('"HOME": account.home, "USER": account.name, "LOGNAME": account.name', environment)
            for forbidden in ("NSHomeDirectory", "NSTemporaryDirectory", "TMPDIR", "CFFIXED_USER_HOME"):
                self.assertNotIn(forbidden, environment)
        diagnostic = swift.split("func testHostedAccountAdmissionOnly() throws {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("try admitHostedAccount()", diagnostic)
        for forbidden in ("XCUIApplication", "LocalFixture", "launchForJourney", "launchedApplication =", "app.launch", "URL("):
            self.assertNotIn(forbidden, diagnostic)
        # Both ordinary journeys retain the same shared guard before app construction.
        self.assertEqual(swift.count("try admitHostedAccount()"), 3)
        for name in ("func testLaunchCancelAndQuit() throws {", "private func launchForJourney() throws"):
            body = swift.split(name, 1)[1]
            self.assertLess(body.index("try admitHostedAccount()"), body.index("XCUIApplication(url:"))

    def test_preview_route_targets_only_unrelated_groups_and_retains_package_gates(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text()
        selected = {block.splitlines()[0].strip() for block in workflow.split("      - name: ")[1:]
                    if "if: github.ref == 'refs/heads/verify/desktop-macos-installed'" in block}
        self.assertEqual(selected, {
            "Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive",
            "Run only the five reviewed nonroot regressions (exact groups 2, 1, 2)"})
        self.assertIn("      - verify/desktop-macos-preview\n", workflow)
        self.assertIn("--message-format=json", workflow)
        self.assertIn('--normal-cargo-messages "$MRK_MACOS_WORK/normal-build.jsonl"', workflow)
        self.assertIn('--normal-cargo-target-dir "$CARGO_TARGET_DIR"', workflow)
        for name in ("Fail fast on native Scripts ownership and package format (never Installer)",
                     "Build the separate fixed eight-case Installer package from the same completed input",
                     "Standard Installer runs the one fixed fixture, never root libtest or a scenario selector",
                     "Nonroot fixture readback leaves protected0700 staging closed and unchanged",
                     "Build the fixed one-shot root Installer and scripts-only package",
                     "Nonroot byte/mode readback, not a headless GUI substitute"):
            block = workflow.split("      - name: " + name + "\n", 1)[1].split("      - name: ", 1)[0]
            self.assertNotIn("if:", block)
        fixture_steps = (
            "Bind this completed signed app and current-source runtime into fresh Installer DATA",
            "Build the separate fixed eight-case Installer package from the same completed input",
            "Standard Installer runs the one fixed fixture, never root libtest or a scenario selector",
            "Nonroot fixture readback leaves protected0700 staging closed and unchanged",
            "Build the fixed one-shot root Installer and scripts-only package")
        positions = [workflow.index("      - name: " + name + "\n") for name in fixture_steps]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(workflow.count('"fixedFixtureCases": 8'), 2)
        self.assertNotIn('"fixedFixtureCases": 0', workflow)
        self.assertLess(workflow.index("observe-installation"), workflow.index("stage_macos_installed.py preview"))
        publish = workflow.split("      - name: Upload only the normal user preview package and guide\n", 1)[1].split("      - name: ", 1)[0]
        self.assertIn("steps.preview.outcome == 'success'", publish)
        self.assertIn("/preview/MobileReleaseKit.pkg", publish)
        self.assertIn("/preview/README.md", publish)
        self.assertIn("/preview/PREVIEW.json", publish)
        self.assertNotIn("**", publish)
        # Observer DATA is independently compiled, never the preview app input.
        for block in normal_app_steps(workflow):
            self.assertNotIn("macos-installed-observation", block)
        for forbidden in ("continue-on-error:", "normal_app_launch_probe", "forceTerminate", "/usr/bin/open ",
                          "workflow_dispatch:"):
            self.assertFalse(forbidden in workflow, forbidden)
        normal_test_name = "Launch the exact ordinary app, Cancel its real Quit sheet, then Quit normally"
        normal_test = workflow_step(workflow, normal_test_name)
        normal_result = workflow_step(workflow, "Preserve original XCTest counts and a closed UI-only result, never a clean-exit claim")
        self.assertLess(workflow.index("stage_macos_installed.py preview"),
                        workflow.index("      - name: " + normal_test_name + "\n"))
        self.assertIn("-only-testing:MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit", normal_test)
        self.assertIn('"cleanExitStatus": None, "allWorkerFinality": "not-established-by-XCTest-UI-state"', normal_result)
        self.assertIn('"fullUIQualified": False, "distributionQualified": False, "productReady": False', normal_result)
        guide = " ".join((root / "desktop/packaging/macos-preview.md").read_text().split())
        for required in ("package-export receipt is intentionally a **build/Installer/readback snapshot**",
                         "automatic-open and normal-Quit fields remain unexecuted at that stage",
                         "same hosted job subsequently runs one external XCTest scenario",
                         "normal-ui/result.json", "A missing, failed or skipped check is not a pass",
                         "does not prove POSIX exit status or every worker's finality",
                         "Gatekeeper", "Do not disable", "NOT READY / undelivered",
                         "fixed eight-case Installer fixture before ordinary install",
                         "project-relative field-picker journeys", "No Store mutation",
                         "project-field Aqua observer failure is preserved and unresolved"):
            self.assertIn(required, guide)


if __name__ == "__main__":
    unittest.main()
