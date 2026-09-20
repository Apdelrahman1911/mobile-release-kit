"""Inert publisher CI contract tests; no compiler, process or native operation."""
from copy import deepcopy
import hashlib
import importlib.util
import io
from pathlib import Path
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("publisher_ci", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def elf_data(extra_tag=None, *, definitions=False):
    """A small structural ELF fixture with no executable program body."""
    raw = bytearray(1536)
    strings = b"\0libc.so.6\0GLIBC_2.34\0"
    interpreter = b"/lib64/ld-linux-x86-64.so.2\0"
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    dynamic = [(1, 1), (5, 1024), (10, len(strings)),
               (0x6ffffffe, 1152), (0x6fffffff, 1)]
    if definitions:
        dynamic += [(0x6ffffffc, 1280), (0x6ffffffd, 1)]
    if extra_tag is not None:
        dynamic.append((extra_tag, 1))
    dynamic.append((0, 0))
    for index, values in enumerate((
        (1, 4, 0, 0, 0, len(raw), len(raw), 4096),
        (3, 4, 512, 512, 512, len(interpreter), len(interpreter), 1),
        (2, 4, 640, 640, 640, len(dynamic) * 16, len(dynamic) * 16, 8),
    )):
        struct.pack_into("<IIQQQQQQ", raw, 64 + 56 * index, *values)
    raw[512:512 + len(interpreter)] = interpreter
    for index, pair in enumerate(dynamic):
        struct.pack_into("<qQ", raw, 640 + 16 * index, *pair)
    raw[1024:1024 + len(strings)] = strings
    struct.pack_into("<HHIII", raw, 1152, 1, 1, 1, 16, 0)
    struct.pack_into("<IHHII", raw, 1168, 0, 0, 2, 11, 0)
    if definitions:
        struct.pack_into("<HHHHIII", raw, 1280, 1, 0, 2, 1, 0, 20, 0)
        struct.pack_into("<II", raw, 1300, 11, 0)
    return bytes(raw)


def package_rows(files):
    rows = {".": {"type": "directory", "mode": 0o755}}
    for name, raw in files.items():
        for parent in reversed(Path(name).parents):
            if parent.as_posix() != ".":
                rows[parent.as_posix()] = {"type": "directory", "mode": 0o755}
        rows[name] = {"type": "file", "mode": 0o644, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()}
    return rows


def package_data(data_files, control_files, *, mutate=None, trailing=False, tar_format=tarfile.USTAR_FORMAT):
    """Construct inert, uncompressed .deb DATA; never call a packaging tool."""
    members = [("debian-binary", b"2.0\n")]
    for archive, files in (("control.tar", control_files), ("data.tar", data_files)):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tar_format) as writer:
            for name, row in package_rows(files).items():
                info = tarfile.TarInfo("./" if name == "." else "./" + name)
                info.mode = row["mode"]
                info.type = tarfile.DIRTYPE if row["type"] == "directory" else tarfile.REGTYPE
                raw = b"" if info.isdir() else files[name]
                info.size = len(raw)
                if mutate is not None:
                    info, raw = mutate(archive, name, info, raw)
                if info is not None:
                    writer.addfile(info, None if info.isdir() else io.BytesIO(raw))
        raw = output.getvalue()
        if trailing and archive == "data.tar":
            raw += b"unaccounted trailing data"
        members.append((archive, raw))
    result = bytearray(b"!<arch>\n")
    for name, raw in members:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(raw):<10}" + chr(96) + "\n"
        result.extend(header.encode("ascii"))
        result.extend(raw)
        if len(raw) % 2:
            result.extend(b"\n")
    return bytes(result)


class PublisherCI(unittest.TestCase):
    def test_ubuntu_supplier_notice_inventory_and_exact_packages(self):
        root = SOURCE / "desktop/packaging/debian/native-notices"
        raw = S.D.read(root / "inputs.json", 1 << 20)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), S.NOTICE_INPUTS_SHA256)
        admitted = S.D.decode(raw, 1 << 20)
        rows = S.D.records(admitted["files"])
        S.C.conventional_files(S.D, root, sorted(
            [*rows.values(), S.D.file_record(root / "inputs.json")], key=lambda row: row["path"]))
        real_open = S.D._open

        def notice_only(path, limit):
            self.assertTrue(path.is_relative_to(root), "Notice lookup touched live host files")
            return real_open(path, limit)

        observed = {}
        with patch.object(S.D, "_open", side_effect=notice_only), \
             patch.object(S, "protected_host_file", side_effect=AssertionError("Live OS notice lookup")):
            for name, expected in admitted["ubuntu"]["packages"].items():
                actual = {key: expected[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion")}
                actual["binaryPackage"] = name + ":amd64"
                owned = {"/" + row["path"] for row in expected["ownedDocumentation"]}
                observed[name] = S.ubuntu_package_notice(admitted, rows, root, actual, owned)
                self.assertEqual(observed[name]["source"], "reviewed-ubuntu-package-member-data")
                self.assertEqual(observed[name]["packageArchive"], expected["archive"])
        self.assertEqual(len(observed), 11)
        self.assertEqual(observed["gcc-13-x86-64-linux-gnu"]["documentationPackages"], ["gcc-13-base"])
        self.assertEqual(observed["libgcc-s1"]["documentationPackages"], ["gcc-14-base"])
        self.assertEqual(observed["binutils-x86-64-linux-gnu"]["documentationPackages"], ["libbinutils", "binutils-common"])
        self.assertEqual(observed["libbinutils"]["documentationPackages"], ["binutils-common"])
        self.assertEqual(observed["libc6"]["documentationPackages"], [])
        for alias, target in (("GPL", "GPL-3"), ("LGPL", "LGPL-3"), ("GFDL", "GFDL-1.3")):
            row = admitted["ubuntu"]["commonLicenses"][alias]
            self.assertEqual(row["alias"]["target"], target)
            self.assertEqual(row["member"]["path"], "usr/share/common-licenses/" + target)

    def test_ubuntu_supplier_notices_refuse_tuple_roster_reference_and_byte_changes(self):
        root = SOURCE / "desktop/packaging/debian/native-notices"
        admitted = S.D.decode(S.D.read(root / "inputs.json", 1 << 20), 1 << 20)
        rows = S.D.records(admitted["files"])
        name = "gcc-13-x86-64-linux-gnu"
        expected = admitted["ubuntu"]["packages"][name]
        actual = {key: expected[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion")}
        actual["binaryPackage"] = name
        owned = {"/" + row["path"] for row in expected["ownedDocumentation"]}
        with patch.object(S, "protected_host_file", side_effect=AssertionError("Live OS notice lookup")):
            for key in ("version", "architecture", "sourcePackage", "sourceVersion"):
                with self.subTest(changed=key), self.assertRaisesRegex(S.D.Refused, "package tuple differs"):
                    S.ubuntu_package_notice(admitted, rows, root, {**actual, key: "other"}, owned)
            with self.assertRaisesRegex(S.D.Refused, "No reviewed Ubuntu notice mapping"):
                S.ubuntu_package_notice(admitted, rows, root, {**actual, "binaryPackage": "other"}, owned)
            with self.assertRaisesRegex(S.D.Refused, "documentation roster differs"):
                S.ubuntu_package_notice(admitted, rows, root, actual, set())
            missing = deepcopy(admitted)
            del missing["ubuntu"]["commonLicenses"]["GPL"]
            with self.assertRaisesRegex(S.D.Refused, "Missing reviewed Ubuntu common license GPL"):
                S.ubuntu_package_notice(missing, rows, root, actual, owned)
            with tempfile.TemporaryDirectory(prefix="mrk-supplier-notice-data-") as name:
                temporary = Path(name)
                target = temporary / expected["copyright"]["noticePath"]
                target.parent.mkdir(parents=True)
                target.write_bytes(b"Not the original Ubuntu copyright.\n")
                with self.assertRaisesRegex(S.D.Refused, "original copyright bytes differ"):
                    S.ubuntu_package_notice(admitted, rows, temporary, actual, owned)

    def test_native_notice_diagnostic_traces_strict_refusal_and_never_continues(self):
        selected = Path("/usr/share/doc/gcc-13-x86-64-linux-gnu/copyright")
        alias = selected.parent
        copyright = Path("/usr/share/doc/gcc-13-base/copyright")
        common = Path("/usr/share/common-licenses/GPL-3")
        bodies = {copyright: b"Inert /usr/share/common-licenses/GPL-3.\n/usr/share/common-licenses/GPL-3\n",
                  common: b"Inert common-license DATA; never executed.\n"}
        real_lstat, real_resolve, real_readlink = Path.lstat, Path.resolve, os.readlink
        real_read, real_record = S.D.read, S.D.file_record
        stop = "Diagnostic-only native notice observation ended; no lifecycle continuation was requested"
        ancestry_refusal = "Native OS input has nonordinary/writable/special ancestry"
        cases = (("copyright-writable", copyright, stat.S_IFREG | 0o664, 0, ancestry_refusal),
                 ("common-writable", common, stat.S_IFREG | 0o664, 0, ancestry_refusal),
                 ("common-directory", common, stat.S_IFDIR | 0o755, 0, ancestry_refusal),
                 ("common-owner", common, stat.S_IFREG | 0o644, 1001, "Native OS input has a nonroot owner"),
                 ("all-protected", None, stat.S_IFREG | 0o644, 0, None))
        for label, rejected, mode, uid, reason in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="mrk-notice-diagnostic-data-") as name:
                root = Path(name)
                (root / "public").mkdir()
                preparation = {"deadline": "1100.0", "sourceSha": "a" * 40, "runId": "10", "attempt": "1",
                               "runnerUid": 1001, "runnerGid": 1001}
                (root / "preparation.json").write_bytes(S.D.canonical(preparation))
                nodes = {}
                for index, path in enumerate((Path("/"), Path("/usr"), Path("/usr/share"),
                                              Path("/usr/share/doc"), copyright.parent, common.parent,
                                              alias, copyright, common)):
                    kind = stat.S_IFLNK | 0o777 if path == alias else (
                        stat.S_IFREG | 0o644 if path in bodies else stat.S_IFDIR | 0o755)
                    nodes[path] = SimpleNamespace(st_dev=1, st_ino=index + 1, st_mode=kind,
                        st_uid=0, st_gid=0, st_nlink=1, st_size=len(bodies.get(path, b"")),
                        st_mtime_ns=1, st_ctime_ns=1)
                if rejected is not None:
                    nodes[rejected].st_mode, nodes[rejected].st_uid = mode, uid
                records, reads = [], []

                def virtual(path):
                    return path == Path("/") or path.is_relative_to("/usr")

                def lstat(path, *args, **kwargs):
                    if virtual(path):
                        self.assertIn(path, nodes, "Unexpected native diagnostic path")
                        return nodes[path]
                    return real_lstat(path, *args, **kwargs)

                def resolve(path, *args, **kwargs):
                    if virtual(path):
                        return copyright if path == selected else path
                    return real_resolve(path, *args, **kwargs)

                def readlink(path, *args, **kwargs):
                    if virtual(Path(path)):
                        self.assertEqual(Path(path), alias)
                        return "gcc-13-base"
                    return real_readlink(path, *args, **kwargs)

                def file_record(path, limit=S.D.MAX_ARCHIVE):
                    if virtual(path):
                        self.assertIn(path, bodies)
                        self.assertLessEqual(len(bodies[path]), limit)
                        records.append((path, limit))
                        return {"path": path.name, "size": len(bodies[path]),
                                "sha256": hashlib.sha256(bodies[path]).hexdigest()}
                    return real_record(path, limit)

                def read(path, limit=32 << 20):
                    if virtual(path):
                        self.assertEqual(path, copyright)
                        self.assertIn((copyright, 2 << 20), records, "References read before protected admission")
                        self.assertLessEqual(len(bodies[path]), limit)
                        reads.append(path)
                        return bodies[path]
                    return real_read(path, limit)

                with patch.object(Path, "lstat", lstat), patch.object(Path, "resolve", resolve), \
                     patch.object(S.os, "readlink", readlink), patch.object(S.D, "file_record", file_record), \
                     patch.object(S.D, "read", read), patch.object(S.time, "monotonic", return_value=100), \
                     patch.object(S.os, "uname", return_value=SimpleNamespace(sysname="Linux", machine="x86_64",
                                  release="mock-kernel", version="mock-version")), \
                     patch.dict(S.os.environ, {"ImageOS": "ubuntu24", "ImageVersion": "mock-image"}), \
                     patch.object(S.sys, "argv", ["ci_ubuntu_publication.py", "diagnose-native-notices"]), \
                     patch.object(S, "prepare", return_value=root) as prepare, \
                     patch.object(S, "verify", side_effect=AssertionError("Lifecycle continuation")) as verify, \
                     patch.object(S, "Check", side_effect=AssertionError("Command owner setup")) as check, \
                     patch.object(S, "local", side_effect=AssertionError("Lifecycle import")) as local:
                    with self.assertRaises(S.D.Refused) as stopped:
                        S.main()
                    self.assertEqual(str(stopped.exception), stop)
                    prepare.assert_called_once_with()
                    verify.assert_not_called()
                    check.assert_not_called()
                    local.assert_not_called()
                raw = (root / "public/native-notice-diagnostic.json").read_bytes()
                report = S.D.decode(raw, 128 << 10)
                self.assertTrue(report["dataOnly"])
                self.assertFalse(report["qualified"])
                self.assertEqual({key: report[key] for key in preparation if key != "deadline"},
                                 {key: value for key, value in preparation.items() if key != "deadline"})
                self.assertEqual(report["originalDeadline"], preparation["deadline"])
                self.assertEqual(report["imageVersion"], "mock-image")
                self.assertEqual(report["kernel"]["release"], "mock-kernel")
                self.assertLessEqual(len(report["trace"]), 256)
                link = next(row for row in report["trace"] if row["operation"] == "readlink")
                self.assertEqual((link["selectedPath"], link["candidate"], link["expectedType"], link["linkTarget"]),
                                 (str(selected), str(alias), "directory", "gcc-13-base"))
                if rejected is not None:
                    failed = report["paths"][-1]
                    self.assertFalse(failed["checked"])
                    self.assertEqual(failed["reason"], reason)
                    last = report["trace"][-1]
                    self.assertEqual(last["selectedPath"], str(selected if rejected == copyright else common))
                    self.assertEqual((last["candidate"], last["component"], last["expectedType"],
                                      last["mode"], last["fileType"], last["permissions"], last["uid"], last["gid"]),
                                     (str(rejected), rejected.name, "file", mode, stat.S_IFMT(mode),
                                      stat.S_IMODE(mode), uid, 0))
                else:
                    self.assertTrue(all(row["checked"] for row in report["paths"]))
                    self.assertEqual(records, [(copyright, 2 << 20), (common, 256 << 10)])
                if rejected == copyright:
                    self.assertFalse(report["references"]["derived"])
                    self.assertEqual(report["references"]["names"], [])
                    self.assertEqual((records, reads), ([], []))
                    self.assertEqual([row["selectedPath"] for row in report["paths"]], [str(selected)])
                else:
                    self.assertEqual(report["references"], {"derived": True, "names": ["GPL-3"]})
                    self.assertEqual(reads, [copyright])
                    self.assertEqual([row["selectedPath"] for row in report["paths"]], [str(selected), str(common)])

    def test_fixed_route_and_compiler_profiles(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.REF,
               "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
               "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        self.assertEqual(S.route(env), "a" * 40)
        for key, value in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_REF", "refs/heads/main"),
                           ("RUNNER_ENVIRONMENT", "self-hosted"), ("MRK_PUSH_EVENT_AFTER", "b" * 40)):
            with self.subTest(field=key), self.assertRaises(ValueError):
                S.route({**env, key: value})
        for library in (False, True):
            argv = S.compile_argv("/tools/cargo", Path("/source"), Path("/target"), library=library)
            self.assertEqual(argv[:2], ["/tools/cargo", "test" if library else "build"])
            self.assertIn("--offline", argv)
            self.assertIn("--locked", argv)
            self.assertEqual(argv[argv.index("--features") + 1], "ubuntu-runtime-publisher")
            self.assertNotIn("development-runtime", argv)
            self.assertEqual("--no-run" in argv, library)

    def test_only_exact_fresh_compiler_artifact_is_selected(self):
        source, root = Path("/source"), Path("/target")
        for library in (False, True):
            executable = root / S.TARGET / ("debug/deps/mobile_release_desktop-0123456789abcdef" if library else "release/mrk-runtime-publish")
            row = {"reason": "compiler-artifact", "executable": str(executable), "fresh": False,
                   "features": S.FEATURES, "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
                   "target": {"kind": ["lib" if library else "bin"], "name": "mobile_release_desktop" if library else "mrk-runtime-publish",
                              "src_path": str(source / "desktop/src-tauri/src" / ("lib.rs" if library else "bin/runtime_publish.rs"))},
                   "profile": {"test": library, "debug_assertions": library, "opt_level": "0" if library else "3"}}
            final = {"reason": "build-finished", "success": True}
            raw = S.D.canonical(row) + S.D.canonical(final)
            self.assertEqual(S.compiled_artifact(raw, source, root, library=library), executable)
            for key, value in (("fresh", True), ("features", []), ("executable", "/different/binary")):
                changed = deepcopy(row)
                changed[key] = value
                with self.subTest(library=library, field=key), self.assertRaises(ValueError):
                    S.compiled_artifact(S.D.canonical(changed) + S.D.canonical(final), source, root, library=library)
            for changed in (S.D.canonical(final), raw + S.D.canonical(final), S.D.canonical(row) * 2 + S.D.canonical(final)):
                with self.assertRaises(ValueError):
                    S.compiled_artifact(changed, source, root, library=library)

    def test_zero_partial_extra_or_failed_tests_are_not_a_pass(self):
        lines = ["running 11 tests", *(f"test {name} ... ok" for name in S.TESTS),
                 "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s"]
        raw = ("\n".join(lines) + "\n").encode("ascii")
        S.test_result(raw, b"")
        for changed in (b"running 0 tests\n", raw.replace(lines[1].encode() + b"\n", b""),
                        raw.replace(b" ... ok", b" ... FAILED", 1), raw + b"test unexpected ... ok\n"):
            with self.assertRaises(ValueError):
                S.test_result(changed, b"")
        with self.assertRaises(ValueError):
            S.test_result(raw, b"unexpected diagnostic")

    def test_single_native_selection_requires_one_actual_exact_pass(self):
        name = "installed_runtime::pure_tests::kernel_scope_is_reviewed_ubuntu"
        self.assertEqual(S.KERNEL_SELECTOR, name)
        raw = ("running 1 test\n"
               f"test {name} ... ok\n"
               "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
               "99 filtered out; finished in 0.01s\n").encode("ascii")
        S.exact_test_result(raw, b"", name)
        for changed in (b"running 0 tests\n", raw.replace(name.encode(), b"different::test"),
                        raw.replace(b" ... ok", b" ... ignored"),
                        raw.replace(b"1 passed; 0 failed", b"0 passed; 1 failed"),
                        raw.replace(b"0 ignored", b"1 ignored"),
                        raw + f"test {name} ... ok\n".encode("ascii")):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                S.exact_test_result(changed, b"", name)
        with self.assertRaises(ValueError):
            S.exact_test_result(raw, b"unexpected diagnostic", name)

    def test_elf_dependency_reader_rejects_loader_overrides_and_out_of_bounds(self):
        observed = S.elf_dependencies(elf_data())
        self.assertEqual(observed["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(observed["needed"], ["libc.so.6"])
        self.assertEqual(observed["versionNeeds"], {"libc.so.6": ["GLIBC_2.34"]})
        self.assertEqual(S.elf_dependencies(elf_data(definitions=True))["versionDefinitions"], ["GLIBC_2.34"])
        for tag in (15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                S.elf_dependencies(elf_data(tag))
        for raw in (elf_data()[:1100], b"inert non-ELF data", elf_data().replace(b"GLIBC_2.34\0", b"GLIBC_2.34x")):
            with self.assertRaises(ValueError):
                S.elf_dependencies(raw)
        outside = bytearray(elf_data())
        struct.pack_into("<Q", outside, 640 + 16 + 8, 1 << 60)
        with self.assertRaises(ValueError):
            S.elf_dependencies(bytes(outside))

    def test_complete_deb_readback_rejects_changed_unowned_or_hidden_members(self):
        files, controls = {"usr/share/inert": b"DATA"}, {"control": b"Package: inert-fixture\n"}
        expected, expected_control = package_rows(files), package_rows(controls)
        with tempfile.TemporaryDirectory(prefix="mrk-deb-readback-data-") as name:
            path = Path(name) / "fixture.deb"
            path.write_bytes(package_data(files, controls))
            S.deb_readback(path, expected, expected_control)
            # Real manifest-addressed package paths require GNU long-name DATA.
            long_name = "usr/lib/mobile-release-kit/runtime-input/" + "a" * 64 + "/python/bin/python3"
            long_files = {long_name: b"inert long-name payload"}
            path.write_bytes(package_data(long_files, controls, tar_format=tarfile.GNU_FORMAT))
            S.deb_readback(path, package_rows(long_files), expected_control)
            path.write_bytes(package_data(long_files, controls, tar_format=tarfile.PAX_FORMAT))
            with self.assertRaises(ValueError):
                S.deb_readback(path, package_rows(long_files), expected_control)
            for change in ("owner", "mode", "bytes", "missing", "link"):
                def mutate(archive, member, info, raw):
                    if archive == "data.tar" and member == "usr/share/inert":
                        if change == "owner":
                            info.uid = 1000
                        elif change == "mode":
                            info.mode = 0o600
                        elif change == "bytes":
                            raw = b"EVIL"
                        elif change == "missing":
                            return None, b""
                        else:
                            info.type, info.linkname, info.size = tarfile.SYMTYPE, "/outside", 0
                            raw = b""
                    return info, raw
                path.write_bytes(package_data(files, controls, mutate=mutate))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    S.deb_readback(path, expected, expected_control)
            extra = {**files, "usr/share/unexpected": b"extra"}
            path.write_bytes(package_data(extra, controls))
            with self.assertRaises(ValueError):
                S.deb_readback(path, expected, expected_control)
            forbidden = {**files, "opt/unexpected": b"never package published versions"}
            path.write_bytes(package_data(forbidden, controls))
            with self.assertRaises(ValueError):
                S.deb_readback(path, package_rows(forbidden), expected_control)
            path.write_bytes(package_data(files, controls, trailing=True))
            with self.assertRaises(ValueError):
                S.deb_readback(path, expected, expected_control)

    def test_failed_or_expired_command_never_becomes_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-ci-data-") as name:
            root = Path(name)
            (root / "public").mkdir()
            argv = ["/inert-tool"]
            outcome = subprocess.CompletedProcess(argv, 7, b"synthetic output", b"synthetic failure")
            with patch.object(S.time, "monotonic", return_value=100), patch.object(S.D, "write", wraps=S.D.write):
                owner = unittest.mock.Mock(return_value=outcome)
                check = S.Check(root, owner, deadline=120)
                self.assertEqual(check.end, 120)
                with self.assertRaises(ValueError):
                    check.command("failed", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                self.assertEqual((root / "public/failed.stderr").read_bytes(), b"synthetic failure")
                self.assertEqual(check.commands[0]["exitCode"], 7)
                self.assertTrue(check.failed)
                with self.assertRaises(ValueError):
                    check.command("must-not-launch", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                expired = S.Check(root, owner, deadline=99)
                with self.assertRaises(ValueError):
                    expired.command("expired", argv, {}, root)
                self.assertEqual(owner.call_count, 1)

    def test_compiler_hardlink_exports_fresh_verified_data_only(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-copy-data-") as name:
            root = Path(name)
            source, alias, destination = root / "compiler-data", root / "compiler-alias", root / "exported-data"
            source.write_bytes(b"inert compiler DATA; never execute")
            source.chmod(0o700)
            os.link(source, alias)
            before = source.stat()
            result = S.artifact_record(source, copy_to=destination)
            self.assertEqual(result["sha256"], S.D.file_record(destination)["sha256"])
            self.assertNotEqual(before.st_ino, destination.stat().st_ino)
            self.assertEqual(source.stat().st_nlink, 2)
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            with self.assertRaises(FileExistsError):
                S.artifact_record(source, copy_to=destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())


if __name__ == "__main__":
    unittest.main()
