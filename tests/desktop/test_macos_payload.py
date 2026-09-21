"""Focused DATA tests: no subprocess, signals, native SDK, runtime or network.

Imports only the inert publisher module. Fixtures are small ordinary task-owned
files or text/tar headers. Even successful owner doubles are DATA, never native
settlement evidence. Execute this file only after SOURCE/COMMAND acceptance.
"""
from __future__ import annotations

from contextlib import nullcontext
import ast
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("mrk_macos_payload_data", SOURCE / "desktop/tools/macos_payload.py")
assert spec is not None and spec.loader is not None
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def archive_bytes(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, kind in members:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = kind, 0o755, 1234567890
            if kind == tarfile.REGTYPE:
                info.size = 6
                archive.addfile(info, io.BytesIO(b"INERT\n"))
            else:
                info.linkname = "../outside"
                archive.addfile(info)
    return result.getvalue()


def native_text(commands):
    # Text expected from otool, not actual Mach-O/native qualification.
    return "/inert/native-copy:\n" + "".join(
        f"Load command {index}\n          cmd {name}\n      cmdsize 64\n" + fields + "\n"
        for index, (name, fields) in enumerate(commands))


BUILD_VERSION = ("LC_BUILD_VERSION", "     platform 1\n        minos 26.0\n          sdk 26.0\n       ntools 1")


def library(name, kind="LC_LOAD_DYLIB"):
    return kind, "         name " + name + " (offset 24)"


def job_double(root, *, result=None, verdict=None):
    # Deliberately bypass Job.__init__: no source/core owner import or install.
    job = payload.Job.__new__(payload.Job)
    job.root, job.records, job.failed, job.evidence_bytes = root, [], False, 0
    job.end, job.hard, job.environment = 100.0, 130.0, {"LANG": "C"}
    job.clock = SimpleNamespace(check=Mock(), phase="closed", expired=False)
    verdict = verdict or SimpleNamespace(complete=True, fatal=False, commands=1,
                                        command_contained=True, profile_calls=0)
    job.guard = SimpleNamespace(handler_state="RESTORED", lifetime_ledger=SimpleNamespace(verdict=lambda: verdict))
    job.run_owned = Mock(return_value=result or SimpleNamespace(returncode=0, stdout=b"inert\n", stderr=b""))
    return job


def tool_path_data():
    # All metadata and resolution below are DATA, never host tool admission.
    bin_path = payload.CLT / "usr/bin"
    sdk, resource = payload.CLT / "SDKs/MacOSX26.5.sdk", payload.CLT / "usr/lib/clang/21"
    aliases = {bin_path / "ranlib": "libtool", bin_path / "otool": "llvm-otool"}
    overrides = {}
    directories = set()
    for path in (bin_path, Path("/usr/bin"), Path("/bin"), resource / "include",
                 resource / "lib/darwin", sdk / "usr/include/ffi", sdk / "usr/lib"):
        directories.update((path, *path.parents))

    def lstat(path):
        if path in overrides:
            return overrides[path]
        mode = stat.S_IFDIR | 0o755 if path in directories else (
            stat.S_IFLNK | 0o777 if path in aliases else stat.S_IFREG | 0o755)
        return SimpleNamespace(st_dev=1, st_ino=int.from_bytes(hashlib.sha256(str(path).encode()).digest()[:4]),
            st_mode=mode, st_uid=0, st_nlink=1, st_size=6, st_mtime_ns=3, st_ctime_ns=4)

    def resolve(path, strict=False):
        for _ in range(9):
            if path not in aliases:
                return path
            target = Path(aliases[path])
            path = target if target.is_absolute() else path.parent / target
        raise AssertionError("An invalid alias route reached the resolution double")

    return SimpleNamespace(bin=bin_path, sdk=sdk, resource=resource, aliases=aliases,
                           overrides=overrides, lstat=lstat, resolve=resolve)


def notice_data(root):
    """Ordinary private DATA files; root/ancestor admission is metadata-double only."""
    clt = root / "clt"
    sdk, resource = clt / "SDKs/MacOSX26.5.sdk", clt / "usr/lib/clang/21"
    paths = (resource / "lib/darwin/libclang_rt.osx.a", resource / "include/stddef.h",
             resource / "include/stdarg.h", resource / "include/stdint.h", sdk / "SDKSettings.json",
             sdk / "usr/include/ffi/ffi.h", sdk / "usr/include/ffi/ffitarget.h",
             sdk / "usr/lib/libSystem.tbd", sdk / "usr/lib/libffi.tbd")
    for path in paths:
        payload.write_file(path, b"INERT HEADER DATA\n", 0o644)
    paths[6].write_bytes(b'#include <ffi/ffitarget_arm64.h>\n#include "external-link.h"\n'
                        b'#include "../outside.h"\n#include HEADER_NAME\n')
    (paths[6].parent / "ffitarget_arm64.h").write_bytes(b'#include "must-not-follow.h"\n')
    (paths[6].parent / "external-link.h").symlink_to(paths[2])
    (paths[1].parent / "same-bytes.h").hardlink_to(paths[1])
    for directory in (clt / "Library/Documentation", clt / "usr/share/doc", clt / "usr/share/clang"):
        directory.mkdir(parents=True, exist_ok=True)
    (clt / "LICENSE.txt").write_bytes(b"INERT NOTICE, NOT LICENSE APPROVAL\n")
    (clt / "usr/share/doc/NOTICE.rtf").write_bytes(b"{INERT RTF; never render}\n")
    output = root / "output"
    (output / "evidence").mkdir(parents=True)
    job = job_double(output)
    job.projections = []
    original_lstat = Path.lstat
    overrides = {}

    def lstat(path):
        if path == Path("/var/db/receipts/com.apple.pkg.CLTools_Executables.plist"):
            raise FileNotFoundError("inert absent receipt")
        value = original_lstat(path)
        fields = {name: getattr(value, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        fields["st_uid"] = 0
        if stat.S_ISDIR(value.st_mode):
            # Avoid asserting host /tmp ancestry is trusted or time-stable.
            fields.update(st_mode=stat.S_IFDIR | 0o755, st_nlink=2, st_size=0, st_mtime_ns=3, st_ctime_ns=4)
        fields.update(overrides.get(path, {}))
        return SimpleNamespace(**fields)

    return SimpleNamespace(clt=clt, sdk=sdk, resource=resource, paths=paths,
                           job=job, lstat=lstat, overrides=overrides)


def smoke_environment_check(environ, stream, **overrides):
    # Compile only this DATA-only function, never SMOKE's native imports/body.
    function, = (node for node in ast.parse(payload.SMOKE).body
                 if isinstance(node, ast.FunctionDef) and node.name == "_assert_clean_environment")
    namespace = {"os": SimpleNamespace(environ=environ), "sys": SimpleNamespace(stderr=stream), **overrides}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<smoke-key-check-data>", "exec"), namespace)
    return namespace["_assert_clean_environment"]


class MacOSPayloadDataTests(unittest.TestCase):
    def test_smoke_environment_key_diagnostic_preserves_assertion_and_redaction(self):
        class KeysOnly(dict):
            def __getitem__(self, key):
                raise AssertionError("Environment values must never be read")
            get = items = values = __getitem__

        expected = {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR"}
        stream = io.StringIO()
        smoke_environment_check(KeysOnly.fromkeys(expected, "DO-NOT-REPORT-VALUE"), stream)()
        self.assertEqual(stream.getvalue(), "")
        environ = KeysOnly.fromkeys((expected - {"HOME"}) | {"UNEXPECTED_KEY"}, "DO-NOT-REPORT-VALUE")
        with self.assertRaises(AssertionError):
            smoke_environment_check(environ, stream)()
        self.assertEqual(stream.getvalue(), "environment-key-mismatch missingCount=1 extraCount=1 "
                         "extraListTruncated=False extraNameTruncated=False missing=[HOME] extra=['UNEXPECTED_KEY']\n")
        self.assertNotIn("DO-NOT-REPORT-VALUE", stream.getvalue())
        self.assertEqual(set(environ), (expected - {"HOME"}) | {"UNEXPECTED_KEY"})

    def test_smoke_environment_key_diagnostic_bounds_and_ascii_escaping(self):
        expected = {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR"}
        stream = io.StringIO()
        with self.assertRaises(AssertionError):
            smoke_environment_check(dict.fromkeys(expected | {"\u00e9\x1b\n\u2603"}, "PRIVATE"), stream)()
        self.assertIn("\\xe9\\x1b\\n\\u2603", stream.getvalue())
        self.assertTrue(all(32 <= ord(char) < 127 for char in stream.getvalue().rstrip("\n")))
        stream = io.StringIO()
        extras = {str(n) + "\U0001f642" * 100 for n in range(10)}
        with self.assertRaises(AssertionError):
            smoke_environment_check(dict.fromkeys(expected | extras, "PRIVATE"), stream)()
        message = stream.getvalue()
        self.assertLessEqual(len(message.encode("ascii")), 8192)
        self.assertIn("missingCount=0 extraCount=10 extraListTruncated=True extraNameTruncated=True", message)
        names = message.split(" extra=[", 1)[1].removesuffix("]\n").split(" | ")
        self.assertEqual(len(names), 8)
        self.assertTrue(all(len(name.encode("ascii")) == 64 and name.endswith("...") for name in names))
        self.assertNotIn("PRIVATE", message)

    def test_smoke_environment_key_diagnostic_keeps_assertion_on_formatting_failure(self):
        environ = dict.fromkeys({"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR", "EXTRA"}, "PRIVATE")
        stream = io.StringIO()
        with self.assertRaises(AssertionError):
            smoke_environment_check(environ, stream, ascii=Mock(side_effect=ValueError("DO-NOT-REPORT-ERROR")))()
        self.assertEqual(stream.getvalue(), "environment-key-mismatch names-unavailable\n")
        with self.assertRaises(AssertionError):
            smoke_environment_check(environ, SimpleNamespace(write=Mock(side_effect=OSError("PRIVATE"))))()

    def test_deadline_allocation_reserves_original_tail_without_renewal(self):
        self.assertEqual(payload.command_timeout(100, 94.1), 2)
        self.assertEqual(payload.command_timeout(100, 95.1), 1)
        self.assertEqual(payload.command_timeout(2000, 0), 720)
        for end, now in ((100, 96.1), (100, 100), (float("inf"), 0), (100, float("nan"))):
            with self.subTest(end=end, now=now), self.assertRaises(payload.Refused):
                payload.command_timeout(end, now)

    def test_only_native_upstream_make_defaults_are_augmented(self):
        original = "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E\nPYTHON_FOR_FREEZE=./_bootstrap_python\n"
        self.assertEqual(payload.no_bytecode_make(original), [
            "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B", "PYTHON_FOR_FREEZE=./_bootstrap_python -B"])
        for changed in (original.replace("./$(BUILDPYTHON) -E", "./python -E"),
                        original.replace("./_bootstrap_python", "/inert/cross-python"),
                        original + "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E\n"):
            with self.subTest(changed=changed), self.assertRaises(payload.Refused):
                payload.no_bytecode_make(changed)
        for suffix in ("", ".exe"):
            self.assertEqual(payload.build_executable("BUILDPYTHON=python$(BUILDEXE)\nBUILDEXE=" + suffix + "\n"), "python" + suffix)
        with self.assertRaises(payload.Refused):
            payload.build_executable("BUILDPYTHON=python$(BUILDEXE)\nBUILDEXE=/alternate\n")
        setup = (SOURCE / "desktop/tools/cpython_macos_setup.local").read_text()
        self.assertIn("_ctypes/malloc_closure.c", setup)
        self.assertIn("_scproxy", payload.setup_names(setup)["disabled"])
        for name in payload.HACL:
            self.assertIn(f"Modules/_hacl/libHacl_{name}.a", setup)
        recipe = inspect.getsource(payload.build)
        for flag in ("--without-mimalloc", "--disable-framework", "--disable-shared", "--with-ensurepip=no",
                     "--with-openssl-rpath=no", "no-autoload-config", "no-module", "PYTHONSTRICTEXTENSIONBUILD"):
            self.assertIn(flag, recipe + inspect.getsource(payload.prepare_tools))
        self.assertNotIn('tools["curl"]', recipe)

    def test_generated_builtin_roster_is_parsed_not_a_linux_count(self):
        text = 'struct _inittab _PyImport_Inittab[] = {\n /* source comment */\n {"sys", NULL},\n {"_ssl", PyInit__ssl},\n {0, 0}\n};'
        self.assertEqual(payload.builtin_table(text), {"sys", "_ssl"})
        for bad in (text.replace('{0, 0}', '{"sys", NULL}, {0, 0}'),
                    text.replace('/* source comment */', '#if SOMETHING\n#endif')):
            with self.assertRaises(payload.Refused):
                payload.builtin_table(bad)

    def test_configuration_evidence_preserves_source_and_build_origins(self):
        names = ("Makefile", "pyconfig.h", "Modules/config.c", "Modules/Setup", "Modules/Setup.local",
                 "Modules/Setup.bootstrap", "Modules/Setup.stdlib", "pybuilddir.txt")
        for case in ("source-only", "build-decoy", "source-missing"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                root = Path(name)
                source, build = root / "sources/cpython", root / "build/cpython"
                expected = {}
                for leaf in names:
                    actual = (source if leaf == "Modules/Setup" else build) / leaf
                    body = ("admitted " + leaf + "\n").encode("ascii")
                    actual.parent.mkdir(parents=True, exist_ok=True)
                    actual.write_bytes(body)
                    expected[leaf] = body
                    # Source-tree decoys must never replace generated build inputs.
                    decoy = (build if leaf == "Modules/Setup" else source) / leaf
                    if leaf != "Modules/Setup" or case != "source-only":
                        decoy.parent.mkdir(parents=True, exist_ok=True)
                        decoy.write_bytes(b"wrong-root decoy\n")
                if case == "source-missing":
                    (source / "Modules/Setup").unlink()
                originals = {p: (p.read_bytes(), p.stat().st_mode) for parent in (source, build)
                             for p in parent.rglob("*") if p.is_file()}
                job = job_double(root)
                job.projections = []
                if case == "source-missing":
                    with self.assertRaises(FileNotFoundError):
                        payload.retain_build_configuration(job)
                    copied = names[:3]
                    self.assertEqual(job.phase, "configuration-Modules-Setup")
                    self.assertFalse((root / "evidence/configuration/Modules/Setup").exists())
                else:
                    payload.retain_build_configuration(job)
                    copied = names
                    self.assertEqual(job.phase, "configuration-pybuilddir.txt")
                self.assertEqual([r["destination"] for r in job.projections],
                                 ["evidence/configuration/" + leaf for leaf in copied])
                for leaf, row in zip(copied, job.projections):
                    actual = (source if leaf == "Modules/Setup" else build) / leaf
                    self.assertEqual(row["source"], str(actual))
                    self.assertEqual(row["sha256"], hashlib.sha256(expected[leaf]).hexdigest())
                    self.assertEqual((root / "evidence/configuration" / leaf).read_bytes(), expected[leaf])
                self.assertEqual(job.evidence_bytes, sum(len(expected[leaf]) for leaf in copied))
                self.assertEqual({p: (p.read_bytes(), p.stat().st_mode) for p in originals}, originals)

    def test_generated_configuration_uses_one_actual_pybuilddir_not_root_guess(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            python_build = root / "cpython"
            relative = "build/lib.macosx-26.0-arm64-3.14"
            generated = python_build / relative
            generated.mkdir(parents=True)
            pointer = python_build / "pybuilddir.txt"
            pointer.write_text(relative + "\n", encoding="ascii")
            (python_build / "build-details.json").write_bytes(b"WRONG ROOT FILE\n")
            contents = {"build-details.json": b'{"location":"actual generated directory"}\n',
                        "_sysconfigdata__darwin_darwin.py": b"build_time_vars = {}\n",
                        "_sysconfig_vars__darwin_darwin.json": b"{}\n"}
            for leaf, body in contents.items():
                (generated / leaf).write_bytes(body)
            selected = payload.generated_configuration(python_build)
            self.assertEqual(selected, {leaf: generated / leaf for leaf in contents})
            # Both consumers use the same selection, even if the routing file
            # is later changed. No build/owner/native function is executed.
            pointer.write_text("invalid after selection\n", encoding="ascii")
            for destination in (root / "evidence/configuration", root / "payload/python/lib/python3.14"):
                for leaf, source in selected.items():
                    payload.copy_file(source, destination / leaf)
                    self.assertEqual((destination / leaf).read_bytes(), contents[leaf])
            (python_build / "not-a-directory").write_bytes(b"ordinary inert file\n")
            for invalid in ("../outside", "/absolute", "build//lib", "build/./lib", "build/../lib",
                            ".", "build/", "build\\lib", "not-a-directory/lib", "build/" + "a" * 1024):
                with self.subTest(invalid=invalid), self.assertRaises(payload.Refused):
                    pointer.write_text(invalid + "\n", encoding="ascii")
                    payload.generated_configuration(python_build)
            pointer.write_text(relative + "\n", encoding="ascii")
            duplicate = generated / "_sysconfigdata_duplicate.py"
            duplicate.write_bytes(b"{}\n")
            with self.assertRaises(payload.Refused):
                payload.generated_configuration(python_build)
            duplicate.unlink()
            (generated / "build-details.json").unlink()
            with self.assertRaises(FileNotFoundError):
                payload.generated_configuration(python_build)
            self.assertEqual((python_build / "build-details.json").read_bytes(), b"WRONG ROOT FILE\n")

    def test_checked_in_source_ca_and_notice_pins_are_coherent(self):
        inputs = payload.load_inputs(SOURCE)
        self.assertEqual([row["id"] for row in inputs["sources"]], ["cpython", "zlib", "openssl"])
        self.assertEqual(inputs["sources"][0]["sha256"],
                         "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81")
        with self.assertRaises(payload.Refused):
            json.loads('{"schemaVersion":1,"schemaVersion":1}', object_pairs_hook=payload.pairs)

    def test_streaming_copy_preserves_bytes_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            source, destination = root / "source", root / "copy"
            original = b"INERT\n" * (payload.CHUNK // 6 + 1)
            source.write_bytes(original)
            row = payload.copy_file(source, destination, mode=0o755)
            self.assertEqual(row, {"size": len(original), "sha256": hashlib.sha256(original).hexdigest()})
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
            with self.assertRaises(FileExistsError):
                payload.copy_file(source, destination)
            self.assertEqual(destination.read_bytes(), original)

    def test_original_reader_closes_once_and_refuses_changed_input(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            source = Path(name) / "input"
            source.write_bytes(b"INERT\n")
            close = payload.os.close
            with patch.object(payload.os, "close", wraps=close) as observed:
                with self.assertRaisesRegex(RuntimeError, "inert consumer"):
                    payload.read_stream(source, 64, Mock(side_effect=RuntimeError("inert consumer")))
                self.assertEqual(observed.call_count, 1)
            with self.assertRaises(payload.Refused):
                payload.read_stream(source, 64, lambda _: source.write_bytes(b"changed and longer\n"))
            source.write_bytes(b"INERT\n")
            alias = source.with_name("second-name")
            alias.hardlink_to(source)
            with self.assertRaisesRegex(payload.Refused, "regular-input-links"):
                payload.file_digest(source)
            expected = {"size": 6, "sha256": hashlib.sha256(b"INERT\n").hexdigest()}
            self.assertEqual(payload.read_stream(source, 64, lambda _: None, expected_links=2), expected)
            for invalid_count in (None, True, 0):
                with self.subTest(invalid_count=invalid_count), self.assertRaisesRegex(payload.Refused, "input-link-count"):
                    payload.read_stream(source, 64, lambda _: None, expected_links=invalid_count)
            with self.assertRaisesRegex(payload.Refused, "input-read-changed"):
                payload.read_stream(source, 64, lambda _: alias.unlink(), expected_links=2)

    def test_protected_tool_links_require_root_leaf_ancestors_and_record_facts(self):
        # Stat/path doubles only: no Linux fixture is declared a trusted Apple
        # tool, and the real protected-file reader never accesses these names.
        values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o755, st_uid=0,
                      st_nlink=2, st_size=6, st_mtime_ns=3, st_ctime_ns=4)
        original = SimpleNamespace(**values)
        root_value = SimpleNamespace(**dict(values, st_ino=1, st_mode=stat.S_IFDIR | 0o755))
        root, leaf = Mock(), Mock()
        root.__str__ = Mock(return_value="/")
        root.lstat.return_value = root_value
        leaf.__str__ = Mock(return_value="/inert-root-owned-tool")
        leaf.resolve.return_value, leaf.parents = leaf, (root,)
        leaf.lstat.return_value = original
        row = {"size": 6, "sha256": hashlib.sha256(b"INERT\n").hexdigest()}
        observed = []
        with patch.object(payload, "read_stream", return_value=row) as read:
            result = payload.protected_file(leaf, observe=observed.append)
            self.assertEqual(result, {"path": str(leaf), "linkCount": 2, **row})
            self.assertEqual(read.call_args.kwargs, {"expected_links": 2})
            self.assertEqual(observed[0]["nodes"][0]["links"], 2)
            self.assertEqual(observed[0]["nodes"][0]["uid"], 0)
            for bad_leaf, bad_root in (
                    (SimpleNamespace(**dict(values, st_uid=1001)), root_value),
                    (SimpleNamespace(**dict(values, st_mode=stat.S_IFREG | 0o775)), root_value),
                    (SimpleNamespace(**dict(values, st_mode=stat.S_IFDIR | 0o755)), root_value),
                    (original, SimpleNamespace(**dict(vars(root_value), st_uid=1001))),
                    (original, SimpleNamespace(**dict(vars(root_value), st_mode=stat.S_IFDIR | 0o777)))):
                with self.subTest(leaf=bad_leaf, root=bad_root):
                    leaf.lstat.return_value, root.lstat.return_value = bad_leaf, bad_root
                    read.reset_mock()
                    observed.clear()
                    with self.assertRaisesRegex(payload.Refused, "tool-ownership"):
                        payload.protected_file(leaf, observe=observed.append)
                    read.assert_not_called()
                    self.assertEqual(len(observed), 1)
            root.lstat.return_value = root_value
            leaf.lstat.side_effect = (original, SimpleNamespace(**dict(values, st_nlink=3)))
            with self.assertRaisesRegex(payload.Refused, "tool-input-changed"):
                payload.protected_file(leaf)
            leaf.lstat.side_effect = None
            leaf.lstat.return_value = SimpleNamespace(**dict(values, st_uid=1001))
            job = SimpleNamespace(phase="new", clock=SimpleNamespace(check=Mock()), save=Mock())
            with self.assertRaisesRegex(payload.Refused, "tool-ownership"):
                payload.inspect_protected(job, "git", leaf)
            self.assertEqual(job.phase, "inspect-git")
            self.assertEqual(job.save.call_args.args[0], "protected-git.json")
            self.assertEqual(job.save.call_args.args[1]["nodes"][0]["uid"], 1001)

    def test_selected_tool_roles_survive_protected_alias_hashing_and_environment(self):
        data = tool_path_data()
        row = {"size": 6, "sha256": hashlib.sha256(b"INERT\n").hexdigest()}
        job = SimpleNamespace(build_environment={}, phase="new", clock=SimpleNamespace(check=Mock()),
                              save=Mock(), copy=Mock(), root=Path("/inert/task"))

        def run(name, argv, **kwargs):
            if name == "sdk-selection":
                return (str(data.sdk) + "\n").encode()
            if name.startswith("select-"):
                return (str((Path("/usr/bin") if argv[-1] == "codesign" else data.bin) / argv[-1]) + "\n").encode()
            if name == "clang-version":
                return b"INERT compiler DATA\n"
            if name == "clang-resources":
                return (str(data.resource) + "\n").encode()
            raise AssertionError("Unexpected DATA command")

        job.run = Mock(side_effect=run)
        with patch.object(Path, "lstat", autospec=True, side_effect=data.lstat), \
             patch.object(Path, "resolve", autospec=True, side_effect=data.resolve), \
             patch.object(Path, "is_dir", return_value=True), patch.object(Path, "is_file", return_value=False), \
             patch.object(payload.os, "readlink", side_effect=data.aliases.__getitem__), \
             patch.object(payload.os.path, "lexists", return_value=False), \
             patch.object(payload.os, "uname", return_value=("Darwin", "INERT")), \
             patch.object(payload, "source_binding"), patch.object(payload, "notice_snapshot") as notices, \
             patch.object(payload, "read_stream", return_value=row) as read:
            tools = payload.prepare_tools(job)
        records = {call.args[0]: call.args[1] for call in job.save.call_args_list}
        toolchain = records["toolchain.json"]
        for name, physical in (("ranlib", "libtool"), ("otool", "llvm-otool"), ("ar", "ar")):
            invocation, target = str(data.bin / name), str(data.bin / physical)
            self.assertEqual(tools[name], invocation)
            self.assertEqual(toolchain["identities"][name], {"invocationPath": invocation,
                             "path": target, "linkCount": 1, **row})
            self.assertEqual(records["protected-" + name + ".json"]["requestedPath"], invocation)
            self.assertEqual(records["protected-" + name + ".json"]["resolvedPath"], target)
            self.assertIn(Path(target), [call.args[0] for call in read.call_args_list])
        self.assertEqual(job.build_environment["RANLIB"], str(data.bin / "ranlib"))
        self.assertEqual(job.build_environment["AR"], str(data.bin / "ar"))
        self.assertEqual(tools["codesign"], "/usr/bin/codesign")
        alias_facts = records["protected-ranlib.json"]["invocationRoute"][0]
        self.assertEqual(alias_facts["linkTarget"], "libtool")
        self.assertEqual(stat.S_IMODE(alias_facts["mode"]), 0o777)
        self.assertEqual(notices.call_args.args[:4], (job, data.resource, data.sdk, toolchain["selectedCompilerInputs"]))
        self.assertEqual(notices.call_args.args[4][1], {key: value for key, value in
                         records["protected-compiler-input-1.json"].items() if key != "role"})

    def test_notice_snapshot_uses_protected_original_bytes_and_complete_accounting(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            data = notice_data(Path(name))
            with patch.object(payload, "CLT", data.clt), \
                 patch.object(Path, "lstat", autospec=True, side_effect=data.lstat), \
                 patch.object(payload.time, "monotonic", return_value=0), \
                 patch.object(payload, "copy_file", side_effect=AssertionError("No raw reopen after protected hashing")):
                facts = []
                inputs = [payload.protected_file(path, observe=facts.append) for path in data.paths]
                with patch.object(payload, "read_stream", wraps=payload.read_stream) as reads:
                    payload.notice_snapshot(data.job, data.resource, data.sdk, inputs, facts)
                report = json.loads((data.job.root / "evidence/vendor-attribution-inputs.json").read_bytes())
                self.assertEqual(report["review"], "unfinished-not-an-approval")
                self.assertEqual(report["limits"]["dataBytes"], 8 * 1024 * 1024)
                self.assertEqual(len(report["observed"]), 9)  # Five headers, SDK JSON, one delegate, two notices.
                self.assertEqual(len(report["directories"]), 6)
                self.assertTrue(all(row["complete"] for row in report["directories"]))
                self.assertEqual(report["snapshotBytes"], sum(row["size"] for row in report["observed"]))
                self.assertEqual(len(data.job.projections), len(report["observed"]))
                for row in report["observed"]:
                    destination = data.job.root / row["destination"]
                    self.assertEqual(destination.read_bytes(), Path(row["source"]).read_bytes())
                    self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), row["sha256"])
                    self.assertEqual(destination.lstat().st_nlink, 1)
                    self.assertEqual(stat.S_IMODE(destination.lstat().st_mode), 0o600)
                first = report["observed"][0]
                self.assertEqual(first["protected"], facts[1])
                self.assertEqual(first["linkCount"], 2)
                originals = [call for call in reads.call_args_list if call.args[0] == data.paths[1]]
                self.assertEqual(len(originals), 1)
                self.assertEqual(originals[0].kwargs["expected_links"], 2)
                self.assertNotIn("must-not-follow.h", " ".join(str(call.args[0]) for call in reads.call_args_list))
                self.assertEqual(sum(row["reason"] == "ffi-include-out-of-scope" for row in report["unresolved"]), 2)
                self.assertTrue(any(row["source"].endswith("CLTools_Executables.plist") and row["reason"] == "missing"
                                    for row in report["unresolved"]))
                self.assertTrue(any(row["source"].endswith("external-link.h") and row["reason"] == "out-of-scope"
                                    and row["resolvedPath"] == str(data.paths[2]) for row in report["unresolved"]))
                retained = [path for path in (data.job.root / "evidence").rglob("*") if path.is_file()]
                self.assertEqual(sum(path.stat().st_size for path in retained), data.job.evidence_bytes)

    def test_notice_snapshot_bounds_are_local_but_input_close_write_and_global_failures_escape(self):
        # All mutations/failures are inert DATA doubles or ordinary fixture I/O.
        for case in ("local-time", "data-limit", "file-limit", "entry-limit", "document-limit", "delegate-limit",
                     "input-drift", "close-error", "write-error", "global-deadline", "cancellation"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                data = notice_data(Path(name))
                if case == "document-limit":
                    for index in range(9):
                        (data.clt / f"NOTICE-{index}.txt").write_bytes(b"INERT\n")
                if case == "delegate-limit":
                    data.paths[6].write_bytes(b"".join(f'#include "target-{i}.h"\n'.encode() for i in range(5)))
                    for index in range(5):
                        (data.paths[6].parent / f"target-{index}.h").write_bytes(b"INERT\n")
                now, seen = [0], []
                with patch.object(payload, "CLT", data.clt), \
                     patch.object(Path, "lstat", autospec=True, side_effect=data.lstat), \
                     patch.object(payload.time, "monotonic", side_effect=lambda: now[0]):
                    facts = []
                    inputs = [payload.protected_file(path, observe=facts.append) for path in data.paths]
                    original_read, original_close, original_scan = payload.read_stream, payload.os.close, payload.os.scandir

                    def read(path, limit, consume, poll=lambda: None, **kwargs):
                        def piece(body):
                            consume(body)
                            if case == "local-time":
                                now[0] = 31
                        return original_read(path, limit, piece, poll, **kwargs)

                    def close(fd):
                        original_close(fd)  # The fixture must not leak a descriptor.
                        if case == "close-error":
                            raise OSError("inert original-close uncertainty")

                    def entries():
                        for index in range(1000):
                            seen.append(index)
                            yield SimpleNamespace(name=f"unrelated-{index}")

                    def scan(path):
                        return nullcontext(entries()) if case == "entry-limit" and path == data.clt else original_scan(path)

                    if case == "input-drift":
                        data.overrides[data.paths[1]] = {"st_ino": -1}
                    if case == "file-limit":
                        data.overrides[data.clt / "LICENSE.txt"] = {"st_size": 2 * 1024 * 1024 + 1}
                    if case == "global-deadline":
                        data.job.clock.check.side_effect = payload.Refused("work-deadline")
                    if case == "cancellation":
                        data.job.clock.check.side_effect = KeyboardInterrupt()
                    with patch.object(payload, "read_stream", side_effect=read), \
                         patch.object(payload.os, "close", side_effect=close), \
                         patch.object(payload.os, "scandir", side_effect=scan), \
                         patch.object(payload, "NOTICE_DATA_LIMIT", 1 if case == "data-limit" else payload.NOTICE_DATA_LIMIT), \
                         (patch.object(payload, "write_file", side_effect=OSError("inert write failure"))
                          if case == "write-error" else nullcontext()):
                        error = {"input-drift": payload.Refused, "close-error": OSError, "write-error": OSError,
                                 "global-deadline": payload.Refused, "cancellation": KeyboardInterrupt}.get(case)
                        if error:
                            with self.assertRaises(error):
                                payload.notice_snapshot(data.job, data.resource, data.sdk, inputs, facts)
                            self.assertFalse((data.job.root / "evidence/vendor-attribution-inputs.json").exists())
                            if case == "write-error":
                                self.assertEqual(data.job.evidence_bytes, inputs[1]["size"])
                        else:
                            payload.notice_snapshot(data.job, data.resource, data.sdk, inputs, facts)
                            report = json.loads((data.job.root / "evidence/vendor-attribution-inputs.json").read_bytes())
                            expected = {"local-time": "snapshot-time-limit", "data-limit": "snapshot-data-limit",
                                        "file-limit": "file-size-limit",
                                        "entry-limit": "directory-entry-limit", "document-limit": "vendor-document-limit",
                                        "delegate-limit": "ffi-include-limit"}[case]
                            self.assertTrue(any(row["reason"] == expected for row in report["unresolved"]))
                            self.assertEqual(report["snapshotBytes"], sum(row["size"] for row in report["observed"]))
                            if case in {"local-time", "data-limit"}:
                                self.assertEqual(report["observed"], [])
                                self.assertEqual(data.job.projections, [])
                                self.assertEqual(list((data.job.root / "evidence").iterdir()),
                                                 [data.job.root / "evidence/vendor-attribution-inputs.json"])
                            if case == "entry-limit":
                                self.assertEqual(len(seen), 129)
                                self.assertFalse(report["directories"][0]["complete"])

    def test_selected_tool_routes_refuse_ambiguity_untrusted_aliases_and_changes(self):
        data = tool_path_data()
        nominal, target = data.bin / "ranlib", data.bin / "libtool"
        raw = (str(nominal) + "\n").encode()
        job = SimpleNamespace(phase="new", clock=SimpleNamespace(check=Mock()), save=Mock())
        row = {"size": 6, "sha256": hashlib.sha256(b"INERT\n").hexdigest()}
        with patch.object(Path, "lstat", autospec=True, side_effect=data.lstat), \
             patch.object(Path, "resolve", autospec=True, side_effect=data.resolve), \
             patch.object(payload.os, "readlink", side_effect=data.aliases.__getitem__), \
             patch.object(payload, "read_stream", return_value=row) as read:
            for invalid in (b"ranlib\n", raw + b"\n", raw + b"/other", b" " + raw,
                            str(target).encode(), b"/tmp/ranlib\n", b"/usr/bin/../bin/ranlib\n"):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(payload.Refused, "tool-selection"):
                    payload.selected_tool(job, "ranlib", invalid)
            read.assert_not_called()
            for path, fields in ((nominal, {"st_uid": 1001}), (data.bin, {"st_mode": stat.S_IFDIR | 0o777}),
                                 (data.bin, {"st_mode": stat.S_IFLNK | 0o777}),
                                 (target, {"st_uid": 1001}), (target, {"st_mode": stat.S_IFREG | 0o775})):
                with self.subTest(path=path, fields=fields):
                    data.overrides[path] = SimpleNamespace(**dict(vars(data.lstat(path)), **fields))
                    with self.assertRaisesRegex(payload.Refused, "tool-route-ownership"):
                        payload.selected_tool(job, "ranlib", raw)
                    read.assert_not_called()
                    self.assertEqual(job.save.call_args.args[0], "protected-ranlib.json")
                    data.overrides.clear()
            for link, code in (("/tmp/libtool", "tool-alias-target"), ("../bin/libtool", "tool-alias-target"),
                               ("ranlib", "tool-alias-cycle")):
                with self.subTest(link=link), self.assertRaisesRegex(payload.Refused, code):
                    data.aliases[nominal] = link
                    payload.selected_tool(job, "ranlib", raw)
            data.aliases[nominal] = "first-alias"
            data.aliases[data.bin / "first-alias"] = str(target)
            invocation, identity = payload.selected_tool(job, "ranlib", raw)
            self.assertEqual(invocation, str(nominal))
            self.assertEqual(identity["path"], str(target))
            data.aliases.clear()
            for index in range(9):
                source = nominal if index == 0 else data.bin / ("alias-" + str(index))
                data.aliases[source] = "alias-" + str(index + 1)
            with self.assertRaisesRegex(payload.Refused, "tool-alias-limit"):
                payload.selected_tool(job, "ranlib", raw)
            data.aliases.clear()
            data.aliases[nominal] = "libtool"

            def changed_route(*args, **kwargs):
                # Change only the alias spelling, with the same terminal target.
                data.aliases[nominal] = str(target)
                return row

            read.side_effect = changed_route
            with self.assertRaisesRegex(payload.Refused, "tool-route-changed"):
                payload.selected_tool(job, "ranlib", raw)
            data.aliases[nominal] = "libtool"

            def changed_parent(*args, **kwargs):
                data.overrides[data.bin] = SimpleNamespace(**dict(vars(data.lstat(data.bin)), st_uid=1001))
                return row

            read.side_effect = changed_parent
            with self.assertRaisesRegex(payload.Refused, "tool-route-changed"):
                payload.selected_tool(job, "ranlib", raw)

    def test_pinned_archive_bytes_are_used_and_original_timestamps_survive(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            body = archive_bytes([("fixed/configure", tarfile.REGTYPE)])
            source = root / "archive"
            source.write_bytes(body)
            pin = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(), "root": "fixed"}
            real_read = payload.read_file
            def read_then_change(path, limit, poll):
                result = real_read(path, limit, poll)
                path.write_bytes(b"changed pathname after checked read")
                return result
            with patch.object(payload, "read_file", side_effect=read_then_change):
                rows = payload.extract_source(source, pin, root / "extracted")
            self.assertEqual((root / "extracted/configure").read_bytes(), b"INERT\n")
            self.assertEqual((root / "extracted/configure").stat().st_mtime_ns, 1234567890000000000)
            self.assertEqual(rows[0]["originalMode"], 0o755)

    def test_archive_traversal_aliases_and_link_headers_never_escape(self):
        cases = ([('fixed/../outside', tarfile.REGTYPE)],
                 [('fixed/Name', tarfile.REGTYPE), ('fixed/name', tarfile.REGTYPE)],
                 [('fixed/link', tarfile.SYMTYPE)])
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                root = Path(name)
                body = archive_bytes(members)
                (root / "archive").write_bytes(body)
                pin = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(), "root": "fixed"}
                with self.assertRaises(payload.Refused):
                    payload.extract_source(root / "archive", pin, root / "extracted")
                self.assertFalse((root / "outside").exists())

    def test_thin_arm64_header_and_complete_load_correspondence(self):
        root = Path("/inert/task")
        commands = [BUILD_VERSION, library("/usr/lib/dyld", "LC_LOAD_DYLINKER"),
                    library("/usr/lib/libSystem.B.dylib"),
                    *(library(str(root / "deps/lib" / name)) for name in payload.DYLIBS)]
        header = "/inert/native-copy:\nMach header\nmagic cputype cpusubtype caps filetype ncmds sizeofcmds flags\nMH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 5 2000 NOUNDEFS\n"
        count = payload.macho_header(header, "EXECUTE")
        original = payload.library_commands(native_text(commands), count)
        changes, expected = payload.relocation(original, 0, root)
        self.assertEqual(set(changes.values()), {"@executable_path/../lib/" + n for n in payload.DYLIBS})
        self.assertIsNone(expected["id"])
        dylib = payload.library_commands(native_text([BUILD_VERSION,
            library(str(root / "deps/lib/libcrypto.3.dylib"), "LC_ID_DYLIB"),
            library("/usr/lib/libSystem.B.dylib")]), 3)
        self.assertEqual(payload.relocation(dylib, 1, root)[1]["id"], "@rpath/libcrypto.3.dylib")
        for bad in (header.replace("ARM64", "X86_64"), "Fat headers\n" + header,
                    header.replace("EXECUTE", "DYLIB")):
            with self.assertRaises(payload.Refused):
                payload.macho_header(bad, "EXECUTE")
        for bad_commands in ([BUILD_VERSION, library("/inert/lib", "LC_LOAD_WEAK_DYLIB")],
                             [BUILD_VERSION, ("LC_DYLD_ENVIRONMENT", "name DYLD_LIBRARY_PATH=/inert (offset 12)")],
                             [BUILD_VERSION, library("/a"), library("/a")]):
            with self.assertRaises(payload.Refused):
                payload.library_commands(native_text(bad_commands), len(bad_commands))
        for bad in (dict(original, dependencies=["/usr/local/lib/libssl.3.dylib"]),
                    dict(original, id="unexpected"), dict(original, rpaths=["/usr/local/lib"])):
            with self.assertRaises(payload.Refused):
                payload.relocation(bad, 0, root)

    def test_failed_or_unsettled_original_result_latches_no_later_command(self):
        for fail_call in (False, True):
            with self.subTest(fail_call=fail_call), tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
                root = Path(name)
                verdict = SimpleNamespace(complete=False, fatal=True, commands=0, command_contained=False, profile_calls=0)
                job = job_double(root, verdict=verdict)
                if fail_call:
                    job.run_owned.side_effect = RuntimeError("inert original failure")
                with patch.object(payload.time, "monotonic", return_value=10), \
                     patch.object(payload.shutil, "disk_usage", return_value=SimpleNamespace(free=3 * 1024**3)):
                    with self.assertRaises((RuntimeError, payload.Refused)):
                        job.run("inert-original", ["/not-executed"])
                    with self.assertRaises(payload.Refused):
                        job.run("never-dispatched", ["/not-executed"])
                self.assertTrue(job.failed)
                self.assertEqual(job.run_owned.call_count, 1)
                self.assertEqual(job.records[0]["status"], "failed")
                self.assertFalse((root / "evidence").exists())

    def test_success_data_requires_original_finality_and_persisted_output_budget(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            job = job_double(root)
            with patch.object(payload.time, "monotonic", return_value=10), \
                 patch.object(payload.shutil, "disk_usage", return_value=SimpleNamespace(free=3 * 1024**3)):
                self.assertEqual(job.run("inert-original", ["/not-executed"]), b"inert\n")
            self.assertEqual(job.evidence_bytes, 6)
            self.assertTrue(payload.original_settled(job))
            job.guard.handler_state = "UNKNOWN"
            self.assertFalse(payload.original_settled(job))
            job.guard.handler_state = "RESTORED"
            job.records[0]["originalFinality"] = False
            self.assertFalse(payload.original_settled(job))
            job.evidence_bytes = payload.EVIDENCE_LIMIT
            with self.assertRaises(payload.Refused):
                job.retain("no-room", b"x")
            self.assertFalse((root / "evidence/no-room").exists())

    def test_cleanup_never_adopts_a_different_task_root(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            job = job_double(root)
            job.root_identity = (-1, -1)
            with patch.object(payload, "original_settled", return_value=True), \
                 patch.object(payload.shutil, "rmtree") as remove:
                remove.avoids_symlink_attacks = True
                with self.assertRaises(payload.Refused):
                    payload.remove_disposable(job)
                remove.assert_not_called()
            self.assertTrue(root.is_dir())

    def test_final_archive_preserves_executable_mode_and_never_executes_payload(self):
        with tempfile.TemporaryDirectory(prefix="mrk-macos-payload-data-") as name:
            root = Path(name)
            payload.write_file(root / "payload/python/bin/python3", b"INERT, NOT AN EXECUTABLE\n", 0o755)
            job = SimpleNamespace(root=root, hard=100)
            with patch.object(payload.time, "monotonic", return_value=1):
                result = payload.archive_payload(job)
            self.assertEqual(result["sha256"], hashlib.sha256((root / "payload.tar").read_bytes()).hexdigest())
            with tarfile.open(root / "payload.tar", "r") as archive:
                members = archive.getmembers()
                self.assertEqual([m.name for m in members], ["payload/python/bin/python3"])
                self.assertEqual(members[0].mode, 0o755)
                with archive.extractfile(members[0]) as body:
                    self.assertEqual(body.read(), b"INERT, NOT AN EXECUTABLE\n")

    def test_single_native_workflow_and_fixed_clean_request_route(self):
        workflow = (SOURCE / ".github/workflows/desktop-macos-payload.yml").read_text()
        self.assertIn("runs-on: macos-26", workflow)
        self.assertNotIn("matrix:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("ci_foundation.py", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("desktop/tools/macos_payload.py", workflow)
        self.assertEqual(payload.REQUEST_SHIM, 'exec "$1" -I -S -B "$2" "$3" < "$4"')
        self.assertIn("assert sys.prefix == str(p / 'python')", payload.SMOKE)
        self.assertIn("assert sys._is_gil_enabled()", payload.SMOKE)
        self.assertIn("assert set(os.environ) ==", payload.SMOKE)


if __name__ == "__main__":
    unittest.main()
