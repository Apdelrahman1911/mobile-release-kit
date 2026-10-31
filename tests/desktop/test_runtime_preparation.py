"""Inert publisher-preparation tests: tiny text files, never an executed runtime.

Select this class explicitly. It does not qualify installation or native custody.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import marshal
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

_SOURCE = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "desktop_runtime_preparation", _SOURCE / "desktop/tools/prepare_runtime.py"
)
assert _SPEC is not None and _SPEC.loader is not None
preparation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(preparation)


class MacCoreBytecodeDataTests(unittest.TestCase):
    """Code objects and inert ZIP bytes only; no payload or native execution."""
    def setUp(self):
        self.core = sorted([(name, b'def inert():\n    return 7\n')
                            for name in preparation.COMMAND_BYTECODE_FILES]
                           + [("mobile_release/fixture.json", b'{"inert":true}\n'),
                              ("mobile_release/metadata_images.py", b'# original source filename retained\n')])
        spec = importlib.util.spec_from_file_location(
            "mac_bytecode_stager_data", _SOURCE / "desktop/tools/stage_macos_installed.py")
        self.stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.stager)
        self.projection = {"src/" + name: (content, 0o444) for name, content in self.core}

    def zip_bytes(self, rows):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in rows:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)
        return buffer.getvalue()

    def compiler_data(self, *, version=(3, 14, 7), optimized=0, implementation="cpython"):
        # A finite profile-parser branch check. The actual host's compiler
        # emits all inert code objects; this mock never qualifies CPython 3.14.7.
        return SimpleNamespace(version_info=version, flags=SimpleNamespace(optimize=optimized),
                               implementation=SimpleNamespace(name=implementation))

    def test_every_derived_byte_matches_original_source_without_executing_it(self):
        rows = preparation._checked_core_bytecode(self.core)
        self.assertEqual(rows, preparation._checked_core_bytecode(self.core))
        self.assertEqual({name: body for name, body in rows if not name.endswith(".pyc")}, dict(self.core))
        for name, content in self.core:
            if name not in preparation.COMMAND_BYTECODE_FILES:
                continue
            bytecode = dict(rows)[name[:-3] + ".pyc"]
            self.assertEqual(bytecode[:4], importlib.util.MAGIC_NUMBER)
            self.assertEqual(bytecode[4:8], (3).to_bytes(4, "little"))
            self.assertEqual(bytecode[8:16], importlib.util.source_hash(content))
            original_code = compile(content, name, "exec", dont_inherit=True, optimize=0)
            original_owner = (original_code,)
            self.assertEqual(bytecode[16:], marshal.dumps(original_owner[0]))
        with patch.object(self.stager, "sys", self.compiler_data()):
            self.stager.current_core_matches(self.zip_bytes(rows), self.projection, macos_command_bytecode=True)
        # The original source-only profile never silently accepts derived files.
        with self.assertRaises(self.stager.Refused):
            self.stager.current_core_matches(self.zip_bytes(rows), self.projection)

    def test_compiled_root_reference_flag_is_stable_with_retained_original(self):
        from importlib import _bootstrap_external
        rows = dict(preparation._checked_core_bytecode(self.core))
        for name, source in self.core:
            if name not in preparation.COMMAND_BYTECODE_FILES:
                continue
            code = compile(source, name, "exec", dont_inherit=True, optimize=0)
            owner = (code,)
            expected = marshal.dumps(owner[0])
            self.assertEqual(expected[0], ord("c") | 0x80)
            generated = bytes(_bootstrap_external._code_to_hash_pyc(
                owner[0], importlib.util.source_hash(source), checked=True))
            self.assertEqual(generated[16:], expected)
            self.assertEqual(rows[name[:-3] + ".pyc"], generated)

    def test_independent_stager_rejects_missing_extra_foreign_and_source_only_substitutions(self):
        rows = preparation._checked_core_bytecode(self.core)
        pyc_name = "mobile_release/_command_process.pyc"
        bytecode = dict(rows)[pyc_name]
        for fault in ("missing-source", "missing-bytecode", "extra-bytecode", "foreign-code",
                      "wrong-source-hash", "wrong-magic", "source-only", "duplicate"):
            with self.subTest(fault=fault):
                changed = list(rows)
                if fault == "missing-source": changed = [(n, b) for n, b in rows if n != "mobile_release/_command_process.py"]
                elif fault == "missing-bytecode": changed = [(n, b) for n, b in rows if n != pyc_name]
                elif fault == "extra-bytecode": changed = sorted(rows + [("mobile_release/foreign.pyc", bytecode)])
                elif fault == "source-only": changed = self.core
                elif fault == "duplicate": changed = sorted(rows + [(pyc_name, bytecode)])
                else:
                    if fault == "foreign-code": modified = bytecode[:16] + marshal.dumps(compile("x = 99", "mobile_release/_command_process.py", "exec", dont_inherit=True, optimize=0))
                    elif fault == "wrong-source-hash": modified = bytecode[:8] + b"0" * 8 + bytecode[16:]
                    else: modified = b"0000" + bytecode[4:]
                    changed = [(n, modified if n == pyc_name else b) for n, b in rows]
                with patch.object(self.stager, "sys", self.compiler_data()), self.assertRaises(self.stager.Refused):
                    self.stager.current_core_matches(self.zip_bytes(changed), self.projection, macos_command_bytecode=True)

    def test_generated_input_compiler_profile_and_original_byte_bound_fail_closed(self):
        for core in (self.core + [("mobile_release/foreign.pyc", b"inert")],
                     self.core + [self.core[0]], [("mobile_release/../foreign.py", b"inert")]):
            with self.assertRaises(preparation.PreparationError): preparation._checked_core_bytecode(core)
        source_bytes = sum(len(content) for _, content in self.core)
        with patch.object(preparation, "MAX_CORE_BYTES", source_bytes):
            with self.assertRaises(preparation.PreparationError): preparation._checked_core_bytecode(self.core)
        for profile in (self.compiler_data(version=(3, 14, 6)), self.compiler_data(optimized=1),
                        self.compiler_data(implementation="other")):
            with patch.object(preparation, "sys", profile), self.assertRaises(preparation.PreparationError):
                preparation._require_core_compiler()
            with patch.object(self.stager, "sys", profile), self.assertRaises(self.stager.Refused):
                self.stager.current_core_matches(self.zip_bytes(self.core), self.projection, macos_command_bytecode=True)
        for target, options in (("x86_64-apple-darwin", dict(history_provider=True, store_component=Path("/inert"))),
                                ("aarch64-apple-darwin", dict(history_provider=True)),
                                ("aarch64-apple-darwin", dict(store_component=Path("/inert")))):
            with self.assertRaises(preparation.PreparationError):
                preparation.prepare_current(Path("/inert"), Path("/inert"), target, macos_command_bytecode=True, **options)

    @unittest.skipIf(sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 7),
                     "requires the original fixed CPython 3.14.7 DATA compiler")
    def test_actual_compiler_derives_and_independently_verifies_the_complete_current_core(self):
        preparation._require_core_compiler()
        package = preparation._root(_SOURCE / "src/mobile_release")
        paths = preparation.files(package)
        originals, core, size = [], [], 0
        for path in paths:
            original = preparation._state(preparation._ordinary(path))
            content = preparation.read_checked(path, limit=preparation.MAX_CORE_BYTES - size)
            size += len(content)
            name = "mobile_release/" + path.relative_to(package).as_posix()
            core.append((name, content)); originals.append((path, original))
        generated = preparation._checked_core_bytecode(core)
        self.assertLessEqual(sum(len(content) for _, content in generated), preparation.MAX_CORE_BYTES)
        self.assertEqual(len(generated), len(core) + len(preparation.COMMAND_BYTECODE_FILES))
        projection = {"src/" + name: (content, 0o444) for name, content in core}
        self.stager.current_core_matches(self.zip_bytes(generated), projection, macos_command_bytecode=True)
        for path, original in originals:
            self.assertEqual(preparation._state(preparation._ordinary(path)), original)


class RuntimePreparationTests(unittest.TestCase):
    def test_windows_checked_reader_keeps_descriptor_change_time_after_suffix_normalization(self):
        # Exercise the actual bounded reader on inert bytes, mocking only the
        # CPython 3.14 Windows metadata shape. This is not native Windows proof.
        content = b"INERT FILE DATA; NEVER EXECUTED\n"
        common = {"st_dev": 7, "st_ino": 13, "st_nlink": 1, "st_size": len(content),
                  "st_mtime_ns": 10000, "st_birthtime_ns": 2000,
                  "st_file_attributes": 0x20, "st_reparse_tag": 0}
        named = SimpleNamespace(**common, st_mode=stat.S_IFREG | 0o777, st_ctime_ns=2000)
        opened = SimpleNamespace(**common, st_mode=stat.S_IFREG | 0o666, st_ctime_ns=3000)
        changed = SimpleNamespace(**common, st_mode=stat.S_IFREG | 0o666, st_ctime_ns=3001)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "python.exe"
            path.write_bytes(content)
            descriptor_stat = Mock(side_effect=[opened, opened])
            with patch.object(preparation, "os", SimpleNamespace(name="nt", fstat=descriptor_stat)), \
                    patch.object(type(path), "lstat", return_value=named) as named_stat:
                self.assertEqual(preparation.read_checked(path, limit=1024), content)
                self.assertEqual(descriptor_stat.call_count, 2)
                self.assertEqual(named_stat.call_count, 2)
            descriptor_stat = Mock(side_effect=[opened, changed])
            with patch.object(preparation, "os", SimpleNamespace(name="nt", fstat=descriptor_stat)), \
                    patch.object(type(path), "lstat", return_value=named):
                with self.assertRaisesRegex(preparation.PreparationError, "changed during reading"):
                    preparation.read_checked(path, limit=1024)
                self.assertEqual(descriptor_stat.call_count, 2)
            self.assertEqual(path.read_bytes(), content)

    def test_portable_names_and_complete_path_depth_match_the_inspector(self):
        for name in ("core.zip", "engine_bootstrap.py", "libstdc++.so.6", "python3", "data-1"):
            self.assertTrue(preparation._safe_name(name), name)
        for name in ("", ".", "..", "trailing.", "x ", "é.py", "a:b", "a/b", "a\\b",
                     "NUL.txt", "com1", "LPT9.log", "file\x00name"):
            self.assertFalse(preparation._safe_name(name), repr(name))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root
            for _ in range(15):
                parent = parent / "a"
                parent.mkdir()
            leaf = parent / "file.txt"
            leaf.write_bytes(b"inert")
            self.assertEqual(preparation.files(root), [leaf])
            leaf.unlink()
            deeper = parent / "a"
            deeper.mkdir()
            (deeper / "file.txt").write_bytes(b"inert")
            with self.assertRaises(preparation.PreparationError):
                preparation.files(root)

    def test_manifest_entry_reservation_empty_directories_and_case_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").write_bytes(b"1")
            (root / "two").write_bytes(b"2")
            with patch.object(preparation, "MAX_ENTRIES", 2):
                self.assertEqual(len(preparation.files(root)), 2)
                with self.assertRaises(preparation.PreparationError):
                    preparation.files(root, reserve_entries=1)
            with patch.object(preparation, "MAX_FILES", 1):
                with self.assertRaises(preparation.PreparationError):
                    preparation.files(root)
            empty = root / "empty"
            empty.mkdir()
            with self.assertRaises(preparation.PreparationError):
                preparation.files(root)
            self.assertTrue(empty.is_dir())  # No repairing/deleting publisher input.
            empty.rmdir()
            with patch.object(preparation, "_safe_name", return_value=True):
                # Native case collision coverage is platform-dependent; the
                # inventory's folded-name policy itself remains shared.
                (root / "ONE").write_bytes(b"collision")
                if len(list(root.iterdir())) == 3:
                    with self.assertRaises(preparation.PreparationError):
                        preparation.files(root)

    def test_deterministic_preparation_is_inspection_only_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            package = source / "src/mobile_release"
            package.mkdir(parents=True)
            (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
            (package / "_desktop_engine.py").write_bytes(b"# inert source; never imported\n")
            (source / "desktop").mkdir()
            for bootstrap in preparation.BOOTSTRAPS:
                (source / "desktop" / bootstrap).write_bytes(b"# inert bootstrap; never executed\n")
            # Deliberately not a real certificate or trust store. These tests
            # check opaque inventory bytes only, never TLS or trust admission.
            (source / "desktop/github-ca.pem").write_bytes(b"INERT CA INVENTORY DATA ONLY\n")
            manifests = []
            for name in ("first", "second"):
                runtime = base / name
                binary_dir = runtime / "python/bin"
                binary_dir.mkdir(parents=True)
                executable = binary_dir / "python3"
                executable.write_bytes(b"not an executable; fixture data only\n")
                result = preparation.prepare(source, runtime, "x86_64-unknown-linux-gnu")
                encoded = (runtime / "manifest.json").read_bytes()
                manifests.append(encoded)
                self.assertEqual(result["qualification"], "prepared-not-native-verified")
                self.assertEqual(result["manifestSha256"], hashlib.sha256(encoded).hexdigest())
                manifest = json.loads(encoded)
                self.assertEqual([item["path"] for item in manifest["files"]],
                                 ["android_build_bootstrap.py", "config_edit_bootstrap.py", "core.zip",
                                  "engine_bootstrap.py", "environment_bootstrap.py", "github-ca.pem",
                                  "github_connection_bootstrap.py", "offline_preflight_bootstrap.py",
                                  "python/bin/python3"])
                self.assertEqual(manifest["protocolSha256"], hashlib.sha256(
                    b"# inert source; never imported\n").hexdigest())
                for item in manifest["files"]:
                    data = (runtime / item["path"]).read_bytes()
                    self.assertEqual((item["size"], item["sha256"]),
                                     (len(data), hashlib.sha256(data).hexdigest()))
                with zipfile.ZipFile(runtime / "core.zip") as archive:
                    self.assertEqual(archive.namelist(),
                                     ["mobile_release/__init__.py", "mobile_release/_desktop_engine.py"])
                with self.assertRaises(preparation.PreparationError):
                    preparation.prepare(source, runtime, "x86_64-unknown-linux-gnu")
                self.assertEqual((runtime / "manifest.json").read_bytes(), encoded)
                self.assertEqual(executable.read_bytes(), b"not an executable; fixture data only\n")
            self.assertEqual(manifests[0], manifests[1])

    def test_current_roster_is_explicit_complete_and_missing_entry_is_no_partial_output(self):
        current_only = (
            "project_recovery_bootstrap.py", "github_preflight_bootstrap.py",
            "ios_archive_bootstrap.py", "github_release_bootstrap.py", "artifact_inspection_bootstrap.py", "github_setup_bootstrap.py", "github_history_bootstrap.py", "local_release_history_bootstrap.py",
            "github_auth_bootstrap.py", "tool_acquisition_bootstrap.py",
        )
        self.assertEqual(preparation.CURRENT_BOOTSTRAPS, (*preparation.BOOTSTRAPS, *current_only))
        self.assertEqual(set(preparation.CURRENT_BOOTSTRAPS) | {preparation.STORE_BOOTSTRAP,
                             preparation.STORE_PREPARE_BOOTSTRAP, preparation.STORE_EXECUTE_BOOTSTRAP, preparation.STORE_RECONCILE_BOOTSTRAP},
                         {path.name for path in (_SOURCE / "desktop").glob("*_bootstrap.py")})
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            package = source / "src/mobile_release"
            package.mkdir(parents=True)
            (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
            (package / "_desktop_engine.py").write_bytes(b"# inert protocol only\n")
            # Current first-party modules are enumerated from the real producer's
            # input tree, not copied into a historical supplier inventory.
            recovery_source = b"# inert workflow recovery SOURCE data; never imported\n"
            (package / "github_workflow_recovery.py").write_bytes(recovery_source)
            desktop = source / "desktop"
            desktop.mkdir()
            for name in (*preparation.BOOTSTRAPS, preparation.GITHUB_CA_NAME):
                (desktop / name).write_bytes(b"INERT DATA; NEVER EXECUTED\n")
            current = base / "current"
            (current / "python/bin").mkdir(parents=True)
            (current / "python/bin/python3").write_bytes(b"INERT SUPPLIER DATA\n")
            for name in current_only:
                with self.subTest(missing_current_entry=name):
                    with self.assertRaises(FileNotFoundError):
                        preparation.prepare_current(source, current, "x86_64-unknown-linux-gnu")
                    self.assertEqual({entry.name for entry in current.iterdir()}, {"python"})
                    (desktop / name).write_bytes(b"INERT CURRENT ENTRY; NEVER EXECUTED\n")
            preparation.prepare_current(source, current, "x86_64-unknown-linux-gnu")
            manifest = json.loads((current / "manifest.json").read_bytes())
            self.assertEqual({row["path"] for row in manifest["files"]},
                set(preparation.CURRENT_BOOTSTRAPS) | {"core.zip", "github-ca.pem", "python/bin/python3"})
            self.assertTrue(set(current_only).isdisjoint(preparation.BOOTSTRAPS))
            with zipfile.ZipFile(current / "core.zip") as archive:
                self.assertEqual(archive.namelist(), ["mobile_release/__init__.py",
                    "mobile_release/_desktop_engine.py", "mobile_release/github_workflow_recovery.py"])
                self.assertEqual(archive.read("mobile_release/github_workflow_recovery.py"), recovery_source)
            # This internal opt-in changes only the canonical inventory, not
            # Mach-O/signature/native admission (owned by the containing stager).
            provider_bytes = b"INERT tools/gh DATA; NEVER EXECUTED\n"
            def provider_input(label):
                runtime = base / label
                (runtime / "python/bin").mkdir(parents=True)
                (runtime / "python/bin/python3").write_bytes(b"INERT SUPPLIER DATA\n")
                (runtime / "tools").mkdir()
                gh = runtime / "tools/gh"
                gh.write_bytes(provider_bytes)
                gh.chmod(0o555)
                return runtime, gh
            for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
                runtime, gh = provider_input("provider-" + target)
                initial = preparation._state(gh.stat())
                prepared = preparation.prepare_current(source, runtime, target, history_provider=True)
                encoded = (runtime / "manifest.json").read_bytes()
                current_manifest = json.loads(encoded)
                self.assertEqual(prepared["manifestSha256"], hashlib.sha256(encoded).hexdigest())
                self.assertEqual(current_manifest["target"], target)
                self.assertEqual(current_manifest["files"], sorted(current_manifest["files"], key=lambda row: row["path"]))
                self.assertEqual({row["path"] for row in current_manifest["files"]},
                    set(preparation.CURRENT_BOOTSTRAPS) | {"core.zip", "github-ca.pem", "python/bin/python3", "tools/gh"})
                self.assertEqual([row for row in current_manifest["files"] if row["path"] == "tools/gh"],
                    [{"path": "tools/gh", "size": len(provider_bytes), "sha256": hashlib.sha256(provider_bytes).hexdigest()}])
                self.assertEqual(gh.read_bytes(), provider_bytes)
                self.assertEqual(preparation._state(gh.stat()), initial)
                self.assertEqual(stat.S_IMODE(gh.stat().st_mode), 0o555)

            for case in ("default", "historical", "linux", "not-bool", "unknown-sibling", "empty-directory",
                         "wrong-mode", "zero-bytes", "file-capacity", "byte-capacity"):
                runtime, gh = provider_input("refuse-provider-" + case)
                call = preparation.prepare_current
                target, options = "aarch64-apple-darwin", {"history_provider": True}
                if case == "default": options = {}
                if case == "historical": call, options = preparation.prepare, {}
                if case == "linux": target = "x86_64-unknown-linux-gnu"
                if case == "not-bool": options = {"history_provider": 1}
                if case == "unknown-sibling": (runtime / "tools/other").write_bytes(b"unknown")
                if case == "empty-directory": (runtime / "tools/empty").mkdir()
                if case == "wrong-mode": gh.chmod(0o444)
                if case == "zero-bytes":
                    gh.chmod(0o755)
                    gh.write_bytes(b"")
                    gh.chmod(0o555)
                bound, limit = (("MAC_MAX_FILES", len(preparation.CURRENT_BOOTSTRAPS) + 4) if case == "file-capacity"
                                else ("MAX_TOTAL_BYTES", 1) if case == "byte-capacity" else
                                ("MAX_TOTAL_BYTES", preparation.MAX_TOTAL_BYTES))
                with self.subTest(history_provider=case), patch.object(preparation, bound, limit):
                    with self.assertRaises(preparation.PreparationError):
                        call(source, runtime, target, **options)
                self.assertEqual({path.name for path in runtime.iterdir()}, {"python", "tools"})
                self.assertFalse((runtime / "manifest.json").exists())

            runtime, gh = provider_input("provider-post-swap")
            original_read = preparation.read_checked
            observed = []
            def change_after_read(path, *, limit):
                value = original_read(path, limit=limit)
                if path == gh and not observed:
                    observed.append(path)
                    gh.chmod(0o755)
                    gh.write_bytes(provider_bytes + b"changed")
                    gh.chmod(0o555)
                return value
            with patch.object(preparation, "read_checked", side_effect=change_after_read):
                with self.assertRaisesRegex(preparation.PreparationError, "Current provider original changed"):
                    preparation.prepare_current(source, runtime, "aarch64-apple-darwin", history_provider=True)
            self.assertEqual(observed, [gh])
            self.assertFalse((runtime / "manifest.json").exists())

    def test_payload_capacity_refuses_before_creating_any_generated_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            runtime = base / "runtime"
            binary_dir = runtime / "python/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python3").write_bytes(b"inert, not executable")
            # One supplier file plus the selected bootstraps/core/CA and the
            # manifest must fit, including the two supplier directories.
            for prepare, names in ((preparation.prepare, preparation.BOOTSTRAPS),
                                   (preparation.prepare_current, preparation.CURRENT_BOOTSTRAPS)):
                for bound, limit in (("MAX_FILES", len(names) + 2), ("MAX_ENTRIES", len(names) + 5)):
                    with self.subTest(profile=prepare.__name__, bound=bound), patch.object(preparation, bound, limit):
                        with self.assertRaises(preparation.PreparationError):
                            prepare(source, runtime, "x86_64-unknown-linux-gnu")
                    self.assertEqual({entry.name for entry in runtime.iterdir()}, {"python"})

    def test_missing_edit_bootstrap_preserves_inputs_before_any_output_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            package = source / "src/mobile_release"
            package.mkdir(parents=True)
            (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
            (package / "_desktop_engine.py").write_bytes(b"# inert protocol source\n")
            (source / "desktop").mkdir()
            passive = source / "desktop/engine_bootstrap.py"
            passive.write_bytes(b"# inert passive bootstrap\n")
            runtime = base / "runtime"
            binary_dir = runtime / "python/bin"
            binary_dir.mkdir(parents=True)
            executable = binary_dir / "python3"
            executable.write_bytes(b"inert, not executable")
            with self.assertRaises(FileNotFoundError):
                preparation.prepare(source, runtime, "x86_64-unknown-linux-gnu")
            self.assertEqual({entry.name for entry in runtime.iterdir()}, {"python"})
            self.assertEqual(executable.read_bytes(), b"inert, not executable")
            self.assertEqual(passive.read_bytes(), b"# inert passive bootstrap\n")

    def test_missing_or_invalid_github_inputs_refuse_before_any_output_write(self):
        for failure in (*preparation.BOOTSTRAPS, "ca", "empty-ca", "large-ca"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                source = base / "source"
                package = source / "src/mobile_release"
                package.mkdir(parents=True)
                (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
                (package / "_desktop_engine.py").write_bytes(b"# inert protocol source\n")
                desktop = source / "desktop"
                desktop.mkdir()
                for name in preparation.BOOTSTRAPS:
                    if name != failure:
                        (desktop / name).write_bytes(b"# inert, never executed\n")
                if failure != "ca":
                    (desktop / "github-ca.pem").write_bytes(
                        b"" if failure == "empty-ca" else b"INERT CA INVENTORY DATA ONLY\n")
                runtime = base / "runtime"
                binary_dir = runtime / "python/bin"
                binary_dir.mkdir(parents=True)
                executable = binary_dir / "python3"
                executable.write_bytes(b"inert, not executable")
                limit = 1 if failure == "large-ca" else preparation.MAX_GITHUB_CA_BYTES
                with patch.object(preparation, "MAX_GITHUB_CA_BYTES", limit):
                    with self.assertRaises((FileNotFoundError, preparation.PreparationError)):
                        preparation.prepare(source, runtime, "x86_64-unknown-linux-gnu")
                self.assertEqual({entry.name for entry in runtime.iterdir()}, {"python"})
                self.assertEqual(executable.read_bytes(), b"inert, not executable")


class StoreRuntimeCompositionTests(unittest.TestCase):
    """Only inert file composition; no Ruby, signature or Store execution."""

    def fixture(self, base, *, history=False):
        source, runtime, component = base / "source", base / "runtime", base / "component"
        package = source / "src/mobile_release"
        package.mkdir(parents=True)
        (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
        (package / "_desktop_engine.py").write_bytes(b"# inert protocol\n")
        (package / "tooling.py").write_bytes((_SOURCE / "src/mobile_release/tooling.py").read_bytes())
        (source / "desktop").mkdir()
        for name in (*preparation.CURRENT_BOOTSTRAPS, preparation.STORE_BOOTSTRAP,
                     preparation.STORE_PREPARE_BOOTSTRAP, preparation.STORE_EXECUTE_BOOTSTRAP, preparation.STORE_RECONCILE_BOOTSTRAP, preparation.GITHUB_CA_NAME):
            (source / "desktop" / name).write_bytes(b"inert first-party payload\n")
        (runtime / "python/bin").mkdir(parents=True)
        (runtime / "python/bin/python3").write_bytes(b"inert Python\n")
        if history:
            (runtime / "tools").mkdir()
            (runtime / "tools/gh").write_bytes(b"inert gh\n")
            (runtime / "tools/gh").chmod(0o555)
        for name in preparation.STORE_REQUIRED_FILES | {"bin/gem", "lib/native/example.bundle"}:
            path = component / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"#!/bin/sh\n# inert, never executed\n" if name == "bin/bundle" else b"inert component\n")
            path.chmod(0o755)
        for name in preparation._store_tooling_files(source)[0]:
            for root in (source, component / "tooling"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"inert current tooling\n")
        return source, runtime, component

    def test_complete_composition_preserves_bytes_and_only_fixed_executable_roles(self):
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                source, runtime, component = self.fixture(Path(temporary), history=True)
                if target == "aarch64-apple-darwin":
                    # Actual retained/copy/POST tree above the former 2048 cap;
                    # larger maximum row counts are checked by bounded parsers.
                    extras=component / "lib/inert-large-roster"
                    extras.mkdir()
                    for index in range(2050):
                        (extras / f"f{index:05}").write_bytes(b"inert")
                # Reuse unchanged dependency bytes, but never the component's
                # old first-party tooling; selected source owns the full subtree.
                (component / "tooling/fastlane/run_lane.rb").write_bytes(b"stale dependency-component tooling")
                (component / "tooling/obsolete.rb").write_bytes(b"not selected")
                names=preparation._store_tooling_files(source)[0]+("fastlane/new_required.rb",)
                (source / "src/mobile_release/tooling.py").write_text("REQUIRED_TOOLING_FILES = "+repr(names)+"\n")
                (source / "fastlane/new_required.rb").write_bytes(b"current extra tooling")
                selected={"tooling/"+name:(source / name).read_bytes() for name in names}
                originals = {path.relative_to(component).as_posix(): (path.read_bytes(), preparation._state(path.stat()))
                             for path in preparation.files(component, max_files=preparation.MAC_MAX_FILES,
                                                          max_entries=preparation.MAC_MAX_ENTRIES)}
                (component / "unused").mkdir()  # Valid empty supplier directory, not output.
                result = preparation.prepare_current(source, runtime, target, history_provider=True,
                                                      store_component=component)
                encoded = (runtime / "manifest.json").read_bytes()
                self.assertEqual(result["manifestSha256"], hashlib.sha256(encoded).hexdigest())
                self.assertEqual(result["qualification"], "prepared-not-native-verified")
                rows = json.loads(encoded)["files"]
                copied = {row["path"][6:]: row for row in rows if row["path"].startswith("store/")}
                expected={name:body for name,(body,_) in originals.items() if not name.startswith("tooling/")} | selected
                self.assertEqual(set(copied), set(expected))
                for name, body in expected.items():
                    self.assertEqual((runtime / "store" / name).read_bytes(), body)
                    self.assertEqual(copied[name]["size"], len(body))
                    self.assertEqual(copied[name]["sha256"], hashlib.sha256(body).hexdigest())
                    self.assertEqual(stat.S_IMODE((runtime / "store" / name).stat().st_mode),
                                     0o555 if name in preparation.STORE_EXECUTABLES else 0o444)
                for name, (body,state) in originals.items():
                    self.assertEqual((component / name).read_bytes(),body)
                    self.assertEqual(preparation._state((component / name).stat()), state)
                self.assertFalse((runtime / "store/tooling/obsolete.rb").exists())
                self.assertTrue((component / "unused").is_dir())
                self.assertFalse((runtime / "store/unused").exists())
                self.assertIn("tools/gh", {row["path"] for row in rows})
                self.assertIn("core.zip", {row["path"] for row in rows})
                for name in (preparation.STORE_BOOTSTRAP, preparation.STORE_PREPARE_BOOTSTRAP,
                             preparation.STORE_EXECUTE_BOOTSTRAP, preparation.STORE_RECONCILE_BOOTSTRAP):
                    self.assertIn(name, {row["path"] for row in rows})
                    self.assertEqual((runtime / name).read_bytes(), (source / "desktop" / name).read_bytes())
                    # Private preparation output; final stager normalizes to0444.
                    self.assertEqual(stat.S_IMODE((runtime / name).stat().st_mode), 0o600)

    def test_refusals_precede_output_and_keep_unknown_inputs(self):
        for case in ("platform", "missing", "missing-execute", "missing-reconcile", "tooling", "changed-gemfile", "changed-lock", "missing-component-lock", "new-core-requirement", "invalid-core-roster", "wrapper", "entry-mode", "link", "case",
                     "invalid-directory", "depth", "file-limit", "byte-limit", "existing-store", "overlap"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                source, runtime, component = self.fixture(Path(temporary))
                target = "x86_64-unknown-linux-gnu" if case == "platform" else "aarch64-apple-darwin"
                if case == "missing": (component / "ca.pem").unlink()
                if case == "missing-execute": (source / "desktop" / preparation.STORE_EXECUTE_BOOTSTRAP).unlink()
                if case == "missing-reconcile": (source / "desktop" / preparation.STORE_RECONCILE_BOOTSTRAP).unlink()
                if case == "tooling": (source / "Gemfile").unlink()
                if case == "changed-gemfile": (source / "Gemfile").write_bytes(b"new dependency")
                if case == "changed-lock": (source / "Gemfile.lock").write_bytes(b"new locked version")
                if case == "missing-component-lock": (component / "tooling/Gemfile.lock").unlink()
                if case == "new-core-requirement":
                    names=preparation._store_tooling_files(source)[0]+("required-new.rb",)
                    (source / "src/mobile_release/tooling.py").write_text("REQUIRED_TOOLING_FILES = "+repr(names)+"\n")
                if case == "invalid-core-roster":
                    (source / "src/mobile_release/tooling.py").write_bytes(b'REQUIRED_TOOLING_FILES = ("../outside.rb",)\n')
                if case == "wrapper": (component / "bin/bundle").write_bytes(b"#!/usr/bin/env sh\n")
                if case == "entry-mode": (component / "bin/ruby").chmod(0o644)
                if case == "link": (component / "linked").symlink_to(component / "ca.pem")
                if case == "case": (component / "CA.pem").write_bytes(b"collision")
                if case == "invalid-directory": (component / "unsafe.").mkdir()
                if case == "depth":
                    nested = component.joinpath(*(["deep"] * preparation.MAX_PATH_PARTS), "file")
                    nested.parent.mkdir(parents=True)
                    nested.write_bytes(b"too deep under store/")
                if case == "existing-store":
                    (runtime / "store").mkdir()
                    (runtime / "store/keep").write_bytes(b"existing user data")
                if case == "overlap": component = runtime
                limit = (len(preparation.files(component)) + len(preparation.CURRENT_BOOTSTRAPS) + 1
                         if case == "file-limit" else preparation.MAC_MAX_FILES)
                with patch.object(preparation, "MAC_MAX_FILES", limit), \
                        patch.object(preparation, "MAX_TOTAL_BYTES", 1 if case == "byte-limit" else preparation.MAX_TOTAL_BYTES):
                    with self.assertRaises((preparation.PreparationError, FileNotFoundError)):
                        preparation.prepare_current(source, runtime, target, store_component=component)
                self.assertFalse((runtime / "manifest.json").exists())
                self.assertFalse((runtime / "core.zip").exists())
                self.assertEqual({entry.name for entry in runtime.iterdir()},
                                 {"python", "store"} if case == "existing-store" else {"python"})
                if case == "existing-store":
                    self.assertEqual((runtime / "store/keep").read_bytes(), b"existing user data")

    def test_changed_original_and_copied_bytes_cannot_receive_manifest(self):
        for case in ("input-during-copy", "tooling-input-during-copy", "output-during-inventory", "core-roster-after-observation"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                source, runtime, component = self.fixture(Path(temporary))
                original = preparation.read_checked
                changed = []
                def read(path, *, limit):
                    body = original(path, limit=limit)
                    if not changed and case == "input-during-copy" and (runtime / "store").exists() and path == component / "ca.pem":
                        path.write_bytes(body + b"changed")
                        changed.append(path)
                    if not changed and case == "tooling-input-during-copy" and (runtime / "store").exists() and path == source / "Gemfile":
                        path.write_bytes(body+b"changed current tooling")
                        changed.append(path)
                    if not changed and case == "output-during-inventory" and path == runtime / "store/ca.pem":
                        changed.append(path)
                        return body + b"changed"
                    if not changed and case == "core-roster-after-observation" and path == source / "src/mobile_release/tooling.py":
                        path.write_bytes(body + b"\n# changed selected source\n")
                        changed.append(path)
                    return body
                with patch.object(preparation, "read_checked", side_effect=read):
                    with self.assertRaises(preparation.PreparationError):
                        preparation.prepare_current(source, runtime, "aarch64-apple-darwin", store_component=component)
                self.assertEqual(len(changed), 1)
                self.assertFalse((runtime / "manifest.json").exists())
                self.assertTrue(component.is_dir())  # Uncertain originals/partial output preserved.
