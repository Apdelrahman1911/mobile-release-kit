"""Inert publisher-preparation tests: tiny text files, never an executed runtime.

Select this class explicitly. It does not qualify installation or native custody.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

_SOURCE = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "desktop_runtime_preparation", _SOURCE / "desktop/tools/prepare_runtime.py"
)
assert _SPEC is not None and _SPEC.loader is not None
preparation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(preparation)


class RuntimePreparationTests(unittest.TestCase):
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
            (source / "desktop/engine_bootstrap.py").write_bytes(b"# inert bootstrap; never executed\n")
            (source / "desktop/config_edit_bootstrap.py").write_bytes(b"# inert edit bootstrap; never executed\n")
            (source / "desktop/github_connection_bootstrap.py").write_bytes(b"# inert GitHub bootstrap; never executed\n")
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
                                 ["config_edit_bootstrap.py", "core.zip", "engine_bootstrap.py",
                                  "github-ca.pem", "github_connection_bootstrap.py", "python/bin/python3"])
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

    def test_payload_capacity_refuses_before_creating_any_generated_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            runtime = base / "runtime"
            binary_dir = runtime / "python/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python3").write_bytes(b"inert, not executable")
            # One Python file plus three bootstraps/core/CA requires six payload
            # slots; the manifest is separately reserved, not a payload.
            with patch.object(preparation, "MAX_FILES", 5):
                with self.assertRaises(preparation.PreparationError):
                    preparation.prepare(source, runtime, "x86_64-unknown-linux-gnu")
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
        for failure in ("bootstrap", "ca", "empty-ca", "large-ca"):
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
                    if not (failure == "bootstrap" and name == "github_connection_bootstrap.py"):
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
