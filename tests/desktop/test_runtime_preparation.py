"""Inert publisher-preparation tests: tiny text files, never an executed runtime.

Select this class explicitly. It does not qualify installation or native custody.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import marshal
import os
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


# The real C/A/W helper import (bootstrap plus _native_process._abi_types(),
# pure ctypes types, no library load), with NOTHING imported first (sys is
# builtin). Run under -v: the interpreter itself reports every source
# compilation and every accepted cache from its very start, including the
# encodings bootstrap that precedes -c, so no Python-level hook can miss one.
_CLOSURE_PROBE = r'''
import sys
sys.path.insert(0, sys.argv[1])
from mobile_release._command_process import helper_main
from mobile_release import _native_process
_native_process._abi_types()
'''


def _import_events(stderr: bytes, library: Path) -> tuple[set[str], set[str]]:
    """(stdlib sources compiled, stdlib sources whose cache was accepted) from -v."""
    root, compiled, cached = str(library) + os.sep, set(), set()
    for line in stderr.decode("utf-8", "surrogateescape").splitlines():
        if line.startswith("# code object from ") and not line.startswith("# code object from '"):
            path = line[len("# code object from "):]
            if path.startswith(root) and path.endswith(".py"):
                compiled.add(path[len(root):])
        elif line.startswith("# ") and " matches " in line:
            path = line.rsplit(" matches ", 1)[1]
            if path.startswith(root) and path.endswith(".py"):
                cached.add(path[len(root):])
    return compiled, cached


_DERIVE_PROBE = r'''
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("p", sys.argv[1])
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
if sys.argv[2] == "noisy":
    # ctypes/inspect/typing/weakref live code holds interned qualnames equal
    # to string constants of the same sources: plain marshal.dumps diverged.
    import ctypes, inspect, typing, weakref, functools, dataclasses, subprocess, tempfile, shutil, json.decoder
lib = os.path.dirname(os.__file__)
sources = {p.STDLIB_ROOT + n: open(os.path.join(lib, n), "rb").read() for n in p.COMMAND_STDLIB_BYTECODE_FILES}
rows = p._checked_stdlib_bytecode(frozenset(sources), sources)
print(json.dumps({name: body.hex() for name, body in rows}))
'''


class MacStdlibBytecodeDataTests(unittest.TestCase):
    """#17: stdlib command-startup bytecode derivation and independent rederivation."""
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "mac_stdlib_bytecode_stager_data", _SOURCE / "desktop/tools/stage_macos_installed.py")
        self.stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.stager)
        # Inert code objects; the actual-compiler test below uses real sources.
        self.sources = {preparation.STDLIB_ROOT + name: b"def inert():\n    return %d\n" % index
                        for index, name in enumerate(sorted(preparation.COMMAND_STDLIB_BYTECODE_FILES))}
        self.supplier = {"python/bin/python3": (b"inert-executable", 0o555),
                         preparation.STDLIB_ROOT + "unrelated.py": (b"# not in the startup roster\n", 0o444),
                         **{name: (content, 0o444) for name, content in self.sources.items()}}

    @staticmethod
    def profile(*, version=(3, 14, 7), optimized=0, implementation="cpython", tag="cpython-314"):
        # Only the fixed profile predicates are substituted; every code object is
        # still produced by this host's real compile()/marshal for BOTH sides.
        return SimpleNamespace(version_info=version, flags=SimpleNamespace(optimize=optimized),
                               implementation=SimpleNamespace(name=implementation, cache_tag=tag))

    def derive(self, supplier=None, sources=None):
        supplier = self.supplier if supplier is None else supplier
        with patch.object(preparation, "sys", self.profile()):
            return preparation._checked_stdlib_bytecode(frozenset(supplier), self.sources if sources is None else sources)

    def verify(self, files, supplier=None):
        with patch.object(self.stager, "sys", self.profile()):
            return self.stager.current_stdlib_bytecode_matches(files, self.supplier if supplier is None else supplier)

    def test_both_rosters_are_identical_and_name_only_source_loaded_modules(self):
        self.assertEqual(preparation.COMMAND_STDLIB_BYTECODE_FILES, self.stager.CURRENT_COMMAND_STDLIB_BYTECODE_FILES)
        self.assertEqual((preparation.STDLIB_ROOT, preparation.STDLIB_CACHE_TAG),
                         (self.stager.CURRENT_STDLIB_ROOT, self.stager.CURRENT_STDLIB_CACHE_TAG))
        self.assertEqual(len(preparation.COMMAND_STDLIB_BYTECODE_FILES), 64)
        # Frozen modules never read bytecode; adding them would be dead payload.
        for frozen in ("os.py", "io.py", "abc.py", "codecs.py", "stat.py", "posixpath.py", "genericpath.py",
                       "ntpath.py", "_collections_abc.py", "zipimport.py", "importlib/_bootstrap.py",
                       "importlib/_bootstrap_external.py", "importlib/machinery.py"):
            self.assertNotIn(frozen, preparation.COMMAND_STDLIB_BYTECODE_FILES)
        self.assertEqual(preparation.stdlib_bytecode_name("json/decoder.py"),
                         "python/lib/python3.14/json/__pycache__/decoder.cpython-314.pyc")
        self.assertEqual(preparation.stdlib_bytecode_name("typing.py"),
                         "python/lib/python3.14/__pycache__/typing.cpython-314.pyc")
        with self.assertRaises(preparation.PreparationError):
            preparation.stdlib_bytecode_name("os.py")

    @unittest.skipIf(sys.platform != "darwin" or sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14),
                     "the closed helper closure is defined for the Mac CPython 3.14 runtime")
    def test_roster_is_exactly_the_real_helper_source_import_closure(self):
        # A NEW stdlib import in the helper closure must update both rosters;
        # otherwise every owned command silently recompiles it again (#17).
        import subprocess
        library = Path(os.__file__).parent
        with tempfile.TemporaryDirectory() as empty:
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-v", "-X", "pycache_prefix=" + empty, "-c",
                                     _CLOSURE_PROBE, str(_SOURCE / "src")], capture_output=True, check=True, timeout=60)
            self.assertEqual(os.listdir(empty), [])
        compiled, cached = _import_events(result.stderr, library)
        self.assertEqual(cached, set())  # Empty prefix: every stdlib import is a source compile.
        self.assertIn("encodings/__init__.py", compiled)  # Startup, before -c, is observed too.
        # A full interpreter with the _zstd extension continues into one more
        # module; the signed runtime refuses compression.zstd before it.
        optional = {"compression/zstd/_zstdfile.py"} if importlib.util.find_spec("_zstd") else set()
        self.assertEqual(compiled - optional, set(preparation.COMMAND_STDLIB_BYTECODE_FILES))

    def test_every_derived_byte_is_independently_rederived_and_sources_are_retained(self):
        rows = self.derive()
        self.assertEqual(rows, self.derive())
        self.assertEqual(len(rows), 64)
        files = {**self.supplier, **{name: (body, 0o600) for name, body in rows}}
        self.assertEqual(self.verify(files), {name for name, _ in rows})
        for name, body in rows:
            source = name.replace("/__pycache__", "").replace(".cpython-314.pyc", ".py")
            content = self.sources[source]
            self.assertEqual(body[:4], importlib.util.MAGIC_NUMBER)
            self.assertEqual(body[4:8], (3).to_bytes(4, "little"))  # Hash-based AND checked.
            self.assertEqual(body[8:16], importlib.util.source_hash(content))
            self.assertEqual(marshal.loads(body[16:]).co_filename, source)  # Logical, reproducible.
            self.assertEqual(files[source], self.supplier[source])

    def test_importer_uses_checked_bytecode_and_never_runs_a_stale_one(self):
        rows = dict(self.derive())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in {**self.sources, **rows}.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content if name in self.sources else rows[name])
            source = root / preparation.STDLIB_ROOT / "json/decoder.py"
            loader = importlib.machinery.SourceFileLoader("mrk_inert_decoder", str(source))
            with patch.object(importlib.machinery.SourceFileLoader, "source_to_code",
                              side_effect=AssertionError("recompiled despite valid bytecode")):
                code = loader.get_code("mrk_inert_decoder")
            self.assertEqual(code.co_filename, str(source))  # Importer rebinds the logical name.
            source.write_bytes(b"def inert():\n    return 'changed'\n")
            compiled = []
            original = importlib.machinery.SourceFileLoader.source_to_code
            def recompile(loader_self, data, path, *args, **kwargs):
                compiled.append(path)
                return original(loader_self, data, path, *args, **kwargs)
            with patch.object(importlib.machinery.SourceFileLoader, "source_to_code", recompile), \
                    patch.object(sys, "dont_write_bytecode", True):
                stale = importlib.machinery.SourceFileLoader("mrk_inert_decoder", str(source)).get_code("mrk_inert_decoder")
            self.assertEqual(compiled, [str(source)])
            self.assertIn("changed", stale.co_consts[0].co_consts)

    def test_independent_verifier_refuses_every_malformed_stale_or_substituted_entry(self):
        # A docstring and assert make optimized code genuinely differ.
        decoder = "python/lib/python3.14/json/decoder.py"
        self.sources[decoder] = b'"""Inert."""\nassert len(__name__) > 0\ndef inert():\n    return 1\n'
        self.supplier[decoder] = (self.sources[decoder], 0o444)
        rows = dict(self.derive())
        target = "python/lib/python3.14/json/__pycache__/decoder.cpython-314.pyc"
        sibling = "python/lib/python3.14/json/__pycache__/encoder.cpython-314.pyc"
        body = rows[target]
        content = self.sources["python/lib/python3.14/json/decoder.py"]
        def recompiled(**kwargs):
            code = compile(content, kwargs.get("filename", "python/lib/python3.14/json/decoder.py"), "exec",
                           dont_inherit=True, optimize=kwargs.get("optimize", 0))
            return preparation._tree_marshal(marshal.dumps(code))
        faults = {
            "missing-bytecode": lambda f: f.pop(target),
            "extra-foreign-bytecode": lambda f: f.update({"python/lib/python3.14/__pycache__/foreign.cpython-314.pyc": (body, 0o600)}),
            "extra-optimized-name": lambda f: f.update({target[:-4] + ".opt-1.pyc": (body, 0o600)}),
            "legacy-pyo": lambda f: f.update({"python/lib/python3.14/json/decoder.pyo": (body, 0o600)}),
            "path-substitution": lambda f: f.update({target: f[sibling], sibling: f[target]}),
            "stale-source": lambda f: f.update({"python/lib/python3.14/json/decoder.py": (content + b"# edited\n", 0o444)}),
            "foreign-code": lambda f: f.update({target: (body[:16] + preparation._tree_marshal(
                marshal.dumps(compile("x = 99", "python/lib/python3.14/json/decoder.py", "exec"))), 0o600)}),
            "untreed-same-code": lambda f: f.update({target: (body[:16] + marshal.dumps(marshal.loads(body[16:])), 0o600)}),
            "trailing-bytes": lambda f: f.update({target: (body + b"N", 0o600)}),
            "wrong-magic": lambda f: f.update({target: (b"0000" + body[4:], 0o600)}),
            "timestamp-pyc": lambda f: f.update({target: (body[:4] + (0).to_bytes(4, "little") + body[8:], 0o600)}),
            "unchecked-hash": lambda f: f.update({target: (body[:4] + (1).to_bytes(4, "little") + body[8:], 0o600)}),
            "wrong-source-hash": lambda f: f.update({target: (body[:8] + b"0" * 8 + body[16:], 0o600)}),
            "optimized-code": lambda f: f.update({target: (body[:16] + recompiled(optimize=2), 0o600)}),
            "absolute-co-filename": lambda f: f.update({target: (body[:16] + recompiled(filename="/build/json/decoder.py"), 0o600)}),
            "truncated": lambda f: f.update({target: (body[:-1], 0o600)}),
        }
        for fault, change in faults.items():
            with self.subTest(fault=fault):
                files = {**self.supplier, **{name: (value, 0o600) for name, value in rows.items()}}
                supplier = dict(self.supplier)
                change(files)
                if fault == "stale-source":
                    supplier["python/lib/python3.14/json/decoder.py"] = files["python/lib/python3.14/json/decoder.py"]
                with self.assertRaises(self.stager.Refused):
                    self.verify(files, supplier)

    def test_tree_marshal_is_identity_free_value_preserving_and_fails_closed_on_both_sides(self):
        shared = "shared-" + "x" * 300
        code = compile(f"a = {shared!r}\nb = {shared!r}\nc = (1, 2.5, -7, 10 ** 40, b'raw', {{'k'}}, ..., None)\n"
                       "def f(x, *, y=None):\n    return x[1:2], sys\n", "python/lib/python3.14/inert.py", "exec",
                       dont_inherit=True, optimize=0)
        raw = marshal.dumps(code)
        tree = preparation._tree_marshal(raw)
        self.assertEqual(self.stager.current_tree_marshal(raw), tree)  # Two independent implementations.
        self.assertNotEqual(tree, raw)
        self.assertEqual(preparation._tree_marshal(tree), tree)  # Fixed point.
        self.assertEqual(marshal.loads(tree), code)
        # Exactly the process-state differences are erased: identity sharing,
        # FLAG_REF and intern marks. Values and types are not.
        text = "".join(["CFUNCTYPE.<locals>", ".CFunctionType"])
        twin = "".join(["CFUNCTYPE.<locals>", ".CFunctionType"])
        self.assertIsNot(text, twin)
        variants = [marshal.dumps((text, text)), marshal.dumps((text, twin)),
                    marshal.dumps((sys.intern(text), twin))]
        self.assertGreater(len(set(variants)), 1)
        for implementation in (preparation._tree_marshal, self.stager.current_tree_marshal):
            self.assertEqual(len({implementation(v) for v in variants}), 1)
            self.assertNotEqual(implementation(marshal.dumps((text, b"x"))), implementation(marshal.dumps((text, "x"))))
            self.assertNotEqual(implementation(marshal.dumps(1)), implementation(marshal.dumps(1.0)))
        bad = {
            "truncated": tree[:-1], "trailing": tree + b"N", "empty": b"",
            "unknown-type": b"?" + tree[1:], "dangling-reference": b"r" + (0).to_bytes(4, "little"),
            "flagged-reference": b"\xf2" + (0).to_bytes(4, "little"),
            "invalid-long": b"l" + (0).to_bytes(4, "little"),
            "oversized-sequence": b"(" + (1 << 30).to_bytes(4, "little"),
            "too-deep": b")\x01" * 200 + b"N",
        }
        for fault, stream in bad.items():
            with self.subTest(fault=fault):
                with self.assertRaises(preparation.PreparationError):
                    preparation._tree_marshal(stream)
                with self.assertRaises(self.stager.Refused):
                    self.stager.current_tree_marshal(stream)

    def test_incoming_bytecode_missing_sources_and_wrong_compiler_fail_closed_on_both_sides(self):
        incoming = dict(self.supplier, **{"python/lib/python3.14/__pycache__/typing.cpython-314.pyc": (b"cached", 0o444)})
        missing = {k: v for k, v in self.supplier.items() if k != "python/lib/python3.14/typing.py"}
        for supplier in (incoming, missing, dict(self.supplier, **{"python/lib/python3.14/x.pyo": (b"o", 0o444)})):
            with self.subTest(roster=sorted(set(supplier) ^ set(self.supplier))):
                with self.assertRaises(preparation.PreparationError):
                    self.derive(supplier, {k: v for k, v in self.sources.items() if k in supplier})
                with self.assertRaises(self.stager.Refused):
                    self.verify(dict(supplier), supplier)
        with self.assertRaises(preparation.PreparationError):  # Foreign/non-python supplier entry.
            self.derive(dict(self.supplier, **{"tools/gh": (b"x", 0o555)}))
        with self.assertRaises(preparation.PreparationError):  # Malformed original source.
            self.derive(sources=dict(self.sources, **{"python/lib/python3.14/typing.py": b"def broken(:\n"}))
        with patch.object(preparation, "MAX_STDLIB_BYTECODE_BYTES", 64), self.assertRaises(preparation.PreparationError):
            self.derive()
        for profile in (self.profile(version=(3, 14, 6)), self.profile(optimized=1),
                        self.profile(implementation="other"), self.profile(tag="cpython-313")):
            with self.subTest(profile=profile):
                with patch.object(preparation, "sys", profile), self.assertRaises(preparation.PreparationError):
                    preparation._checked_stdlib_bytecode(frozenset(self.supplier), self.sources)
                with patch.object(self.stager, "sys", profile), self.assertRaises(self.stager.Refused):
                    self.stager.current_stdlib_bytecode({k: v for k, v in self.supplier.items()})

    def test_writer_creates_only_new_cache_entries_and_restores_read_only_supplier_modes(self):
        rows = self.derive()
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            for name, content in self.sources.items():
                path = runtime / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o444)
            parents = sorted({p for name in self.sources for p in (runtime / name).parents if runtime / "python" in (p, *p.parents)},
                             key=lambda p: -len(p.parts))
            for directory in parents:
                directory.chmod(0o555)
            before = {name: preparation._state(preparation._ordinary(runtime / name)) for name in self.sources}
            directory_before = {d: (d.stat().st_ino, d.stat().st_mode) for d in parents}
            old = os.umask(0o077)
            try:
                preparation._write_stdlib_bytecode(runtime, rows)
            finally:
                os.umask(old)
            for name, body in rows:
                path = runtime / name
                self.assertEqual(path.read_bytes(), body)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o555)
            self.assertEqual({d: (d.stat().st_ino, d.stat().st_mode) for d in parents}, directory_before)
            self.assertEqual({name: preparation._state(preparation._ordinary(runtime / name)) for name in self.sources}, before)
            # A second creation never adopts or overwrites the existing cache.
            with self.assertRaises(preparation.PreparationError):
                preparation._write_stdlib_bytecode(runtime, rows)
            self.assertEqual(stat.S_IMODE((runtime / preparation.STDLIB_ROOT).stat().st_mode), 0o555)
            with self.assertRaises(preparation.PreparationError):
                preparation._write_stdlib_bytecode(runtime, [("python/lib/python3.14/typing.cpython-314.pyc", b"x")])
            for directory in (runtime, *parents, *{(runtime / n).parent for n, _ in rows}):
                directory.chmod(0o700)

    @unittest.skipIf(sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 7),
                     "requires the original fixed CPython 3.14.7 DATA compiler")
    def test_derived_bytes_are_independent_of_process_import_history(self):
        # Plain marshal.dumps follows live process state (FLAG_REF refcounts,
        # merging with live interned strings): ctypes/inspect/typing/weakref
        # diverged under a noisy history. The tree form must not.
        import subprocess
        outputs = []
        for history in ("clean", "noisy"):
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _DERIVE_PROBE,
                                     str(_SOURCE / "desktop/tools/prepare_runtime.py"), history],
                                    capture_output=True, check=True, timeout=120)
            outputs.append(json.loads(result.stdout))
        self.assertEqual(len(outputs[0]), 64)
        self.assertEqual(outputs[0], outputs[1])
        library = Path(os.__file__).resolve().parent
        supplier = {preparation.STDLIB_ROOT + n: ((library / n).read_bytes(), 0o444)
                    for n in preparation.COMMAND_STDLIB_BYTECODE_FILES}
        # This process has already imported unittest/zipfile/... (noisiest).
        self.assertEqual({k: v.hex() for k, v in self.stager.current_stdlib_bytecode(supplier).items()}, outputs[0])

    @unittest.skipIf(sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 7),
                     "requires the original fixed CPython 3.14.7 DATA compiler")
    def test_actual_compiler_derives_and_independently_verifies_the_actual_supplier_stdlib(self):
        library = Path(os.__file__).resolve().parent
        sources, supplier = {}, {"python/bin/python3": (b"inert-executable", 0o555)}
        for name in sorted(preparation.COMMAND_STDLIB_BYTECODE_FILES):
            content = preparation.read_checked(library / name, limit=preparation.MAX_STDLIB_BYTECODE_BYTES)
            sources[preparation.STDLIB_ROOT + name] = content
            supplier[preparation.STDLIB_ROOT + name] = (content, 0o444)
        rows = preparation._checked_stdlib_bytecode(frozenset(supplier), sources)
        self.assertLessEqual(sum(len(body) for _, body in rows), preparation.MAX_STDLIB_BYTECODE_BYTES)
        files = {**supplier, **{name: (body, 0o600) for name, body in rows}}
        self.assertEqual(self.stager.current_stdlib_bytecode_matches(files, supplier), {name for name, _ in rows})
        for name, body in rows:
            self.assertEqual(importlib.util.source_hash(sources[marshal.loads(body[16:]).co_filename]), body[8:16])

    @unittest.skipIf(sys.platform != "darwin" or sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 7),
                     "the real helper start is defined for the Mac CPython 3.14.7 runtime")
    def test_real_helper_interpreter_loads_every_derived_cache_and_compiles_no_stdlib_source(self):
        # The actual -I -S -B helper start, observed by the interpreter's own
        # -v import events: the derived rows (relocated only by the standard
        # pycache_prefix lookup) are accepted for every roster module and no
        # stdlib source is compiled; without them all 64 are compiled.
        import subprocess
        library = Path(os.__file__).parent
        sources, supplier = {}, {"python/bin/python3": (b"inert-executable", 0o555)}
        for name in sorted(preparation.COMMAND_STDLIB_BYTECODE_FILES):
            content = (library / name).read_bytes()
            sources[preparation.STDLIB_ROOT + name] = content
            supplier[preparation.STDLIB_ROOT + name] = (content, 0o444)
        rows = dict(preparation._checked_stdlib_bytecode(frozenset(supplier), sources))
        events = {}
        with tempfile.TemporaryDirectory() as temporary:
            for state in ("without", "with"):
                prefix = Path(temporary) / state
                prefix.mkdir()
                if state == "with":
                    for name in preparation.COMMAND_STDLIB_BYTECODE_FILES:
                        parent, _, leaf = name.rpartition("/")
                        target = prefix / str(library / parent).lstrip(os.sep) / (leaf[:-3] + ".cpython-314.pyc")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(rows[preparation.stdlib_bytecode_name(name)])
                before = sorted(p.relative_to(prefix) for p in prefix.rglob("*"))
                result = subprocess.run([sys.executable, "-I", "-S", "-B", "-v", "-X", "pycache_prefix=" + str(prefix),
                                         "-c", _CLOSURE_PROBE, str(_SOURCE / "src")],
                                        capture_output=True, check=True, timeout=60)
                self.assertEqual(sorted(p.relative_to(prefix) for p in prefix.rglob("*")), before)
                events[state] = _import_events(result.stderr, library)
        roster = set(preparation.COMMAND_STDLIB_BYTECODE_FILES)
        optional = {"compression/zstd/_zstdfile.py"} if importlib.util.find_spec("_zstd") else set()
        self.assertEqual(events["without"][1], set())
        self.assertEqual(events["without"][0] - optional, roster)
        self.assertEqual(events["with"][1], roster)
        self.assertEqual(events["with"][0] - optional, set())


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
