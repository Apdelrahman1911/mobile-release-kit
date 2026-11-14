"""Inert DATA tests for the compiler-output role reader (POSIX link simulation).
No compiler, installer or native process runs.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[2] / 'desktop/tools'
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location('windows_compiler_evidence', TOOLS / 'windows_compiler_evidence.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
BIN = 'mrk-windows-runtime-publish'

class CompilerOutput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); root = Path(self.tmp.name)
        self.release = root / 'release'; (self.release / 'deps').mkdir(parents=True)
        self.logs = root / 'logs'; self.exe = self.release / (BIN + '.exe')
        self.deps = self.release / 'deps' / 'mrk_windows_runtime_publish-0123456789abcdef.exe'
    def tearDown(self): self.tmp.cleanup()
    def read(self): return m.compiler_output_record(self.exe, binary=BIN, limit=1 << 20, logs=self.logs, role='publisher')
    def facts(self): return json.loads((self.logs / 'publisher-compiler-output-metadata.json').read_text())

    def test_single_link(self):
        self.exe.write_bytes(b'MZ1'); r = self.read()
        self.assertEqual((r['size'], r['links'], r['cargoDepsOriginal']), (3, 1, None))
    def test_cargo_uplift_pair(self):
        self.deps.write_bytes(b'MZ22'); os.link(self.deps, self.exe); r = self.read()
        self.assertEqual((r['links'], r['cargoDepsOriginal']), (2, self.deps.name))
        self.assertEqual(self.facts()['original']['links'], 2)
    def test_unrelated_second_link_refused(self):
        other = self.release / 'elsewhere.exe'; other.write_bytes(b'MZ'); os.link(other, self.exe)
        self.deps.write_bytes(b'MZ')  # same name, different file ID
        with self.assertRaisesRegex(ValueError, 'compiler-output-links'): self.read()
        self.assertEqual(len(self.facts()['counterparts']), 1)
    def test_wrong_deps_name_refused(self):
        bad = self.release / 'deps' / 'other_crate-0123456789abcdef.exe'; bad.write_bytes(b'MZ'); os.link(bad, self.exe)
        with self.assertRaisesRegex(ValueError, 'compiler-output-links'): self.read()
    def test_three_links_refused(self):
        self.deps.write_bytes(b'MZ'); os.link(self.deps, self.exe); os.link(self.deps, self.release / 'x.exe')
        with self.assertRaisesRegex(ValueError, 'compiler-output-links'): self.read()
    def test_symlink_refused(self):
        self.deps.write_bytes(b'MZ'); self.exe.symlink_to(self.deps)
        with self.assertRaisesRegex(ValueError, 'compiler-output-ordinary'): self.read()
    def test_empty_and_oversize_refused(self):
        self.exe.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'compiler-output-bound'): self.read()
        self.exe.write_bytes(b'x' * ((1 << 20) + 1))
        with self.assertRaisesRegex(ValueError, 'compiler-output-bound'): self.read()

if __name__ == '__main__': unittest.main()
