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
        self.release = root / 'target' / 'x86_64-pc-windows-msvc' / 'release'; (self.release / 'deps').mkdir(parents=True)
        self.logs = root / 'logs'; self.exe = self.release / (BIN + '.exe')
        self.deps = self.release / 'deps' / 'mrk_windows_runtime_publish-0123456789abcdef.exe'
    def tearDown(self): self.tmp.cleanup()
    def read(self): return m.compiler_output_record(self.exe, binary=BIN, limit=1 << 20, logs=self.logs, role='publisher')
    def facts(self): return json.loads((self.logs / 'publisher-compiler-output-metadata.json').read_text())

    def test_single_link(self):
        self.exe.write_bytes(b'MZ1'); r = self.read()
        self.assertEqual((r['size'], r['links'], r['cargoOriginal']), (3, 1, None))
    def test_cargo_uplift_pair(self):
        self.deps.write_bytes(b'MZ22'); os.link(self.deps, self.exe); r = self.read()
        self.assertEqual((r['links'], r['cargoOriginal']), (2, 'x86_64-pc-windows-msvc/release/deps/' + self.deps.name))
        self.assertEqual(self.facts()['original']['links'], 2)
    def test_unrelated_second_link_refused(self):
        other = Path(self.tmp.name) / 'outside.exe'; other.write_bytes(b'MZ'); os.link(other, self.exe)
        self.deps.write_bytes(b'MZ')  # same name, different file ID
        with self.assertRaisesRegex(ValueError, 'compiler-output-links'): self.read()
        self.assertEqual(len(self.facts()['counterparts']), 1)
    def test_partner_in_other_build_directory(self):
        other = self.release.parents[1] / 'build-dir' / 'x' ; other.mkdir(parents=True)
        partner = other / 'mrk-windows-runtime-publish.exe'; partner.write_bytes(b'MZ333'); os.link(partner, self.exe)
        r = self.read(); self.assertEqual(r['cargoOriginal'], 'build-dir/x/mrk-windows-runtime-publish.exe')
    def test_unnamed_partner_inside_target_recorded(self):
        odd = self.release / 'deps' / 'mrk_windows_runtime_publish-1a2b'; odd.write_bytes(b'MZ'); os.link(odd, self.exe)
        self.assertEqual(self.read()['cargoOriginal'], 'x86_64-pc-windows-msvc/release/deps/mrk_windows_runtime_publish-1a2b')
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
