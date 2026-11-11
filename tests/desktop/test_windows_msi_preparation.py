"""Inert DATA tests. MRK_MSI_TEST_SOURCE/FIXTURES must name explicit roots.
Fixtures are intentionally retained; no compiler or native process runs.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import xml.etree.ElementTree as ET

TOOLS = Path(__file__).resolve().parents[2] / 'desktop/tools'
def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name+'.py'))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
m = load('prepare_windows_msi')
t = load('windows_msi_transaction')
SOURCE = Path(os.environ['MRK_MSI_TEST_SOURCE'])
FIXTURES = Path(os.environ['MRK_MSI_TEST_FIXTURES'])

class Preparation(unittest.TestCase):
    def setUp(self):
        self.root = FIXTURES / self._testMethodName
        self.root.mkdir(parents=True, exist_ok=False)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        files = {}
        for name in [m.SHELL, m.PUBLISHER] + ['runtime/'+p for p in m.roster(SOURCE)]:
            path = self.inputs / name; path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps({'target':m.TARGET,'protocolSha256':'b'*64}).encode() if name == 'runtime/manifest.json' else ('INERT:'+name).encode()
            path.write_bytes(data); files[name] = {'size':len(data), 'sha256':m.digest(data)}
        self.b = {'schema':1, 'sourceCommit':'ac506bb3aa663b1389f21d2cc2ff4b9b21ad96e3',
                  'sourceTree':'e88750f60d1027cd8f7bb5a3f736cbb38ace2770','version':'0.1.4',
                  'target':m.TARGET, 'manifestSha256':files['runtime/manifest.json']['sha256'],
                  'protocolSha256':'b'*64, 'sourceFiles':{p:m.digest((SOURCE/p).read_bytes()) for p in m.SOURCE_REQUIRED}, 'files':files}
        self.binding = self.root / 'binding.json'
    def bind(self):
        raw=json.dumps(self.b).encode(); self.binding.write_bytes(raw); return m.digest(raw)
    def valid(self): return m.validate(SOURCE, self.inputs, self.binding, self.bind())
    def refused(self):
        with self.assertRaises(m.Refused): self.valid()
    def test_complete_assembly(self):
        sha=self.bind(); out=self.root/'assembly'
        m.prepare(SOURCE,self.inputs,self.binding,sha,out)
        for name in self.b['files']:
            self.assertEqual((out/'payload'/name).read_bytes(), (self.inputs/name).read_bytes())
        xml=ET.parse(out/'Package.wxs'); ns={'w':m.NS}
        self.assertEqual(len(xml.findall('.//w:File',ns)),49)
        self.assertEqual(len(xml.findall('.//w:Component',ns)),49)
        self.assertEqual(xml.find('.//w:Launch',ns).get('Condition'),'0')
        self.assertEqual(xml.find('.//w:CustomAction',ns).get('Return'),'check')
        self.assertEqual(xml.find('.//w:CustomAction',ns).get('ExeCommand'),'')
        self.assertEqual(xml.find('.//w:Package',ns).get('Scope'),'perMachine')
        self.assertNotIn('PackageCode', xml.find('.//w:Package',ns).attrib)
        for forbidden in ['RemoveFile','RemoveFolder','CreateFolder','InstallExecuteSequence','Shortcut','MajorUpgrade']:
            self.assertEqual(xml.findall('.//w:'+forbidden,ns),[])
        self.assertNotIn('versions', (out/'Package.wxs').read_text())
        self.assertNotIn('requireAdministrator', (out/'Package.wxs').read_text())
        with self.assertRaises(m.Refused): m.prepare(SOURCE,self.inputs,self.binding,sha,out)
    def test_tampered_file(self):
        (self.inputs/m.SHELL).write_bytes(b'tampered'); self.refused()
    def test_same_length_tamper_still_fails_content_hash(self):
        path = self.inputs / m.SHELL
        data = path.read_bytes()
        path.write_bytes(b'X' + data[1:])
        with self.assertRaisesRegex(m.Refused, 'input hash mismatch'):
            self.valid()
    def test_extra_input(self):
        (self.inputs/'extra.dll').write_bytes(b'extra'); self.refused()
    def test_empty_extra_directory(self):
        (self.inputs/'unused').mkdir(); self.refused()
    def test_symlink_input(self):
        extra=self.root/'extra'; extra.write_bytes(b'extra')
        (self.inputs/'link').symlink_to(extra); self.refused()
    def test_hardlink_input(self):
        os.link(self.inputs/m.SHELL,self.root/'alias'); self.refused()
    def test_wrong_source(self):
        self.b['sourceFiles']['desktop/src-tauri/src/runtime.rs']='0'*64; self.refused()
    def test_wrong_protocol(self):
        self.b['protocolSha256']='c'*64; self.refused()
    def test_wrong_manifest(self):
        self.b['manifestSha256']='c'*64; self.refused()
    def test_wrong_target(self):
        self.b['target']='aarch64-pc-windows-msvc'; self.refused()
    def test_missing_file(self):
        del self.b['files'][m.PUBLISHER]; self.refused()
    def test_bad_binding_hash(self):
        self.bind()
        with self.assertRaises(m.Refused): m.validate(SOURCE,self.inputs,self.binding,'0'*64)
    def test_duplicate_json(self):
        with self.assertRaises(m.Refused): m.decode(b'{"schema":1,"schema":1}')
    def test_version_mapping(self):
        for value in ['0.1.4.1','0.1.4-beta','256.1.1','1.256.1','1.1.65536','01.1.1']:
            with self.assertRaises(m.Refused): m.version(value)
        self.assertEqual(m.version('0.1.4'),'0.1.4')
    def test_identity(self):
        first=m.identity(self.b)
        self.b['files'][m.SHELL]['sha256']='0'*64
        second=m.identity(self.b)
        self.assertEqual(first['productCode'],second['productCode'])
        self.assertNotEqual(first['assemblyBindingSha256'],second['assemblyBindingSha256'])
        self.b['version']='0.1.5'
        third=m.identity(self.b)
        self.assertNotEqual(second['productCode'],third['productCode'])
        self.assertEqual(second['upgradeCode'],third['upgradeCode'])
    def test_no_build_override(self):
        with self.assertRaisesRegex(m.Refused,'unqualified'): m.require_build_qualification()
    def test_path_injection(self):
        for value in ['../x','/x','x\\y','x:ads','x/../y','x//y','x/$var','x.']:
            with self.assertRaises(m.Refused): m.relative(value)

class MetadataRegression(unittest.TestCase):
    def snapshot(self, value, **changes):
        fields = {key: getattr(value, key) for key in dir(value) if key.startswith('st_')}
        fields.update(changes)
        return SimpleNamespace(**fields)

    def test_access_time_only_is_not_mutation(self):
        old = SOURCE.stat()
        new = self.snapshot(old, st_atime=old.st_atime + 10, st_atime_ns=old.st_atime_ns + 10000000000)
        self.assertTrue(m.unchanged(old, new))

    def test_all_security_identity_and_mutation_fields_remain_checked(self):
        old = SOURCE.stat()
        for field in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size',
                      'st_mtime_ns','st_ctime_ns','st_birthtime_ns','st_birthtime',
                      'st_flags','st_gen','st_file_attributes','st_reparse_tag'):
            with self.subTest(field=field):
                self.assertFalse(m.unchanged(old, self.snapshot(old, **{field:getattr(old,field,0)+1})))

    def test_read_accepts_atime_drift_and_hashes_actual_bytes(self):
        root = FIXTURES / self._testMethodName; root.mkdir(parents=True)
        path = root / 'data'; path.write_bytes(b'actual-content')
        original = os.fstat
        def read_stat(fd):
            value = original(fd)
            return self.snapshot(value, st_atime=value.st_atime + 10, st_atime_ns=value.st_atime_ns + 10000000000)
        with patch.object(m.os, 'fstat', side_effect=read_stat):
            self.assertEqual(m.digest(m.read(path, 64)), hashlib.sha256(b'actual-content').hexdigest())

    def test_read_refuses_opened_permission_drift(self):
        root = FIXTURES / self._testMethodName; root.mkdir(parents=True)
        path = root / 'data'; path.write_bytes(b'actual-content')
        original = os.fstat
        def changed_stat(fd):
            value = original(fd)
            return self.snapshot(value, st_mode=value.st_mode ^ 0o020)
        with patch.object(m.os, 'fstat', side_effect=changed_stat):
            with self.assertRaisesRegex(m.Refused, 'input replaced'): m.read(path, 64)

    def test_validation_and_copy_accept_read_atime_drift(self):
        fixture = Preparation('test_complete_assembly'); fixture._testMethodName = self._testMethodName; fixture.setUp()
        original = os.fstat
        def read_stat(fd):
            value = original(fd)
            return self.snapshot(value, st_atime=value.st_atime + 10, st_atime_ns=value.st_atime_ns + 10000000000)
        with patch.object(m.os, 'fstat', side_effect=read_stat):
            fixture.test_complete_assembly()

class Policy(unittest.TestCase):
    def new(self): return t.Transaction('a'*64)
    def complete(self):
        x=self.new(); self.assertTrue(x.start(target_absent=True,original_inputs_locked=True))
        self.assertEqual(x.returned(original_exit=0,original_handles_settled=True),t.State.PUBLISHED)
        self.assertTrue(x.activate(same_binding='a'*64,protected_fullwalk=True)); return x
    def test_completed_maintenance(self):
        x=self.complete()
        self.assertTrue(x.maintenance(same_binding='a'*64,completion_owner_authenticated=True,original_exit_settled=True,protected_fullwalk=True))
        self.assertFalse(x.may_remove_retained_runtime())
    def test_matching_bytes_not_completion(self):
        for state in t.State:
            x=self.new(); x.state=state
            self.assertFalse(x.maintenance(same_binding='a'*64,completion_owner_authenticated=False,original_exit_settled=True,protected_fullwalk=True))
    def test_occupied_refused(self):
        x=self.new(); self.assertFalse(x.start(target_absent=False,original_inputs_locked=True))
        self.assertFalse(x.may_replace_inputs())
    def test_exit_two_not_success(self):
        x=self.new(); x.start(target_absent=True,original_inputs_locked=True)
        self.assertEqual(x.returned(original_exit=2,original_handles_settled=True),t.State.FAILED)
        self.assertFalse(x.activate(same_binding='a'*64,protected_fullwalk=True))
    def test_unknown_absorbing(self):
        x=self.new(); x.start(target_absent=True,original_inputs_locked=True)
        x.returned(original_exit=0,original_handles_settled=False)
        self.assertEqual(x.returned(original_exit=0,original_handles_settled=True),t.State.UNKNOWN)
        self.assertFalse(x.may_replace_inputs())
    def test_parent_death_blocks_maintenance(self):
        x=self.complete(); x.parent_lost()
        self.assertFalse(x.may_replace_inputs())
    def test_no_early_activation(self):
        x=self.new(); x.start(target_absent=True,original_inputs_locked=True)
        self.assertFalse(x.activate(same_binding='a'*64,protected_fullwalk=True))
    def test_bad_completion_binding(self):
        x=self.complete()
        self.assertFalse(x.maintenance(same_binding='b'*64,completion_owner_authenticated=True,original_exit_settled=True,protected_fullwalk=True))
if __name__=='__main__': unittest.main(verbosity=2)
