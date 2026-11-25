"""Real own-file originals with inert Mac admission/command seams, not qualification."""
import hashlib
import json
import os
import sys
import time
import types
import tempfile
import stat
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mobile_release import android_current_tools_macos as subject
from mobile_release import android_build_tools_macos as mac
from mobile_release import _command_process as command
from mobile_release import checked_files
from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError, ProcessError
from mobile_release.reporting import Status
from .test_android_upload_validation import jarsigner_output


class RegisteredCurrentMacTests(unittest.TestCase):
    def fixture(self, stack, profile=mac.PROFILE):
        from desktop.test_android_build_tools import mac_documents, mac_encoded
        temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="mrk-current-tools-"))
        prefix = Path(temporary) / profile
        folder = prefix / '501' / ('ab'*16)
        folder.mkdir(parents=True)
        body, provider = mac_documents(profile=profile)
        pins = None
        for row in body['files']:
            content = ('inert registered role '+row['path']).encode()
            row.update(size=len(content), sha256=hashlib.sha256(content).hexdigest())
            path = folder/row['path']; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(content); path.chmod(row['mode'])
            if row['path'] == 'bundletool/bundletool.jar':
                body['bundletool']['sha256'] = row['sha256']
                pins = {'bytes':row['size'], 'sha256':row['sha256']}
        raw, provider_raw, record, binding = mac_encoded(body,provider,profile=profile)
        for name, content in zip(mac.HEADERS,(record,raw,provider_raw)):
            (folder/name).write_bytes(content); (folder/name).chmod(0o444)
        # Test-only admission seam: these actual private originals are user-owned,
        # not an installed root-owned Mac registration. Normalize only the pure
        # existing protection predicate; all FD/name/mode/hash/close work is real.
        def admitted(details, *, directory=False, stable_contents=True, mac=False):
            self.assertEqual(directory, stat.S_ISDIR(details.st_mode))
            base = (details.st_dev, details.st_ino, details.st_mode, 0, 0)
            return base + ((details.st_nlink,details.st_size,details.st_mtime_ns,details.st_ctime_ns)
                if stable_contents else ()) + ((0,) if mac else ())
        for path in reversed(list(folder.rglob('*'))):
            if path.is_dir():path.chmod(0o555)
        folder.chmod(0o555)
        observed = folder.stat()
        binding['root'] = str(folder)
        binding['rootIdentity'] = dict(device=str(observed.st_dev),inode=str(observed.st_ino),
            mode=observed.st_mode,uid=0,gid=0)
        data = {'binding':binding,'pins':pins}
        stack.enter_context(patch.object(mac,'PREFIX',str(prefix)))
        stack.enter_context(patch.object(subject.common,'_identity',admitted))
        stack.enter_context(patch.object(mac, 'BUNDLETOOL_SIGNED_BYTES', data['pins']['bytes']))
        stack.enter_context(patch.object(mac, 'BUNDLETOOL_SIGNED_SHA256', data['pins']['sha256']))
        stack.enter_context(patch.object(subject, 'sys', types.SimpleNamespace(platform='darwin', exc_info=sys.exc_info)))
        os_view = types.SimpleNamespace(**{k: getattr(os,k) for k in dir(os)})
        os_view.stat_result = types.SimpleNamespace(st_flags=0)
        os_view.uname = lambda: types.SimpleNamespace(machine='arm64' if profile==mac.PROFILE else 'x86_64')
        stack.enter_context(patch.object(subject, 'os', os_view))
        now=time.monotonic_ns()
        value={'schemaVersion':1,'toolchain':data['binding'], 'runDeadlineNs':str(now+200*10**9),
               'hardDeadlineNs':str(now+205*10**9)}
        return value

    def capture(self, records, *, fail=None):
        def call(argv, **kwargs):
            evidence=kwargs['_evidence']
            owner=evidence._current_android
            role=owner.pending[1]
            records.append((role, owner, evidence, tuple(argv), kwargs, len(os.listdir('/proc/self/fd'))))
            self.assertEqual(set(kwargs), {'cwd','environ','capture','timeout','output_limit','cancellation','_evidence'})
            self.assertEqual(kwargs['output_limit'],2*1024**2)
            self.assertTrue(str(argv[0]).startswith(owner.binding.root+'/jdk/'))
            self.assertNotIn('GOOGLE_APPLICATION_CREDENTIALS',kwargs['environ'])
            self.assertNotIn('MOBILE_RELEASE_BUNDLETOOL_JAR',kwargs['environ'])
            self.assertIn('-XX:-UsePerfData' if role=='bundletool' else '-J-XX:-UsePerfData',argv)
            evidence._attempt(owner.guard, timeout=kwargs['timeout'], ordinary=True)
            # Exercise the real _Outer endpoint calculation, stopping before its
            # first native/original context acquisition. No actual process runs.
            class BeforeContext(Exception): pass
            admitted=[]
            def context(role,nonce,run,hard,**options):
                admitted.append((role,run,hard,options))
                raise BeforeContext()
            with patch.object(command,'_Context',context), self.assertRaises(BeforeContext):
                command._Outer(owner.guard,False,kwargs['timeout'],None,None,
                    suppress_cancel=False,evidence=evidence)
            timing=owner.pending[4]
            self.assertEqual(admitted[0][:3],('O',timing.run,timing.hard))
            self.assertIs(admitted[0][3]['guard'],owner.guard)
            self.assertEqual(timing.hard-timing.run,command.CLEANUP_NS)
            self.assertLessEqual(timing.hard,owner.run_end)
            with self.assertRaises(Exception):
                evidence._fixed_timing(owner.guard,timeout=kwargs['timeout'],owns=False,scope=None,binding=None)
            if fail==role:
                raise ProcessCleanupError('inert native finality unknown')
            if role=='bundletool':
                out='<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.reader" android:versionCode="42" android:versionName="1.2.3"><application /></manifest>'
            elif role=='jarsigner': out=jarsigner_output()
            else: out='Signer #1:\nCertificate #1:\nSHA256: '+':'.join(['AA']*32)+'\n'
            return types.SimpleNamespace(returncode=4 if role=='jarsigner' else 0,stdout=out,stderr='')
        return call

    def validate(self, owner):
        with patch('mobile_release.android.validate_aab_structure',return_value=['base/manifest/AndroidManifest.xml']):
            return owner.validate(Path('/inert/app-release.aab'),expected_application_id='com.example.reader',
                release=ReleaseVersion('1.2.3',42),expected_fingerprint='a'*64)

    def test_actual_role_originals_both_profiles_and_exact_command_timing(self):
        for profile in (mac.PROFILE,mac.INTEL_PROFILE):
            with self.subTest(profile=profile), ExitStack() as stack:
                value=self.fixture(stack,profile); records=[]
                before=len(os.listdir('/proc/self/fd'))
                stack.enter_context(patch.object(subject,'run_owned',self.capture(records)))
                with subject.registered_current_tools(json.dumps(value)) as owner:
                    findings=self.validate(owner)
                    self.assertEqual({f.code for f in findings if f.status == Status.PASS},
                        {'android.aab.structure','android.aab.manifest','android.aab.signature','android.aab.signer'})
                    self.assertLessEqual(len(owner.reader.descriptors),owner.original_quote)
                    self.assertLessEqual(owner.original_quote,subject.ORIGINAL_LIMIT)
                    self.assertLess(max(r[5] for r in records),128)
                self.assertTrue(owner.closed)
                self.assertTrue(all(s.state=='CLOSED' for s in owner.reader.descriptors))
                self.assertEqual([r[0] for r in records],list(subject.ROLES))
                self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_bad_root_manifest_request_and_cap_refuse_before_native(self):
        with ExitStack() as stack:
            value=self.fixture(stack); records=[]
            stack.enter_context(patch.object(subject,'run_owned',self.capture(records)))
            changes=[lambda v:v['toolchain']['rootIdentity'].__setitem__('inode','1'),
                     lambda v:v['toolchain'].__setitem__('inventorySha256','0'*64),
                     lambda v:v.__setitem__('runDeadlineNs','01'),
                     lambda v:v.__setitem__('hardDeadlineNs',str(int(v['hardDeadlineNs'])+1))]
            for change in changes:
                bad=json.loads(json.dumps(value));change(bad)
                with self.subTest(change=change), self.assertRaises(ValidationError):
                    with subject.registered_current_tools(json.dumps(bad)): self.fail('must refuse')
            for raw in ('x'*(subject.REQUEST_LIMIT+1),json.dumps(value)[:-1]+',"schemaVersion":1}'):
                with self.assertRaises(ValidationError): subject.request_data(raw)
            with patch.object(subject,'ORIGINAL_LIMIT',4), self.assertRaises(ValidationError):
                with subject.registered_current_tools(json.dumps(value)):self.fail('must refuse')
            self.assertEqual([],records)

    def test_midway_unknown_stops_and_independent_originals_close(self):
        with ExitStack() as stack:
            value=self.fixture(stack);records=[]
            stack.enter_context(patch.object(subject,'run_owned',self.capture(records,fail='jarsigner')))
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ProcessError) as failure:
                with subject.registered_current_tools(json.dumps(value)) as owner:self.validate(owner)
            self.assertTrue(failure.exception.fatal)
            self.assertEqual(['bundletool','jarsigner'],[r[0] for r in records])
            self.assertTrue(owner.failed and owner.closed)
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_changed_role_post_cannot_publish_success_and_still_closes(self):
        with ExitStack() as stack:
            value=self.fixture(stack);records=[]
            actual=self.capture(records)
            def changed(argv,**kwargs):
                result=actual(argv,**kwargs)
                owner=kwargs['_evidence']._current_android
                node,_=owner.leaves[0]
                # Genuine named original drift, within our own tiny fixture.
                # Restore permissions, not identity/mtime/content correspondence.
                node.canonical.chmod(0o755)
                node.canonical.write_bytes(b'changed inert role')
                node.canonical.chmod(0o555)
                return result
            stack.enter_context(patch.object(subject,'run_owned',changed))
            with self.assertRaises(ValidationError):
                with subject.registered_current_tools(json.dumps(value)) as owner:self.validate(owner)
            self.assertEqual(['bundletool'],[r[0] for r in records])
            self.assertTrue(owner.closed)

    def test_unknown_original_close_is_not_retried_or_success(self):
        with ExitStack() as stack:
            value=self.fixture(stack);records=[]
            stack.enter_context(patch.object(subject,'run_owned',self.capture(records)))
            original=os.close; seen=[]; selected=[None]
            def close(fd):
                if fd==selected[0]:
                    seen.append(fd); original(fd)
                    raise OSError('inert lost close return')
                original(fd)
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ProcessError) as failure:
                with subject.registered_current_tools(json.dumps(value)) as owner:
                    self.validate(owner)
                    selected[0]=owner.reader.descriptors[-1].number
                    stack.enter_context(patch.object(checked_files.os,'close',close))
            self.assertTrue(failure.exception.fatal)
            self.assertEqual(1,len(seen))
            self.assertFalse(owner.closed)
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_preparse_and_expired_timing_refuse_without_json_or_native(self):
        checkpoints=[]
        good=b'{"files":['+b','.join([b'{"path":"role","size":1,"sha256":"a","mode":365}']*16384)+b']}'
        self.assertLess(subject.predecode(good,lambda:checkpoints.append(True)),128<<20)
        self.assertGreater(len(checkpoints),1)
        for raw in (b'['*17+b']'*17,b'['+b'0,'*150000+b'0]',b'x'*(subject.common.MAX_MANIFEST_BYTES+1)):
            with self.assertRaises(ValidationError): subject.predecode(raw,lambda:None)
        with ExitStack() as stack:
            value=self.fixture(stack)
            value['runDeadlineNs']='1';value['hardDeadlineNs']=str(1+5*10**9)
            with patch.object(subject,'finite_scratch',side_effect=AssertionError('no scratch before admission')):
                with self.assertRaises(ValidationError):
                    with subject.registered_current_tools(json.dumps(value)):pass


if __name__=='__main__':unittest.main()
