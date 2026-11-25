"""Original files + shared IPA policy; explicit inert Mac/native boundaries."""
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from mobile_release import ios_current_tools_macos as subject
from mobile_release import ios_upload_validation as gate
from mobile_release import _command_process as command
from mobile_release.config import load_config
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessError, ProcessCleanupError
from mobile_release.provenance import seal, sha256_file
from .helpers import ios_config, write_project
from .evidence_helpers import build_lifecycle
from .ios_entitlement_helpers import NativeProfileSeam, modernize_ipa_fixture, CERTIFICATE, profile

class CurrentIPAToolsTests(unittest.TestCase):
    def fixture(self, stack, *, deep=False):
        root=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='mrk-ipa-current-')))
        tools=root/'system';tools.mkdir()
        for name in subject.NAMES:
            p=tools/name;p.write_bytes(b'inert role '+name.encode());p.chmod(0o555)
        original=subject.tool_data
        def identity(st):
            row=original(st);row['uid']=0;return row
        def protection(st,directory=False):
            self.assertEqual(directory,stat.S_ISDIR(st.st_mode))
            if not directory: self.assertFalse(st.st_mode&0o7022)
            if not directory:self.assertEqual(st.st_nlink,1)
        stack.enter_context(patch.object(subject,'SYSTEM',tools))
        stack.enter_context(patch.object(subject,'tool_data',identity))
        stack.enter_context(patch.object(subject.CurrentIPATools,'protected',staticmethod(protection)))
        stack.enter_context(patch.object(subject,'sys',types.SimpleNamespace(platform='darwin',exc_info=sys.exc_info)))
        stack.enter_context(patch('mobile_release.ios.sys',types.SimpleNamespace(platform='darwin')))
        now=time.monotonic_ns()
        request=dict(schemaVersion=1,signingTools={name:identity((tools/name).stat()) for name in subject.NAMES},
                     runDeadlineNs=str(now+200*10**9),hardDeadlineNs=str(now+205*10**9))
        project=root/'project'
        if deep: project=project/'work'/'apps'/'original'/'selected'/'release-project'
        project.mkdir(parents=True)
        config=load_config(write_project(project,ios_config(),platform='ios'))
        build_lifecycle(config,platform='ios')
        ipa=project/'app.ipa';modernize_ipa_fixture(ipa)
        cfg=json.loads(config.path.read_bytes());cfg['ios']['distributionCertificateSha256']=hashlib.sha256(CERTIFICATE).hexdigest()
        config.path.write_text(json.dumps(cfg));config=load_config(config.path)
        fixture=Path(__file__).parents[1]/'fixtures/local-intent-ios-candidate-valid.json'
        intent=json.loads(fixture.read_bytes());intent.pop('integrity')
        intent['configuration']['sha256']=sha256_file(config.path)
        intent['signing'][0].update(certificateSha256=hashlib.sha256(CERTIFICATE).hexdigest(),profileUuid=profile()['UUID'],profileExpiresAt='2099-01-01T00:00:00Z')
        intent['artifacts'][0].update(fileName=ipa.name,size=ipa.stat().st_size,sha256=sha256_file(ipa))
        intent=seal(intent);ipath=project/'intent.json';ipath.write_text(json.dumps(intent))
        arguments=dict(app_root=project,config_path=config.path,intent_path=ipath,ipa_path=ipa,intent_sha256=intent['integrity']['sha256'],tools_request=json.dumps(request))
        return request,arguments,tools

    def capture(self, native, records):
        def call(argv,**kwargs):
            evidence=kwargs['_evidence'];owner=evidence._current_ios
            records.append((owner,evidence,tuple(argv),len(os.listdir('/proc/self/fd'))))
            self.assertEqual(kwargs['output_limit'],8*1024**2)
            self.assertFalse(any(k.startswith('MOBILE_RELEASE') for k in kwargs['environ']))
            evidence._attempt(owner.guard,timeout=kwargs['timeout'],ordinary=True)
            class BeforeContext(Exception):pass
            observed=[]
            def context(role,nonce,run,hard,**options):
                observed.append((role,run,hard,options));raise BeforeContext()
            with patch.object(command,'_Context',context),self.assertRaises(BeforeContext):
                command._Outer(owner.guard,False,kwargs['timeout'],None,None,suppress_cancel=False,evidence=evidence)
            timing=owner.pending[4]
            self.assertEqual(observed[0][:3],('O',timing.run,timing.hard))
            self.assertLessEqual(timing.hard,owner.run_end)
            self.assertEqual(timing.hard-timing.run,command.CLEANUP_NS)
            with self.assertRaises(Exception):evidence._fixed_timing(owner.guard,timeout=kwargs['timeout'],owns=False,scope=None,binding=None)
            return native([Path(argv[0]).name,*argv[1:]],**kwargs)
        return call

    def test_same_original_tools_one_snapshot_full_policy_and_fixed_native_clock(self):
        with ExitStack() as stack:
            request,args,tools=self.fixture(stack);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication())
            stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            stack.enter_context(patch.object(gate,'ipa_signing_evidence',side_effect=AssertionError('no second extraction/profile')))
            before=len(os.listdir('/proc/self/fd'))
            result=gate.validate_current_local_upload(**args)
            self.assertEqual(result['operationIntentSha256'],args['intent_sha256'])
            self.assertEqual(result['ipaSha256'],sha256_file(args['ipa_path']))
            self.assertTrue(records);owner=records[0][0]
            self.assertTrue(owner.closed and owner.snapshot_binding.finished)
            self.assertEqual(owner.signing['profileUuid'],profile()['UUID'])
            self.assertTrue(all(s.close_state=='CLOSED' for s in owner.tools.values()))
            self.assertFalse(owner.snapshot.temporary.exists())
            self.assertLess(max(r[3] for r in records),256)
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_foreign_ci_intent_and_signer_mismatch_cannot_return_eligibility(self):
        with ExitStack() as stack:
            _,args,_=self.fixture(stack);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            document=json.loads(args['intent_path'].read_bytes());document['signing'][0]['profileUuid']='87654321-1234-1234-1234-1234567890AB';document.pop('integrity')
            document=seal(document);args['intent_path'].write_text(json.dumps(document));args['intent_sha256']=document['integrity']['sha256']
            with self.assertRaisesRegex(ValidationError,'signer/profile'):gate.validate_current_local_upload(**args)
            self.assertTrue(records[0][0].closed)
            document['documentType']='release-operation-intent';document.pop('integrity');document=seal(document)
            args['intent_path'].write_text(json.dumps(document));args['intent_sha256']=document['integrity']['sha256'];records.clear()
            with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
            self.assertEqual([],records)

    def test_bad_tool_request_and_changed_original_refuse_and_close(self):
        with ExitStack() as stack:
            request,args,tools=self.fixture(stack)
            for key,value in [('runDeadlineNs','01'),('hardDeadlineNs',request['runDeadlineNs']),('unexpected',True)]:
                bad={**request,key:value}
                with self.assertRaises(ValidationError):subject.request_data(json.dumps(bad))
            bad=json.loads(json.dumps(request));bad['signingTools']['security']['inode']='1'
            args['tools_request']=json.dumps(bad)
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))
            args['tools_request']=json.dumps(request);native=NativeProfileSeam();records=[];capture=self.capture(native,records)
            def change(argv,**kwargs):
                result=capture(argv,**kwargs);(tools/'security').chmod(0o755);(tools/'security').write_bytes(b'changed original');return result
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',change))
            with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
            self.assertEqual(len(records),1);self.assertTrue(records[0][0].closed)

    def test_unknown_command_preserves_failure_and_consumes_tools_once(self):
        with ExitStack() as stack:
            _,args,_=self.fixture(stack);native=NativeProfileSeam();records=[];capture=self.capture(native,records)
            def fail(argv,**kwargs):
                capture(argv,**kwargs);raise ProcessCleanupError('inert native lifetime unknown')
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',fail))
            with self.assertRaises(ProcessError):gate.validate_current_local_upload(**args)
            self.assertEqual(len(records),1);self.assertTrue(records[0][0].failed)
            self.assertTrue(all(s.close_state=='CLOSED' for s in records[0][0].tools.values()))
        # Published containment alone is not consumption of the original call.
        # Exercise the real ledger with an actually retained command entry.
        from mobile_release.cancellation import DefaultCancellation
        guard=DefaultCancellation(ProcessCleanupError,'inert cleanup')
        owner=object.__new__(subject.CurrentIPATools);owner.guard=guard;owner.pending=None
        ledger=guard.lifetime_ledger;original=object()
        ledger._bind_command(original)
        # Exact internal cut after publication, before consumption; no producer
        # or effect is run and this synthetic ledger grants no native finality.
        ledger._command_published=True
        facts=ledger.verdict()
        self.assertTrue(facts.contained);self.assertFalse(facts.complete)
        self.assertTrue(facts.fatal);self.assertFalse(ledger.fatal)
        self.assertIs(ledger._command,original);self.assertFalse(owner.idle())

    def test_final_input_mutation_and_profile_refusal_cannot_escape_post(self):
        with ExitStack() as stack:
            _,args,_=self.fixture(stack);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            actual=subject.CurrentIPATools.validated
            def changed(owner,*a,**kw):
                actual(owner,*a,**kw)
                args['ipa_path'].write_bytes(b'changed original after actual policy')
            stack.enter_context(patch.object(subject.CurrentIPATools,'validated',changed))
            with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
            self.assertTrue(records[0][0].closed)
        with ExitStack() as stack:
            _,args,_=self.fixture(stack);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication())
            stack.enter_context(patch.object(native,'authenticate_cms',side_effect=ValidationError('inert CMS rejection')))
            stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
            self.assertFalse(records);self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_unknown_consuming_tool_close_is_not_retried(self):
        with ExitStack() as stack:
            _,args,_=self.fixture(stack);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            actual_close=subject.CurrentIPATools.close;os_close=os.close;attempts=[]
            def close(owner):
                target=owner.tools['security'].number
                def lost(number):
                    if number==target:
                        attempts.append(number);os_close(number);raise OSError('inert consumed close result lost')
                    os_close(number)
                with patch.object(os,'close',lost): return actual_close(owner)
            stack.enter_context(patch.object(subject.CurrentIPATools,'close',close))
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ProcessError):gate.validate_current_local_upload(**args)
            self.assertEqual(1,len(attempts));owner=records[0][0]
            self.assertFalse(owner.closed);self.assertEqual('UNKNOWN',owner.tools['security'].close_state)
            self.assertTrue(all(s.close_state=='CLOSED' for n,s in owner.tools.items() if n!='security'))
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_zip_preallocation_and_expiry_refuse_before_native_or_zipinfo(self):
        import zipfile
        with ExitStack() as stack:
            _,args,_=self.fixture(stack)
            with zipfile.ZipFile(args['ipa_path'],'w') as archive:
                for index in range(8193):archive.writestr(str(index),b'')
            with patch.object(zipfile,'ZipFile',side_effect=AssertionError('must refuse before ZipInfo allocation')):
                with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)
        with ExitStack() as stack:
            request,args,_=self.fixture(stack)
            with patch.object(subject.time,'monotonic_ns',return_value=int(request['runDeadlineNs'])):
                with self.assertRaises(ValidationError):gate.validate_current_local_upload(**args)

    def test_realistic_depth_reuses_original_ancestry_without_reopening(self):
        with ExitStack() as stack:
            _,args,_=self.fixture(stack,deep=True);native=NativeProfileSeam();records=[]
            stack.enter_context(native.profile_authentication());stack.enter_context(patch.object(subject,'run_owned',self.capture(native,records)))
            gate.validate_current_local_upload(**args)
            owner=records[0][0]
            self.assertLess(len(owner.inputs.descriptors),sum(len(p.parts) for p in owner.input_paths))
            self.assertLessEqual(len(owner.inputs.descriptors),owner.input_quote)
            directories=[n for n in owner.inputs.nodes if n.directory]
            self.assertEqual(len(directories),len({(id(n.parent),n.name) for n in directories}))
            self.assertTrue(owner.closed)
