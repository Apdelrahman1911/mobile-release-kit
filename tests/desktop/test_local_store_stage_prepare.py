"""Actual prior Prepare/Execute and same-engine later Prepare; inert SDK/native."""
import hashlib
import io
import json
from pathlib import Path
import traceback
import unittest
from unittest.mock import patch
import zipfile
from uuid import UUID
from mobile_release import _desktop_store_prepare_protocol as wire
from mobile_release.local_release_journal import canonical
import test_local_store_execute as android_fixture
import test_local_ios_store_execute as ios_fixture
from test_local_store_stages import documents

STAGE='77777777-7777-4777-8777-777777777777'

class LocalStoreStagePrepareTests(unittest.TestCase):
    @staticmethod
    def detail(engine,terminal):
        message=repr(terminal)+getattr(engine,'inert_debug','');error=engine.primary
        for _ in range(4):
            if error is None:break
            message+=''.join(traceback.format_exception(error));error=error.__context__
        return message
    def prepare(self,platform):
        case=(ios_fixture.IOSStoreExecuteTests if platform=='ios' else android_fixture.LocalStoreExecuteTests)(methodName='runTest')
        case.setUp();self.addCleanup(case.doCleanups);f=case.f
        terminal,engine,_,_,_=f.run_original(_execute=True)
        self.assertEqual(terminal['outcome'],'complete',str(engine.primary))
        prior=Path(engine.service.record._output).read_bytes()
        value=f.value;c=value['context'];value['protocol']=wire.PROTOCOL;value['operationId']=UUID(STAGE).hex
        c.update(operation='local-store-prepare',stage='external-testing',predecessorOperationId=c['candidateOperationId'],
            predecessorReceiptSha256=hashlib.sha256(prior).hexdigest(),confirmation=f'external-testing:{platform}:1.2.3:42')
        c.pop('intentSha256');c.pop('toolchainSelection',None)
        for name in ('toolchain','signingTools','uploadSelection'):value['native'].pop(name,None)
        if platform=='ios':c['supplementalAssignments']=dict(reviewContact=dict(recordId='d'*32,recordRevision=1),
            commitment=dict(recordId='e'*32,recordRevision=1),reviewDemo=None)
        # Native Git admission is an inert seam, as in the existing fixture.
        # The selected original metadata files themselves are actual reads,
        # identity/roster checks, same-byte ZIP+tree, and positive closes.
        relative=f'release/store/{"ios" if platform=="ios" else "android"}/en-US/title.txt'
        path=f.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'Original stage title\n');path.chmod(0o644)
        body=path.read_bytes()
        from mobile_release.metadata import PLATFORM_METADATA_ROOTS
        for selected in PLATFORM_METADATA_ROOTS[platform]:
            for original in sorted((f.root/'release/store'/selected).rglob('*')):
                if original.is_file():
                    raw=original.read_bytes();name=original.relative_to(f.root).as_posix().encode()
                    f.rows.append((name,hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest().encode()))
        f.rows.sort()
        intent,_,_=documents(platform,'external-testing');f.stage_precondition=intent['storePrecondition']
        if platform=='android':f.stage_precondition['snapshot']['bundles'][0]['sha256']=f.manifest['files'][0]['sha256']
        if platform=='ios':
            f.stage_precondition['appIdentity']=f.manifest['bundleId']
        observed=[]
        def snapshot(argv,env,value):
            key='MOBILE_RELEASE_STORE_LANE_LOCAL_STAGE';ctx=json.loads(env[key]);observed.append(ctx)
            self.assertEqual(set(ctx),{'stage','platform','metadataInputs'})
            self.assertEqual((ctx['stage'],ctx['platform']),('external-testing',platform))
            root=Path(ctx['metadataInputs']['root']);self.assertEqual(root.name,'metadata-tree')
            self.assertEqual((root/relative.removeprefix('release/store/')).read_bytes(),body)
            self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE',env)
            self.assertNotIn('MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON',env)
            return value,0
        f.stage_snapshot=snapshot
        return f,prior,observed
    def check(self,platform):
        f,prior,observed=self.prepare(platform)
        t,e,events,calls,high=f.run_original()
        self.assertEqual(t['outcome'],'complete',self.detail(e,t))
        self.assertEqual(events,list(wire.PHASES));self.assertEqual(len(calls),15 if platform=='ios' else 14)
        self.assertEqual(e.service.observation.calls,8);self.assertEqual(len(observed),1)
        self.assertTrue(e.service.closed());self.assertTrue(e.service.stage_predecessors.closed)
        self.assertTrue(e.service.metadata_tree.closed and e.service.metadata_tree.retired)
        self.assertFalse(e.service.metadata_scratch._path.exists())
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        out=f.root/'.mobile-release/store/local'/UUID(STAGE).hex
        self.assertEqual({p.name for p in out.iterdir()},{'operation-intent.json','store-precondition.json','store-metadata.zip'})
        intent=json.loads((out/'operation-intent.json').read_bytes())
        self.assertEqual(intent['predecessors']['candidateReceiptSha256'],hashlib.sha256(prior).hexdigest())
        with zipfile.ZipFile(io.BytesIO((out/'store-metadata.zip').read_bytes())) as z:
            self.assertEqual(z.read(('ios' if platform=='ios' else 'android')+'/en-US/title.txt'),b'Original stage title\n')
        self.assertEqual(t['result']['preparedIntent']['operationId'],STAGE)
        self.assertEqual(t['result']['headSequence'],9);wire.validate_result(t['result'],platform=platform,selected='external-testing')
    def test_same_original_android_prepare_uses_new_metadata_without_rebuild(self):self.check('android')
    def test_same_original_ios_prepare_uses_three_roots_and_supplemental_input(self):self.check('ios')

    def test_pending_ack_refusal_does_not_read_material_or_enter_lane(self):
        f,_,observed=self.prepare('android')
        t,e,events,calls,_=f.run_original(fault='prepare-pending')
        self.assertNotEqual(t['outcome'],'complete',self.detail(e,t));self.assertIsNone(t['result'])
        self.assertEqual(events,list(wire.PHASES[:3]));self.assertEqual(len(calls),6)
        self.assertFalse(e.input._material_read);self.assertEqual(observed,[])
        self.assertEqual(f.current_phase(),'promotion-pending');self.assertTrue(e.service.closed(),self.detail(e,t))

    def test_last_source_mutation_cannot_publish_ready_intent(self):
        for target in ('metadata','predecessor'):
            with self.subTest(target=target):
                f,_,observed=self.prepare('android')
                def change(engine):
                    p=(f.root/'release/store/android/en-US/title.txt') if target=='metadata' else (f.root/'.mobile-release/store/local'/UUID(f.value['context']['candidateOperationId']).hex/'operation-intent.json')
                    p.write_bytes(b'changed across final original status')
                f.stage_final_source=change
                t,e,events,calls,_=f.run_original()
                self.assertNotEqual(t['outcome'],'complete',self.detail(e,t));self.assertIsNone(t['result'])
                self.assertEqual(len(calls),14);self.assertEqual(len(observed),1)
                self.assertNotIn('prepare-settled',events);self.assertEqual(f.current_phase(),'promotion-pending')
                self.assertFalse((f.root/'.mobile-release/store/local'/UUID(STAGE).hex/'operation-intent.json').exists())
                self.assertTrue(e.service.stage_predecessors.closed)

    def test_original_tree_close_unknown_cannot_fund_final_bundle_or_publication(self):
        f,_,_=self.prepare('ios')
        t,e,events,calls,_=f.run_original(fault='stage-tree-close')
        self.assertEqual(t['outcome'],'unknown',self.detail(e,t));self.assertIsNone(t['result'])
        self.assertFalse(e.service.stage_source_closed);self.assertFalse(e.service.closed())
        self.assertEqual(f.current_phase(),'promotion-pending');self.assertNotIn('prepare-settled',events)
        self.assertTrue(any(s.close_state=='UNKNOWN' for s in e.service.metadata_tree.slots))

    def test_whole_phase_quote_refuses_before_tree_acquisition_pending_or_material(self):
        f,_,observed=self.prepare('android')
        from mobile_release.local_store_prepare import LocalStorePrepareRun
        original=LocalStorePrepareRun.metadata_quote
        def refuse(owner,directories,scratch):
            # Same actual pre-acquisition quote; extra real directory demand
            # models an admitted but over-cap metadata roster, not cap raising.
            return original(owner,directories+256,scratch)
        with patch.object(LocalStorePrepareRun,'metadata_quote',refuse):t,e,events,calls,_=f.run_original()
        self.assertNotEqual(t['outcome'],'complete',self.detail(e,t));self.assertIsNone(t['result'])
        self.assertEqual(events,['lease-ready']);self.assertEqual(len(calls),6);self.assertEqual(observed,[])
        self.assertFalse(e.input._material_read);self.assertIsNone(e.service.metadata_tree)
        self.assertEqual(f.current_phase(),'settled-success');self.assertTrue(e.service.closed(),self.detail(e,t))
