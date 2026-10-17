"""Existing whole Prepare engine with actual iOS originals; native/ASC are inert."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import test_local_store_prepare as original
from test_local_store_prepare import OP,ENROLLMENT,KEY,canonical,S,W
from mobile_release.local_release_journal import LocalReleaseJournal
from mobile_release.local_ios_candidate_bundle import archive_digest
from mobile_release.ios_artifacts import _File

class IOSStorePrepareTests(unittest.TestCase):
    fixture_platform='ios'
    setUp=original.LocalStorePrepareTests.setUp
    current_phase=original.LocalStorePrepareTests.current_phase
    run_original=original.LocalStorePrepareTests.run_original

    def ios_bundle(self,config,c):
        self.bundle=self.root/'.mobile-release/desktop-ios-archive'/OP.replace('-','')
        self.bundle.mkdir(parents=True,mode=0o700)
        p=self.bundle
        while p!=self.root:p.chmod(0o700);p=p.parent
        archive=self.bundle/'archive.xcarchive';archive.mkdir(mode=0o755)
        app=archive/'App.app';app.mkdir(mode=0o755)
        body=b'inert original archive';(app/'Info.plist').write_bytes(body);(app/'Info.plist').chmod(0o644)
        inventory={'App.app':None,'App.app/Info.plist':_File(len(body),hashlib.sha256(body).hexdigest(),body[:4])}
        (self.bundle/'export').mkdir(mode=0o700)
        rows=[]
        for name in ('export/App.ipa','store-metadata.zip','validation-report.json'):
            body=('inert retained '+name).encode();p=self.bundle/name;p.write_bytes(body);p.chmod(0o600)
            rows.append(dict(fileName=name,bytes=len(body),sha256=hashlib.sha256(body).hexdigest()))
        manifest=dict(schemaVersion=1,scope='local-ios-candidate-inputs',operationId=OP,enrollment=ENROLLMENT,
            sourceCommit='a'*40,sourceTree='b'*40,savedConfig=c['savedConfig'],savedVersion=c['savedVersion'],
            bundleId=config['ios']['bundleId'],signing=dict(platform='ios',kind='apple-distribution',
                teamId=config['ios']['teamId'],certificateSha256=config['ios']['distributionCertificateSha256'],
                profileUuid='12345678-1234-1234-1234-123456789ABC',profileExpiresAt='2027-01-01T00:00:00Z'),
            files=rows,archive=dict(directory='archive.xcarchive',entries=2,bytes=inventory['App.app/Info.plist'].size,sha256=archive_digest(inventory)))
        if hasattr(self,'manifest_change'):self.manifest_change(manifest)
        return manifest

    def test_actual_prepare15_pending_before_asc_and_current_original_publication(self):
        before={p.relative_to(self.bundle).as_posix():(p.stat().st_ino,p.read_bytes()) for p in self.bundle.rglob('*') if p.is_file()}
        t,e,events,calls,high=self.run_original()
        self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(len(calls),15)
        self.assertEqual(t['lifetime']['commands'],15);self.assertEqual(events,list(W.PHASES))
        self.assertEqual(len(e.service._source_rows),8);self.assertEqual(len(e.service._runtime_rows),7)
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
        self.assertEqual(e.service.bundle.tree_reads,2);self.assertTrue(e.service.bundle.tree_closed())
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        result=t['result'];self.assertEqual(result['scope'],'local-ios-store-prepare');self.assertEqual(result['headSequence'],5)
        p=result['preparedIntent'];self.assertEqual(len(p),12);self.assertEqual(p['appStoreAppId'],'1234567890')
        self.assertEqual(p['destination'],{'channel':'testflight-internal'});self.assertEqual(p['limitations'],W.IOS_LIMITATIONS)
        self.assertNotIn('applicationId',p);W.validate_result(result,platform='ios')
        with self.assertRaises(W.ProtocolError):W.validate_result(result)
        for key,bad in [('applicationId','com.other.app'),('appStoreAppId',123),('bundleId','9wrong.bundle'),
                        ('destination',{'channel':'internal'}),('limitations',W.LIMITATIONS)]:
            changed=copy.deepcopy(result);changed['preparedIntent'][key]=bad
            with self.subTest(key=key),self.assertRaises(W.ProtocolError):W.validate_result(changed,platform='ios')
        changed=copy.deepcopy(result);changed['preparedIntent']['appStoreAppId']='00123'
        W.validate_result(changed,platform='ios') # Existing config string semantics, not normalization.
        from mobile_release.local_release_intent import decode_local_operation_intent
        target=Path(e.service.record._output);raw=target.with_name('operation-intent.json').read_bytes()
        intent=decode_local_operation_intent(raw,platform='ios')
        self.assertEqual(intent['signing'],[self.manifest['signing']]);self.assertEqual(intent['artifacts'][3]['sha256'],self.manifest['archive']['sha256'])
        self.assertEqual(intent['preparedBy']['assignment']['kind'],'asc-p8')
        self.assertEqual(before,{p.relative_to(self.bundle).as_posix():(p.stat().st_ino,p.read_bytes()) for p in self.bundle.rglob('*') if p.is_file()})
        self.assertNotIn('INERT',json.dumps(t));self.assertNotIn(str(self.root),json.dumps(t))

    def test_pending_rejection_and_bad_p8_never_reach_lane(self):
        for fault,count in [('prepare-pending',6),('bad-p8',12)]:
            with self.subTest(fault=fault):
                if fault!='prepare-pending':self.doCleanups();self.setUp()
                t,e,events,calls,_=self.run_original(fault=fault)
                self.assertNotEqual(t['outcome'],'complete',repr(e.primary));self.assertIsNone(t['result'])
                self.assertEqual(len(calls),count);self.assertEqual(self.current_phase(),'prepare-pending')
                self.assertFalse(any(a[-1]=='ios_testflight_internal' for a in calls))
                self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
                self.assertEqual(e.input._material_read,fault=='bad-p8')

    def test_final_ack_drain_consumes_original_after_stop_or_work_timeout_without_success(self):
        for fault,reason in [('ack-stop','cancelled'),('ack-time','timed-out')]:
            with self.subTest(fault=fault):
                if fault!='ack-stop':self.doCleanups();self.setUp()
                parsed=[];original_reply=W.reply
                def reply(raw,request,kind,step):
                    value=original_reply(raw,request,kind,step)
                    if step==4:parsed.append(step)
                    return value
                with patch.object(W,'reply',reply):t,e,events,calls,_=self.run_original(fault=fault)
                self.assertEqual(parsed,[4]) # Exact actual reply validated, not merely attempted/drained away at close.
                self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertEqual(t['lifetime']['stopObserved'],reason)
                self.assertEqual(events,list(W.PHASES));self.assertEqual(len(calls),15)
                self.assertEqual(e.input.reply_step,4);self.assertFalse(e.input._ios_final_reply)
                self.assertTrue(e.input.material_closed());self.assertTrue(e.service.closed())
                self.assertEqual(self.current_phase(),'prepared')

    def test_snapshot_drift_missing_nested_terminal_and_unknown_publication_close_refuse(self):
        for i,fault in enumerate(('snapshot-platform','snapshot-missing','nested-terminal','bundle-post','publication-post','publication-close')):
            with self.subTest(fault=fault):
                if i:self.doCleanups();self.setUp()
                t,e,events,calls,_=self.run_original(fault=fault)
                self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result'])
                self.assertEqual(self.current_phase(),'prepared' if fault.startswith('publication-') else 'prepare-pending')
                if fault=='publication-close':self.assertEqual(t['outcome'],'unknown');self.assertFalse(e.service.closed())

    def test_ios_context_and_result_do_not_extend_mutating_or_default_android_grammars(self):
        c=self.value['context'];self.assertEqual(W.context(c,apple_prepare=True),c)
        with self.assertRaises(W.ProtocolError):W.context(c)
        from mobile_release import _desktop_store_execute_protocol as execute,_desktop_store_reconcile_protocol as reconcile
        for codec,operation in [(execute,'local-store-execute'),(reconcile,'local-store-reconcile')]:
            row={**c,'operation':operation,'intentSha256':'c'*64}
            with self.assertRaises(ValueError):codec.context(row)
        from mobile_release import _desktop_local_history_protocol as h
        row=dict(projectId='p',executionMode='local',action='review-prepared',platform='ios',candidateOperationId=OP)
        self.assertEqual(h.context(row),row)
        for action in ('review-execution','review-reconcile','review-recovery'):
            with self.assertRaises(ValueError):h.context({**row,'action':action})

    def test_ios_tree_reservation_preserves256_and_android_original_quote(self):
        self.assertEqual(S.resource_quote(project_depth=8,version_parent_depth=9,source=48,history_depth=8)['total'],178)
        found=[]
        for source in range(1,97):
            try:q=S.resource_quote(project_depth=16,version_parent_depth=17,source=source,history_depth=8,platform='ios')
            except W.ProtocolError:continue
            found.append(q['total'])
        self.assertIn(256,found)
        with self.assertRaises(W.ProtocolError):S.resource_quote(project_depth=16,version_parent_depth=17,source=96,history_depth=8,platform='ios')

    def request(self,fd,action):
        from test_local_release_history import LocalHistoryTests
        value=LocalHistoryTests.request(self,fd,action)
        value['context'].update(platform='ios',candidateOperationId=OP)
        return value

    def test_current_prepared_history_reuses_original_ios_files_without_store_or_old_finality(self):
        from test_local_release_history import LocalHistoryTests
        t,e,_,_,_=self.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        result=t['result']['preparedIntent'];target=Path(e.service.record._output).parent
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in target.iterdir()}
        t,events,h=LocalHistoryTests.run_original(self,'review-prepared')
        self.assertEqual(t['outcome'],'complete',repr(h.primary));p=t['result']['preparedIntent']
        self.assertEqual(len(p),14);self.assertEqual({k:p[k] for k in result},result)
        self.assertEqual(p['observation'],'current-prepared-files-only');self.assertEqual(p['priorPrepareFinality'],'not-established')
        self.assertEqual(t['lifetime']['commands'],0);self.assertEqual([r[0] for r in events],['lease-ready','history-head'])
        self.assertTrue(h.service.bundle.tree_closed());self.assertEqual(h.service.bundle.bindings,{})
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in target.iterdir()})
        (target/'store-precondition.json').write_bytes(before['store-precondition.json'][1]+b' ')
        t,_,_=LocalHistoryTests.run_original(self,'review-prepared')
        self.assertEqual(t['outcome'],'refused');self.assertIsNone(t['result'])

    def test_authenticated_but_wrong_source_bundle_or_signing_never_requests_material(self):
        for i,change in enumerate((lambda m:m.update(bundleId='com.other.application'),
                lambda m:m['signing'].update(certificateSha256='f'*64),
                lambda m:m.update(sourceCommit='f'*40))):
            with self.subTest(case=i):
                self.doCleanups();self.manifest_change=change;self.setUp()
                t,e,events,calls,_=self.run_original()
                self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result'])
                self.assertEqual(events,['lease-ready']);self.assertEqual(len(calls),6)
                self.assertFalse(e.input._material_read);self.assertEqual(self.current_phase(),'inputs-ready')
                self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
