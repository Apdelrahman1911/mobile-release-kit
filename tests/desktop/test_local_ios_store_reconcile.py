"""Actual iOS Reconcile owners/originals; inert native admission and ASC lane."""
import copy
import json
from pathlib import Path
import unittest
import test_local_ios_store_execute as execute_fixture
from mobile_release import _desktop_store_reconcile_protocol as W

class IOSStoreReconcileTests(unittest.TestCase):
    def setUp(self):
        self.prior=execute_fixture.IOSStoreExecuteTests(methodName='runTest');self.prior.setUp();self.addCleanup(self.prior.doCleanups)
        self.f=self.prior.f
        t,e,_,_,_=self.f.run_original(_execute=True,fault='execute-pending')
        self.assertIsNone(t['result']);self.assertEqual(self.f.current_phase(),'execute-pending')
        self.f.value['protocol']=W.PROTOCOL;self.f.value['context']['operation']='local-store-reconcile'
        for key in ('signingTools','uploadSelection'):self.f.value['native'].pop(key)
        self.f.execution_receipt=self.receipt
        self.resolves=len(self.prior.resolutions)
        self.old=self.f.root/'.mobile-release/store/lane-attempts-v1/old-unknown.pending'
        self.old.write_bytes(b'unknown old original remains');self.old.chmod(0o600)
    def receipt(self,argv,env):
        self.assertIn('MOBILE_RELEASE_STORE_LANE_LOCAL_RECONCILE',env)
        self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE',env)
        self.assertNotIn('DEVELOPER_DIR',env);self.assertNotIn('JAVA_HOME',env)
        context=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_RECONCILE']);self.assertEqual(set(context),{'authority','expectedIntentSha256'})
        self.assertEqual(context['authority']['purpose'],'recover')
        self.assertEqual(context['authority']['assignment']['kind'],'asc-p8')
        self.assertEqual(env['MOBILE_RELEASE_IOS_ARCHIVE_PATH'],str(self.f.bundle/'archive.xcarchive'))
        self.assertEqual(env['MOBILE_RELEASE_IOS_IPA_PATH'],str(self.f.bundle/'export/App.ipa'))
        i=self.prior.intent
        value=dict(documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',
            project=i['project'],operationId=i['operationId'],candidateSha256=i['candidateSha256'],
            operationIntentSha256=i['integrity']['sha256'],preparedBy=i['preparedBy'],executedBy=context['authority'],
            operation='ios_testflight_internal',platform='ios',appIdentity=i['application']['id'],
            marketingVersion=i['version']['marketing'],buildNumber=i['version']['build'],observedAt='2026-10-17T00:00:00Z',
            result='reconciled',state='processed',appStoreAppId=i['application']['storeAppId'],
            buildResourceId='12345678-1234-1234-1234-123456789abc',processingState='VALID',autoNotifyEnabled=False)
        if hasattr(self,'change_receipt'):self.change_receipt(value)
        return value,0
    def originals(self):
        return {str(p):(p.stat().st_ino,p.read_bytes()) for root in (self.f.home,self.prior.prepared,self.f.bundle)
            for p in root.rglob('*') if p.is_file()}
    def test_actual15_readonly_head_originals_and_no_upload_tools(self):
        before=self.originals();old=(self.old.stat().st_ino,self.old.read_bytes())
        t,e,events,calls,high=self.f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',''.join(__import__('traceback').format_exception(e.primary)))
        self.assertEqual(len(calls),15);self.assertEqual(t['lifetime']['commands'],15);self.assertEqual(events,list(W.PHASES))
        self.assertEqual([r['kind'] for r in e.service._runtime_rows],['probe']*5+['apple-key','lane'])
        self.assertEqual(len(self.prior.resolutions),self.resolves);self.assertIsNone(e.service.tool_reader)
        self.assertEqual(e.input.reply_step,2);self.assertFalse(e.input._ios_final_reply)
        self.assertEqual(e.service.bundle.tree_reads,2);self.assertTrue(e.service.bundle.tree_closed())
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed());self.assertTrue(e.service.store_completed)
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertEqual(before,self.originals())
        self.assertEqual(old,(self.old.stat().st_ino,self.old.read_bytes()));self.assertEqual(list(self.old.parent.iterdir()),[self.old])
        r=t['result'];W.validate_result(r,platform='ios');self.assertEqual(r['headSequence'],6)
        self.assertEqual(r['scope'],'local-ios-store-reconcile');self.assertEqual(len(r['reconciliationReceipt']),16)
        self.assertEqual(r['reconciliationReceipt']['observation'],'current-internal-build-only')
        self.assertEqual(r['reconciliationReceipt']['priorExecutionFinality'],'not-established')
        with self.assertRaises(ValueError):W.validate_result(r)
        self.assertNotIn(str(self.f.root),json.dumps(t))
    def test_head_and_bad_asc_refuse_before_lane(self):
        for n,(fault,count) in enumerate((('history-head',6),('bad-p8',12),('cancel-after-pending',6))):
            if n:self.doCleanups();self.setUp()
            before=self.originals();t,e,events,calls,_=self.f.run_original(_reconcile=True,fault=fault)
            self.assertIsNone(t['result']);self.assertEqual(len(calls),count);self.assertEqual(before,self.originals())
            self.assertFalse(e.service.store_completed);self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_receipt_partial_foreign_and_actual_final_source_refuse(self):
        for n,kind in enumerate(('processing','notify','foreign','last-source','bundle-post')):
            if n:self.doCleanups();self.setUp()
            if kind=='processing':self.change_receipt=lambda r:r.update(processingState='PROCESSING')
            elif kind=='notify':self.change_receipt=lambda r:r.update(autoNotifyEnabled=True)
            elif kind=='foreign':self.change_receipt=lambda r:r['executedBy'].update(purpose='execute')
            t,e,_,calls,_=self.f.run_original(_reconcile=True,fault=kind if kind in {'last-source','bundle-post'} else None)
            self.assertIsNone(t['result']);self.assertFalse(e.service.store_completed);self.assertEqual(self.f.current_phase(),'execute-pending')
            self.assertTrue(self.old.exists());self.assertTrue(e.input.material_closed());self.assertTrue(e.service.closed(),repr(e.primary))
            if hasattr(self,'change_receipt'):del self.change_receipt
    def test_unknown_original_close_blocks_final_archive_and_success(self):
        before=self.originals();t,e,_,calls,_=self.f.run_original(_reconcile=True,fault='prepared-close')
        self.assertEqual((t['outcome'],t['reason']),('unknown','cleanup-unknown'),repr(e.primary))
        self.assertIsNone(t['result']);self.assertEqual(len(calls),15);self.assertEqual(e.service.bundle.tree_reads,1)
        self.assertEqual(before,self.originals());self.assertFalse(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_context_history_and_settlement_are_explicit_platform_closed(self):
        self.assertEqual(W.context(self.f.value['context']),self.f.value['context'])
        for mutate in (lambda c:c.update(settlement=None),lambda c:c.update(operation='local-store-recovery-settle',settlement='record-current-target'),
                       lambda c:c.update(toolchainSelection={}),lambda c:c.update(platform='android')):
            c=copy.deepcopy(self.f.value['context']);mutate(c)
            with self.assertRaises(ValueError):W.context(c)
        from mobile_release import _desktop_local_history_protocol as h
        c=dict(projectId='p',executionMode='local',action='review-reconcile',platform='ios',candidateOperationId=self.f.value['context']['candidateOperationId'])
        self.assertEqual(h.context(c),c)
        with self.assertRaises(ValueError):h.context({**c,'action':'review-recovery'})
    def test_restart_prepared_review_accepts_ios_execution_chain_only(self):
        from test_local_release_history import LocalHistoryTests
        before=self.originals();t,events,h=LocalHistoryTests.run_original(self.f,'review-reconcile')
        self.assertEqual(t['outcome'],'complete',repr(h.primary));r=t['result']['preparedIntent']
        self.assertEqual(len(r),14);self.assertEqual(r['bundleId'],self.prior.intent['application']['id'])
        self.assertEqual(r['priorPrepareFinality'],'not-established');self.assertEqual(before,self.originals())
        self.assertEqual([kind for kind,_ in events],['lease-ready','history-head']);self.assertTrue(h.service.closed());self.assertTrue(h.input.closed and h.input.lease_closed)
