"""Real owned source/lane/journal restart composition; inert native/Play boundary."""
import copy
import json
from pathlib import Path
import unittest
import test_local_store_execute as execute_fixture
from mobile_release import _desktop_store_reconcile_protocol as W

class LocalStoreReconcileTests(unittest.TestCase):
    def setUp(self):
        self.prior=execute_fixture.LocalStoreExecuteTests(methodName='runTest');self.prior.setUp();self.addCleanup(self.prior.doCleanups)
        self.f=self.prior.f
        t,e,_,_,_=self.f.run_original(_execute=True,fault='execute-pending')
        self.assertIsNone(t['result']);self.assertEqual(self.f.current_phase(),'execute-pending')
        self.f.value['protocol']=W.PROTOCOL;c=self.f.value['context'];c['operation']='local-store-reconcile'
        c.pop('toolchainSelection');self.f.value['native'].pop('toolchain')
        self.f.execution_receipt=self.receipt
        self.old=self.f.root/'.mobile-release/store/lane-attempts-v1/old-unknown.pending'
        self.old.write_bytes(b'unknown originals are not adopted');self.old.chmod(0o600)
    def receipt(self,argv,env):
        self.assertIn('MOBILE_RELEASE_STORE_LANE_LOCAL_RECONCILE',env)
        self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE',env)
        self.assertNotIn('JAVA_HOME',env);self.assertNotIn('MOBILE_RELEASE_BUNDLETOOL_JAR',env)
        # Reuse the existing complete authenticated target body fixture. This
        # adapter is only the inert Ruby/provider boundary, not core admission.
        value,status=self.prior.receipt(argv,dict(env,MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE=env['MOBILE_RELEASE_STORE_LANE_LOCAL_RECONCILE']))
        value['result']='reconciled';value['storeState']['mode']='recovery';value['storeState'].pop('mutationEditId',None)
        if hasattr(self,'mutate_receipt'):self.mutate_receipt(value)
        return value,status
    def originals(self):
        roots=(self.f.home,self.prior.prepared)
        return {str(p):(p.stat().st_ino,p.read_bytes()) for root in roots for p in root.rglob('*') if p.is_file()}
    def test_restart_target_readback_preserves_journal_prepared_and_old_marker(self):
        before=self.originals();old=(self.old.stat().st_ino,self.old.read_bytes())
        t,e,events,calls,high=self.f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',''.join(__import__('traceback').format_exception(e.primary)) if e.primary else '')
        self.assertEqual(events,list(W.PHASES));self.assertEqual(len(calls),14);self.assertEqual(t['lifetime']['commands'],14)
        self.assertEqual(t['result']['headSequence'],6);self.assertEqual(self.f.current_phase(),'execute-pending')
        self.assertEqual(before,self.originals());self.assertEqual(old,(self.old.stat().st_ino,self.old.read_bytes()))
        self.assertEqual([p.name for p in self.old.parent.iterdir()],[self.old.name])
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed());self.assertTrue(e.service.store_completed)
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertIsNone(e.service.tool_reader);self.assertIsNone(e.service.pending_head)
        r=t['result']['reconciliationReceipt'];self.assertEqual(r['authorizationId'],'66666666-6666-4666-8666-666666666666')
        self.assertEqual(r['priorExecutionFinality'],'not-established');self.assertEqual(r['result'],'reconciled')
        self.assertNotIn(str(self.f.root),json.dumps(t));W.validate_result(t['result'])
    def test_checkpoint_refusal_precedes_material_and_store_without_new_marker(self):
        before=self.originals();t,e,events,calls,_=self.f.run_original(_reconcile=True,fault='history-head')
        self.assertIsNone(t['result']);self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read)
        self.assertEqual(before,self.originals());self.assertEqual([p.name for p in self.old.parent.iterdir()],[self.old.name])
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_foreign_receipt_cannot_accept_or_retire_new_attempt(self):
        before=self.originals();self.mutate_receipt=lambda r:r['executedBy'].update(purpose='execute')
        t,e,events,calls,_=self.f.run_original(_reconcile=True)
        self.assertIsNone(t['result']);self.assertEqual(len(calls),12);self.assertFalse(e.service.store_completed)
        self.assertEqual(before,self.originals());self.assertTrue(self.old.exists())
        self.assertEqual(len(list(self.old.parent.iterdir())),2);self.assertTrue(e.service.closed())
    def test_actual_last_source_change_refuses_target_and_preserves_attempt(self):
        t,e,events,calls,_=self.f.run_original(_reconcile=True,fault='last-source')
        self.assertIsNone(t['result']);self.assertEqual(len(calls),14);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertEqual(len(list(self.old.parent.iterdir())),2)
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_same_old_auth_and_changed_intent_refuse_before_google(self):
        for fault in ('same-authorization',None):
            if fault is None:self.f.value['context']['intentSha256']='f'*64
            t,e,events,calls,_=self.f.run_original(_reconcile=True,fault=fault)
            self.assertIsNone(t['result']);self.assertEqual(events,['lease-ready']);self.assertEqual(len(calls),6)
            self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed())
    def append_failure(self,phase):
        # Authenticated disk-journal fixture only, not claimed native closure.
        import time
        from test_local_release_history import ENROLLMENT,KEY
        from mobile_release.local_release_journal import LocalReleaseJournal
        j=LocalReleaseJournal(str(self.f.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY)
        j.open_existing()
        try:j._append(expected_head=j.head(),operation_id=self.f.value['context']['candidateOperationId'],phase=phase,
            payload={'phase':'execute-pending','reason':'cleanup-unknown' if phase=='reconciliation-required' else 'store-refused'})
        finally:j.close()
    def test_reconciliation_required_stays_fenced_after_current_target(self):
        self.append_failure('reconciliation-required');before=self.originals()
        t,e,_,calls,_=self.f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(len(calls),14)
        self.assertEqual(t['result']['headSequence'],7);self.assertEqual(self.f.current_phase(),'reconciliation-required')
        self.assertEqual(before,self.originals());self.assertTrue(self.old.exists())
    def test_settled_failure_is_observation_only_not_repaired(self):
        self.append_failure('settled-failure');before=self.originals()
        t,e,_,_,_=self.f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(self.f.current_phase(),'settled-failure')
        self.assertEqual(before,self.originals());self.assertIsNone(e.service.pending_head)
    def test_known_stop_after_head_ack_never_receives_google(self):
        before=self.originals();t,e,_,calls,_=self.f.run_original(_reconcile=True,fault='cancel-after-pending')
        self.assertEqual((t['outcome'],t['reason'],t['lifetime']['stopObserved']),('cancelled','cancelled','cancelled'))
        self.assertIsNone(t['result']);self.assertFalse(e.input._material_read);self.assertEqual(len(calls),6)
        self.assertEqual(before,self.originals());self.assertTrue(e.service.closed())
    def test_unknown_original_prepared_close_never_accepts_new_target(self):
        before=self.originals();t,e,_,calls,_=self.f.run_original(_reconcile=True,fault='prepared-close')
        self.assertEqual((t['outcome'],t['reason']),('unknown','cleanup-unknown'),repr(e.primary))
        self.assertIsNone(t['result']);self.assertFalse(e.service.store_completed);self.assertEqual(len(calls),14)
        self.assertEqual(before,self.originals());self.assertFalse(e.service.closed());self.assertTrue(e.input.material_closed())
        self.assertTrue(all(p.closed() for p in e.service.fence_readers))
    def test_existing_new_output_is_preserved_before_any_source_or_store_call(self):
        target=self.prior.prepared.with_name(self.prior.prepared.name+'-recover-'+'66666666666646668666666666666666')
        target.mkdir(mode=0o700);leaf=target/'raw-store-receipt.json';leaf.write_bytes(b'foreign original');leaf.chmod(0o600)
        t,e,events,calls,_=self.f.run_original(_reconcile=True)
        self.assertIsNone(t['result']);self.assertEqual(events,[]);self.assertEqual(calls,[])
        self.assertEqual(leaf.read_bytes(),b'foreign original');self.assertTrue(e.service.closed())
    def test_existing_new_attempt_collision_is_not_removed_or_reused(self):
        from mobile_release.local_release_receipt import local_execution_attempt_key
        from mobile_release.local_release_journal import canonical
        intent=self.prior.intent;raw=(self.prior.prepared/'operation-intent.json').read_bytes()
        authority=dict(intent['preparedBy'],purpose='recover',authorizationId='66666666-6666-4666-8666-666666666666',intentSha256=intent['integrity']['sha256'])
        key=local_execution_attempt_key(intent_data=raw,authority_data=canonical(authority),purpose='recover',expected_intent_sha256=intent['integrity']['sha256'])
        marker=self.old.parent/(key+'.pending');marker.write_bytes(b'occupied original');marker.chmod(0o600)
        before=self.originals();t,e,events,calls,_=self.f.run_original(_reconcile=True)
        self.assertIsNone(t['result']);self.assertEqual(len(calls),11);self.assertFalse(e.service.record._attempted)
        self.assertEqual(marker.read_bytes(),b'occupied original');self.assertEqual(before,self.originals())
        # Existing original marker acquisition conservatively retains unknown
        # on a failed create-exclusive call; do not manufacture close credit.
        self.assertEqual((t['outcome'],t['reason']),('unknown','cleanup-unknown'))
        self.assertFalse(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_closed_context_and_result_do_not_accept_tools_or_retry_claim(self):
        for mutate in (lambda c:c.update(toolchainSelection={}),lambda c:c.update(operation='local-store-execute'),
                       lambda c:c.update(intentSha256='')):
            c=copy.deepcopy(self.f.value['context']);mutate(c)
            with self.assertRaises(ValueError):W.context(c)
        t,e,_,_,_=self.f.run_original(_reconcile=True);self.assertEqual(t['outcome'],'complete',repr(e.primary))
        for mutate in (lambda r:r.update(headSequence=5),lambda r:r['reconciliationReceipt'].update(result='accepted'),
                       lambda r:r['reconciliationReceipt'].update(priorExecutionFinality='established'),
                       lambda r:r['reconciliationReceipt'].update(retryAllowed=True)):
            r=copy.deepcopy(t['result']);mutate(r)
            with self.assertRaises(ValueError):W.validate_result(r)
