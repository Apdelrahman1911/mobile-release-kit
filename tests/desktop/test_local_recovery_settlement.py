"""Original core owners; native anchors/Store are inert, old tail is never proven."""
import copy
import hashlib
import json
import time
import unittest
from uuid import UUID
import test_local_store_reconcile as fixture
from mobile_release import _desktop_store_reconcile_protocol as W
from mobile_release.local_release_journal import LocalReleaseJournal,canonical
from mobile_release.local_release_receipt import local_execution_attempt_key
from test_local_release_history import ENROLLMENT,KEY

class LocalRecoverySettlementTests(unittest.TestCase):
    def setUp(self):
        self.r=fixture.LocalStoreReconcileTests(methodName='runTest');self.r.setUp();self.addCleanup(self.r.doCleanups)
        self.f=self.r.f;self.old=self.r.old;self.old.unlink()
        c=self.f.value['context'];c.update(operation='local-store-recovery-settle',settlement=W.SETTLEMENT)
        self.intent=self.r.prior.intent;raw=(self.r.prior.prepared/'operation-intent.json').read_bytes()
        authority=dict(self.intent['preparedBy'],purpose='execute',authorizationId='55555555-5555-4555-8555-555555555555',intentSha256=c['intentSha256'])
        key=local_execution_attempt_key(intent_data=raw,authority_data=canonical(authority),purpose='execute',expected_intent_sha256=c['intentSha256'])
        self.marker=self.old.parent/(key+'.pending')
        self.body=dict(version=1,key=key,nonce='8'*32,lane='android_internal_upload',mode='execute',
            output=str(self.r.prior.prepared.with_name(self.r.prior.prepared.name+'-execute-'+UUID(authority['authorizationId']).hex)/'raw-store-receipt.json'))
        self.marker.write_bytes(canonical(self.body)+b'\n');self.marker.chmod(0o600)
    def journal(self):
        j=LocalReleaseJournal(str(self.f.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing();return j
    def run_original(self,**kwargs):return self.f.run_original(_reconcile=True,**kwargs)
    def test_new_checkpoint_retains_marker_and_never_claims_old_finality(self):
        old=(self.marker.stat().st_ino,self.marker.read_bytes());before=self.r.originals()
        t,e,events,calls,high=self.run_original()
        self.assertEqual(t['outcome'],'complete',getattr(e,'inert_debug','')+repr(e.primary))
        self.assertEqual(events,[*W.PHASES,'recovery-settled']);self.assertEqual(len(calls),14)
        self.assertEqual(t['result']['scope'],'local-android-recovery-settlement');self.assertEqual(t['result']['headSequence'],7)
        self.assertEqual(t['result']['reconciliationReceipt']['priorExecutionFinality'],'not-established')
        self.assertEqual(old,(self.marker.stat().st_ino,self.marker.read_bytes()))
        self.assertEqual([self.marker.name],sorted(p.name for p in self.marker.parent.iterdir()))
        j=self.journal()
        try:
            last=j._rows[-1][0];self.assertEqual(last['phase'],'target-reconciled')
            self.assertEqual(last['payload']['preservedAttempt']['binding']['sha256'],hashlib.sha256(old[1]).hexdigest())
            self.assertFalse(j.history_summary()[-1]['recoveryRequired'])
            self.assertEqual(last['payload']['receiptSha256'],hashlib.sha256(e.service.readback._content).hexdigest())
            self.assertEqual(last['payload']['executeAuthorizationId'],'55555555-5555-4555-8555-555555555555')
        finally:j.close()
        for name,value in before.items():
            p=__import__('pathlib').Path(name);self.assertEqual(value,(p.stat().st_ino,p.read_bytes()))
        self.assertTrue(e.service.closed());self.assertTrue(all(p.closed() for p in e.service.fence_readers))
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
    def test_unknown_or_partial_or_foreign_marker_refuses_before_google(self):
        self.marker.write_bytes(b'partial')
        t,e,events,calls,_=self.run_original()
        self.assertIsNone(t['result']);self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read)
        self.assertEqual(self.marker.read_bytes(),b'partial');self.assertEqual(self.f.current_phase(),'execute-pending')
        self.assertTrue(e.service.closed())
    def test_extra_original_name_is_not_adopted(self):
        self.old.write_bytes(b'unknown');self.old.chmod(0o600)
        t,e,events,calls,_=self.run_original()
        self.assertIsNone(t['result']);self.assertEqual(len(calls),6);self.assertEqual(self.old.read_bytes(),b'unknown')
        self.assertTrue(e.service.closed());self.assertEqual(self.f.current_phase(),'execute-pending')
    def test_absent_old_marker_is_a_fact_not_old_finality(self):
        self.marker.unlink();t,e,events,calls,_=self.run_original()
        self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(len(calls),14)
        j=self.journal()
        try:self.assertIsNone(j._rows[-1][0]['payload']['preservedAttempt'])
        finally:j.close()
        self.assertEqual(t['result']['reconciliationReceipt']['priorExecutionFinality'],'not-established')
    def test_final_source_marker_change_refuses_checkpoint(self):
        self.f.recovery_final_source=lambda _:self.marker.write_bytes(b'changed at final source')
        t,e,events,calls,_=self.run_original()
        self.assertIsNone(t['result']);self.assertNotIn('recovery-settled',events)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertEqual(len(calls),14)
    def test_lost_final_ack_preserves_new_journal_and_old_marker(self):
        old=self.marker.read_bytes();t,e,events,calls,_=self.run_original(fault='recovery-settled')
        self.assertIsNone(t['result']);self.assertEqual(self.f.current_phase(),'target-reconciled')
        self.assertEqual(self.marker.read_bytes(),old);self.assertEqual(len(calls),14)
        self.assertTrue(e.service.closed())
    def test_after_ack_marker_change_never_accepts_result(self):
        self.f.recovery_after_ack=lambda _:self.marker.write_bytes(b'changed after actual ACK')
        t,e,events,calls,_=self.run_original()
        self.assertIsNone(t['result']);self.assertEqual(self.f.current_phase(),'target-reconciled')
        self.assertEqual(len(calls),14);self.assertTrue(e.service.closed())
    def test_variant_result_cannot_pass_ordinary_reconcile_validator(self):
        t,e,_,_,_=self.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        W.validate_result(t['result'],settlement=True)
        with self.assertRaises(ValueError):W.validate_result(t['result'])
        for change in ({'settlement':'repair-old-finality'},{'operation':'local-store-reconcile'}):
            c=copy.deepcopy(self.f.value['context']);c.update(change)
            with self.assertRaises(ValueError):W.context(c)
    def next_prepared(self):
        """New retained candidate fixture, then REAL Prepare on the same journal.

        Candidate bytes/native admission remain inert; no old intent/journal is
        relabeled or edited. The new unique operation goes through actual owners.
        """
        import os,stat
        from mobile_release import _desktop_store_prepare_protocol as P,_desktop_store_execute_protocol as X
        operation='88888888-8888-4888-8888-888888888888';c=self.f.value['context']
        manifest=copy.deepcopy(self.f.manifest);manifest['operationId']=operation
        target=self.f.bundle.parent.parent/UUID(operation).hex/'artifacts';target.mkdir(parents=True,mode=0o700)
        target.parent.chmod(0o700)
        for row in manifest['files']:
            p=target/row['fileName'];p.write_bytes((self.f.bundle/row['fileName']).read_bytes());p.chmod(0o600)
        raw=canonical(manifest)+b'\n';p=target/'candidate-inputs.json';p.write_bytes(raw);p.chmod(0o600)
        c.update(operation='local-store-prepare',candidateOperationId=operation,candidateSha256=hashlib.sha256(raw).hexdigest())
        c.pop('settlement');c.pop('intentSha256');self.f.value['protocol']=P.PROTOCOL
        self.f.manifest,self.f.bundle=manifest,target
        j=self.journal()
        try:
            j._append(expected_head=j.head(),operation_id=operation,phase='inputs-pending',payload=dict(
                configurationSha256=c['savedConfig']['sha256'],versionSha256=c['savedVersion']['sha256'],sourceCommit='a'*40,sourceTree='b'*40))
            j._append(expected_head=j.head(),operation_id=operation,phase='inputs-ready',payload=dict(candidateSha256=c['candidateSha256']))
        finally:j.close()
        t,e,_,calls,_=self.f.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(len(calls),14)
        prepared=self.r.prior.prepared.with_name(UUID(operation).hex)
        self.r.prior.intent=json.loads((prepared/'operation-intent.json').read_bytes());self.f.execution_receipt=self.r.prior.receipt
        c.update(operation='local-store-execute',intentSha256=self.r.prior.intent['integrity']['sha256'])
        raw=(self.f.tools/'android-toolchain.json').read_bytes();st=self.f.tools.stat()
        c['toolchainSelection']=dict(instance='1'*32,ownerUid=os.getuid(),catalogGeneration=1,recordSha256='2'*64,
            inventorySha256=hashlib.sha256(raw).hexdigest(),osProviderSha256='3'*64)
        self.f.value['native']['toolchain']=dict(schemaVersion=2,profile='android-registered-macos-arm64-v1',root=str(self.f.tools),
            rootIdentity=dict(device=str(st.st_dev),inode=str(st.st_ino),mode=stat.S_IFDIR|0o555,uid=0,gid=0),
            inventorySha256=c['toolchainSelection']['inventorySha256'],selection=c['toolchainSelection'])
        self.f.value['protocol']=X.PROTOCOL
        return operation
    def test_next_unique_prepare_execute_requires_exact_conserved_fence(self):
        t,e,_,_,_=self.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        old=(self.marker.stat().st_ino,self.marker.read_bytes());operation=self.next_prepared()
        t,e,events,calls,high=self.f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',getattr(e,'inert_debug','')+repr(e.primary));self.assertEqual(len(calls),14)
        self.assertEqual(t['result']['executionReceipt']['operationId'],operation);self.assertEqual(t['result']['headSequence'],13)
        self.assertEqual(old,(self.marker.stat().st_ino,self.marker.read_bytes()))
        self.assertEqual([self.marker.name],sorted(p.name for p in self.marker.parent.iterdir()))
        self.assertTrue(e.service.closed());self.assertEqual(len(e.service.prior_readers),1)
        self.assertTrue(all(p.closed() for p in e.service.prior_readers));self.assertLessEqual(high,e.service.quote['total'])
    def test_later_execute_refuses_changed_preserved_marker_before_pending(self):
        t,e,_,_,_=self.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary));self.next_prepared()
        self.marker.write_bytes(b'old writer changed original after settlement')
        t,e,events,calls,_=self.f.run_original(_execute=True)
        self.assertIsNone(t['result']);self.assertEqual(len(calls),6);self.assertEqual(events,['lease-ready'])
        self.assertFalse(e.input._material_read);self.assertEqual(self.f.current_phase(),'prepared');self.assertTrue(e.service.closed())
    def test_failed_and_unknown_execution_suffixes_accept_only_new_target_checkpoint(self):
        for phase in ('settled-failure','reconciliation-required'):
            with self.subTest(phase=phase):
                if phase=='reconciliation-required':self.doCleanups();self.setUp()
                self.r.append_failure(phase);t,e,events,calls,_=self.run_original()
                self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(t['result']['headSequence'],8)
                self.assertEqual(len(calls),14);self.assertEqual(events[-1],'recovery-settled')
    def test_repeated_settlement_is_not_authorized_by_new_uuid(self):
        t,e,_,_,_=self.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        before=self.r.originals();t,e,events,calls,_=self.run_original()
        self.assertIsNone(t['result']);self.assertEqual(calls,[]);self.assertFalse(e.input._material_read)
        self.assertEqual(self.r.originals(),before)
    def test_journal_rejects_crossed_authority_and_intent_before_new_row(self):
        from mobile_release.local_release_journal import LocalJournalError
        before=self.r.originals();op=self.f.value['context']['candidateOperationId']
        payload=dict(intentSha256=self.intent['integrity']['sha256'],receiptSha256='1'*64,
            executeAuthorizationId='55555555-5555-4555-8555-555555555555',recoveryAuthorizationId='66666666-6666-4666-8666-666666666666',
            assignmentRevision=self.f.value['context']['recordRevision'],preservedAttempt=None,priorExecutionFinality='not-established')
        for change in ({'executeAuthorizationId':'77777777-7777-4777-8777-777777777777'},
                       {'assignmentRevision':self.f.value['context']['recordRevision']+1},{'intentSha256':'f'*64},{'priorExecutionFinality':'settled'},
                       {'preservedAttempt':{'name':'../../foreign','binding':{}}}):
            j=self.journal()
            try:
                with self.assertRaises(LocalJournalError):j._append(expected_head=j.head(),operation_id=op,phase='target-reconciled',payload={**payload,**change})
            finally:j.close()
            self.assertEqual(before,self.r.originals())
    def test_unknown_marker_parent_close_vetoes_result_after_real_checkpoint(self):
        before=self.marker.read_bytes();t,e,events,calls,_=self.run_original(fault='recovery-marker-close')
        self.assertEqual((t['outcome'],t['reason']),('unknown','cleanup-unknown'));self.assertIsNone(t['result'])
        self.assertEqual(self.f.current_phase(),'target-reconciled');self.assertEqual(events[-1],'recovery-settled')
        self.assertEqual(len(calls),14);self.assertEqual(self.marker.read_bytes(),before);self.assertFalse(e.service.closed())
        self.assertTrue(e.input.material_closed());self.assertTrue(all(p.closed() for p in e.service.prepared_readers))

class RecoveryHistoryTests(unittest.TestCase):
    """Actual settlement + fresh original History engine, no Store in review."""
    def setUp(self):
        self.fixture=LocalRecoverySettlementTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f;t,e,_,_,_=self.fixture.run_original(fault='recovery-settled')
        self.assertIsNone(t['result']);self.assertEqual(self.f.current_phase(),'target-reconciled')
        self.root,self.home,self.base=self.f.root,self.f.home,self.f.base
        self.receipt=__import__('pathlib').Path(e.service.record._output)
    def request(self,fd,action):
        import test_local_release_history as history
        from mobile_release import _desktop_local_history_protocol as h
        value=history.LocalHistoryTests.request(self,fd,action)
        if h.candidate_action(value['context']):value['context']['candidateOperationId']=self.f.value['context']['candidateOperationId']
        return value
    def run_history(self,action='review-recovery',**kw):
        import test_local_release_history as history
        return history.LocalHistoryTests.run_original(self,action,**kw)
    def test_restart_current_recovery_files_never_repair_lost_original_ack(self):
        before=self.fixture.r.originals();raw=self.receipt.read_bytes();marker=self.fixture.marker.read_bytes()
        t,events,e=self.run_history();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        r=t['result'];s=r['reconciliationReceipt']
        self.assertEqual(set(r),{'schemaVersion','scope','enrolled','headSequence','history','limitations','reconciliationReceipt'})
        self.assertEqual(len(s),15);self.assertEqual(s['observation'],'current-recovery-files-only')
        self.assertEqual(s['priorExecutionFinality'],'not-established');self.assertEqual(s['result'],'reconciled')
        self.assertEqual(s['receiptSha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(s['authorizationId'],'66666666-6666-4666-8666-666666666666')
        self.assertEqual([v[0] for v in events],['lease-ready','history-head']);self.assertEqual(t['lifetime']['commands'],0)
        self.assertTrue(e.service.closed());self.assertEqual(len(e.service.prepared_readers),2)
        self.assertEqual(self.fixture.r.originals(),before);self.assertEqual(self.receipt.read_bytes(),raw);self.assertEqual(self.fixture.marker.read_bytes(),marker)
        with self.assertRaises(ValueError):W.validate_result(dict(schemaVersion=1,scope='local-android-recovery-settlement',headSequence=7,reconciliationReceipt=s),settlement=True)
        t,_,_=self.run_history('review-execution');self.assertIsNone(t['result'])
        t,_,_=self.run_history('verify');self.assertNotIn('reconciliationReceipt',t['result'])
    def test_earlier_terminal_recovery_is_visible_without_next_operation_authority(self):
        j=self.fixture.journal()
        try:j._append(expected_head=j.head(),operation_id='99999999-9999-4999-8999-999999999999',phase='inputs-pending',payload={
            'configurationSha256':'a'*64,'versionSha256':'b'*64,'sourceCommit':'a'*40,'sourceTree':'b'*40})
        finally:j.close()
        t,events,e=self.run_history();self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(t['result']['headSequence'],8)
        self.assertEqual(t['result']['reconciliationReceipt']['operationId'],self.f.value['context']['candidateOperationId'])
        self.assertEqual(t['lifetime']['commands'],0)
    def test_current_receipt_bytes_and_prepared_post_are_required(self):
        from unittest.mock import patch
        from mobile_release import local_execution_review as review
        actual=review.validate_local_execution_receipt
        def drift(*args,**kw):
            v=actual(*args,**kw);self.receipt.write_bytes(self.receipt.read_bytes()+b' ');return v
        with patch.object(review,'validate_local_execution_receipt',drift):t,events,e=self.run_history()
        self.assertIsNone(t['result']);self.assertTrue(e.service.closed());self.assertEqual(t['lifetime']['commands'],0)
    def test_changed_recovery_receipt_cannot_self_authorize_against_journal(self):
        raw=json.loads(self.receipt.read_bytes());raw['executedBy']['authorizationId']='77777777-7777-4777-8777-777777777777'
        self.receipt.write_bytes(canonical(raw)+b'\n');t,_,e=self.run_history()
        self.assertIsNone(t['result']);self.assertTrue(e.service.closed());self.assertEqual(t['lifetime']['commands'],0)
