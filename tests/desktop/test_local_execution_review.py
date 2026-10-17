"""Real History/OFD/journal/current files; native and Store replies stay inert."""
import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import UUID
import test_local_prepared_review as prepared_fixture
import test_local_candidate_inputs as candidate
import test_local_release_history as history
from mobile_release import local_execution_review as review, local_prepared_review as prepared
from mobile_release import build_inputs
from mobile_release import _desktop_local_history_protocol as wire
from mobile_release.local_release_journal import canonical
from mobile_release.provenance import _play_digest

AUTH = '55555555-5555-4555-8555-555555555555'

class ExecutionReviewTests(unittest.TestCase):
    setUp = history.LocalHistoryTests.setUp
    tearDown = history.LocalHistoryTests.tearDown
    run_original = history.LocalHistoryTests.run_original
    journal = candidate.CandidateHistoryTests.journal
    pending = candidate.CandidateHistoryTests.pending
    ready = candidate.CandidateHistoryTests.ready
    prepared = prepared_fixture.PreparedReviewTests.prepared
    def request(self, fd, action):
        value = history.LocalHistoryTests.request(self, fd, action)
        if wire.candidate_action(value['context']): value['context']['candidateOperationId'] = candidate.CANDIDATE
        return value
    def completed(self, *, mutate=None, pending=None, settled=None, phase='settled-success'):
        directory, intent = self.prepared()
        authority = dict(intent['preparedBy'], purpose='execute', authorizationId=AUTH, intentSha256=intent['integrity']['sha256'])
        receipt = json.loads((Path(__file__).parents[1]/'fixtures/local-execution-receipt-valid.json').read_bytes())
        receipt.update(project=intent['project'], operationId=intent['operationId'], candidateSha256=intent['candidateSha256'],
            operationIntentSha256=intent['integrity']['sha256'], preparedBy=intent['preparedBy'], executedBy=authority,
            appIdentity=intent['application']['id'], marketingVersion=intent['version']['marketing'],
            buildNumber=intent['version']['build'], versionCode=intent['version']['build'])
        snapshot=intent['storePrecondition']['snapshot']; before,target=snapshot['destinationState'],snapshot['destinationTargetState']
        without=lambda track:[r for r in track['releases'] if str(intent['version']['build']) not in r['versionCodes']]
        receipt['storeState'].update(destinationBeforeSha256=_play_digest(before), destinationExpectedSha256=_play_digest(target),
            destinationCommittedSha256=_play_digest(target), unrelatedBeforeSha256=_play_digest(without(before),'release-set'),
            unrelatedCommittedSha256=_play_digest(without(target),'release-set'), targetReleaseSha256=_play_digest(snapshot['targetRelease'],'release'))
        if mutate: mutate(receipt)
        raw=canonical(receipt)+b'\n'
        target=directory.with_name(directory.name+'-execute-'+UUID(AUTH).hex);target.mkdir(mode=0o700)
        path=target/review.NAME;path.write_bytes(raw);path.chmod(0o600)
        p=dict(intentSha256=intent['integrity']['sha256'],confirmationSha256=authority['confirmationSha256'],
            authorizationId=AUTH,assignmentRevision=authority['assignment']['expectedRevision'])
        s=dict(intentSha256=intent['integrity']['sha256'],receiptSha256=hashlib.sha256(raw).hexdigest())
        if pending:p.update(pending)
        if settled:s.update(settled)
        j=self.journal()
        try:
            j._append(expected_head=j.head(),operation_id=candidate.CANDIDATE,phase='execute-pending',payload=p)
            if phase:
                payload=s if phase=='settled-success' else dict(phase='execute-pending',reason='store-refused' if phase=='settled-failure' else 'response-unknown')
                j._append(expected_head=j.head(),operation_id=candidate.CANDIDATE,phase=phase,payload=payload)
        finally:j.close()
        return path, directory, intent
    def refused(self, *, unknown=False):
        terminal,events,engine=self.run_original('review-execution',expect_unknown=unknown)
        self.assertEqual(terminal['outcome'],'unknown' if unknown else 'refused',engine.primary);self.assertIsNone(terminal['result'])
        self.assertEqual([e[0] for e in events],['lease-ready','history-head'])
        self.assertEqual(terminal['lifetime']['commands'],0)
        return engine
    def test_real_restart_and_earlier_completed_operation_are_read_only(self):
        path, directory, intent=self.completed();before={p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        for expected_head in (7,8):
            terminal,events,engine=self.run_original('review-execution')
            self.assertEqual(terminal['outcome'],'complete',engine.primary)
            result=terminal['result'];summary=result['executionReceipt']
            self.assertEqual(set(result),{'schemaVersion','scope','enrolled','headSequence','history','limitations','executionReceipt'})
            self.assertEqual(len(summary),15);self.assertEqual(result['headSequence'],expected_head)
            self.assertEqual(summary['receiptSha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(summary['intentSha256'],intent['integrity']['sha256'])
            self.assertEqual(summary['authorizationId'],AUTH)
            self.assertEqual((summary['observation'],summary['priorExecutionFinality']),('current-execution-files-only','not-established'))
            self.assertEqual([e[0] for e in events],['lease-ready','history-head']);self.assertEqual(terminal['lifetime']['commands'],0)
            self.assertTrue(engine.service.bundle.closed);self.assertEqual(len(engine.service.prepared_readers),2)
            self.assertTrue(all(p.closed() for p in engine.service.prepared_readers));self.assertNotIn(str(self.root),json.dumps(result))
            self.assertEqual(before,{p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()})
            if expected_head==7:
                j=self.journal()
                try:j._append(expected_head=j.head(),operation_id='66666666-6666-4666-8666-666666666666',phase='inputs-pending',payload=candidate.PENDING)
                finally:j.close()
                before={p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        # The old action cannot mislabel a completed operation as only prepared.
        terminal,_,_=self.run_original('review-prepared');self.assertEqual(terminal['outcome'],'refused')
        terminal,_,_=self.run_original('verify');self.assertNotIn('executionReceipt',terminal['result'])
    def test_pending_failed_and_reconciliation_required_are_not_repaired(self):
        for phase in (None,'settled-failure','reconciliation-required'):
            with self.subTest(phase=phase):
                self.tearDown();self.setUp();path,_,_=self.completed(phase=phase);raw=path.read_bytes()
                self.refused();self.assertEqual(path.read_bytes(),raw)
    def test_authenticated_journal_and_receipt_cross_bindings_refuse(self):
        cases=[dict(pending={'authorizationId':'77777777-7777-4777-8777-777777777777'}),
            dict(pending={'assignmentRevision':2}),dict(pending={'confirmationSha256':'9'*64}),
            dict(settled={'receiptSha256':'9'*64}),
            dict(mutate=lambda r:r['executedBy'].update(authorizationId='77777777-7777-4777-8777-777777777777')),
            dict(mutate=lambda r:r['executedBy']['assignment'].update(expectedRevision=2)),
            dict(mutate=lambda r:r.update(origin='ci')),
            dict(mutate=lambda r:r['storeState'].update(destinationCommittedSha256='9'*64))]
        # Actual journal admission itself forbids either crossed adjacent intent
        # digest. Do not fabricate an impossible authenticated chain for review.
        from mobile_release.local_release_journal import LocalJournalError
        for options in (dict(pending={'intentSha256':'9'*64}),dict(settled={'intentSha256':'9'*64})):
            self.tearDown();self.setUp()
            with self.assertRaises(LocalJournalError):self.completed(**options)
        for index,options in enumerate(cases):
            with self.subTest(index=index):
                self.tearDown();self.setUp();path,_,_=self.completed(**options);raw=path.read_bytes()
                self.refused();self.assertEqual(path.read_bytes(),raw)
    def test_missing_extra_unsafe_or_changed_receipt_is_preserved(self):
        for kind in ('missing','extra','mode','changed','symlink','hardlink'):
            with self.subTest(kind=kind):
                self.tearDown();self.setUp();path,_,_=self.completed();raw=path.read_bytes()
                if kind=='missing':path.unlink()
                elif kind=='extra':(path.parent/'unknown').write_bytes(b'preserve')
                elif kind=='mode':path.chmod(0o644)
                elif kind=='changed':path.write_bytes(raw+b' ')
                elif kind=='symlink':path.rename(self.base/'receipt');path.symlink_to(self.base/'receipt')
                else:os.link(path,self.base/'receipt')
                self.refused();self.assertEqual(path.exists(),kind!='missing')
    def test_receipt_and_prepared_originals_post_after_decode(self):
        for kind in ('receipt','intent','snapshot','receipt-root'):
            with self.subTest(kind=kind):
                self.tearDown();self.setUp();path,directory,_=self.completed();actual=review.validate_local_execution_receipt
                def drift(*args,**kwargs):
                    result=actual(*args,**kwargs)
                    if kind=='receipt-root':
                        old=path.parent.with_name('old-receipt');path.parent.rename(old);path.parent.mkdir(mode=0o700)
                        path.write_bytes((old/review.NAME).read_bytes());path.chmod(0o600)
                    else:
                        selected={'receipt':path,'intent':directory/'operation-intent.json','snapshot':directory/'store-precondition.json'}[kind]
                        selected.write_bytes(selected.read_bytes()+b' ')
                    return result
                with patch.object(review,'validate_local_execution_receipt',drift):self.refused(unknown=kind=='receipt-root')
    def test_candidate_original_changed_after_prior_success_refuses(self):
        self.completed();path=self.root/'.mobile-release/desktop-android-build'/UUID(candidate.CANDIDATE).hex/'artifacts/app-release.aab'
        path.write_bytes(b'foreign candidate bytes');self.refused();self.assertEqual(path.read_bytes(),b'foreign candidate bytes')
    def test_lost_consuming_receipt_close_is_unknown_not_success(self):
        path,_,_=self.completed();raw=path.read_bytes();original=build_inputs._FD.open;close=os.close;selected=[];lost=[]
        def opened(slot,name,*args,**kwargs):
            number=original(slot,name,*args,**kwargs)
            if name==review.NAME and not selected:selected.append(number)
            return number
        def closing(number):
            if selected and number==selected[0] and not lost:
                lost.append(number);close(number);raise OSError('inert receipt close return lost')
            return close(number)
        with patch.object(build_inputs._FD,'open',opened),patch.object(os,'close',closing):
            terminal,_,engine=self.run_original('review-execution')
        self.assertEqual(len(lost),1);self.assertEqual(terminal['outcome'],'unknown');self.assertIsNone(terminal['result'])
        self.assertTrue(engine.guard.lifetime_ledger.fatal);self.assertEqual(path.read_bytes(),raw)
    def test_request_and_preallocation_are_closed_before_parsing(self):
        value=dict(projectId='registered-project',executionMode='local',action='review-execution',candidateOperationId=candidate.CANDIDATE)
        self.assertEqual(wire.context(value),value)
        for change in (lambda v:v.pop('candidateOperationId'),lambda v:v.update(action='verify'),lambda v:v.update(recover=True),
                       lambda v:v.update(candidateOperationId='not-a-uuid')):
            v=copy.deepcopy(value);change(v)
            with self.assertRaises(ValueError):wire.context(v)
        with patch.object(review,'decode_local_operation_intent',side_effect=AssertionError('no decode before budget')):
            with self.assertRaises(ValueError):review._intent_quote(b'['+b'0,'*110000+b'0]',lambda:None)
        with patch.object(prepared.json,'loads',side_effect=AssertionError('no snapshot decode before retained-byte quote')):
            # This valid lexical shape fits one graph but not an extra2MiB.
            raw=b'['+b'0,'*335100+b'0]'
            own=prepared.decode_quote(raw,4<<20)
            self.assertLessEqual(own,prepared.MEMORY_LIMIT)
            with self.assertRaises(ValueError):prepared._snapshot(raw,'a'*64,retained_bytes=2<<20)
    def test_deep_actual_root_refuses_before_journal_or_namespace_acquisition(self):
        self.root=self.base/'deep'
        for _ in range(80):self.root=self.root/'d'
        self.root.mkdir(parents=True,mode=0o700)
        terminal,events,engine=self.run_original('review-execution')
        self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
        self.assertEqual(events,[]);self.assertIsNone(engine.service.invocation)
        self.assertEqual(list(self.root.iterdir()),[]);self.assertEqual(list(self.home.iterdir()),[])
    def test_existing_execute_final_ack_failure_can_only_review_current_files(self):
        # The real original Execute engine writes/settles its journal but loses
        # its final ACK. Native admission/Store replies remain the existing model;
        # the new History run must not claim that old terminal succeeded.
        import test_local_store_execute as execute_fixture
        fixture=execute_fixture.LocalStoreExecuteTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        terminal,old,events,calls,_=fixture.f.run_original(_execute=True,fault='execute-settled')
        self.assertIsNone(terminal['result']);self.assertEqual(len(calls),14)
        self.assertEqual(fixture.f.current_phase(),'settled-success')
        saved=self.root,self.home,self.base
        self.root,self.home,self.base=fixture.f.root,fixture.f.home,fixture.f.base
        try:
            terminal,_,engine=self.run_original('review-execution')
            self.assertEqual(terminal['outcome'],'complete',engine.primary)
            self.assertEqual(terminal['result']['executionReceipt']['priorExecutionFinality'],'not-established')
            self.assertEqual(terminal['lifetime']['commands'],0)
        finally:self.root,self.home,self.base=saved

if __name__=='__main__':unittest.main()
