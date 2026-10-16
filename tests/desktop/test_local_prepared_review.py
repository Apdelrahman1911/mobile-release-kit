"""Actual History engine, authenticated journal, originals; no native/Store calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import UUID
import test_local_candidate_inputs as candidate
import test_local_release_history as history
from mobile_release import local_prepared_review as review
from mobile_release import build_inputs
from mobile_release.local_release_intent import decode_local_operation_intent
from mobile_release.local_release_journal import canonical
from mobile_release.provenance import seal, canonical_json_bytes

class PreparedReviewTests(unittest.TestCase):
    setUp=history.LocalHistoryTests.setUp
    tearDown=history.LocalHistoryTests.tearDown
    run_original=history.LocalHistoryTests.run_original
    journal=candidate.CandidateHistoryTests.journal
    pending=candidate.CandidateHistoryTests.pending
    ready=candidate.CandidateHistoryTests.ready
    def request(self,fd,action):
        value=history.LocalHistoryTests.request(self,fd,action)
        if action in {'review-inputs','abandon-inputs','review-prepared'}:
            value['context']['candidateOperationId']=candidate.CANDIDATE
        return value
    def prepared(self,*,mutate=None,broad=False,pending_only=False,confirmation=None,snapshot_mutate=None):
        _,manifest,digest=self.ready()
        value=json.loads((Path(__file__).parents[1]/'fixtures/local-intent-candidate-valid.json').read_bytes())
        value.pop('integrity')
        value['project']=copy.deepcopy(history.ENROLLMENT)
        value['operationId']=candidate.CANDIDATE;value['candidateSha256']=digest
        source=dict(commit=manifest['sourceCommit'],tree=manifest['sourceTree'],ref='refs/heads/main')
        value['candidateSource']=copy.deepcopy(source);value['operationSource']=source
        value['application']['id']=manifest['applicationId']
        value['version']=dict(marketing='1.0.0',build=1);value['confirmation']='candidate:android:1.0.0:1'
        value['configuration']['sha256']=manifest['savedConfig']['sha256']
        value['configuration']['metadataSha256']=manifest['files'][1]['sha256']
        for row,actual in zip(value['artifacts'],manifest['files']):
            row.update(size=actual['bytes'],sha256=actual['sha256'],architectures=[])
        value['signing'][0]['certificateSha256']=manifest['signerSha256']
        authority=value['preparedBy'];authority.update(project=value['project'],operationId=candidate.CANDIDATE,
            candidateSha256=digest,source=source,confirmationSha256=hashlib.sha256(value['confirmation'].encode()).hexdigest())
        pre=value['storePrecondition'];pre.update(appIdentity=manifest['applicationId'],marketingVersion='1.0.0',buildNumber=1)
        snap=pre['snapshot'];snap['targetRelease']['versionCodes']=['1'];snap['targetRelease']['name']='1.0.0'
        snap['destinationTargetState']['releases']=[copy.deepcopy(snap['targetRelease'])]
        if broad:
            snap['bundles']=[dict(versionCode=i,sha256='b'*64) for i in range(2,10002)]
        if mutate:mutate(value)
        value=seal(value)
        raw=canonical(value)+b'\n'
        decode_local_operation_intent(raw) # genuinely permitted Prepare document, not bypassed validation
        if snapshot_mutate:
            pre=copy.deepcopy(pre);snapshot_mutate(pre)
        snapshot=json.dumps(pre,ensure_ascii=False,indent=2).encode()+b'\n'
        if broad:
            snapshot+=b' '*(review.FILES['store-precondition.json']-len(snapshot))
        directory=self.root/'.mobile-release/store/local'/UUID(candidate.CANDIDATE).hex
        parent=self.root
        for part in directory.relative_to(self.root).parts:
            parent/=part;parent.mkdir(mode=0o700,exist_ok=True);parent.chmod(0o700)
        for name,data in (('operation-intent.json',raw),('store-precondition.json',snapshot)):
            p=directory/name;p.write_bytes(data);p.chmod(0o600)
        j=self.journal()
        try:
            j._append(expected_head=j.head(),operation_id=candidate.CANDIDATE,phase='prepare-pending',
                payload=dict(candidateSha256=digest,confirmationSha256=confirmation or hashlib.sha256(b'candidate:android:1.0.0:1').hexdigest()))
            if not pending_only:j._append(expected_head=j.head(),operation_id=candidate.CANDIDATE,phase='prepared',
                payload=dict(candidateSha256=digest,intentSha256=value['integrity']['sha256'],
                    storePreconditionSha256=hashlib.sha256(snapshot).hexdigest()))
        finally:j.close()
        return directory,value
    def test_real_history_restart_observes_exact_prepared_files(self):
        directory,value=self.prepared();before={p.name:p.read_bytes() for p in directory.iterdir()}
        terminal,events,engine=self.run_original('review-prepared')
        self.assertEqual(terminal['outcome'],'complete',engine.primary)
        result=terminal['result'];self.assertEqual(set(result),{'schemaVersion','scope','enrolled','headSequence','history','limitations','preparedIntent'})
        self.assertEqual(result['headSequence'],5);summary=result['preparedIntent']
        self.assertEqual(len(summary),13);self.assertEqual(summary['intentSha256'],value['integrity']['sha256'])
        self.assertNotEqual(summary['intentSha256'],hashlib.sha256(before['operation-intent.json']).hexdigest())
        self.assertEqual(summary['storePreconditionSha256'],hashlib.sha256(before['store-precondition.json']).hexdigest())
        self.assertEqual(summary['observation'],'current-prepared-files-only')
        self.assertEqual(summary['priorPrepareFinality'],'not-established')
        self.assertEqual([e[0] for e in events],['lease-ready','history-head'])
        self.assertEqual(terminal['lifetime']['commands'],0)
        self.assertTrue(engine.service.bundle.closed);self.assertTrue(all(p.closed() for p in engine.service.prepared_readers))
        self.assertEqual(before,{p.name:p.read_bytes() for p in directory.iterdir()})
    def test_maximum_play_bundle_count_and_snapshot_bytes_fit_same_memory_owner(self):
        directory,_=self.prepared(broad=True)
        raw=(directory/'store-precondition.json').read_bytes()
        self.assertEqual(len(raw),4<<20)
        self.assertLess(review.decode_quote(raw,4<<20),96<<20)
        terminal,_,engine=self.run_original('review-prepared')
        self.assertEqual(terminal['outcome'],'complete',engine.primary)
    def test_pending_or_crossed_authentic_intent_cannot_be_reviewed(self):
        directory,_=self.prepared(pending_only=True)
        terminal,_,_=self.run_original('review-prepared');self.assertEqual(terminal['outcome'],'refused')
        self.assertEqual(set(p.name for p in directory.iterdir()),set(review.FILES))
    def test_sealed_valid_but_crossed_bundle_or_confirmation_is_refused(self):
        changes=[lambda v:v['signing'][0].update(certificateSha256='9'*64),
                 lambda v:v['artifacts'][0].update(sha256='9'*64),
                 lambda v:v['configuration'].update(sha256='9'*64),
                 lambda v:(v['operationSource'].update(commit='9'*40),v['candidateSource'].update(commit='9'*40)),
                 lambda v:v['project'].update(projectBinding='9'*64)]
        # Every scenario uses an independently enrolled genuine tiny journal.
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.tearDown();self.setUp()
                directory,_=self.prepared(mutate=change)
                terminal,_,_=self.run_original('review-prepared')
                self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
                self.assertEqual(set(p.name for p in directory.iterdir()),set(review.FILES))
    def test_journal_confirmation_and_raw_snapshot_do_not_replace_semantic_intent_binding(self):
        for options in ({'confirmation':'9'*64}, {'snapshot_mutate':lambda p:p.update(observedAt='2026-01-02T00:00:00Z')}):
            with self.subTest(options=tuple(options)):
                self.tearDown();self.setUp();self.prepared(**options)
                terminal,_,_=self.run_original('review-prepared')
                self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
    def test_collision_permissions_snapshot_hash_and_post_parse_drift_refuse(self):
        directory,_=self.prepared();intent=directory/'operation-intent.json';snapshot=directory/'store-precondition.json'
        original=snapshot.read_bytes();(directory/'unknown').write_bytes(b'preserve')
        terminal,_,_=self.run_original('review-prepared');self.assertEqual(terminal['outcome'],'refused')
        (directory/'unknown').unlink();intent.chmod(0o644)
        terminal,_,_=self.run_original('review-prepared');self.assertEqual(terminal['outcome'],'refused')
        intent.chmod(0o600);snapshot.write_bytes(original+b' ')
        terminal,_,_=self.run_original('review-prepared');self.assertEqual(terminal['outcome'],'refused')
        snapshot.write_bytes(original);actual=review._snapshot
        def drift(raw,expected,**kwargs):
            actual(raw,expected,**kwargs);intent.write_bytes(intent.read_bytes()+b' ')
        with patch.object(review,'_snapshot',drift):
            terminal,_,_=self.run_original('review-prepared')
        self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
    def test_replaced_project_before_private_reader_cannot_be_adopted(self):
        self.prepared();original=review._app_private_directory;changed=[]
        def replace(*args,**kwargs):
            if not changed:
                changed.append(True);self.root.rename(self.base/'old-project');self.root.mkdir(mode=0o700)
                import shutil
                shutil.copytree(self.base/'old-project'/'.mobile-release',self.root/'.mobile-release')
            return original(*args,**kwargs)
        with patch.object(review,'_app_private_directory',replace),patch.object(review,'_read_file',side_effect=AssertionError('no read of replacement root')):
            terminal,_,_=self.run_original('review-prepared')
        self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
        self.assertTrue(changed)
    def test_unknown_private_original_close_never_publishes_summary(self):
        self.prepared();original=build_inputs._FD.open;close=os.close;selected=[];lost=[]
        def opened(slot,name,*args,**kwargs):
            number=original(slot,name,*args,**kwargs)
            if name=='operation-intent.json' and not selected:selected.append(number)
            return number
        def closing(number):
            if selected and number==selected[0] and not lost:
                lost.append(number);close(number);raise OSError('inert-original-close-unknown')
            return close(number)
        with patch.object(build_inputs._FD,'open',opened),patch.object(os,'close',closing):
            terminal,_,engine=self.run_original('review-prepared')
        self.assertEqual(len(lost),1);self.assertEqual(terminal['outcome'],'unknown');self.assertIsNone(terminal['result'])
        self.assertTrue(engine.guard.lifetime_ledger.fatal)
    def test_byte_node_and_depth_admission_precedes_json_allocation(self):
        with patch.object(review.json,'loads',side_effect=AssertionError('decoder must not run')):
            for raw in (b' '*(4<<20)+b'{}', b'['+b'0,'*400000+b'0]', b'['*66+b'0'+b']'*66):
                with self.subTest(size=len(raw)),self.assertRaises(ValueError):review._snapshot(raw,'a'*64)
        ticks=[]
        def stopped():
            ticks.append(True)
            if len(ticks)==2:raise ValueError('inert original stop')
        with patch.object(review.json,'loads',side_effect=AssertionError('stopped before parse')),self.assertRaises(ValueError):
            review._snapshot(b' '*200000+b'{}','a'*64,checkpoint=stopped)
        self.assertEqual(len(ticks),2)
        # Legitimate broad versionCodes is not a 4096-node historical JSON cap.
        value=json.loads((Path(__file__).parents[1]/'fixtures/local-intent-candidate-valid.json').read_bytes())['storePrecondition']
        codes=sorted(str(i) for i in range(100,10100))
        release={'status':'completed','versionCodes':codes}
        value['snapshot']['destinationState']['releases']=[release]
        value['snapshot']['destinationTargetState']['releases']=sorted([release,value['snapshot']['targetRelease']],key=canonical_json_bytes)
        raw=canonical_json_bytes(value)
        review._snapshot(raw,hashlib.sha256(raw).hexdigest())

if __name__=='__main__':unittest.main()
