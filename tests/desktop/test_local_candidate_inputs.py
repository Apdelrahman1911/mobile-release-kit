"""Real inherited-lease/history/retained-file IO; native phase replies inert.

No native process, Keychain or Store access. The original engine remains active
through real checkpoint exchange, positive reader/journal/lease closes and EOF.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from uuid import UUID
import test_local_release_history as history
from mobile_release import local_candidate_bundle as bundle
from mobile_release.local_release_journal import LocalReleaseJournal,canonical

CANDIDATE='33333333-3333-4333-8333-333333333333'
PENDING=dict(sourceCommit='c'*40,sourceTree='d'*40,configurationSha256='e'*64,versionSha256='f'*64)

class CandidateHistoryTests(unittest.TestCase):
    setUp=history.LocalHistoryTests.setUp
    tearDown=history.LocalHistoryTests.tearDown
    run_original=history.LocalHistoryTests.run_original
    def request(self,fd,action):
        data=history.LocalHistoryTests.request(self,fd,action)
        if action in {'review-inputs','abandon-inputs'}:data['context']['candidateOperationId']=CANDIDATE
        return data
    def journal(self):
        j=LocalReleaseJournal(str(self.home),end=time.monotonic()+20,enrollment=history.ENROLLMENT,key=history.KEY)
        j.open_existing();return j
    def pending(self):
        terminal,_,engine=self.run_original()
        import traceback
        self.assertEqual(terminal['outcome'],'complete',''.join(traceback.format_exception(engine.primary)) if engine.primary else None)
        j=self.journal()
        try:j._append(expected_head=j.head(),operation_id=CANDIDATE,phase='inputs-pending',payload=PENDING)
        finally:j.close()
    def ready(self):
        self.pending()
        directory=self.root/'.mobile-release/desktop-android-build'/UUID(CANDIDATE).hex/'artifacts'
        parent=self.root
        for name in directory.relative_to(self.root).parts:
            parent/=name;parent.mkdir(mode=0o700,exist_ok=True);parent.chmod(0o700)
        rows=[]
        for name,_ in bundle.FILES:
            value=('inert exact retained '+name).encode()
            p=directory/name;p.write_bytes(value);p.chmod(0o600)
            rows.append(dict(fileName=name,bytes=len(value),sha256=hashlib.sha256(value).hexdigest()))
        manifest=dict(schemaVersion=1,scope='local-android-candidate-inputs',operationId=CANDIDATE,
            enrollment=history.ENROLLMENT,sourceCommit=PENDING['sourceCommit'],sourceTree=PENDING['sourceTree'],
            savedConfig=dict(bytes=1,sha256=PENDING['configurationSha256']),
            savedVersion=dict(source='release/version.json',bytes=1,sha256=PENDING['versionSha256'],name='1.0.0',build=1),
            applicationId='com.example.candidate',signerSha256='a'*64,files=rows)
        raw=canonical(manifest)+b'\n'; p=directory/bundle.MANIFEST;p.write_bytes(raw);p.chmod(0o600)
        digest=hashlib.sha256(raw).hexdigest()
        j=self.journal()
        try:j._append(expected_head=j.head(),operation_id=CANDIDATE,phase='inputs-ready',payload={'candidateSha256':digest})
        finally:j.close()
        return directory,manifest,digest
    def test_ready_review_real_engine_reads_exact_retained_bundle_and_closes(self):
        directory,manifest,digest=self.ready();before={p.name:p.read_bytes() for p in directory.iterdir()}
        terminal,events,engine=self.run_original('review-inputs')
        self.assertEqual(terminal['outcome'],'complete',engine.primary)
        result=terminal['result']['candidateInputs']
        self.assertEqual(result['files'],manifest['files']);self.assertEqual(result['candidateSha256'],digest)
        self.assertEqual(result['observation'],'current-bundle-only')
        self.assertEqual(result['priorCreateFinality'],'not-established')
        self.assertEqual(terminal['lifetime']['commands'],0)
        self.assertEqual([e[0] for e in events],['lease-ready','history-head'])
        self.assertTrue(engine.service.bundle.closed)
        self.assertTrue(all(s.state=='CLOSED' for s in engine.service.bundle.reader.descriptors))
        self.assertEqual({p.name:p.read_bytes() for p in directory.iterdir()},before)
    def test_pending_review_and_abandon_are_real_legal_history_transitions(self):
        self.pending()
        terminal,_,_=self.run_original('review-inputs')
        self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        terminal,events,_=self.run_original('abandon-inputs')
        self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        self.assertEqual([e[0] for e in events],['lease-ready','history-head','abandoned-head'])
        j=self.journal()
        try:self.assertEqual(j._rows[-1][0]['payload'],{'phase':'inputs-pending','reason':'cancelled'})
        finally:j.close()
        self.assertFalse((self.root/'.mobile-release').exists())
    def test_ready_abandon_preserves_all_files_and_cannot_repeat(self):
        directory,_,_=self.ready();before={p.name:p.read_bytes() for p in directory.iterdir()}
        terminal,_,_=self.run_original('abandon-inputs')
        self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        self.assertEqual({p.name:p.read_bytes() for p in directory.iterdir()},before)
        terminal,events,_=self.run_original('abandon-inputs')
        self.assertEqual(terminal['outcome'],'refused');self.assertEqual(len(events),2)
        review,_,_=self.run_original('review-inputs')
        self.assertEqual(review['outcome'],'complete');self.assertIsNone(review['result']['candidateInputs'])
    def test_after_prepare_abandon_refuses_without_journal_mutation(self):
        self.ready();j=self.journal()
        try:
            j._append(expected_head=j.head(),operation_id=CANDIDATE,phase='prepare-pending',payload={'candidateSha256':j._rows[-1][0]['payload']['candidateSha256'],'confirmationSha256':'9'*64})
            head=j.head()
        finally:j.close()
        terminal,events,_=self.run_original('abandon-inputs')
        self.assertEqual(terminal['outcome'],'refused');self.assertEqual(len(events),2)
        j=self.journal()
        try:self.assertEqual(j.head(),head)
        finally:j.close()
    def test_extra_leaf_and_changed_retained_bytes_refuse_not_adopt(self):
        directory,_,_=self.ready();p=directory/'extra';p.write_bytes(b'inert');p.chmod(0o600)
        terminal,_,_=self.run_original('review-inputs');self.assertNotEqual(terminal['outcome'],'complete')
        p.unlink();p=directory/'store-metadata.zip';p.write_bytes(b'changed')
        terminal,_,_=self.run_original('review-inputs');self.assertNotEqual(terminal['outcome'],'complete')
        self.assertEqual(p.read_bytes(),b'changed')
    def test_final_hash_drift_withholds_summary(self):
        directory,_,_=self.ready();original=bundle.CandidateBundleReview.finish
        def changed(owner):
            (directory/'validation-report.json').write_bytes(b'changed-before-final-hash')
            return original(owner)
        with patch.object(bundle.CandidateBundleReview,'finish',changed):
            terminal,_,_=self.run_original('review-inputs')
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
    def test_unknown_consuming_close_is_retained_and_never_publishes(self):
        self.ready();original=bundle._Reader.close;lost=[]
        def uncertain(reader):
            selected=next((n for n in reader.nodes if n.name==bundle.MANIFEST and not n.directory),None)
            if selected is None or lost:return original(reader)
            fd=reader._number(selected.slot); real_close=os.close
            def close(number):
                if number==fd:
                    lost.append(number);real_close(number);raise OSError('inert-lost-original-close')
                return real_close(number)
            with patch.object(os,'close',close):return original(reader)
        with patch.object(bundle._Reader,'close',uncertain):
            terminal,_,engine=self.run_original('review-inputs',expect_unknown=True)
        self.assertEqual(len(lost),1)
        self.assertEqual(terminal['outcome'],'unknown');self.assertIsNone(terminal['result'])
        self.assertTrue(engine.guard.lifetime_ledger.fatal)
        self.assertTrue(any(slot.state=='UNKNOWN' for slot in engine.service.bundle.reader.descriptors))
    def test_manifest_grammar_and_saved_source_binding_are_exact(self):
        _,value,_=self.ready();base=copy.deepcopy(value)
        for change in ({'sourceCommit':'A'*40},{'sourceTree':True},{'signerSha256':'x'*64},
                {'files':list(reversed(value['files']))},{'operationId':'a'*32}):
            with self.subTest(change=change),self.assertRaises(bundle.CandidateBundleError):
                bundle.manifest_data(canonical({**value,**change})+b'\n',operation_id=CANDIDATE,enrollment=history.ENROLLMENT,pending=PENDING)
        bad=copy.deepcopy(value);bad['savedConfig']['sha256']='9'*64
        with self.assertRaises(bundle.CandidateBundleError):bundle.manifest_data(canonical(bad)+b'\n',operation_id=CANDIDATE,enrollment=history.ENROLLMENT,pending=PENDING)
        self.assertEqual(bundle.manifest_data(canonical(value)+b'\n',operation_id=CANDIDATE,enrollment=history.ENROLLMENT,pending=PENDING),base)
    def test_candidate_context_is_closed_and_old_context_cannot_supply_uuid(self):
        value=dict(projectId='registered-project',executionMode='local',action='review-inputs',candidateOperationId=CANDIDATE)
        self.assertEqual(history.wire.context(value),value)
        for change in ({'candidateOperationId':'a'*32},{'candidateOperationId':True},{'action':'verify'}):
            with self.subTest(change=change),self.assertRaises(ValueError):history.wire.context({**value,**change})
        missing=dict(value);del missing['candidateOperationId']
        with self.assertRaises(ValueError):history.wire.context(missing)
        self.assertEqual(str(bundle.CandidateBundleError('PRIVATE-SENTINEL')),'Local candidate inputs unavailable')

if __name__=='__main__':unittest.main()
