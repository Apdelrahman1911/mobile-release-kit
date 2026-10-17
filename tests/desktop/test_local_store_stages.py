"""Later-stage DATA and actual disk journal; no native/Store/consent claims."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from mobile_release import local_release_intent as L, local_release_receipt as R, local_release_journal as J
from mobile_release.provenance import seal, validate_operation_intent, _validate_operation_intent_body
from mobile_release.errors import ValidationError
from mobile_release.local_release_journal import canonical
from unit.evidence_helpers import ios_precondition, raw_receipt

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'
CANDIDATE='33333333-3333-4333-8333-333333333333'
EXTERNAL='44444444-4444-4444-8444-444444444444'
PRODUCTION='55555555-5555-4555-8555-555555555555'
KEY=b'K'*32

def encoded(value):return json.dumps(value, separators=(',',':'), ensure_ascii=False).encode()
def fixture(name):return json.loads((FIXTURES/name).read_bytes())
def reseal(value):return seal({k:v for k,v in value.items() if k!='integrity'})
def documents(platform, stage):
    value=fixture('local-intent-ios-candidate-valid.json' if platform=='ios' else 'local-intent-candidate-valid.json')
    candidate=value['operationId']
    value.update(stage=stage,operationId=EXTERNAL if stage=='external-testing' else PRODUCTION,candidateOperationId=candidate,
        confirmation=f'{stage}:{platform}:1.2.3:42')
    if platform=='android':
        ci=fixture('intent-external-valid.json' if stage=='external-testing' else 'intent-production-valid.json')
        value['destination']=ci['destination'];value['storePrecondition']=ci['storePrecondition']
    else:
        value['storePrecondition']=ios_precondition(None,stage=stage)
        value['destination']={'channel':'testflight-external'} if stage=='external-testing' else {'channel':'app-store-review','automaticRelease':False}
    value['privateStateCommitments']=value['storePrecondition']['snapshot'].get('privateStateCommitments',{})
    value['predecessors']={'candidateManifestSha256':value['candidateSha256'],'candidateReceiptSha256':'a'*64}
    if stage=='production-submit':
        value['predecessors']['externalReceiptSha256']='b'*64
        value['operationSource']=dict(value['operationSource'],commit='9'*40,tree='8'*40,ref='refs/heads/production')
    prepared=value['preparedBy'];prepared.update(operationId=value['operationId'],source=value['operationSource'],
        confirmationSha256=hashlib.sha256(value['confirmation'].encode()).hexdigest())
    if platform=='ios':
        prepared['supplementalAssignments']=[dict(prepared['assignment'],kind=kind,recordId=token*32)
            for kind,token in [('apple-review-contact','c'),('operation-commitment','d')]]
    value=reseal(value)
    authority=dict(prepared,purpose='execute',intentSha256=value['integrity']['sha256'],authorizationId='66666666-6666-4666-8666-666666666666')
    # Existing inert fixture constructs the shared platform body, not CI authority.
    body=raw_receipt(dict(value,authorizedBy={}))
    for key in ('authorizedBy','executedBy'):body.pop(key)
    receipt=dict(body,documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',
        project=value['project'],operationId=value['operationId'],candidateSha256=value['candidateSha256'],
        candidateOperationId=candidate,stage=stage,preparedBy=prepared,executedBy=authority)
    return value,authority,receipt

def args(intent,authority):return dict(intent_data=encoded(intent),authority_data=encoded(authority),purpose='execute',
    expected_intent_sha256=intent['integrity']['sha256'],platform=intent['platform'],stage=intent['stage'])

class LocalStoreStageDataTests(unittest.TestCase):
    def test_four_stage_platforms_share_exact_body_without_default_admission(self):
        for platform in ('android','ios'):
            for stage in ('external-testing','production-submit'):
                with self.subTest(platform=platform,stage=stage):
                    intent,authority,receipt=documents(platform,stage)
                    self.assertEqual(L.decode_local_operation_intent(encoded(intent),platform=platform,stage=stage),intent)
                    self.assertEqual(R.validate_local_execution_receipt(encoded(receipt),**args(intent,authority)),receipt)
                    self.assertEqual(len(R.local_execution_attempt_key(**args(intent,authority))),64)
                    with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(intent),platform=platform)
                    with self.assertRaises(R.LocalReceiptError):R.validate_local_execution_receipt(encoded(receipt),**{k:v for k,v in args(intent,authority).items() if k!='stage'})
                    with self.assertRaises(ValidationError):validate_operation_intent(intent)
        for name in ('intent-candidate-valid.json','intent-external-valid.json','intent-production-valid.json'):
            ci=fixture(name);validate_operation_intent(ci)
            with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(ci),stage=ci['stage'])
    def test_later_authority_has_exact_current_supplemental_revisions_not_recover(self):
        i,a,r=documents('ios','external-testing')
        for mutate in (lambda d:d['preparedBy'].pop('supplementalAssignments'),
            lambda d:d['preparedBy']['supplementalAssignments'].reverse(),
            lambda d:d['preparedBy']['supplementalAssignments'][0].update(contextRevision=True),
            lambda d:d['preparedBy']['supplementalAssignments'][0].update(recordId=d['preparedBy']['assignment']['recordId']),
            lambda d:d.update(candidateOperationId=d['operationId']),
            lambda d:d['predecessors'].update(candidateManifestSha256='0'*64)):
            bad=copy.deepcopy(i);mutate(bad)
            with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(reseal(bad)),platform='ios',stage='external-testing')
        changed=copy.deepcopy(a);changed['supplementalAssignments'][0]['expectedRevision']+=1
        with self.assertRaises(L.LocalIntentError):L.validate_local_execution_authority(encoded(changed),intent_data=encoded(i),purpose='execute',platform='ios',stage='external-testing')
        with self.assertRaises(L.LocalIntentError):L.validate_local_execution_authority(encoded(dict(a,purpose='recover')),intent_data=encoded(i),purpose='recover',platform='ios',stage='external-testing')
    def test_predecessor_stage_receipt_uses_full_target_and_no_retry_adoption(self):
        for platform in ('android','ios'):
            for stage in ('external-testing','production-submit'):
                i,a,r=documents(platform,stage)
                changes=[lambda v:v.update(stage='candidate'),lambda v:v.update(candidateOperationId=EXTERNAL),
                    lambda v:v.update(result='reconciled'),lambda v:v.update(state='processed'),
                    lambda v:v['executedBy'].update(authorizationId='77777777-7777-4777-8777-777777777777')]
                if platform=='ios':changes += [lambda v:v.update(buildResourceId='foreign'),lambda v:v.update(processingState='PROCESSING')]
                else:changes += [lambda v:v.update(sourceTrack='foreign'),lambda v:v['storeState'].update(sourceCommittedSha256='f'*64)]
                for mutate in changes:
                    bad=copy.deepcopy(r);mutate(bad)
                    with self.subTest(platform=platform,stage=stage,change=mutate),self.assertRaises(R.LocalReceiptError):R.validate_local_execution_receipt(encoded(bad),**args(i,a))
    def test_ios_stage_archive_is_explicit_and_original_ci_candidate_grammar_unchanged(self):
        i,_,_=documents('ios','external-testing')
        for encoding in ('files','local-ios-directory'):
            with self.assertRaises(ValidationError):_validate_operation_intent_body(i,stage='external-testing',platform='ios',artifact_encoding=encoding)
        _validate_operation_intent_body(i,stage='external-testing',platform='ios',artifact_encoding='local-ios-stage-directory')
        candidate=fixture('local-intent-ios-candidate-valid.json')
        self.assertEqual(L.decode_local_operation_intent(encoded(candidate),platform='ios'),candidate)

class LocalStoreStageJournalTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=Path.home());self.home=Path(self.temp.name);self.books=[]
        self.enrollment=fixture('local-intent-candidate-valid.json')['project']
    def tearDown(self):
        for book in self.books:
            if not book.closed:book.close()
            self.assertFalse(book.ancestors);self.assertEqual(book._key,bytes(32))
        self.temp.cleanup()
    def book(self):
        book=J.LocalReleaseJournal(str(self.home),end=time.monotonic()+20,enrollment=self.enrollment,key=KEY)
        self.books.append(book);book.open();return book
    def append(self,b,phase,payload,op=CANDIDATE):return b._append(expected_head=b.head(),operation_id=op,phase=phase,payload=payload)
    def candidate(self,b):
        self.append(b,'genesis',{'rootIdentity':dict(device=1,inode=9,uid=os.geteuid(),gid=os.getegid(),mode=0o700)},None)
        self.append(b,'inputs-pending',dict(sourceCommit='c'*40,sourceTree='d'*40,configurationSha256='e'*64,versionSha256='f'*64))
        self.append(b,'inputs-ready',dict(candidateSha256='1'*64))
        self.append(b,'prepare-pending',dict(candidateSha256='1'*64,confirmationSha256='2'*64))
        self.complete(b,CANDIDATE,'3'*64,'6'*64)
    def complete(self,b,op,intent,receipt):
        self.append(b,'prepared',dict(candidateSha256='1'*64,intentSha256=intent,storePreconditionSha256='4'*64),op)
        self.append(b,'execute-pending',dict(intentSha256=intent,confirmationSha256='2'*64,authorizationId='66666666-6666-4666-8666-666666666666',assignmentRevision=1),op)
        self.append(b,'settled-success',dict(intentSha256=intent,receiptSha256=receipt),op)
    def pending(self,stage='external-testing'):
        return dict(stage=stage,candidateOperationId=CANDIDATE,candidateSha256='1'*64,
            predecessorOperationId=CANDIDATE if stage=='external-testing' else EXTERNAL,
            predecessorReceiptSha256='6'*64 if stage=='external-testing' else '7'*64,
            sourceCommit='c'*40,sourceTree='d'*40,configurationSha256='e'*64,versionSha256='f'*64,
            metadataSha256='8'*64,confirmationSha256='2'*64)
    def test_real_candidate_external_production_rows_reload_without_fake_build(self):
        b=self.book();self.candidate(b)
        self.append(b,'promotion-pending',self.pending(),EXTERNAL);self.complete(b,EXTERNAL,'5'*64,'7'*64)
        self.append(b,'promotion-pending',self.pending('production-submit'),PRODUCTION);self.complete(b,PRODUCTION,'8'*64,'9'*64)
        head=b.head();self.assertEqual(head['sequence'],15);b.close();b=self.book();self.assertEqual(b.head(),head)
        self.assertEqual([r['phase'] for r,_ in b._rows].count('inputs-pending'),1)
    def test_wrong_predecessor_or_reused_pair_refuses_before_disk_append(self):
        b=self.book();self.candidate(b)
        rows=[r for r,_ in b._rows]
        for updates in (dict(stage='production-submit'),dict(predecessorReceiptSha256='9'*64),dict(candidateSha256='9'*64),dict(candidateOperationId=EXTERNAL)):
            with self.assertRaises(J.LocalJournalError):J.promotion_lineage(rows,operation_id=EXTERNAL,payload=self.pending()|updates)
        self.append(b,'promotion-pending',self.pending(),EXTERNAL);self.complete(b,EXTERNAL,'5'*64,'7'*64)
        count=len(b._rows)
        with self.assertRaises(J.LocalJournalError):self.append(b,'promotion-pending',self.pending(),PRODUCTION)
        self.assertEqual(len(b._rows),count)
        self.assertEqual(len(list(Path(b.path).glob('*.json'))) if hasattr(b,'path') else len(b.leaves),count)
    def test_failed_or_reconciled_predecessor_does_not_admit_promotion(self):
        b=self.book();self.candidate(b);rows=[copy.deepcopy(r) for r,_ in b._rows]
        for phase in ('settled-failure','reconciliation-required','target-reconciled','execute-pending'):
            changed=copy.deepcopy(rows);changed[-1]['phase']=phase
            with self.assertRaises(J.LocalJournalError):J.promotion_lineage(changed,operation_id=EXTERNAL,payload=self.pending())
    def test_new_stage_requires_four_forward_slots_before_append(self):
        b=self.book();self.candidate(b);rows=[r for r,_ in b._rows]
        # Exact arithmetic boundary in DATA, not 500 unneeded disk writes.
        filler=[copy.deepcopy(rows[0]) for _ in range(509-len(rows))]
        J.promotion_lineage([rows[0],*filler,*rows[1:]],operation_id=EXTERNAL,payload=self.pending())
        with self.assertRaises(J.LocalJournalError):J.promotion_lineage([rows[0],rows[0],*filler,*rows[1:]],operation_id=EXTERNAL,payload=self.pending())

class LocalStorePredecessorTests(unittest.TestCase):
    """Real original parents/files/HMAC journal; no modeled native authority."""
    def setUp(self):
        from mobile_release.cancellation import DefaultCancellation
        from mobile_release.owned_process import ProcessCleanupError
        from mobile_release.build_inputs import _Directory
        self.assertNotEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=Path.home()); self.home=Path(self.temp.name)
        self.root=self.home/'project';self.root.mkdir(mode=0o700)
        self.account=self.home/'account';self.account.mkdir(mode=0o700)
        self.guard=DefaultCancellation(ProcessCleanupError,'test original predecessor cleanup')
        self.project=_Directory(self.root,self.guard);self.project.acquire()
        self.book=J.LocalReleaseJournal(str(self.account),end=time.monotonic()+20,
            enrollment=fixture('local-intent-candidate-valid.json')['project'],key=KEY)
        self.book.open(); r=self.root.stat()
        self.append('genesis',dict(rootIdentity=dict(device=r.st_dev,inode=r.st_ino,mode=r.st_mode&0o7777,uid=r.st_uid,gid=r.st_gid)),None)
        self.inputs=[]
    def tearDown(self):
        try:
            for value in self.inputs:
                if not value.close_claimed:
                    try:value.close()
                    except BaseException:pass
                self.assertTrue(all(all(s.number is None for s in out.slots+out.parent.slots) for out in value.readers))
            self.project.close()
        finally:
            self.book.close(); self.temp.cleanup()
    def append(self,phase,payload,operation=CANDIDATE):
        return self.book._append(expected_head=self.book.head(),operation_id=operation,phase=phase,payload=payload)
    def write(self,path,raw):
        parent=self.root
        for part in path.parent.relative_to(self.root).parts:
            parent/=part;parent.mkdir(mode=0o700,exist_ok=True)
        path.write_bytes(raw);path.chmod(0o600)
    def completed(self,platform,stage='candidate',candidate=None,receipt_state=None):
        if stage=='candidate':
            i=fixture('local-intent-ios-candidate-valid.json' if platform=='ios' else 'local-intent-candidate-valid.json')
        else:
            i,_,_=documents(platform,stage)
            i['predecessors']['candidateReceiptSha256']=candidate[1]
            # New stage metadata bytes genuinely differ; original binary/report/archive unchanged.
            rawzip=b'PK\x05\x06'+bytes(18)
            i['artifacts'][1].update(size=len(rawzip),sha256=hashlib.sha256(rawzip).hexdigest())
            i['configuration']['metadataSha256']=i['artifacts'][1]['sha256']
            i=reseal(i)
        a=dict(i['preparedBy'],purpose='execute',authorizationId='66666666-6666-4666-8666-666666666666',intentSha256=i['integrity']['sha256'])
        body=raw_receipt(dict(i,authorizedBy={}))
        for k in ('authorizedBy','executedBy'):body.pop(k)
        r=dict(body,documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',
            project=i['project'],operationId=i['operationId'],candidateSha256=i['candidateSha256'],preparedBy=i['preparedBy'],executedBy=a)
        if stage!='candidate':r.update(stage=stage,candidateOperationId=CANDIDATE)
        if receipt_state is not None:r['state']=receipt_state
        raw=canonical(r)+b'\n';digest=hashlib.sha256(raw).hexdigest()
        kwargs=dict(intent_data=encoded(i),authority_data=encoded(a),purpose='execute',expected_intent_sha256=i['integrity']['sha256'],platform=platform,stage=stage)
        R.validate_local_execution_receipt(raw,**kwargs)
        snapshot=canonical(i['storePrecondition'])+b'\n'
        op=i['operationId']; directory=self.root/'.mobile-release/store/local'/op.replace('-','')
        self.write(directory/'operation-intent.json',canonical(i)+b'\n')
        self.write(directory/'store-precondition.json',snapshot)
        if stage!='candidate':self.write(directory/'store-metadata.zip',rawzip)
        receipt_dir=directory.with_name(directory.name+'-execute-'+a['authorizationId'].replace('-',''))
        self.write(receipt_dir/'raw-store-receipt.json',raw)
        first=dict(sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
            configurationSha256=i['configuration']['sha256'],versionSha256='f'*64)
        if stage=='candidate':
            self.append('inputs-pending',first,op)
            self.append('inputs-ready',dict(candidateSha256=i['candidateSha256']),op)
            self.append('prepare-pending',dict(candidateSha256=i['candidateSha256'],confirmationSha256=a['confirmationSha256']),op)
        else:
            self.append('promotion-pending',first|dict(stage=stage,candidateOperationId=CANDIDATE,candidateSha256=i['candidateSha256'],
                predecessorOperationId=CANDIDATE,predecessorReceiptSha256=candidate[1],metadataSha256=i['configuration']['metadataSha256'],
                confirmationSha256=a['confirmationSha256']),op)
        self.append('prepared',dict(candidateSha256=i['candidateSha256'],intentSha256=i['integrity']['sha256'],storePreconditionSha256=hashlib.sha256(snapshot).hexdigest()),op)
        self.append('execute-pending',dict(intentSha256=i['integrity']['sha256'],authorizationId=a['authorizationId'],
            confirmationSha256=a['confirmationSha256'],assignmentRevision=a['assignment']['expectedRevision']),op)
        self.append('settled-success',dict(intentSha256=i['integrity']['sha256'],receiptSha256=digest),op)
        return i,digest,directory,receipt_dir
    def reader(self,previous,stage='external-testing'):
        from mobile_release.local_store_predecessor import StorePredecessorInputs
        i,digest,_,_=previous
        p=dict(stage=stage,candidateOperationId=CANDIDATE,candidateSha256=i['candidateSha256'],
            predecessorOperationId=i['operationId'],predecessorReceiptSha256=digest,
            sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
            configurationSha256=i['configuration']['sha256'],versionSha256='f'*64,metadataSha256='e'*64,
            confirmationSha256=hashlib.sha256(f'{stage}:{i["platform"]}:1.2.3:42'.encode()).hexdigest())
        value=StorePredecessorInputs(self.project,self.book,self.guard,operation_id=EXTERNAL if stage=='external-testing' else PRODUCTION,payload=p,platform=i['platform'])
        self.inputs.append(value);return value
    def test_real_original_candidate_and_external_chain_both_platforms(self):
        # Separate original journal/project per platform, never replace enrollment mid-owner.
        for platform in ('android','ios'):
            if platform=='ios':self.tearDown();self.setUp()
            c=self.completed(platform);r=self.reader(c);r.acquire()
            facts=r.facts();self.assertEqual(facts['candidate']['receiptSha256'],c[1]);self.assertEqual(len(r.readers),2)
            r.close();self.assertTrue(r.closed)
            e=self.completed(platform,'external-testing',c);r=self.reader(e,'production-submit');r.acquire()
            self.assertEqual(len(r.readers),4);self.assertNotEqual(r.facts()['candidate']['configuration']['metadataSha256'],r.facts()['predecessor']['configuration']['metadataSha256'])
            # Real allowed later row does not cause original inputs to be re-adopted.
            self.append('promotion-pending',r.payload,PRODUCTION);r.post();r.close();self.assertTrue(r.closed)
    def test_changed_receipt_hash_and_foreign_authority_are_refused(self):
        c=self.completed('android');path=c[3]/'raw-store-receipt.json'
        data=json.loads(path.read_bytes());data['executedBy']['authorizationId']='77777777-7777-4777-8777-777777777777'
        path.write_bytes(canonical(data)+b'\n')
        r=self.reader(c)
        with self.assertRaises(Exception):r.acquire()
        r.close();self.assertTrue(r.closed);self.assertTrue(r.failed)
    def test_replacement_or_added_leaf_after_acquire_preserves_files_and_refuses(self):
        c=self.completed('android');r=self.reader(c);r.acquire()
        old=c[2];moved=old.with_name(old.name+'-preserved');old.rename(moved);old.mkdir(mode=0o700)
        for p in moved.iterdir():self.write(old/p.name,p.read_bytes())
        with self.assertRaises(Exception):r.post()
        try:r.close()
        except Exception:pass
        self.assertTrue(moved.exists());self.assertTrue(old.exists());self.assertTrue(r.failed)
    def test_occupied_roster_and_insufficient_original_budget_before_read(self):
        from unittest.mock import patch
        from mobile_release import local_store_predecessor as module
        c=self.completed('android');self.write(c[2]/'unrelated',b'preserve')
        r=self.reader(c)
        with self.assertRaises(Exception):r.acquire()
        r.close();self.assertTrue(r.closed);self.assertTrue((c[2]/'unrelated').exists())
        (c[2]/'unrelated').unlink() # fixture only, not recovery
        r=self.reader(c)
        with patch.object(module.StorePredecessorInputs,'descriptor_quote',return_value=256),patch.object(module,'_read_file',side_effect=AssertionError('no read before admission')):
            with self.assertRaises(J.LocalJournalError):r.acquire()
        r.close();self.assertEqual(r.readers,[])
    def test_cancel_and_lost_original_close_remain_unaccepted(self):
        from unittest.mock import patch
        from mobile_release import build_inputs
        c=self.completed('android');r=self.reader(c);r.acquire()
        # Published successful native close without its returned observation stays unknown.
        original=os.close;fired=[];target=r.readers[-1].slots[-1].number
        def lost(number):
            if not fired and number==target:
                fired.append(number);original(number);raise OSError('lost original close return')
            return original(number)
        with patch.object(build_inputs.os,'close',lost):
            with self.assertRaises(Exception):r.close()
        self.assertTrue(fired);self.assertTrue(r.failed);self.assertFalse(r.closed)
        self.assertTrue(all(all(s.number is None for s in out.slots+out.parent.slots) for out in r.readers))

    def test_approved_but_not_available_external_receipt_cannot_admit_production(self):
        c=self.completed('ios');e=self.completed('ios','external-testing',c,receipt_state='approved')
        r=self.reader(e,'production-submit')
        with self.assertRaises(J.LocalJournalError):r.acquire()
        r.close();self.assertTrue(r.closed);self.assertTrue(r.failed)
        self.assertEqual(self.book._rows[-1][0]['operationId'],EXTERNAL)
