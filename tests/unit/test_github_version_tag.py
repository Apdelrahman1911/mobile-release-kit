"""Real typed dispatch/ledger/record code; inert HTTP/storage, never a live tag."""
from __future__ import annotations
import copy
from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import patch

from mobile_release import github_play_cleanup as p
from mobile_release import github_version_tag as tag
from mobile_release import version_future_tag as policy_tag
from mobile_release import _github_play_cleanup_transport as transport
from mobile_release._github_connection_transport import ReadResult, _ResponseRole, _role_limits, _ExchangeProfile
from mobile_release.config import default_config_data
from test_github_play_cleanup import Fixture, MemoryJournal, A, B, C, TREE_A, TREE_B, contents, tree
from test_version_allocation import CurrentInventoryLedgerTests, NOW

TAG = 'refs/tags/release-1.4'
class TagFixture(Fixture):
    def __init__(self):
        super().__init__()
        config = default_config_data({'ios': {'bundleId': 'com.example.inert'}})
        config['source']['candidateBranch'] = 'main'; config['ios']['appStoreAppId'] = '1234567890'
        self.config = p.canonical(config); self.version_path = config['version']['source']
        self.version = b'VERSION_NAME=1.4.0\nBUILD_NUMBER=10\n'
        self.source = tag.saved_source(self.config)
        item = CurrentInventoryLedgerTests().selected()
        self.request = replace(item, project_id=self.authority.project_id,
            base_version=p.ReleaseVersion('1.4.0', 10),
            identity_revision=hashlib.sha256(self.config).hexdigest(), future_tag=TAG,
            source=p.policy.SourceBinding(A, TREE_A, 'refs/heads/main', self.source.saved_sha256, hashlib.sha256(self.version).hexdigest()),
            version_policy=replace(item.version_policy, rules=(p.policy.RefRule(TAG, 'build'),)))
        observations = tuple(replace(o, identity_revision=self.request.identity_revision)
            for o in CurrentInventoryLedgerTests().observed())
        self.ledger = self.ledger.append(self.request, observations, now=NOW)
        self.row = self.ledger.reservations[-1]
        self.checkpoint = p.allocation.Checkpoint(1, self.ledger.head_sha256, C)
        self.target = replace(self.target, version_tag=tag.Selection(self.request.candidate_id, self.row.sha256, B))
        self.tag_body = None
    def __call__(self, request):
        root = '/repos/fixture/app'
        if request.path == root + '/git/ref/' + TAG.removeprefix('refs/'):
            self.calls.append(request); status, value = (404, None) if self.tag_body is None else (200, copy.deepcopy(self.tag_body))
        elif request.path == root + '/git/commits/' + B:
            self.calls.append(request); status, value = 200, {'sha':B,'tree':{'sha':TREE_B},'parents':[{'sha':A}]}
        else:
            def extend(req, n, status, value):
                if req.path == root + '/git/trees/' + TREE_B + '?recursive=1':
                    value = tree(TREE_B, {p.WORKFLOW_PATH:p.canonical_caller(self.target),p.version_text.CONFIG_PATH:self.config})
                return prior(req,n,status,value) if prior else (status,value)
            prior = self.change; self.change = extend
            try: return super().__call__(request)
            finally: self.change = prior
        if self.change: status,value = self.change(request,len(self.calls),status,value)
        return ReadResult({'status':status,'body':value,'failure':'none'},self.control)

class GitHubVersionTagTests(unittest.TestCase):
    def setUp(self):
        self.block = patch('subprocess.Popen',side_effect=AssertionError('no process'));self.block.start();self.addCleanup(self.block.stop)
    def test_same_prepare_owner_nineteen_reads_returns_exact_future_intent_without_play_record(self):
        f=TagFixture();value=f.prepare();raw=value.value()
        self.assertEqual(len(f.calls),19);self.assertTrue(all(r.method=='GET' for r in f.calls))
        self.assertEqual((value.source_sha,raw['candidate']['source']['commit'],raw['candidate']['futureTag']),(B,A,TAG))
        self.assertFalse({'journalBlob','journalSha256','journalRevision'} & raw.keys())
        self.assertEqual(p.Prepared.parse(raw),value)
        self.assertEqual(raw['candidate']['version'],{'name':'1.4.0','build':11})
        for word in ['ciphertext','editId','token','runId','privateKey']: self.assertNotIn(word,p.canonical(raw).decode())
        self.assertIn('branch-triggered',raw['confirmation']);self.assertIn('other automation',raw['confirmation'])
    def test_full_branch_counter_original_source_and_absence_are_not_renderer_authority(self):
        for cut in ['account','branch','config','parent','tag','late-counter']:
            f=TagFixture()
            def change(req,n,status,value):
                if cut=='account' and n==1:value['id']=12
                if cut=='branch' and n==3:value['commit']['sha']=A
                if cut=='config' and n==12:value=contents(p.version_text.CONFIG_PATH,b'{}')
                if cut=='parent' and n==11:value['parents'].append({'sha':C})
                if cut=='tag' and n==15:status,value=200,{'ref':TAG,'object':{'type':'commit','sha':B}}
                if cut=='late-counter' and n==17:value['object']['sha']=A
                return status,value
            f.change=change
            with self.subTest(cut=cut),self.assertRaises(p.Refused):f.prepare()
            self.assertTrue(all(r.method=='GET' for r in f.calls))
    def test_original_journal_claim_precedes_single_fixed_dispatch_only_ack_unconfirmed(self):
        f=TagFixture();prepared=f.prepare();f.calls.clear();journal=MemoryJournal()
        def check(req,n,status,value):
            if req.method=='POST':
                self.assertEqual(n,13);self.assertTrue(journal.attempts[prepared.target.marker]['data']['claimed'])
                self.assertEqual(json.loads(req.body),{'ref':'main','inputs':{'operation':'bind-version-tag','platform':'ios',
                    'confirmation':f'bind-version-tag:ios:{f.request.candidate_id}:{f.row.sha256}:{B}'}})
            return status,value
        f.change=check;result=p.dispatch(prepared,f.source,f,journal)
        self.assertEqual((result['effect'],result['reason']),('acknowledged-unconfirmed','none'))
        self.assertIsNone(result['observed']);p.action_result(result,prepared,'dispatch')
        self.assertEqual(sum(r.method=='POST' for r in f.calls),1)
    def test_once_key_excludes_final_commit_tag_and_row_from_identity_but_compares_body(self):
        f=TagFixture();prepared=f.prepare();other=replace(prepared,target=replace(prepared.target,
            marker='b'*32,version_tag=replace(prepared.target.version_tag,final_commit='e'*40)),source_sha='e'*40)
        other=p.Prepared.parse(other.value())
        self.assertEqual(p.once_key(prepared),p.once_key(other));self.assertNotEqual(p.digest(prepared),p.digest(other))
        journal=MemoryJournal();journal.create_intent(prepared.value());journal.claim()
        with self.assertRaises(p.Refused):journal.create_intent(other.value())
        self.assertFalse(other.target.marker in journal.attempts)
    def test_lost_post_ack_retains_original_and_new_marker_cannot_resend(self):
        f=TagFixture();prepared=f.prepare();journal=MemoryJournal();f.calls.clear()
        def lost(req,n,status,value):
            if req.method=='POST':raise OSError('synthetic private transport text')
            return status,value
        f.change=lost;result=p.dispatch(prepared,f.source,f,journal)
        self.assertEqual(result['effect'],'potentially-applied');self.assertNotIn('private',p.canonical(result).decode())
        replacement=replace(prepared,target=replace(prepared.target,marker='b'*32));f.change=None;f.calls.clear()
        second=p.dispatch(replacement,f.source,f,journal)
        self.assertEqual(second['reason'],'previous-attempt');self.assertFalse(any(r.method=='POST' for r in f.calls))
    def test_old_cleanup_grant_shape_and_typed_tag_selection_are_not_interchangeable(self):
        f=TagFixture();prepared=f.prepare()
        for change in ['null','old-fields','no-purpose','source-tag','row-drift']:
            raw=copy.deepcopy(prepared.value())
            if change=='null':raw['target']['versionTag']=None
            if change=='old-fields':raw['journalRevision']=1
            if change=='no-purpose':raw['target'].pop('versionTag')
            if change=='source-tag':raw['candidate']['source']['ref']=TAG
            if change=='row-drift':raw['target']['versionTag']['rowSha256']='e'*64
            with self.subTest(change=change),self.assertRaises(ValueError):p.Prepared.parse(raw)
        old=Fixture().prepare();self.assertNotIn('versionTag',old.target.value());self.assertIn('journalRevision',old.value())
        self.assertNotEqual(p.once_key(old),p.once_key(prepared))
    def test_later_exact_ledger_and_tag_read_is_observation_not_create_or_permission(self):
        f=TagFixture();prepared=f.prepare();f.calls.clear()
        binding=policy_tag.Binding(f.request.candidate_id,f.row.sha256,B,TREE_B,'00000000-0000-4000-8000-000000000009','44',1)
        f.ledger=policy_tag.append_binding(f.ledger,binding)
        f.tag_body={'ref':TAG,'object':{'type':'commit','sha':B}}
        result=p.observe({'prepared':prepared.value(),'claimed':True,'acknowledged':False},f)
        self.assertEqual((result['effect'],result['observed']['binding']),('observed-unconfirmed','claimed-tag-matches'))
        self.assertFalse(result['acknowledged']);self.assertTrue(all(r.method=='GET' for r in f.calls))
        p.action_result(result,prepared,'observe')
        with self.assertRaises(ValueError):p.action_result(result,Fixture().prepare(),'observe')
    def test_new_tag_http_role_is_closed_get_and_same_existing_profile_only(self):
        f=TagFixture();prepared=f.prepare()
        request=p.HttpRequest('GET','/repos/fixture/app/git/ref/tags/release-1.4',None)
        self.assertIs(transport.request_role(f.target,f.source,prepared,'dispatch',request),_ResponseRole.VERSION_TAG_READ)
        for path in ['/repos/fixture/app/git/refs','/repos/fixture/app/git/ref/heads/main','/repos/fixture/app/git/ref/tags/a?ref=main']:
            with self.assertRaises(ValueError):transport.validate_endpoint(_ResponseRole.VERSION_TAG_READ,'GET',path)
        with self.assertRaises(ValueError):transport.request_role(Fixture().target,None,None,'prepare',request)
        transport.validate_body(_ResponseRole.PLAY_CLEANUP_WRITE,p.dispatch_body(prepared))
        with self.assertRaises(ValueError):transport.validate_endpoint(_ResponseRole.VERSION_TAG_READ,'POST',request.path)
        self.assertTrue(_role_limits(_ExchangeProfile.PLAY_CLEANUP,_ResponseRole.VERSION_TAG_READ))

    def test_malformed_original_commit_and_pending_only_target_never_prepare(self):
        for index, field, value in [(10, 'tree', None), (11, 'tree', []), (11, 'parents', [None])]:
            f=TagFixture()
            def change(req,n,status,body):
                if n==index: body[field]=value
                return status,body
            f.change=change
            with self.subTest(index=index,field=field),self.assertRaises(p.Refused):f.prepare()
            self.assertEqual(len(f.calls),index)
        f=TagFixture(); old=Fixture().prepare().value()
        old['target']['purpose']='version-tag'
        with self.assertRaises(ValueError):p.Prepared.parse(old)
        listing=replace(f.target,version_tag=None,pending_purpose='version-tag')
        self.assertEqual(p.Target.parse(listing.value()),listing)
        with self.assertRaises(ValueError):p.prepare(listing,f.source,f)
        self.assertFalse(f.calls)
