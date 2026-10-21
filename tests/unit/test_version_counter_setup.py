"""Actual first-counter policy with inert provider replies, never native authority."""
from __future__ import annotations
import base64
import copy
import json
import unittest
from mobile_release import version_counter_setup as p, github_setup_publication as old
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
from mobile_release._github_setup_publication_journal import Journal, summary
from test_github_setup import draft
from test_github_setup_publication import target as old_target, source as old_source, Reader as OldReader

BASE, BASE_TREE, COMMIT = 'a'*40, 'b'*40, 'c'*40
VERSION = b'# original saved version\nVERSION_NAME=1.2.3\nBUILD_NUMBER=7\n'
CONFIG = json.dumps(draft()).encode()
def target(**changes):
 value = {'purpose': 'version-counter', 'projectBinding':'d'*64, 'repository':'owner/app',
 'accountId':'11', 'repositoryId':'22', 'base':'main', 'marker':'e'*32, 'projectId':'f'*32,
 'ledgerId':'00000000-0000-4000-8000-000000000007',
 'initialVersion':{'name':'1.2.3','build':7}, 'savedConfig':old._fingerprint(CONFIG),
 'savedVersion':{'path':'release/version.properties',**old._fingerprint(VERSION)}}
 value.update(changes)
 return p.Target.parse(value)

class Reader:
 def __init__(self, selected=None):
  self.selected=selected or target();self.calls=[];self.head=None;self.fail=None;self.before=None
  self.account=11;self.repo=22;self.source=BASE;self.alter=None
 def __call__(self, request):
  self.calls.append(request)
  if self.before:self.before(len(self.calls),request)
  p.request_role(self.selected,request)
  path=request.path.removeprefix('/repos/owner/app');raw,blob,release,root=p.objects(self.selected)
  code=201 if request.method=='POST' else 200
  def commit():return {'sha':COMMIT,'tree':{'sha':root},'parents':[], 'message':self.selected.title}
  if path=='/user':value={'id':self.account,'login':'owner'}
  elif path=='':value={'id':self.repo,'full_name':'owner/app','default_branch':'main','visibility':'private','archived':False,'permissions':{'pull':True}}
  elif path.startswith('/git/ref/heads/'):
   name=path.removeprefix('/git/ref/heads/');sha=self.head if name==self.selected.head else self.source
   if sha is None:
    if self.fail==len(self.calls):raise ReadFailure('network-unavailable')
    return ReadResult({'status':404,'body':None,'failure':'none'},_control())
   value={'ref':'refs/heads/'+name,'object':{'type':'commit','sha':sha}}
  elif request.method=='POST':
   if path=='/git/trees':value={'sha':root}
   elif path=='/git/commits':value=commit()
   elif path=='/git/refs':self.head=COMMIT;value={'ref':'refs/heads/'+self.selected.head,'object':{'type':'commit','sha':COMMIT}}
   else:raise AssertionError(path)
  elif path=='/git/commits/'+BASE:value={'sha':BASE,'tree':{'sha':BASE_TREE}}
  elif path=='/git/commits/'+COMMIT:value=commit()
  elif path=='/git/trees/'+root:value={'sha':root,'truncated':False,'tree':[{'path':'release','mode':'040000','type':'tree','sha':release}]}
  elif path=='/git/trees/'+release:value={'sha':release,'truncated':False,'tree':[{'path':p.allocation.LEDGER_PATH.split('/')[1],'mode':'100644','type':'blob','sha':blob}]}
  elif path=='/git/blobs/'+blob:value={'sha':blob,'size':len(raw),'encoding':'base64','content':base64.b64encode(raw).decode()}
  else:raise AssertionError(path)
  if self.alter:self.alter(request,value)
  if self.fail==len(self.calls):raise ReadFailure('network-unavailable')
  return ReadResult({'status':code,'body':value,'failure':'none'},_control())

class MemoryJournal:
 """Inert storage ONLY; call the actual Journal state transitions/codec."""
 def __init__(self):
  self.book=Journal('/inert/home',end=0);self.book._create=self.create;self.book._post=lambda:None
  self.files={};self.events=[];self.fail=None
 @property
 def publications(self):return self.book.publications
 def create(self,name,raw):
  self.events.append(name)
  if self.fail==name.split('.')[1:3]:raise OSError('inert journal failure')
  if name in self.files:raise AssertionError('overwrite')
  self.files[name]=raw
 def create_intent(self,v):self.book.create_intent(v)
 def claim_write(self,v):self.book.claim_write(v)
 def record(self,p,v):self.book.record(p,v)
 def reopen(self):
  next=MemoryJournal();next.files=dict(self.files)
  next.book._names=lambda:set(next.files);next.book._read=lambda n:next.files[n]
  next.book._load();return next

class CounterPolicyTests(unittest.TestCase):
 def review(self):
  r=Reader();j=MemoryJournal();review=p.prepare(target(),r,j);r.calls.clear();return review,r,j
 def test_canonical_existing_genesis_initial_saved_data_and_readonly_eight(self):
  r=Reader();j=MemoryJournal();v=p.prepare(target(),r,j)
  self.assertEqual(len(r.calls),8);self.assertTrue(all(c.method=='GET' for c in r.calls));self.assertEqual(j.files,{})
  raw,blob,release,root=p.objects(target());ledger=p.allocation.Ledger(target().genesis(),())
  self.assertEqual(ledger.reservations,());self.assertEqual(ledger.genesis.initial_version.build,7)
  self.assertEqual(raw,ledger.to_bytes());self.assertEqual(old.git_hash('blob',raw),blob)
  self.assertEqual(p.Prepared.parse(v.view()),v);self.assertEqual(summary(v.summary()),v.summary())
  self.assertEqual(v.view()['head'],'mrk-version-allocations');self.assertIn('NOT a verified Store floor',v.view()['confirmation'])
 def test_exact_twenty_create_schedule_root_commit_and_no_other_mutations(self):
  v,r,j=self.review();out=p.publish(v,r,j);self.assertEqual((out['reason'],out['effect']),('none','counter-observed'))
  self.assertEqual(len(r.calls),20);posts=[(i+1,c) for i,c in enumerate(r.calls) if c.method=='POST']
  self.assertEqual([i for i,c in posts],[6,10,14]);self.assertEqual(json.loads(posts[0][1].body),{'tree':[{'path':p.allocation.LEDGER_PATH,'mode':'100644','type':'blob','content':target().ledger().decode()}]})
  self.assertEqual(json.loads(posts[1][1].body)['parents'],[])
  self.assertEqual(out['claimed'],['tree','commit','branch']);self.assertEqual(out['confirmed']['branch'],COMMIT)
  self.assertEqual(len(j.files),7);self.assertEqual(j.reopen().publications,j.publications)
  self.assertNotIn('protected',out);self.assertNotIn('pull',out)
 def test_strict_target_review_and_source_without_version_normalization(self):
  p.source_matches(CONFIG,VERSION,target())
  for a,b in ((CONFIG+b' ',VERSION),(CONFIG,VERSION+b'\n')):
   with self.assertRaises(ValueError):p.source_matches(a,b,target())
  for changes in ({'purpose':'other'},{'base':p.allocation.LEDGER_BRANCH},{'projectId':'0'*32},{'ledgerId':'not-a-uuid'},
    {'initialVersion':{'name':'release-next','build':7}}, {'extra':True}):
   with self.subTest(changes=changes),self.assertRaises(ValueError):target(**changes)
  v,_,_=self.review()
  for key,value in [('ledger',v.view()['ledger']+'\n'),('baseCommit','bad'),('desiredTree','1'*40),('confirmation','yes')]:
   data=v.view();data[key]=value
   with self.assertRaises(ValueError):p.Prepared.parse(data)
 def test_current_counter_malformed_ref_account_source_and_tree_drift_refuse(self):
  for field,value in [('head',COMMIT),('head','not-an-oid'),('account',13),('repo',99),('source','9'*40)]:
   v,r,j=self.review();setattr(r,field,value);out=p.publish(v,r,j)
   self.assertNotEqual(out['reason'],'none');self.assertFalse(any(c.method=='POST' for c in r.calls));self.assertEqual(j.files,{})
 def test_whole_roster_same_repository_or_project_blocks_new_marker_or_account(self):
  v,r,j=self.review();p.publish(v,r,j);restored=j.reopen()
  for changes in ({'marker':'1'*32},{'accountId':'99','marker':'2'*32,'repository':'renamed/app'},
                  {'repositoryId':'77','marker':'3'*32}):
   r=Reader();selected=target(**changes)
   with self.assertRaises(p.Refused) as error:p.prepare(selected,r,restored)
   self.assertEqual(error.exception.reason,'counter-intent-exists');self.assertEqual(r.calls,[])
  selected=target(projectBinding='4'*64,repositoryId='88',marker='5'*32)
  p.first_use(restored.publications,selected)
 def test_all_twenty_response_cuts_never_repeat_or_send_later_write(self):
  for cut in range(1,21):
   with self.subTest(cut=cut):
    v,r,j=self.review();r.fail=cut;out=p.publish(v,r,j)
    self.assertNotEqual(out['reason'],'none');self.assertEqual(len(r.calls),cut)
    self.assertEqual(out['effect'],'not-sent' if cut<6 else 'potentially-applied');self.assertIsNone(out['counter'])
    self.assertEqual(sum(c.method=='POST' for c in r.calls),sum(i<=cut for i in (6,10,14)))
 def test_every_durable_claim_and_result_failure_stops_the_original(self):
  for phase in ('intent','tree','commit','branch'):
   for point in (('json',) if phase=='intent' else ('claim','result')):
    with self.subTest(phase=phase,point=point):
     v,r,j=self.review();j.fail=[phase,point];out=p.publish(v,r,j)
     self.assertEqual(out['reason'],'journal-unavailable')
     expected=0 if phase=='intent' else ('tree','commit','branch').index(phase)+(point=='result')
     self.assertEqual(sum(c.method=='POST' for c in r.calls),expected)
 def test_lost_ref_response_reconciles_exact_claimed_commit_get_only_and_never_rearms(self):
  v,r,j=self.review();r.fail=14;out=p.publish(v,r,j);self.assertEqual(out['effect'],'potentially-applied')
  restored=j.reopen();original=next(iter(restored.publications.values()));r.calls=[];r.fail=None
  out=p.reconcile(original['summary'],original['confirmed'],tuple(original['claimed']),r)
  self.assertEqual(out['effect'],'counter-observed');self.assertLessEqual(len(r.calls),12);self.assertTrue(all(c.method=='GET' for c in r.calls))
  r.calls=[];self.assertEqual(p.publish(v,r,restored)['reason'],'counter-intent-exists');self.assertEqual(r.calls,[])
  r.head='9'*40;self.assertEqual(p.reconcile(original['summary'],original['confirmed'],tuple(original['claimed']),r)['effect'],'unresolved')
 def test_unknown_object_identity_is_not_search_or_retry_authority(self):
  for cut in (6,10):
   v,r,j=self.review();r.fail=cut;p.publish(v,r,j);record=next(iter(j.publications.values()));r.calls=[]
   out=p.reconcile(record['summary'],record['confirmed'],tuple(record['claimed']),r)
   self.assertEqual(out['effect'],'unresolved');self.assertEqual(r.calls,[])
 def test_readback_extra_tree_corrupt_blob_parent_or_message_never_acknowledges(self):
  for kind in ('tree','blob','parent','message'):
   v,r,j=self.review()
   def alter(req,value):
    if kind=='tree' and '/git/trees/' in req.path:value['tree'].append({'path':'extra','mode':'100644','type':'blob','sha':'1'*40})
    if kind=='blob' and '/git/blobs/' in req.path:value['content']=base64.b64encode(b'corrupt').decode()
    if kind=='parent' and req.path.endswith('/git/commits/'+COMMIT):value['parents']=[{'sha':BASE}]
    if kind=='message' and req.path.endswith('/git/commits/'+COMMIT):value['message']='different'
   r.alter=alter;out=p.publish(v,r,j);self.assertNotEqual(out['reason'],'none');self.assertNotIn('branch',out['claimed'])
 def test_transport_rejects_pr_existing_tree_parent_update_and_extra_roles(self):
  for path,body in [('/pulls',{}),('/git/trees',{'base_tree':BASE,'tree':[]}),('/git/commits',{'message':target().title,'tree':p.objects(target())[3],'parents':[BASE]}),('/git/refs',{'ref':'refs/heads/other','sha':COMMIT})]:
   with self.assertRaises(ValueError):p.request_role(target(),old.HttpRequest('POST','/repos/owner/app'+path,old._canonical(body)))
  for method in ('PUT','PATCH','DELETE'):
   with self.assertRaises(ValueError):p.request_role(target(),old.HttpRequest(method,'/repos/owner/app/git/refs',b'{}'))
 def test_old_five_file_summary_and_journal_bytes_stay_separate(self):
  legacy=old.prepare(old_target(),old_source(),OldReader());j=MemoryJournal();j.create_intent(legacy.summary())
  self.assertEqual(p.target(old_target().value()),old_target());self.assertEqual(p.prepared(legacy.view()),legacy)
  self.assertEqual(j.reopen().publications,j.publications);self.assertNotIn('purpose',legacy.summary()['target'])
  p.first_use(j.publications,target())
  bad=copy.deepcopy(legacy.summary());bad['protocol']=p.PROTOCOL
  with self.assertRaises(ValueError):summary(bad)

if __name__=='__main__':unittest.main()
