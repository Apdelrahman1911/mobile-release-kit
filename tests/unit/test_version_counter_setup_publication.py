"""Real finite source reader + original journal codec with inert storage/HTTP ports."""
import hashlib,json,time,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from mobile_release import _github_setup_publication_runtime as runtime
from mobile_release import _github_setup_publication_transport as live
from mobile_release import _github_connection_transport as http
from mobile_release import github_setup_publication as old, github_setup_secret_inputs as source
from test_version_counter_setup import target,Reader,MemoryJournal,CONFIG,VERSION,old_target
class CounterRuntimeTests(unittest.TestCase):
 def setUp(self):
  self.holder=tempfile.TemporaryDirectory(prefix='mrk-counter-inert-');self.addCleanup(self.holder.cleanup)
  self.home=Path(self.holder.name);self.root=self.home/'project';(self.root/'release').mkdir(parents=True)
  (self.root/old.CONFIG_PATH).write_bytes(CONFIG);(self.root/'release/version.properties').write_bytes(VERSION)
  m=self.root.stat();self.capture={'root':str(self.root),'rootIdentity':{'device':str(m.st_dev),'inode':str(m.st_ino),'mode':m.st_mode,'uid':m.st_uid,'gid':m.st_gid}}
  self.reader=Reader();self.close=None;self.journal=MemoryJournal()
  original=self
  class InertJournal(runtime.Journal):
   # The original codec/transitions above run, but this storage port is DATA.
   # UID0 never weakens or enters the real nonroot private custodian.
   def __init__(self,home,*,end):super().__init__(home,end=end)
   def open(self):
    self._names=lambda:set(original.journal.files);self._read=lambda n:original.journal.files[n]
    self._create=original.journal.create;self._post=lambda:None;self._load()
   def close(self):pass
  self.fake_journal=InertJournal
  patcher=patch.object(runtime,'Journal',InertJournal);patcher.start();self.addCleanup(patcher.stop)
 def initial(self,kind,prepared=None):
  selected=target().value()
  if kind=='pending':
   selected=old_target().value();selected['projectBinding']=target().project_binding
  return old._canonical({'protocol':old.PROTOCOL,'id':'counter_inert','action':{'kind':kind,'target':selected,
   'source':self.capture if kind in ('prepare','publish') else None,'home':str(self.home),
   'preparedSha256':None if prepared is None else hashlib.sha256(old._canonical(prepared)).hexdigest()}})+b'\n'
 def factory(self,token,**kwargs):
  self.assertEqual(token,'INERT_COUNTER_TOKEN');self.assertIs(kwargs['_setup_budget'].profile,http._ExchangeProfile.PUBLICATION)
  def send(method,path,body,*,_role):
   http._request_limits(http._ExchangeProfile.PUBLICATION,_role,method,path)
   return self.reader(old.HttpRequest(method,path,body))
  return send
 def run_original(self,kind,prepared=None):
  req=runtime.parse_initial(self.initial(kind,prepared));fields={
   'requestSha256':req.digest,'token':None if kind=='pending' else 'INERT_COUNTER_TOKEN','prepared':prepared}
  if kind!='pending':fields['projectId']=target().project_id
  go=old._canonical({'protocol':old.PROTOCOL,'id':req.id,'go':fields})+b'\n'
  token,retained=runtime.parse_go(go,req)
  with patch.object(live,'_make_live_exchange',side_effect=self.factory):
   result=runtime.execute(req,token,retained,started=time.monotonic(),runtime_dir='/inert')
  raw=runtime.encode_result(req,result);self.assertNotIn(b'INERT_COUNTER_TOKEN',raw);self.assertNotIn(str(self.root).encode(),raw)
  return result
 def test_real_two_sources_and_original_seven_journal_transitions_then_no_replay(self):
  reviewed=self.run_original('prepare');self.assertEqual(reviewed['reason'],'none');self.assertEqual(len(self.reader.calls),8)
  self.assertEqual(reviewed['configuration']['savedVersion'],old._fingerprint(VERSION))
  prepared=reviewed['prepared'];self.reader.calls=[]
  result=self.run_original('publish',prepared);self.assertEqual(result['publication']['effect'],'counter-observed');self.assertEqual(len(self.reader.calls),20)
  self.assertEqual(len(self.journal.files),7)  # Inert persistence, not a native durability claim.
  self.reader.calls=[];pending=self.run_original('pending')['pending'];self.assertEqual(len(pending),1);self.assertEqual(self.reader.calls,[])
  retry=self.run_original('publish',prepared);self.assertEqual(retry['reason'],'counter-intent-exists');self.assertEqual(self.reader.calls,[])
  self.assertEqual(self.run_original('reconcile')['publication']['effect'],'counter-observed')
 def test_configuration_version_changes_and_source_alias_refuse_without_http(self):
  for path,raw in ((old.CONFIG_PATH,CONFIG+b' '),('release/version.properties',VERSION+b'\n')):
   original=(self.root/path).read_bytes();(self.root/path).write_bytes(raw);self.reader.calls=[]
   self.assertEqual(self.run_original('prepare')['reason'],'source-changed');self.assertEqual(self.reader.calls,[]);(self.root/path).write_bytes(original)
  (self.root/'release/VERSION.properties').write_bytes(VERSION);self.reader.calls=[]
  self.assertEqual(self.run_original('prepare')['reason'],'configuration-changed');self.assertEqual(self.reader.calls,[])
 def test_same_source_budget_negative_finality_and_no_other_read_grants(self):
  self.assertEqual(source._counter_open_attempts(1),323)
  self.assertEqual(source._counter_open_attempts(32),2338)
  for depth in (0,33,True,1.0):
   with self.assertRaises(source.SecretConfigurationError):source._counter_open_attempts(depth)
  budget=http._Budget(time.monotonic(),_profile=http._ExchangeProfile.PUBLICATION)
  with source.observe_publication_configuration(self.capture,budget=budget,counter=True) as original:
   self.assertEqual(original.version_bytes(),VERSION);book=original._budget
   self.assertLessEqual(book.live,40);self.assertEqual(book.max_opens,388);self.assertEqual(book.counter_version,(self.root/'release/version.properties',65536))
  self.assertTrue(book.closed);self.assertEqual(book.live,0);self.assertFalse(book.handles)
  with self.assertRaises(source.SecretConfigurationError):original.version_bytes()
  ordinary=http._Budget(time.monotonic(),_profile=http._ExchangeProfile.PUBLICATION)
  with source.observe_publication_configuration(self.capture,budget=ordinary) as old_original:
   self.assertEqual(old_original._budget.max_opens,128)
   with self.assertRaises(source.SecretConfigurationError):old_original.version_bytes()
 def test_real_version_drift_during_request_keeps_original_claim_no_later_post(self):
  prepared=self.run_original('prepare')['prepared'];self.reader.calls=[]
  def drift(count,request):
   if count==10:(self.root/'release/version.properties').write_bytes(VERSION+b'\n')
  self.reader.before=drift;result=self.run_original('publish',prepared)
  self.assertEqual(result['publication']['effect'],'potentially-applied');self.assertIsNone(result['publication']['counter'])
  self.assertEqual(sum(c.method=='POST' for c in self.reader.calls),2)
 def test_ordinary_open_cap_exhaustion_is_not_bypassed_and_counter_keeps_all_checks(self):
  observed=source.observe_publication_configuration
  from contextlib import contextmanager
  @contextmanager
  def old_cap(*args,**kwargs):
   with observed(*args,**kwargs) as v:
    v._budget.max_opens=128  # Inert reproduction of the inherited one-file cap.
    yield v
  prepared=self.run_original('prepare')['prepared'];self.reader.calls=[]
  with patch.object(runtime,'observe_publication_configuration',old_cap):
   failed=self.run_original('publish',prepared)
  self.assertEqual((failed['reason'],len(self.reader.calls)),('resources-unavailable',13))
  self.assertEqual(failed['publication']['effect'],'potentially-applied')
 def test_private_unresolved_project_requires_exact_native_go_before_review(self):
  from mobile_release import version_counter_setup as counter
  row=json.loads(self.initial('prepare'));row['action']['target']['projectId']=None
  request=runtime.parse_initial(old._canonical(row)+b'\n')
  self.assertIsNone(request.target.project_id)
  good={'protocol':old.PROTOCOL,'id':request.id,'go':{'requestSha256':request.digest,
   'token':'INERT_COUNTER_TOKEN','prepared':None,'projectId':target().project_id}}
  token,go=runtime.parse_go(old._canonical(good)+b'\n',request)
  self.assertEqual(go.target,target())
  for value in (None,'0'*32,'x'*32):
   bad=json.loads(json.dumps(good));bad['go']['projectId']=value
   with self.assertRaises(ValueError):runtime.parse_go(old._canonical(bad)+b'\n',request)
  del good['go']['projectId']
  with self.assertRaises(ValueError):runtime.parse_go(old._canonical(good)+b'\n',request)
  with self.assertRaises(ValueError):counter.Target.parse(row['action']['target'])
 def test_journal_close_port_failure_never_produces_completion(self):
  request=runtime.parse_initial(self.initial('prepare'))
  close=runtime.Journal.close
  def fail(book):close(book);raise OSError('inert original close receipt lost')
  with patch.object(live,'_make_live_exchange',side_effect=self.factory),patch.object(runtime.Journal,'close',fail):
   with self.assertRaises(OSError):runtime.execute(request,'INERT_COUNTER_TOKEN',__import__('mobile_release.version_counter_setup',fromlist=['NativeGo']).NativeGo(target(),None),started=time.monotonic(),runtime_dir='/inert')
 def test_private_kind_source_home_review_and_target_remain_closed(self):
  good=json.loads(self.initial('prepare'))
  for update in ({'home':None},{'preparedSha256':'a'*64},{'source':None}):
   value=json.loads(self.initial('prepare'));value['action'].update(update)
   with self.assertRaises(ValueError):runtime.parse_initial(old._canonical(value)+b'\n')
  good['action']['target']['purpose']='unknown'
  with self.assertRaises(ValueError):runtime.parse_initial(old._canonical(good)+b'\n')
  wrong=json.loads(self.initial('pending'));wrong['action']['target']=target().value()
  with self.assertRaises(ValueError):runtime.parse_initial(old._canonical(wrong)+b'\n')
if __name__=='__main__':unittest.main()
