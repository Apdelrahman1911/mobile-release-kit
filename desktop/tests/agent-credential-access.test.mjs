// Actual existing Asset and permission controllers with inert public DATA and
// bounded promises only. No native picker/vault/credential/IPC/process is used.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { AgentUploadKeyAccessController } from '../src/agentUploadKeyAccessController.ts';
import { agentUploadKeySelection, agentUploadKeyCommands, agentUploadKeyConsent, parseAgentUploadKeySelection,
  parseAgentUploadKeyAccess, createAgentUploadKeyAccessPort } from '../src/agentUploadKeyAccess.ts';
import { parseAgentCredentialPrepared, agentCredentialOptions } from '../src/agentCredentialAccess.ts';
import { parseAgentUploadKeyPrepared } from '../src/agentUploadKeyReuse.ts';
const id=c=>c.repeat(32), record={recordId:id('c'),expectedRevision:1};
const scope={platform:'ios',stage:'candidate',purpose:'signing',executionMode:'local'};
const context={revision:1,projectId:'inert-credential-project',...scope}, cap={available:true,reason:'none'};
const row=(patch={})=>({recordId:id('c'),revision:1,kind:'apple-p12',storage:'encrypted',availability:'unassigned',label:null,payloadState:'not-checked',...patch});
const status=(n=1,patch={})=>({schemaVersion:3,statusRevision:n,mode:'encrypted',persistence:{state:'unlocked',reason:'none',keyAccess:'read-write'},
  capability:{...cap},modes:{session:{...cap},encrypted:{...cap}},context:{...context},records:[row()],assignments:[],operation:null,...patch});
const assessment=()=>({schemaVersion:1,policyVersion:'credential-policy-v1',kind:'apple-p12',context:{...scope},
  applicability:{state:'required',reason:'selected'},state:'configured',identity:'not-applicable',fields:[
    {id:'file',requirement:'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64',presence:'supplied',state:'configured',issues:[],checks:[{scope:'pfx-envelope',outcome:'asserted-pass'}]},
    {id:'password',requirement:'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD',presence:'supplied',state:'configured',issues:[],checks:[{scope:'value-admission',outcome:'passed'}]}],
  assurance:{basis:'supplied-input-only',scalarValuesProcessed:true,fileObservationsProcessed:true,selectedFilesRead:false,keyringAccessed:false,
    storageWritesPerformed:false,projectCodeExecuted:false,sourceCustody:'not-established',nativeValidation:'not-run',serviceValidation:'not-run',releaseReadiness:'unknown'}});
const operation=(patch={})=>({operationId:7,operation:'prepare',phase:'preview',reason:'none',source:'captured',settlement:'known',storageOutcome:null,
  selectionToken:null,assessment:assessment(),preview:{token:id('a'),action:'bind',expiresInMs:10000,
    subject:{type:'record',kind:'apple-p12',change:'assign',recordId:id('c'),recordRevision:1}},...patch});
const preview=(n=2,patch={})=>status(n,{records:[row({payloadState:'assessed'})],operation:operation(),...patch});
const savePreview=()=>status(3,{records:[],operation:operation({operationId:3,preview:{token:id('a'),action:'save',expiresInMs:10000,
  subject:{type:'record',kind:'apple-p12',change:'new',recordId:null,recordRevision:null}}})});
const stamp=(patch={})=>({credentialKind:'apple-p12',assetOperationId:7,statusRevision:2,contextRevision:1,recordId:id('c'),expectedRevision:1,
  previewToken:id('a'),remainingMs:10000,...patch});
const access=(kind='credential-assess-existing',patch={})=>({schemaVersion:1,serviceInstance:id('b'),projectId:id('a'),grantId:id('d'),kind,
  requestId:null,enabled:true,remainingMs:299000,consumed:false,...patch});
const completed=(patch={})=>access('credential-assess-existing',{requestId:id('e'),enabled:false,remainingMs:0,consumed:true,prepared:stamp(),...patch});
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};}
async function flush(){for(let i=0;i<24;i++)await Promise.resolve();}
async function fixture(t,existing=true){
  let project={project:{id:context.projectId,name:'Inert'},draft:{schemaVersion:1},revision:1,baselineGeneration:1};
  let current=status(0,{records:existing?[row()]:[]}),event,now=100,holdReads=false,nonce='d';
  const assetCalls=[],permissionCalls=[],source={peer:null,port:null};
  const call=(list,command,input)=>{const d=deferred();list.push({command,input,...d});return d.promise;};
  const api={mode:'native',assetStatus:()=>holdReads?call(assetCalls,'read'):Promise.resolve(current),subscribeAssets:async fn=>{event=fn;return()=>{};},
    setAssetContext:x=>call(assetCalls,'context',x),chooseAsset:x=>call(assetCalls,'choose',x),prepareCredential:x=>call(assetCalls,'prepare',x),
    commitAsset:x=>call(assetCalls,'commit',x),bindAsset:x=>call(assetCalls,'bind',x),discardAsset:x=>call(assetCalls,'discard',x)};
  const assets=new AssetSessionController(()=>project,()=>now,()=>source.peer);assets.setScope(scope);await assets.connect(api);assets.submitContext();await flush();
  current=status(1,{records:existing?[row()]:[]});assetCalls.at(-1).resolve(current);await flush();assert.equal(assets.getSnapshot().contextCurrent,true);
  assert.ok(parseAssetStatus(preview()));assert.ok(parseAssetStatus(savePreview()));
  holdReads=true;
  const port={status:()=>call(permissionCalls,'status'),allow:x=>call(permissionCalls,'allow',x),revoke:x=>call(permissionCalls,'revoke',x)};
  source.port=port;const session={};
  const controller=new AgentUploadKeyAccessController({current:()=>({port:source.port,nativeSession:session,projectId:context.projectId,project,
    assets:assets.getSnapshot(),generateReady:false,blockedReason:source.peer}),now:()=>now,nonce:()=>id(nonce),
    prepareExisting:r=>assets.prepareExistingForCli(r),prepareCredential:(r,k)=>assets.prepareCredentialForCli(r,k)});
  const off=assets.subscribe(()=>controller.syncContext());
  t.after(async()=>{controller.dispose();assets.dispose();off();for(const c of [...assetCalls,...permissionCalls])c.reject({code:'inert_closed'});await controller.whenSettled();});
  return{assets,controller,assetCalls,permissionCalls,source,port,last:()=>permissionCalls.at(-1),read:()=>assetCalls.filter(c=>c.command==='read').at(-1),
    emit:v=>{current=v;event(v);},reply:(command,v)=>{current=v;assetCalls.filter(c=>c.command===command).at(-1).resolve(v);},
    nonce:v=>{nonce=v;},time:v=>{now=v;},changeProject:()=>{project={...project,revision:project.revision+1};assets.syncProject();}};
}
function choose(h){assert.equal(h.controller.setKind('credential-assess-existing'),true);assert.equal(h.controller.setAcknowledged(true),false);
  assert.equal(h.controller.setPrepareRecord(record),true);assert.equal(h.controller.setAcknowledged(true),true);assert.equal(h.controller.allowReason(),null);}
async function allowed(h){choose(h);const a=h.controller.allow();h.last().resolve(access());await a;}
function noMutation(h){assert.ok(h.assetCalls.every(c=>!['commit','bind','discard'].includes(c.command)));}
async function correlate(h){const check=h.controller.check();h.last().resolve(completed());await flush();assert.ok(h.read());
  assert.equal(h.assets.getSnapshot().reviewReady,false);h.read().resolve(preview());await check;assert.equal(h.assets.getSnapshot().reviewReady,true);}

test('general actions and optional kind stamp remain closed, bounded, distinct from old Android',async()=>{
  const foreignScope=preview();delete foreignScope.operation.assessment.context.executionMode;
  assert.equal(parseAssetStatus(foreignScope),null,'omitted assessment mode is not local scope');
  const calls=[],port=createAgentUploadKeyAccessPort(async(command,body)=>{calls.push({command,body:JSON.parse(new TextDecoder().decode(body)),bytes:body.length});return access();});
  for(const credentialKind of ['android-keystore','android-firebase','apple-p12','apple-profile','asc-p8','ios-firebase','google-service-account',
    'project-read-token','apple-review-contact','apple-review-demo','operation-commitment']){
    for(const kind of ['credential-import-prepared','credential-assess-existing','credential-assign-reviewed']){
      const selection=kind==='credential-assess-existing'?{kind,credentialKind,...record}:{kind,credentialKind,previewOperationId:3,previewToken:id('a')};
      if(credentialKind==='android-keystore'&&kind!=='credential-import-prepared'){assert.equal(parseAgentUploadKeySelection(selection),null);continue;}
      assert.deepEqual(parseAgentUploadKeySelection(selection),selection);
      await port.allow({projectId:context.projectId,consentId:id('d'),contextRevision:1,expectedStatusRevision:2,selection});
      assert.equal(calls.at(-1).body.consentVersion,agentUploadKeyConsent(kind));
      for(const field of ['password','path','fields','label','replace','autoAssign'])assert.equal(parseAgentUploadKeySelection({...selection,[field]:'not-forwarded'}),null);
    }
  }
  assert.ok(calls.every(c=>c.command==='allow_agent_upload_key'&&c.bytes+96<=1024));
  for(const credentialKind of ['google-wif','apple-distribution-key','other'])assert.equal(parseAgentUploadKeySelection({kind:'credential-import-prepared',credentialKind,previewOperationId:3,previewToken:id('a')}),null);
  assert.deepEqual(parseAgentCredentialPrepared(stamp()),stamp());assert.equal(parseAgentUploadKeyPrepared(stamp()),null);
  const ordinary=stamp();delete ordinary.credentialKind;assert.ok(parseAgentUploadKeyPrepared(ordinary));assert.equal(parseAgentCredentialPrepared(ordinary),null);
  assert.equal(parseAgentUploadKeyAccess(completed({kind:'prepare-existing'})),null);
  assert.equal(parseAgentUploadKeyAccess(completed({prepared:ordinary})),null);
  for(const credentialKind of [null,'android-keystore','apple-distribution-key'])assert.equal(parseAgentCredentialPrepared(stamp({credentialKind})),null);
  let read=false;const malicious=stamp();Object.defineProperty(malicious,'credentialKind',{enumerable:true,get(){read=true;return'apple-p12';}});
  assert.equal(parseAgentCredentialPrepared(malicious),null);assert.equal(read,false);
});

test('actual Desktop Choose and Prepare must return before NEW import delegation; permission sends no private value',async t=>{
  const h=await fixture(t,false);h.controller.setKind('credential-import-prepared');assert.equal(h.controller.setAcknowledged(true),false);
  assert.equal(h.assets.choose('apple-p12'),true);h.reply('choose',status(2,{records:[],operation:operation({operationId:2,operation:'choose-file',phase:'selected',assessment:null,preview:null,selectionToken:id('b')})}));await flush();
  assert.equal(h.assets.prepareSelection({password:'inert-not-a-credential'},'Inert label'),true);
  assert.ok(parseAssetStatus(savePreview()));h.emit(savePreview());assert.equal(h.controller.setAcknowledged(true),false,'event is not original return');
  h.reply('prepare',savePreview());await flush();assert.equal(h.assets.getSnapshot().reviewReady,true);
  assert.equal(h.controller.setAcknowledged(true),true);const allow=h.controller.allow();
  assert.deepEqual(h.last().input.selection,{kind:'credential-import-prepared',credentialKind:'apple-p12',previewOperationId:3,previewToken:id('a')});
  assert.ok(!JSON.stringify(h.last().input).includes('inert-not-a-credential'));h.last().resolve(access('credential-import-prepared'));await allow;
  assert.equal(await h.controller.allow(),false);noMutation(h);
  h.emit(status(4,{operation:operation({operationId:4,operation:'commit',phase:'idle',preview:null,assessment:null,
    storageOutcome:{effect:'known-applied',durability:'confirmed',cleanup:'known'}})}));
  assert.equal(h.assets.getSnapshot().reviewReady,false);assert.equal(agentUploadKeySelection(h.assets.getSnapshot(),'credential-assign-reviewed',false,100),null);
  const check=h.controller.check();h.last().resolve(access('credential-import-prepared',{requestId:id('e'),enabled:false,remainingMs:0,consumed:true}));await check;
  assert.equal(h.controller.setKind('credential-assess-existing'),false,'consumed permission is not withdrawn');
  const revoke=h.controller.revoke();h.last().resolve(access('credential-import-prepared',{requestId:id('e'),enabled:false,remainingMs:0,consumed:true}));await revoke;
  assert.equal(h.controller.setKind('credential-assess-existing'),true);assert.equal(h.controller.setPrepareRecord(record),true);assert.equal(h.controller.getSnapshot().acknowledged,false);
  noMutation(h);assert.equal(h.assetCalls.filter(c=>c.command==='prepare').length,1,'no chained reassessment');
});

test('same permission controller: fresh authenticated-read stamp needs a separate actual status return then Revoke before Assign',async t=>{
  const h=await fixture(t);await allowed(h);assert.equal(h.assetCalls.filter(c=>c.command==='prepare').length,0);
  h.emit(preview());assert.equal(h.assets.getSnapshot().reviewReady,false);await correlate(h);
  assert.equal(h.controller.setKind('credential-assign-reviewed'),false);
  const revoke=h.controller.revoke();h.last().resolve(completed());await revoke;
  assert.equal(h.assets.getSnapshot().reviewReady,true,'withdrawing completed permission does not discard its original ordinary review');
  h.nonce('f');assert.equal(h.controller.setKind('credential-assign-reviewed'),true);assert.equal(h.controller.getSnapshot().acknowledged,false);
  assert.equal(h.controller.setAcknowledged(true),true);const assign=h.controller.allow();
  assert.deepEqual(h.last().input.selection,{kind:'credential-assign-reviewed',credentialKind:'apple-p12',previewOperationId:7,previewToken:id('a')});
  h.last().resolve(access('credential-assign-reviewed',{grantId:id('f')}));await assign;
  assert.match(agentUploadKeyCommands(h.controller.getSnapshot().access)[0],/mrk credential-submit/);noMutation(h);
});

test('coalesced pre-stamp read is joined then replaced by one fresh read, never an origin receipt',async t=>{
  const h=await fixture(t);await allowed(h);const prior=h.assets.checkStatus();await flush();const first=h.read();
  const check=h.controller.check();h.last().resolve(completed());await flush();assert.equal(h.assetCalls.filter(c=>c.command==='read').length,1);
  first.resolve(preview());await prior;await flush();assert.notEqual(h.read(),first);assert.equal(h.assets.getSnapshot().reviewReady,false);
  h.read().resolve(preview());await check;assert.equal(h.assets.getSnapshot().reviewReady,true);noMutation(h);
});

test('lost Allow, wrong-kind stamp and unsolicited Check never manufacture a usable general review',async t=>{
  for(const failure of ['lost','wrong-kind','unsolicited']){
    const h=await fixture(t);
    if(failure==='lost'){choose(h);const p=h.controller.allow();h.last().reject({code:'inert_lost'});await p;}else if(failure!=='unsolicited')await allowed(h);
    h.emit(preview());const check=h.controller.check();h.last().resolve(completed({prepared:stamp(failure==='wrong-kind'?{credentialKind:'asc-p8'}:{})}));await check;
    assert.equal(h.assets.getSnapshot().reviewReady,false);assert.equal(h.assetCalls.filter(c=>c.command==='read').length,0);
    if(failure==='lost')assert.equal(h.controller.getSnapshot().unknown,true);noMutation(h);
  }
});

test('general Allow rematches original API/project/peer and scope ABA after listeners',async t=>{
  for(const change of ['project','api','peer','scope']){
    const h=await fixture(t);choose(h);let fired=false;
    const off=h.controller.subscribe(()=>{if(!fired&&h.controller.getSnapshot().pending==='allow'){fired=true;
      if(change==='project')h.changeProject();if(change==='api')h.source.port={...h.port};if(change==='peer')h.source.peer='other original';
      if(change==='scope'){h.assets.setScope({...scope,purpose:'full'});h.assets.setScope(scope);}}});
    assert.equal(await h.controller.allow(),false);off();assert.equal(h.permissionCalls.length,0);noMutation(h);
  }
});

test('general fresh-read listener and original expiry cannot renew or publish an Assign review',async t=>{
  for(const failure of ['peer','expiry']){
    const h=await fixture(t);await allowed(h);h.emit(preview());let fired=false;
    const off=h.assets.subscribe(()=>{if(!fired&&h.assets.getSnapshot().observing){fired=true;if(failure==='peer')h.source.peer='other';else h.time(300101);}});
    const check=h.controller.check();h.last().resolve(completed());await check;off();
    assert.equal(h.assets.getSnapshot().reviewReady,false);assert.equal(h.assetCalls.filter(c=>c.command==='read').length,0);noMutation(h);
  }
});

test('selection refuses session-only, pending, unassessed and replacement inputs without changing old Android route',async t=>{
  const h=await fixture(t);assert.equal(agentCredentialOptions(h.assets.getSnapshot()).length,1);await allowed(h);await correlate(h);
  const a=h.assets.getSnapshot();assert.ok(agentUploadKeySelection(a,'credential-assign-reviewed',false,100));
  for(const value of [{...a,reviewReady:false},{...a,originPending:true},{...a,busy:'prepare'},{...a,contextCurrent:false},
    {...a,status:{...a.status,mode:'session'}},{...a,status:{...a.status,records:[row()]}},
    {...a,status:{...a.status,records:[row({kind:'android-keystore',payloadState:'assessed'})]}}])assert.equal(agentUploadKeySelection(value,'credential-assign-reviewed',false,100),null);
  assert.equal(agentUploadKeySelection(a,'bind-reviewed',false,100),null);
  const importView={...a,status:savePreview(),intent:{type:'record',kind:'apple-p12',change:'new',record:null}};
  assert.ok(agentUploadKeySelection(importView,'credential-import-prepared',false,100));
  for(const change of ['replace','assign','delete'])assert.equal(agentUploadKeySelection({...importView,intent:{...importView.intent,change,record}},'credential-import-prepared',false,100),null);
  noMutation(h);
});
