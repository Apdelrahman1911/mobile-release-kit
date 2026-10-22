// Fixed public DATA and controlled original promises only. No bridge, provider,
// vault, token or native operation is entered by this suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { GitHubRemoteSetupController, githubRemoteSetupOwnerReason } from '../src/GitHubRemoteSetupController.ts';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { parseGithubActionSelection, parseGithubActionStatus, parseAgentGithubActionAccess, createAgentGithubActionPort } from '../src/agentGithubActionAccess.ts';
import { parseGithubRemoteSettingsSelection, parseGithubRemoteSettingsReference, parseGithubRemoteSettingsResult, githubRemoteSettingsPreparedHash, githubRemoteSettingsResultMatches, githubRemoteSettingsReferenceMatches } from '../src/githubRemoteSetupDelegation.ts';
import { parseGitHubRemoteSetupStatus, githubRemoteSetupConfirmation, GITHUB_REMOTE_SETUP_ENVIRONMENTS, GITHUB_REMOTE_SETUP_VARIABLE_FIELDS, GITHUB_REMOTE_SETUP_ENVIRONMENT_CONFIRMATION, GITHUB_REMOTE_SETUP_VARIABLE_CONFIRMATION } from '../src/GitHubRemoteSetupProtocol.ts';

const copy=structuredClone,hex=(c,n=32)=>c.repeat(n),time='2026-10-09T12:00:00Z',expiry='2026-10-09T12:02:00Z';
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const actions=()=>({kind:'actions_enabled',enabled:true});
const policy=()=>({kind:'workflow_token_policy',defaultWorkflowPermissions:'write',canApprovePullRequestReviews:true});
const environment=(mode='configure')=>({kind:'environment_protection',mode,stage:'candidate',waitTimerMinutes:17,preventSelfReview:mode==='create'?true:null,reviewerLogin:mode==='create'?'Example-User':null,branches:mode==='create'?'protected':null});
const variable=(requirement='MOBILE_RELEASE_ANDROID_KEY_ALIAS',mode='create')=>({kind:'environment_variable',mode,stage:'candidate',requirement,source:{recordId:hex('c'),recordRevision:4,contextRevision:5}});
const values={MOBILE_RELEASE_ANDROID_KEY_ALIAS:'release.key-1',MOBILE_RELEASE_GOOGLE_WIF_PROVIDER:'projects/123/locations/global/workloadIdentityPools/release/providers/github',MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT:'release-bot@example-project.iam.gserviceaccount.com',MOBILE_RELEASE_ASC_KEY_ID:'A1B2C3D4E5',MOBILE_RELEASE_ASC_ISSUER_ID:'12345678-1234-5678-abcd-123456789abc',MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION:'fixture-v1'};
function value(text){return {text,bytes:Buffer.byteLength(text),sha256:createHash('sha256').update(text).digest('hex')};}
function idle(revision=1){return {schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,observed:null};}
function operation(kind,revision=3){return {...idle(revision),operation:{id:`github-setup-${kind==='prepare'?1:2}`,kind,phase:'settled',reason:'none',effect:kind==='prepare'?'not-started':'readback-confirmed',writeClaimed:kind!=='prepare',writeAcknowledged:kind!=='prepare'}};}
function review(selection=actions()){
  const target={projectBinding:hex('b',64),repository:'owner/app',accountId:'11',repositoryId:'22',selection};let prepared;
  if(selection.kind==='environment_variable'){
    const old=value('previous-public-identifier'),before={environmentName:GITHUB_REMOTE_SETUP_ENVIRONMENTS[selection.stage],environmentId:'33',name:selection.requirement,value:selection.mode==='create'?null:{bytes:old.bytes,sha256:old.sha256},metadata:selection.mode==='create'?null:{createdAt:time,updatedAt:time}};
    prepared={target,before,after:{name:selection.requirement,value:value(values[selection.requirement])},configuration:{savedConfig:{bytes:524288,sha256:hex('d',64)},canonicalConfig:{bytes:4000,sha256:hex('e',64)}},observedAt:time,confirmation:GITHUB_REMOTE_SETUP_VARIABLE_CONFIRMATION};
  }else if(selection.kind==='environment_protection'){
    const old={waitTimerMinutes:0,protectedBranches:true,requiredReviewers:{preventSelfReview:false,reviewers:[{type:'Team',id:'9223372036854775805'},{type:'User',id:'9223372036854775807'}]}},create=selection.mode==='create';
    const before={name:GITHUB_REMOTE_SETUP_ENVIRONMENTS[selection.stage],id:create?null:'33',policy:create?null:old},reviewer=create?{id:'44',login:'example-user',permission:'read'}:null;
    const after=create?{waitTimerMinutes:17,protectedBranches:true,requiredReviewers:{preventSelfReview:true,reviewers:[{type:'User',id:reviewer.id}]}}:{...old,waitTimerMinutes:17};
    prepared={target,before,after,reviewer,observedAt:time,confirmation:GITHUB_REMOTE_SETUP_ENVIRONMENT_CONFIRMATION};
  }else{
    const before=selection.kind==='actions_enabled'?{enabled:false,allowed_actions:'selected',sha_pinning_required:true}:{default_workflow_permissions:'read',can_approve_pull_request_reviews:false};
    const after=selection.kind==='actions_enabled'?{...before,enabled:true}:{default_workflow_permissions:selection.defaultWorkflowPermissions,can_approve_pull_request_reviews:selection.canApprovePullRequestReviews};
    prepared={target,before,after,observedAt:time,confirmation:githubRemoteSetupConfirmation(selection.kind,'owner/app')};
  }
  const result={...operation('prepare'),observed:copy(prepared.before),consent:{id:hex('a'),expiresAt:expiry,prepared}};
  assert.ok(parseGitHubRemoteSetupStatus(result),'fixture must pass original native Status parser');return result;
}
function applied(r){const p=r.consent.prepared;let observed=copy(p.after);
  if(p.target.selection.kind==='environment_variable')observed={...p.before,value:{bytes:p.after.value.bytes,sha256:p.after.value.sha256},metadata:{createdAt:time,updatedAt:time}};
  else if(p.target.selection.kind==='environment_protection')observed={name:p.before.name,id:p.before.id??'55',policy:copy(p.after)};
  const result={...operation('apply',5),observed};assert.ok(parseGitHubRemoteSetupStatus(result));return result;
}
function selection(kind='remote-setup-prepare',r=null,setting=actions()){
  return kind==='remote-setup-prepare'?{kind,sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,selection:setting}:{kind,sessionId:'session-a',expectedRevision:r.revision,consentId:r.consent.id,confirm:true};
}
function reference(s,r=null){return s.kind==='remote-setup-prepare'?{kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision,requestSha256:hash(s)}:
  {kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision,consentId:s.consentId,preparedSha256:githubRemoteSettingsPreparedHash(r.consent.prepared)};}
function compact(s,setting=actions()) {return {type:'remote-settings',setting:setting.kind,reason:s.operation.reason,writeClaimed:s.operation.writeClaimed,writeAcknowledged:s.operation.writeAcknowledged,consentId:s.consent?.id??null,preparedSha256:s.consent?githubRemoteSettingsPreparedHash(s.consent.prepared):null,observationSha256:s.observed===null?null:hash(s.observed)};}
function final(s,n,r=null){return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex(s.kind==='remote-setup-prepare'?'4':'6')},grantId:hex(s.kind==='remote-setup-prepare'?'3':'5'),review:reference(s,r),revision:7,state:'complete',settlement:'settled',operationId:n.operation.id,reason:'none',effect:s.kind==='remote-setup-prepare'?'none':'settings-readback-observed',neverAdmitted:false,doNotReplay:true,result:compact(n,s.kind==='remote-setup-prepare'?s.selection:r.consent.prepared.target.selection)};}
function access(s,r=null,status=null,patch={}) {return {permissionRevision:s.kind==='remote-setup-prepare'?'1':'3',serviceInstance:hex('2'),projectId:hex('1'),grantId:hex(s.kind==='remote-setup-prepare'?'3':'5'),review:reference(s,r),enabled:status===null,remainingMs:status===null?100000:0,consumed:status!==null,pending:status!==null&&status.settlement!=='settled',unknown:status?.state==='unknown',status,...patch};}
const empty=(revision='0')=>({permissionRevision:revision,serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null});
function assets(s){const f=GITHUB_REMOTE_SETUP_VARIABLE_FIELDS[s.requirement];return {mode:'native',contextCurrent:true,busy:null,updatingContext:false,observing:false,observationFailed:false,blocked:false,error:null,originPending:false,status:{schemaVersion:3,statusRevision:12,mode:'session',persistence:null,capability:{available:true,reason:'none'},operation:null,context:{revision:s.source.contextRevision,projectId:'project',platform:f.platform,stage:s.stage,purpose:'full'},records:[{recordId:s.source.recordId,revision:s.source.recordRevision,kind:f.kind,availability:'assigned',storage:'session',label:null,payloadState:'assessed'}],assignments:[{recordId:s.source.recordId,recordRevision:s.source.recordRevision,contextRevision:s.source.contextRevision,kind:f.kind,availability:'available'}]}};}
function connection(){return {mode:'native',context:{documentId:'doc',projectId:'project',projectGeneration:1,repository:'owner/app'},status:{revision:12,session:{id:'session-a',projectId:'project',targetRepository:'owner/app',state:'connected'},account:{state:'observed',value:{id:'11'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app'}}},busy:null,uncertain:false,blocked:false,retirementPending:false};}
function deferred(){let yes,no;const d={ended:false,promise:new Promise((y,n)=>{yes=y;no=n})};d.resolve=v=>{d.ended=true;yes(v)};d.reject=e=>{d.ended=true;no(e)};return d;}
async function flush(){for(let i=0;i<24;i++)await Promise.resolve();}
const retained=[];
async function fixture(setting=actions()){
  let current=idle(),view=connection(),listener=null,material=setting.kind==='environment_variable'?assets(setting):null,peer=null;const calls=[];
  const h={deferStatus:false,calls,setting};const call=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const api={mode:'native',subscribeGitHubRemoteSetup:async f=>{listener=f;return()=>{listener=null}},githubRemoteSetupStatus:()=>h.deferStatus?call('status',{}):Promise.resolve(copy(current)),githubRemoteSetupPrepare:a=>call('prepare',a),githubRemoteSetupApply:a=>call('apply',a),githubRemoteSetupDiscard:a=>call('discard',a),githubRemoteSetupCancel:a=>call('cancel',a)};
  const controller=new GitHubRemoteSetupController(()=>view,()=>peer,()=>material);
  Object.assign(h,{api,controller,call,count:k=>calls.filter(x=>x.kind===k).length,last:k=>calls.filter(x=>x.kind===k).at(-1),emit(s){current=copy(s);listener?.(copy(s))},retain(s){current=copy(s)},reply(k,s){current=copy(s);h.last(k).resolve(copy(s))},move(){view={...view,context:{...view.context,projectGeneration:view.context.projectGeneration+1}};controller.syncContext()},asset(v){material=copy(v);controller.syncAssetSession()},peer(v){peer=v}});
  retained.push(h);await controller.connect(api);controller.setSelection(setting);return h;
}
async function permission(h){
  let epoch={},peer=null,c;const port={};for(const name of ['access','allow','request','revoke'])port[name]=(arg,revision)=>h.call('permission-'+name,{arg:arg??null,revision:revision??null});
  c=new AgentGithubActionAccessController({current:()=>({port,nativeSession:h,projectId:'project',epoch,preview:false,blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:githubRemoteSetupOwnerReason(h.controller.getSnapshot())),reviews:['remote-setup-prepare','remote-setup-apply'].map(k=>h.controller.agentSelection(k)).filter(Boolean)}),syncOriginal:()=>{h.controller.syncContext();h.controller.syncAssetSession()},delegate:s=>h.controller.delegatePrepared(s)});
  const p={controller:c,last:k=>h.last('permission-'+k),count:k=>h.count('permission-'+k),peer(v){peer=v;c.syncContext()},move(){epoch={};c.syncContext()}};h.permission=p;c.choose('remote-setup-prepare');
  const work=c.check();p.last('access').resolve(empty());await work;return p;
}
async function allow(h,p,s,r=null){p.controller.syncContext();assert.equal(p.controller.consentReason(),null);assert.equal(p.controller.acknowledge(true),true);const w=p.controller.allow();assert.ok(p.last('allow'));p.last('allow').resolve(access(s,r));assert.equal(await w,true);assert.equal(p.controller.getSnapshot().unknown,false);}
async function serviceFinal(p,status,s,r=null){const w=p.controller.check();p.last('access').resolve(access(s,r,status));await flush();p.last('request').resolve(status);await w;}
test.afterEach(async()=>{for(const h of retained.splice(0)){for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();h.permission?.controller.dispose();h.controller.dispose();for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();assert.ok(h.calls.every(c=>c.ended));}});

test('four non-secret groups and six assigned public fields use exact original command grammar/order',()=>{
  for(const setting of [actions(),policy(),environment(),environment('create'),...Object.keys(values).map(k=>variable(k))]){
    const s=selection('remote-setup-prepare',null,setting),r=review(setting),parsed=parseGithubRemoteSettingsSelection(s);assert.ok(parsed);assert.ok(parseGithubActionSelection(s));
    assert.equal(hash(parsed),hash(s));assert.ok(githubRemoteSettingsReferenceMatches(reference(s),parsed));
    assert.equal(githubRemoteSettingsPreparedHash(r.consent.prepared),hash(r.consent.prepared));
    const result=compact(r,setting);assert.ok(parseGithubRemoteSettingsResult(result,s.kind));assert.ok(githubRemoteSettingsResultMatches(result,r,setting));
    const a=selection('remote-setup-apply',r);assert.ok(parseGithubRemoteSettingsSelection(a));assert.ok(parseGithubRemoteSettingsReference(reference(a,r)));
  }
  for(const bad of [{...selection(),selection:{kind:'environment_secret',mode:'create',stage:'candidate',requirement:'MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64',source:variable().source}}, {...selection(),selection:{...variable(),value:'arbitrary'}}, {...selection(),selection:{...variable(),source:['c'.repeat(32),4,5]}}, {...selection(),purpose:null}, {...selection(),token:'not-accepted'}])assert.equal(parseGithubRemoteSettingsSelection(bad),null);
  assert.ok(parseGithubRemoteSettingsSelection({...selection(),selection:{kind:'actions_enabled',enabled:false}})); // the original enabled boolean supports both values
  let reads=0;const getter=selection();Object.defineProperty(getter,'selection',{enumerable:true,get(){reads++;return actions()}});assert.equal(parseGithubRemoteSettingsSelection(getter),null);assert.equal(reads,0);
});
test('complete Prepared comparison keeps untouched policies/rosters/configuration and real public value bytes',()=>{
  for(const s of [actions(),environment(),variable()]){const r=review(s),p=r.consent.prepared,before=githubRemoteSettingsPreparedHash(p);
    const reversed=Object.fromEntries(Object.entries(p).reverse());assert.equal(githubRemoteSettingsPreparedHash(reversed),before);
    const changed=copy(p);if(s.kind==='actions_enabled'){changed.before.allowed_actions='all';changed.after.allowed_actions='all'}else if(s.kind==='environment_protection'){changed.before.policy.requiredReviewers.reviewers[0].id='44';changed.after.requiredReviewers.reviewers[0].id='44'}else changed.after.value=value('different-valid-alias');
    assert.notEqual(githubRemoteSettingsPreparedHash(changed),before);
    const invalid=copy(p);invalid.target.selection.kind='environment_secret';assert.throws(()=>githubRemoteSettingsPreparedHash(invalid));
  }
});
test('compact DATA distinguishes NoChange, acknowledged204, readback, wrong origins and unknown',()=>{
  const s=selection(),r=review(),f=final(s,r);assert.ok(parseGithubActionStatus(f));assert.ok(parseAgentGithubActionAccess(access(s,null,f)));
  const noChange={...operation('prepare'),consent:null,observed:copy(r.consent.prepared.after)};noChange.operation.reason='no-change';const noFinal=final(s,noChange);assert.ok(parseGithubActionStatus(noFinal));assert.equal(noFinal.result.consentId,null);
  const expired=copy(r);expired.consent=null;expired.operation.reason='consent-expired';const expiredFinal={...final(s,expired),state:'refused',reason:'expired'};assert.ok(parseGitHubRemoteSetupStatus(expired));assert.ok(parseGithubActionStatus(expiredFinal));assert.ok(githubRemoteSettingsResultMatches(expiredFinal.result,expired,actions()));
  const a=selection('remote-setup-apply',r),done=applied(r),af=final(a,done,r);assert.ok(parseGithubActionStatus(af));
  const acknowledged=copy(done);acknowledged.operation.reason='response-invalid';acknowledged.operation.effect='unknown';acknowledged.observed=null;
  const uncertain={...final(a,acknowledged,r),state:'refused',reason:'native-refused',effect:'potentially-applied'};assert.ok(parseGithubActionStatus(uncertain));
  for(const mutate of [v=>v.effect='settings-readback-observed',v=>v.result.observationSha256=hex('d',64),v=>v.result.reason='none',v=>delete v.result.writeClaimed,v=>v.result.setting='environment_secret']){const bad=copy(uncertain);mutate(bad);assert.equal(parseGithubActionStatus(bad),null);}
  assert.equal(parseGithubActionStatus({...f,effect:'settings-readback-observed'}),null);assert.equal(parseGithubActionStatus({...af,operationId:'github-preflight-2'}),null);
  const unknown={...af,state:'unknown',settlement:'unknown',reason:'cleanup-unknown'};assert.equal(parseGithubActionStatus(unknown),null);delete unknown.result;unknown.effect='potentially-applied';assert.ok(parseGithubActionStatus(unknown));
});
test('existing RAW port uses two exact non-secret consents without changing ordinary four methods',async()=>{
  const calls=[],port=createAgentGithubActionPort(async(name,body)=>{calls.push([name,JSON.parse(new TextDecoder().decode(body))]);return null});
  await port.allow(selection(),'0');await port.allow(selection('remote-setup-apply',review()),'2');
  assert.equal(calls.length,2);assert.equal(calls[0][0],'allow_agent_github_action');assert.equal(calls[0][1].consentVersion,'agent-remote-setup-prepare-once-v1');assert.equal(calls[1][1].consentVersion,'agent-remote-setup-apply-once-v1');
  assert.throws(()=>port.allow({...selection(),selection:{...variable(),kind:'environment_secret'}},'0'));
});
test('actual controller+single permission instance require joined native read, explicit withdraw and separate confirmed Apply',async()=>{
  const h=await fixture(),p=await permission(h),s=h.controller.agentSelection('remote-setup-prepare'),r=review();await allow(h,p,s);
  h.controller.prepare();h.controller.apply();assert.equal(h.count('prepare')+h.count('apply'),0);
  h.emit(r);assert.equal(h.controller.currentConsent(),null);assert.equal(h.count('discard'),0);
  await serviceFinal(p,final(s,r),s);assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.getSnapshot().pending,true);
  h.deferStatus=true;const read=h.controller.checkStatus();await flush();assert.equal(h.controller.currentConsent(),null);h.reply('status',r);await read;
  assert.ok(h.controller.currentConsent());assert.equal(h.controller.getSnapshot().pending,false);assert.equal(p.controller.choose('remote-setup-apply'),false);
  const withdraw=p.controller.revoke();p.last('revoke').resolve(access(s,null,final(s,r),{permissionRevision:'2',enabled:false}));await withdraw;
  const checked=p.controller.check();p.last('access').resolve(empty('2'));await checked;
  assert.ok(h.controller.currentConsent());assert.equal(h.controller.agentSelection('remote-setup-apply'),null);h.controller.setConfirmed(true);assert.equal(p.controller.choose('remote-setup-apply'),true);
  const a=h.controller.agentSelection('remote-setup-apply');await allow(h,p,a,r);const done=applied(r);h.emit(done);await serviceFinal(p,final(a,done,r),a,r);
  const last=h.controller.checkStatus();await flush();h.reply('status',done);await last;assert.equal(h.controller.getSnapshot().pending,false);assert.equal(h.controller.currentConsent(),null);
  assert.equal(h.count('prepare')+h.count('apply')+h.count('discard'),0);assert.equal(p.count('allow'),2);
});
test('returned native read taken before service final is not retroactive readiness',async()=>{
  const h=await fixture(),s=h.controller.agentSelection('remote-setup-prepare'),d=h.controller.delegatePrepared(s),r=review();assert.ok(d.current());d.allowReturned();h.retain(r);await h.controller.checkStatus();assert.equal(d.released(),false);
  d.observe(final(s,r));assert.equal(h.controller.currentConsent(),null);await h.controller.checkStatus();assert.equal(d.released(),true);assert.ok(h.controller.currentConsent());
});
test('ordinary terminal event cannot release the actual Prepare caller or enable delegation',async()=>{
  const h=await fixture(),r=review();h.controller.prepare();h.emit(r);assert.equal(h.controller.getSnapshot().pending,true);assert.equal(h.controller.agentSelection('remote-setup-apply'),null);
  h.reply('prepare',r);await flush();assert.equal(h.controller.getSnapshot().pending,false);h.controller.setConfirmed(true);assert.ok(h.controller.agentSelection('remote-setup-apply'));
});
test('NoChange never produces an Apply consent or automatic follow-on',async()=>{
  const h=await fixture(),s=h.controller.agentSelection('remote-setup-prepare'),d=h.controller.delegatePrepared(s),n={...operation('prepare'),observed:review().consent.prepared.after};n.operation.reason='no-change';d.allowReturned();d.observe(final(s,n));h.retain(n);await h.controller.checkStatus();assert.equal(d.released(),true);assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.agentSelection('remote-setup-apply'),null);assert.equal(h.calls.length,0);
});
test('wrong service hash and unknown history do not become a native Consent',async()=>{
  for(const unknown of [false,true]){const h=await fixture(),s=h.controller.agentSelection('remote-setup-prepare'),d=h.controller.delegatePrepared(s),r=review(),f=final(s,r);d.allowReturned();
    if(unknown){f.state='unknown';f.settlement='unknown';f.reason='history-unavailable';delete f.result}else f.result.preparedSha256=hex('f',64);
    d.observe(f);h.retain(r);await h.controller.checkStatus();assert.equal(d.released(),false);assert.equal(h.controller.currentConsent(),null);assert.equal(h.count('discard'),0);assert.equal(h.controller.getSnapshot().uncertain,unknown);
  }
});
test('context/source ABA cannot overwrite a newer selection or adopt old review',async()=>{
  for(const variableSource of [false,true]){const setting=variableSource?variable():actions(),h=await fixture(setting),s=h.controller.agentSelection('remote-setup-prepare'),d=h.controller.delegatePrepared(s),r=review(setting);d.allowReturned();
    if(variableSource){const changed=assets(setting);changed.status.context.revision++;h.asset(changed);h.asset(assets(setting));h.controller.setSelection(setting)}else{h.controller.setSelection(policy());h.controller.setSelection(actions())}
    d.observe(final(s,r));h.retain(r);await h.controller.checkStatus();assert.equal(d.released(),true);assert.equal(h.controller.currentConsent(),null);assert.equal(h.count('discard'),1);
  }
});
test('reentrant peer arrival performs zero Allow; explicit original read releases only unsubmitted comparison',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);let once=false;const stop=h.controller.subscribe(()=>{if(!once&&h.controller.getSnapshot().pending){once=true;p.peer('Peer original changed')}});
  assert.equal(await p.controller.allow(),false);stop();assert.equal(p.count('allow'),0);assert.equal(h.controller.getSnapshot().pending,true);await h.controller.checkStatus();assert.equal(h.controller.getSnapshot().pending,false);assert.equal(h.calls.filter(c=>['prepare','apply','discard'].includes(c.kind)).length,0);
});
test('lost Allow stays original Unknown through withdrawal and late native success',async()=>{
  const h=await fixture(),p=await permission(h),s=h.controller.agentSelection('remote-setup-prepare');p.controller.acknowledge(true);const w=p.controller.allow();p.last('allow').reject(new Error('fixed failure'));await w;assert.equal(p.controller.getSnapshot().unknown,true);
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(s,null,null,{enabled:false,remainingMs:0,permissionRevision:'2'}));await revoke;h.retain(review());await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null);assert.equal(await p.controller.allow(),false);assert.equal(p.count('allow'),1);
});
