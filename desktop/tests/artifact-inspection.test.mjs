// Pure renderer DATA only. No files are inspected, no native commands/tools,
// credentials, network, process, Store action or lifecycle result is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ARTIFACT_CHECKS, ARTIFACT_LIMITATIONS, parseArtifactInspectionResult,
  artifactInspectionCheckRows, artifactInspectionHelp, artifactInspectionLimitationText,
} from '../src/artifactInspectionProtocol.ts';

const hash = 'a'.repeat(64);
function result(format = 'aab') {
  return {
    schemaVersion:1,scope:'selected-artifact-bytes-only',format,
    usedConfig:{bytes:123,sha256:hash},usedVersion:{bytes:32,sha256:'b'.repeat(64),name:'1.2.3',build:7},
    artifacts:[{role:'artifact',selectionId:'1'.repeat(32),label:`fixture.${format}`,kind:'file',bytes:100,entries:1,
      identity:{method:'sha256-file',sha256:hash}}],
    observed:{applicationId:format==='aab'?'org.fixture.app':null,bundleId:format==='ipa'?'org.fixture.app':null,
      versionName:'1.2.3',versionBuild:'7',signerSha256:'c'.repeat(64),teamId:format==='ipa'?'FIXTURETEAM':null},
    checks:ARTIFACT_CHECKS.map(check=>({check,status:'pass',reason:'none'})),limitations:[...ARTIFACT_LIMITATIONS],
  };
}
function aab() {
  const value=result();
  for(const key of ['profile-entitlements','archive-pair','symbols']) {
    Object.assign(value.checks.find(row=>row.check===key),{status:'not_applicable',reason:'none'});
  }
  Object.assign(value.checks.find(row=>row.check==='signer-policy'),{status:'unavailable',reason:'saved-policy-missing'});
  Object.assign(value.checks.find(row=>row.check==='current-validity'),{status:'unavailable',reason:'prerequisite-not-run'});
  return value;
}
function ipa() {
  const value=result('ipa');
  Object.assign(value.checks.find(row=>row.check==='archive-pair'),{status:'unavailable',reason:'archive-not-selected'});
  Object.assign(value.checks.find(row=>row.check==='symbols'),{status:'unavailable',reason:'symbols-not-selected'});
  return value;
}

test('artifact result retains independent byte, signature and saved-policy facts with closed role identity',()=>{
  const input=aab(), parsed=parseArtifactInspectionResult(input);
  assert.ok(parsed);
  assert.notEqual(parsed,input);assert.notEqual(parsed.artifacts,input.artifacts);
  input.observed.applicationId='changed.after.copy';
  assert.equal(parsed.observed.applicationId,'org.fixture.app');
  assert.equal(parsed.checks.find(row=>row.check==='signature').status,'pass');
  assert.equal(parsed.checks.find(row=>row.check==='signer-policy').status,'unavailable');
  assert.ok(parseArtifactInspectionResult(ipa()));
  const paired=ipa();
  paired.artifacts.push({role:'archive',selectionId:'2'.repeat(32),label:'fixture.xcarchive',kind:'directory',bytes:200,entries:3,
    identity:{method:'sha256-tree-v1',sha256:'d'.repeat(64)}});
  paired.artifacts.push({role:'dsyms',selectionId:'3'.repeat(32),label:'fixture.dSYMs',kind:'directory',bytes:100,entries:2,
    identity:{method:'sha256-tree-v1',sha256:'e'.repeat(64)}});
  Object.assign(paired.checks.find(row=>row.check==='archive-pair'),{status:'pass',reason:'none'});
  Object.assign(paired.checks.find(row=>row.check==='symbols'),{status:'pass',reason:'none'});
  assert.ok(parseArtifactInspectionResult(paired));
  // Packed optional inputs are files too; they are not silently treated as
  // directory commitments. Empty files/trees can yield failed structure checks.
  const packed=structuredClone(paired);
  for(const input of packed.artifacts.slice(1)){input.kind='file';input.entries=1;input.identity.method='sha256-file';}
  assert.ok(parseArtifactInspectionResult(packed));
  const empty=aab();empty.artifacts[0].bytes=0;
  Object.assign(empty.checks.find(row=>row.check==='structure'),{status:'fail',reason:'malformed-structure'});
  assert.ok(parseArtifactInspectionResult(empty));
  const emptyTree=structuredClone(paired);emptyTree.artifacts[1].bytes=0;emptyTree.artifacts[1].entries=1;
  assert.ok(parseArtifactInspectionResult(emptyTree));
  for(const mutate of [
    v=>{v.extra=true;},v=>{delete v.observed.teamId;},v=>{v.format='apk';},
    v=>{v.artifacts[0].path='/arbitrary/native/path';},v=>{v.artifacts[0].identity.method='sha256-tree-v1';},
    v=>{v.artifacts[0].entries=2;},v=>{v.usedConfig.sha256='A'.repeat(64);},
    v=>{v.observed.bundleId='not.applicable';},v=>{v.observed.teamId='NOTAAB';},v=>{v.artifacts[0].bytes=0;},
    v=>{v.artifacts[0].selectionId='not-native-id';},v=>{v.limitations.reverse();},
    v=>{v.observed.applicationId='private\nlog';},v=>{v.observed.versionBuild='١';},
  ]) {const value=aab();mutate(value);assert.equal(parseArtifactInspectionResult(value),null);}
  for(const mutate of [
    v=>{v.observed.applicationId='not.ipa';},
    v=>{v.artifacts[1].selectionId=v.artifacts[0].selectionId;},
    v=>{v.artifacts.splice(1,1);},v=>{v.artifacts.reverse();},v=>{v.format='aab';},
  ]) {const value=structuredClone(paired);mutate(value);assert.equal(parseArtifactInspectionResult(value),null);}
});

test('artifact result refuses malformed bounded data without invoking getters or serialization hooks',()=>{
  let entered=0;
  const value=aab();Object.defineProperty(value.observed,'teamId',{enumerable:true,get(){entered++;throw Error('not entered');}});
  assert.equal(parseArtifactInspectionResult(value),null);assert.equal(entered,0);
  const hook=aab();hook.toJSON=()=>{entered++;return aab();};
  assert.equal(parseArtifactInspectionResult(hook),null);assert.equal(entered,0);
  const cycle=aab();cycle.observed=cycle;assert.equal(parseArtifactInspectionResult(cycle),null);
  const inherited=Object.create(aab());assert.equal(parseArtifactInspectionResult(inherited),null);
  const sparse=aab();delete sparse.checks[0];assert.equal(parseArtifactInspectionResult(sparse),null);
  const symbol=aab();symbol[Symbol('hidden')]=true;assert.equal(parseArtifactInspectionResult(symbol),null);
  for(const number of [-0,-1,NaN,Infinity,1.5,Number.MAX_SAFE_INTEGER+1]){
    const bad=aab();bad.artifacts[0].bytes=number;assert.equal(parseArtifactInspectionResult(bad),null);
  }
  const label=aab();label.artifacts[0].label='é'.repeat(127)+'a';assert.ok(parseArtifactInspectionResult(label));
  label.artifacts[0].label+='a';assert.equal(parseArtifactInspectionResult(label),null);
  for(const label of ['', 'parent/child.aab','parent\\child.aab','bad\0.aab','\ud800']){
    const bad=aab();bad.artifacts[0].label=label;assert.equal(parseArtifactInspectionResult(bad),null);
  }
  const large=aab();large.observed.applicationId='x'.repeat(65537);assert.equal(parseArtifactInspectionResult(large),null);
  for(const [field,limit] of [['bytes',1024**3],['entries',1]]){
    const boundary=aab();boundary.artifacts[0][field]=limit;assert.ok(parseArtifactInspectionResult(boundary));
    boundary.artifacts[0][field]++;assert.equal(parseArtifactInspectionResult(boundary),null);
  }
  const ipaFile=ipa();ipaFile.artifacts[0].bytes=4*1024**3;assert.ok(parseArtifactInspectionResult(ipaFile));
  ipaFile.artifacts[0].bytes++;assert.equal(parseArtifactInspectionResult(ipaFile),null);
  const tree=ipa();tree.artifacts[0].bytes=0;
  Object.assign(tree.checks.find(row=>row.check==='structure'),{status:'fail',reason:'malformed-structure'});
  tree.artifacts.push({role:'archive',selectionId:'2'.repeat(32),label:'boundary.xcarchive',kind:'directory',bytes:16*1024**3,entries:8192,
    identity:{method:'sha256-tree-v1',sha256:hash}});
  Object.assign(tree.checks.find(row=>row.check==='archive-pair'),{status:'unavailable',reason:'prerequisite-not-run'});
  assert.ok(parseArtifactInspectionResult(tree));
  for(const mutate of [v=>{v.artifacts[1].bytes++;},v=>{v.artifacts[1].entries++;},v=>{v.artifacts[1].entries=0;},v=>{v.artifacts[0].bytes=1;}]){
    const bad=structuredClone(tree);mutate(bad);assert.equal(parseArtifactInspectionResult(bad),null);
  }
  const config=aab();config.usedConfig.bytes=512*1024;assert.ok(parseArtifactInspectionResult(config));
  config.usedConfig.bytes++;assert.equal(parseArtifactInspectionResult(config),null);
  const version=aab();version.usedVersion={bytes:65536,sha256:hash,name:'1'.repeat(64),build:2_100_000_000};
  assert.ok(parseArtifactInspectionResult(version));
  for(const mutate of [v=>{v.usedVersion.bytes++;},v=>{v.usedVersion.bytes=0;},v=>{v.usedVersion.name+='1';},
    v=>{v.usedVersion.name='branch/main';},v=>{v.usedVersion.build++;},v=>{v.usedVersion.build=0;},v=>{v.usedVersion.build='7';}]){
    const bad=structuredClone(version);mutate(bad);assert.equal(parseArtifactInspectionResult(bad),null);
  }

});

test('artifact check rows cannot equate missing tools or policy with verification and render fixed explanations',()=>{
  const input=aab();
  Object.assign(input.checks.find(row=>row.check==='signature'),{status:'unavailable',reason:'tools-unavailable'});
  const parsed=parseArtifactInspectionResult(input);assert.ok(parsed);
  const rows=artifactInspectionCheckRows(parsed);
  assert.deepEqual(rows.map(row=>row.check),ARTIFACT_CHECKS);
  assert.equal(rows.find(row=>row.check==='signature').statusLabel,'Unavailable / not established');
  assert.match(rows.find(row=>row.check==='signature').explanation,/tool was unavailable/);
  assert.match(rows.find(row=>row.check==='signer-policy').explanation,/artifact metadata cannot replace/);
  const failure=ipa();Object.assign(failure.checks.find(row=>row.check==='expected-version'),{status:'fail',reason:'version-mismatch'});
  assert.ok(parseArtifactInspectionResult(failure),'a completed observation can contain failed checks');
  for(const mutate of [
    v=>{v.checks[0].status='verified';},v=>{v.checks[0].reason='raw private exception';},
    v=>{v.checks[0].status='pass';v.checks[0].reason='tools-unavailable';},
    v=>{v.checks[1].check=v.checks[0].check;},v=>{v.checks.reverse();},
  ]) {const bad=aab();mutate(bad);assert.equal(parseArtifactInspectionResult(bad),null);}
  assert.deepEqual(ARTIFACT_CHECKS,['byte-identity','structure','manifest','expected-identity','expected-version','signature',
    'profile-entitlements','current-validity','signer-policy','archive-pair','symbols']);
  const matrix=[
    ['structure','fail','unsupported-format'],['structure','fail','input-limit'],['structure','fail','malformed-structure'],
    ['manifest','fail','malformed-structure'],['manifest','unavailable','tools-unavailable'],['manifest','unavailable','prerequisite-not-run'],
    ['expected-identity','fail','identity-mismatch'],['expected-identity','unavailable','prerequisite-not-run'],
    ['expected-version','fail','version-mismatch'],['expected-version','unavailable','prerequisite-not-run'],
    ['signature','fail','signature-invalid'],['signature','unavailable','tools-unavailable'],['signature','unavailable','prerequisite-not-run'],
    ['profile-entitlements','fail','profile-invalid'],['profile-entitlements','unavailable','tools-unavailable'],['profile-entitlements','unavailable','prerequisite-not-run'],
    ['current-validity','fail','signing-time-invalid'],['current-validity','unavailable','tools-unavailable'],['current-validity','unavailable','prerequisite-not-run'],
    ['signer-policy','fail','signer-mismatch'],['signer-policy','unavailable','saved-policy-missing'],['signer-policy','unavailable','signer-unobserved'],['signer-policy','unavailable','prerequisite-not-run'],
  ];
  for(const [check,status,reason] of matrix){
    const value=ipa();Object.assign(value.checks.find(row=>row.check===check),{status,reason});
    assert.ok(parseArtifactInspectionResult(value),`${check}/${status}/${reason}`);
    Object.assign(value.checks.find(row=>row.check===check),{status:status==='fail'?'unavailable':'fail'});
    assert.equal(parseArtifactInspectionResult(value),null,`wrong status for ${check}/${reason}`);
  }
  for(const mutate of [
    v=>{Object.assign(v.checks[0],{status:'fail',reason:'input-limit'});},
    v=>{Object.assign(v.checks.find(row=>row.check==='current-validity'),{status:'pass',reason:'none'});},
    v=>{Object.assign(v.checks.find(row=>row.check==='profile-entitlements'),{status:'pass',reason:'none'});},
    v=>{Object.assign(v.checks.find(row=>row.check==='signature'),{status:'unavailable',reason:'none'});},
    v=>{v.checks.pop();},
  ]){const bad=aab();mutate(bad);assert.equal(parseArtifactInspectionResult(bad),null);}
  const missing=ipa();Object.assign(missing.checks.find(row=>row.check==='archive-pair'),{status:'unavailable',reason:'prerequisite-not-run'});
  assert.equal(parseArtifactInspectionResult(missing),null,'known missing archive has its exact missing-input reason');
  assert.match(artifactInspectionHelp.requiredWhen,/registered project.*saved configuration.*draft is clean/);
  assert.match(artifactInspectionHelp.format,/selected label.*do not mean/);
  assert.match(artifactInspectionHelp.failure,/Missing verification tools or saved signer policy/);
  assert.match(artifactInspectionHelp.failure,/Cancel requests a stop, not immediate cleanup/);
  assert.match(artifactInspectionLimitationText['byte-observation-not-source-provenance'],/do not authenticate/);
  assert.match(artifactInspectionLimitationText['current-signature-not-store-or-release-authority'],/not Store acceptance/);
});

// Same app-owned controller exercised with inert native ports. These statuses
// are DATA fixtures, not actual native picker/tool/finality evidence.
import { ArtifactInspectionController, artifactInspectionOwnerReason } from '../src/artifactInspection.ts';
import { parseArtifactInspectionStatus, copyArtifactInspectionRequest, ARTIFACT_INSPECTION_EVENT } from '../src/artifactInspectionProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { readFileSync } from 'node:fs';
const OP='a'.repeat(32),OWNER='b'.repeat(32),CONTENT={bytes:123,sha256:hash};
const copy=value=>structuredClone(value);
const flush=async()=>{for(let i=0;i<16;i++)await Promise.resolve();};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
function idle(revision=0,generation=0){return {schemaVersion:1,statusRevision:revision,availability:'available',selection:{generation,projectId:null,format:null,phase:'idle',reason:'none',operation:null,items:[]},operation:null};}
function projectWorkspace(){
  let value=workspaceReducer(initialWorkspace,{type:'select',project:{id:'fixture',name:'Inert fixture project',path:'/never-forwarded'}});
  value=workspaceReducer(value,{type:'snapshot-start',projectId:'fixture',requestId:1});
  const assurance={basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'};
  return workspaceReducer(value,{type:'snapshot-done',projectId:'fixture',requestId:1,observedAt:1,snapshot:{root:'/never-opened',observedAt:'',observationScope:'single-request-non-atomic',
    config:{path:'release/mobile-release.json',state:'format-valid',data:{android:{enabled:true}},content:copy(CONTENT),issues:[]},
    discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance,issues:[]}});
}
function harness(t){
  let workspace=projectWorkspace(),registry=idle(),other=null,clock=10;
  const calls=[],listeners=[];
  const call=(kind,input)=>{const value={kind,input:copy(input),...deferred()};calls.push(value);return value.promise;};
  const api={mode:'native',subscribeArtifactInspection:async callback=>{const row={callback,closed:false};listeners.push(row);return ()=>{row.closed=true;};},
    artifactInspectionStatus:async()=>copy(registry),pickArtifactInspection:input=>call('pick',input),prepareArtifactInspection:input=>call('prepare',input),
    startArtifactInspection:input=>call('start',input),cancelArtifactInspection:(operationId,ownerGeneration)=>call('cancel',{operationId,ownerGeneration}),
    discardArtifactInspection:input=>call('discard',input)};
  const controller=new ArtifactInspectionController({selectedProject:()=>workspace.projects[workspace.selectedId]??null,otherOperationReason:()=>other,now:()=>clock});
  controller.syncProject();controller.setVisible(true);const ready=controller.connect(api);t.after(()=>controller.dispose());
  return {controller,api,calls,listeners,ready,get state(){return controller.getSnapshot();},get current(){return copy(registry);},get project(){return workspace.projects[workspace.selectedId];},
    emit(value){registry=copy(value);listeners.at(-1)?.callback(copy(value));},reply(call,value){registry=copy(value);call.resolve(copy(value));},
    edit(action){controller.beforeWorkspaceAction(action);workspace=workspaceReducer(workspace,action);controller.syncProject();},
    replace(changes){workspace={...workspace,projects:{...workspace.projects,fixture:{...workspace.projects.fixture,...changes}}};controller.syncProject();},
    other(value){other=value;},clock(value){clock=value;}};
}
async function chosen(h,selectionId='1'.repeat(32)){
  await h.ready;void h.controller.pick('artifact');const call=h.calls.at(-1);assert.equal(call.kind,'pick');
  const selecting=idle(h.current.statusRevision+1,h.current.selection.generation);
  selecting.selection={...selecting.selection,projectId:'fixture',format:'aab',phase:'picking',operation:{operationId:1,role:'artifact'}};
  selecting.operation=h.current.operation;
  h.reply(call,selecting);await flush();assert.equal(h.state.pickerPending,true);
  const ready=copy(selecting);ready.statusRevision++;ready.selection={generation:selecting.selection.generation+1,projectId:'fixture',format:'aab',phase:'ready',reason:'none',operation:null,
    items:[{selectionId,role:'artifact',label:'fixture.aab',kind:'file'}]};
  h.emit(ready);assert.equal(h.state.pickerPending,false);assert.equal(h.controller.prepareReason(),null);
  return ready;
}
async function reviewed(h){
  await chosen(h);void h.controller.prepare();const call=h.calls.at(-1);assert.equal(call.kind,'prepare');
  const next=h.current;next.statusRevision++;next.operation={operationId:OP,ownerGeneration:OWNER,context:copy(call.input),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null};
  h.emit(next);assert.equal(h.state.consent,null,'status/event alone cannot arm consent before original Prepare reply');
  h.reply(call,next);await flush();assert.ok(h.state.consent);assert.equal(h.state.consent.acknowledged,false);return next;
}

test('artifact native bridge keeps all six closed raw commands separate from picker and run identities',async()=>{
  const calls=[],events=[];
  const api=createNativeApi('native',async(command,raw)=>{assert.ok(raw instanceof Uint8Array);calls.push({command,input:JSON.parse(new TextDecoder().decode(raw))});return idle();},async(event,callback)=>{events.push(event);callback(idle());return ()=>{};});
  const prepare={projectId:'fixture',draftRevision:0,baselineGeneration:0,savedConfig:copy(CONTENT),format:'aab',selections:{artifact:'1'.repeat(32),archive:null,dsyms:null}};
  await api.pickArtifactInspection({projectId:'fixture',format:'aab',role:'artifact'});await api.prepareArtifactInspection(prepare);
  await api.startArtifactInspection({operationId:OP,ownerGeneration:OWNER,consentVersion:'selected-artifact-inspection-v1'});
  await api.cancelArtifactInspection(OP,OWNER);await api.artifactInspectionStatus();await api.discardArtifactInspection({selectionGeneration:1,operationId:OP,ownerGeneration:OWNER});
  const unlisten=await api.subscribeArtifactInspection(value=>assert.ok(value));unlisten();
  assert.deepEqual(calls.map(value=>value.command),['artifact_inspection_pick','artifact_inspection_prepare','artifact_inspection_start','artifact_inspection_cancel','artifact_inspection_status','artifact_inspection_discard']);
  assert.deepEqual(events,[ARTIFACT_INSPECTION_EVENT]);assert.deepEqual(calls[1].input,prepare);
  for(const [command,request] of [['artifact_inspection_pick',{projectId:'fixture',format:'ipa',role:'artifact',path:'/arbitrary'}],
    ['artifact_inspection_cancel',{operationId:1,ownerGeneration:OWNER}],['artifact_inspection_discard',{selectionGeneration:1,operationId:OP,ownerGeneration:null}],
    ['artifact_inspection_prepare',{...prepare,selections:{artifact:'1'.repeat(32),archive:null,dsyms:'2'.repeat(32)}}]])assert.equal(copyArtifactInspectionRequest(command,request),null);
  const stopped=createNativeApi('unavailable',async()=>{throw Error('never native');});await assert.rejects(stopped.artifactInspectionStatus(),{code:'artifact_inspection_unavailable'});
  const forged=idle();forged.selection={...forged.selection,phase:'ready'};assert.equal(parseArtifactInspectionStatus(forged),null);
  const wrong=idle();wrong.selection.phase='unknown';assert.equal(parseArtifactInspectionStatus(wrong),null);
});

test('artifact picker requires original asynchronous settlement and preserves only known cancelled replacement',async(t)=>{
  const h=harness(t);const before=await chosen(h);
  void h.controller.pick('artifact');const pick=h.calls.at(-1);assert.equal(pick.kind,'pick');
  const choosing=copy(before);choosing.statusRevision++;choosing.selection.phase='picking';choosing.selection.operation={operationId:2,role:'artifact'};
  h.reply(pick,choosing);await flush();assert.ok(artifactInspectionOwnerReason(h.state));assert.equal(h.controller.canCancel(),false,'run cancel is not picker cancel');
  assert.equal(h.calls.filter(call=>call.kind==='cancel').length,0);
  const cancelled=copy(before);cancelled.statusRevision=choosing.statusRevision+1;cancelled.selection.reason='cancelled';h.emit(cancelled);
  assert.equal(h.state.pickerPending,false);assert.equal(h.controller.prepareReason(),null);assert.deepEqual(copy(h.state.status.selection.items),before.selection.items);
  h.other('An initialization or credential owner is unknown.');await h.controller.prepare();assert.equal(h.calls.filter(call=>call.kind==='prepare').length,0);h.other(null);
  h.controller.selectionIntent();h.controller.selectionIntent();assert.match(h.controller.prepareReason(),/Choose the required/,'away and back never restores eligibility');
  const late=harness(t);await late.ready;void late.controller.pick('artifact');const lateCall=late.calls.at(-1);late.controller.versionIntent();
  const returned=copy(before);returned.statusRevision=1;late.reply(lateCall,returned);await flush();assert.equal(late.state.pickerPending,false);assert.notEqual(late.controller.prepareReason(),null);
});

test('artifact review binds clean saved inputs and one original start while complete keeps failed checks distinct',async(t)=>{
  const h=harness(t);let current=await reviewed(h);
  assert.equal(h.calls.filter(call=>call.kind==='start').length,0);assert.match(h.controller.runReason(),/Acknowledge/);
  h.controller.setAcknowledged(OP,OWNER,true);assert.equal(h.controller.runReason(),null);
  void h.controller.start(OP,OWNER);void h.controller.start(OP,OWNER);const start=h.calls.at(-1);assert.equal(start.kind,'start');assert.equal(h.calls.filter(call=>call.kind==='start').length,1);
  current={...current,statusRevision:current.statusRevision+1,operation:{...current.operation,phase:'running',intentUsable:false}};h.reply(start,current);await flush();
  h.controller.setVisible(false);assert.ok(artifactInspectionOwnerReason(h.state));assert.equal(h.calls.filter(call=>call.kind==='cancel').length,0,'page navigation does not stop a started app-owned run');
  const report=aab();Object.assign(report.checks.find(row=>row.check==='expected-version'),{status:'fail',reason:'version-mismatch'});
  current={...current,statusRevision:current.statusRevision+1,operation:{...current.operation,phase:'terminal',outcome:'complete',reason:'none',result:report}};h.emit(current);
  assert.equal(h.state.status.operation.result.checks.find(row=>row.check==='expected-version').status,'fail');assert.equal(h.state.historical,false);
  h.controller.setVisible(true);assert.match(h.controller.prepareReason(),/old or consumed/);void h.controller.start(OP,OWNER);assert.equal(h.calls.filter(call=>call.kind==='start').length,1);
  const dirty=harness(t);await chosen(dirty);dirty.replace({draft:{android:{enabled:false}}});assert.match(dirty.controller.prepareReason(),/Save or reset/);
  const invalid=harness(t);await chosen(invalid);invalid.replace({validation:{valid:false},validatedRevision:invalid.project.revision,validatedBaselineGeneration:invalid.project.baselineGeneration});assert.match(invalid.controller.prepareReason(),/invalid or stale/);
});

test('artifact late replies expiry discard and unknown preserve the original owner without rearming consent',async(t)=>{
  const h=harness(t);await chosen(h);void h.controller.prepare();const call=h.calls.at(-1);h.controller.versionIntent();
  const awaiting=h.current;awaiting.statusRevision++;awaiting.operation={operationId:OP,ownerGeneration:OWNER,context:copy(call.input),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null};
  h.reply(call,awaiting);await flush();assert.equal(h.state.consent,null);assert.equal(h.calls.filter(value=>value.kind==='cancel').length,1);
  const unknown=copy(awaiting);unknown.statusRevision++;unknown.operation={...unknown.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown'};
  h.reply(h.calls.at(-1),unknown);await flush();assert.ok(h.state.nativeBlocked);assert.ok(artifactInspectionOwnerReason(h.state));
  h.controller.beginConnection();assert.equal(h.listeners[0].closed,false,'unknown original observer stays retained');assert.notEqual(h.controller.discardReason(),null);
  const expiry=harness(t);await reviewed(expiry);expiry.clock(300_010);await expiry.controller.checkStatus();await flush();assert.equal(expiry.state.consent,null);assert.equal(expiry.calls.filter(value=>value.kind==='cancel').length,1);
  const discard=harness(t);await reviewed(discard);void discard.controller.discard();const disposal=discard.calls.at(-1);assert.equal(disposal.kind,'discard');
  assert.deepEqual(disposal.input,{selectionGeneration:1,operationId:OP,ownerGeneration:OWNER});
  discard.reply(disposal,idle(discard.current.statusRevision+1,2));await flush();assert.equal(discard.state.status.operation,null);assert.equal(discard.state.discardPending,false);assert.equal(artifactInspectionOwnerReason(discard.state),null);
  await discard.controller.checkStatus();assert.equal(discard.state.integrityFailed,false,'discarded Attempt no longer owns idle status routing');
  await chosen(discard,'2'.repeat(32));void discard.controller.prepare();const second=discard.calls.at(-1);assert.equal(second.kind,'prepare');
  const fresh=discard.current;fresh.statusRevision++;fresh.operation={operationId:'c'.repeat(32),ownerGeneration:'d'.repeat(32),context:copy(second.input),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null};
  discard.reply(second,fresh);await flush();assert.ok(discard.state.consent);assert.equal(discard.state.integrityFailed,false);
  // Retire a pending Cancel's routing only after known terminal+discard. Its
  // delayed completion must not restore the old run or erase consumed IDs.
  const stopped=harness(t);let stopStatus=await reviewed(stopped);stopped.controller.setAcknowledged(OP,OWNER,true);
  void stopped.controller.start(OP,OWNER);const start=stopped.calls.at(-1);
  stopStatus={...stopStatus,statusRevision:stopStatus.statusRevision+1,operation:{...stopStatus.operation,phase:'running',intentUsable:false}};stopped.reply(start,stopStatus);await flush();
  assert.equal(stopped.controller.cancel(),true);const lateCancel=stopped.calls.at(-1);assert.equal(lateCancel.kind,'cancel');
  stopStatus={...stopStatus,statusRevision:stopStatus.statusRevision+1,operation:{...stopStatus.operation,phase:'terminal',outcome:'cancelled',reason:'cancelled',result:null}};stopped.emit(stopStatus);
  void stopped.controller.discard();const stoppedDisposal=stopped.calls.at(-1);assert.equal(stoppedDisposal.kind,'discard');
  stopped.reply(stoppedDisposal,idle(stopped.current.statusRevision+1,2));await flush();await stopped.controller.checkStatus();
  lateCancel.resolve(copy(stopStatus));await flush();assert.equal(stopped.state.status.operation,null);assert.equal(stopped.state.integrityFailed,false);assert.equal(stopped.state.cancelClaimed,null);
  void stopped.controller.pick('artifact');const reusedPick=stopped.calls.at(-1);assert.equal(reusedPick.kind,'pick');
  const reused=idle(stopped.current.statusRevision+1,3);reused.selection={generation:3,projectId:'fixture',format:'aab',phase:'ready',reason:'none',operation:null,items:[{selectionId:'1'.repeat(32),role:'artifact',label:'fixture.aab',kind:'file'}]};
  stopped.reply(reusedPick,reused);await flush();assert.equal(stopped.state.integrityFailed,true,'discard never frees consumed native IDs for reuse');
});

test('artifact App uses one existing screen and reciprocal initialization asset and saved-owner guards',()=>{
  const source=name=>readFileSync(new URL(`../src/${name}`,import.meta.url),'utf8');
  const app=source('App.tsx'),page=source('pages/Artifacts.tsx'),component=source('components/ArtifactInspection.tsx');
  assert.match(app,/const savedCommandBusy[^\n]*=> artifactBusy\(\)/);
  assert.match(app,/otherOperationReason: \(\) => preflightBusy\(\) \?\? androidBusy\(\) \?\? recoveryBusy\(\) \?\? iosBusy\(\) \?\? savedCommandPrerequisiteReason\(\)/);
  assert.ok(app.indexOf('artifactInspectionControllerRef.current?.beforeWorkspaceAction(action)')<app.indexOf('const next = workspaceReducer(previous, action)'));
  for(const seam of ['artifactInspection.beginConnection()','artifactInspection.connect(connection)','artifactInspection.dispose()','artifactInspection.snapshotIntent(projectId)','artifactInspection.selectionIntent()','artifactInspection.setSelectionPending(true)','artifactInspection.setSelectionPending(false)'])assert.ok(app.includes(seam),seam);
  assert.match(page,/<ArtifactInspection state=\{inspectionState\}/);assert.match(page,/<ReleaseEvidence /);
  const preview=source('preview.ts');
  for(const name of ['pickArtifactInspection','prepareArtifactInspection','startArtifactInspection','cancelArtifactInspection','artifactInspectionStatus','discardArtifactInspection','subscribeArtifactInspection'])assert.ok(preview.includes(`${name}: artifactInspectionUnavailable`));
  assert.match(component,/<HelpButton content=\{artifactInspectionHelp\}/);assert.match(component,/native panel’s Cancel/);assert.match(component,/No path is entered as text/);
});
