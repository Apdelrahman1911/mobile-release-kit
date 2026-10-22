// Actual controllers with inert returned-call ports only. No filesystem,
// native source/permit, tool process, download, registration or qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { AgentToolSetupController } from '../src/agentToolSetupController.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { copyToolSetupInput, parseToolSetupReview, parseToolSetupStatus, toolSetupConsent, toolSetupCommands } from '../src/agentToolSetup.ts';
import { parseToolSetupAcquisition, reviewedAcquisitionContext, reviewedAcquisitionReview, acquisitionComponents } from '../src/toolSetupAcquisition.ts';
import { TOOL_ACQUISITION_CONSENT } from '../src/toolAcquisitionProtocol.ts';

const ID=n=>n.toString(16).padStart(32,'0'),PROJECT=ID(1),INSTANCE=ID(2),GRANT=ID(3),REVIEW=ID(4),REQUEST=ID(5),OP=ID(6),OWNER=ID(7),INSPECT=ID(8),INSPECT_OWNER=ID(9);
const SHA='a'.repeat(64),CONTENT={bytes:120,sha256:SHA},clone=v=>structuredClone(v),nativeParts=['jdk','sdk-platform','sdk-build-tools','gradle'];
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
const context=()=>({projectId:'project-1',draftRevision:1,baselineGeneration:1,savedConfig:clone(CONTENT),action:'inspect',review:null});
const status=(revision=1,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:operation&&operation.phase!=='terminal'?'busy':'available',operation});
const prepared=(c,operationId=OP,ownerGeneration=OWNER)=>({operationId,ownerGeneration,context:clone(c),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const requirements=(mask=15)=>({kind:'tool-requirements-observation',protectedTools:'none-in-supported-catalogue',components:{missing:nativeParts.filter((_,i)=>mask&(1<<i)),compatible:nativeParts.filter((_,i)=>!(mask&(1<<i)))},
  requirements:{schemaVersion:1,basis:'unverified-static-source-hints',sourcesSha256:SHA,complete:true,platform:'android',projectCodeExecuted:false,
    xcode:{version:'26.3',build:'17C529'},android:{jdk:{state:'literal',value:'17'},agp:{state:'literal',value:'8.9.2'},sdkPlatform:{state:'literal',value:'android-35'},
      sdkBuildTools:{state:'unspecified',value:null},gradle:{state:'literal',version:'8.14.5',distributionUrl:'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip',sha256:SHA}}}});
const terminal=(p,result,outcome='complete')=>({...clone(p),phase:'terminal',intentUsable:false,outcome,reason:outcome==='complete'?'none':'cancelled',result:outcome==='complete'?clone(result):null});
function staged(mask=15){const missing=nativeParts.filter((_,i)=>mask&(1<<i));return {schemaVersion:1,kind:'staged-tool-sources',operationId:OP,
  contextSha256:SHA,referenceSha256:'b'.repeat(64),projectionSha256:'c'.repeat(64),cacheJob:`tool-${OP}`,lookupScope:'registered-selected-known',reusedArchives:[],downloadedArchives:missing,
  groups:[['jdk',['jdk']],['sdk',['sdk-platform','sdk-build-tools']],['gradle',['gradle']]].flatMap(([group,parts])=>{
    const chosen=parts.filter(p=>missing.includes(p));return chosen.length?[{group,components:chosen,allRequiredComponentsStaged:chosen.length===parts.length,next:chosen.length===parts.length?'choose-native-source':'complete-sdk-manually'}]:[];}),
  assurance:{nativeFinality:false,registered:false,readyToBuild:false}};}
function workspace(){let w=workspaceReducer(initialWorkspace,{type:'select',project:{id:'project-1',name:'Inert',path:'/never-opened'}});
  w=workspaceReducer(w,{type:'snapshot-start',projectId:'project-1',requestId:1});return workspaceReducer(w,{type:'snapshot-done',projectId:'project-1',requestId:1,observedAt:1,
    snapshot:{root:'/never-opened',config:{path:'release/mobile-release.json',state:'format-valid',data:{android:{enabled:true,module:':app'}},content:clone(CONTENT),issues:[]},discovery:{hints:{}},issues:[]}});}
function harness(t,observation=requirements()){
  let w=workspace(),known=[{},{},{}],native=status(),listener=null,input=null,latest=null,allowGate=null,revokeGate=null,statusGate=null;
  const calls=[],reads=[],readGates=[],session={};
  const api={mode:'native',subscribe:async f=>{listener=f;return()=>{listener=null;};},status:()=>{reads.push(clone(native));return readGates.shift()?.promise??Promise.resolve(clone(native));},
    prepare:async c=>{calls.push(['gui-prepare',clone(c)]);assert.equal(c.action,'inspect');return clone(native=status(2,prepared(c,INSPECT,INSPECT_OWNER)));},
    start:async r=>{calls.push(['gui-start',clone(r)]);assert.equal(r.operationId,INSPECT);return clone(native=status(3,terminal(native.operation,observation)));},
    cancel:async r=>{calls.push(['gui-cancel',clone(r)]);return clone(native);}};
  const tool=new ToolAcquisitionController({selectedProject:()=>w.projects[w.selectedId],otherOperationReason:()=>null,knownTools:()=>known});
  tool.setVisible(true);const ready=tool.connect(api);
  const access=(enabled=true,s=null)=>({serviceInstance:INSTANCE,projectId:PROJECT,grantId:GRANT,reviewId:REVIEW,review:clone(input.review),enabled,
    remainingMs:enabled?300000:0,consumed:s!==null,pending:s!==null&&s.settlement!=='settled',unknown:s?.state==='unknown',requestId:s?REQUEST:null,status:s});
  const done=(outcome='complete',hasOperation=true)=>({origin:{projectId:PROJECT,serviceInstance:INSTANCE,requestId:REQUEST},grantId:GRANT,reviewId:REVIEW,revision:3,
    review:clone(input.review),state:outcome==='complete'?'complete':'cancelled',settlement:'settled',reason:outcome==='complete'?'none':'permission-revoked',
    operation:hasOperation?{operationId:OP,ownerGeneration:OWNER,registrationGeneration:null}:null,outcome,
    result:outcome==='complete'?{kind:'acquire-reviewed-missing',staged:clone(input.review.acquisition.missing)}:null});
  const port={allow:(id,body)=>{calls.push(['allow',id]);input=clone(body);return allowGate?.promise??Promise.resolve(latest=access());},
    access:async()=>{calls.push(['access']);return clone(latest);},revoke:()=>{calls.push(['revoke']);return revokeGate?.promise??Promise.resolve(latest=access(false));},
    requestStatus:()=>{calls.push(['service-status']);return statusGate?.promise??Promise.resolve(clone(latest.status));}};
  const agent=new AgentToolSetupController({current:()=>({port,nativeSession:session,projectId:'project-1',epoch:w.projects[w.selectedId],preview:false,
    reviews:[tool.savedRequirementsReview(),tool.reviewedAcquisitionReview()].filter(Boolean),blockedReason:null}),delegate:r=>r.kind==='acquire-reviewed-missing'?tool.delegateReviewedAcquisition(r):tool.delegateSavedRequirements(r),
    nonce:()=>GRANT,now:()=>100,prepareRequirements:()=>tool.prepareForCli(),prepareReason:()=>tool.checkReason()});
  t.after(()=>{agent.dispose();tool.dispose();});
  return {tool,agent,ready,calls,reads,readGates,access,done,get input(){return input;},get current(){return native;},
    emit(s){native=clone(s);listener?.(clone(s));},setNative(s){native=clone(s);},latest(s){latest=clone(s);},
    allowGate(g){allowGate=g;},revokeGate(g){revokeGate=g;},statusGate(g){statusGate=g;},
    source(){known=[{},{},{}];tool.syncProject();agent.syncContext();},
    aba(){const p=w.projects[w.selectedId];tool.selectionIntent();w={...w,projects:{...w.projects,[p.project.id]:{...p}}};tool.syncProject();agent.syncContext();},
    async inspect(){await ready;await tool.inspect();agent.syncContext();},
    select(){assert.equal(agent.choose('acquire-reviewed-missing'),true);agent.syncContext();assert.ok(agent.getSnapshot().review);}};
}
async function allowed(h){await h.inspect();h.select();assert.equal(h.agent.acknowledge(true),true);assert.equal(await h.agent.allow(),true);}
const comparison=(mask=15)=>reviewedAcquisitionReview(context(),{operationId:INSPECT,ownerGeneration:INSPECT_OWNER},SHA,requirements(mask).components);

test('all sixteen partitions keep exactly the missing set; old six bytes and new strict fields stay separate',()=>{
  for(let mask=0;mask<16;mask++){
    const r=comparison(mask);if(!mask){assert.equal(r,null);continue;}
    assert.deepEqual(clone(parseToolSetupReview(r)),r);
    assert.deepEqual(r.acquisition.missing,acquisitionComponents.filter((_,i)=>mask&(1<<i)));
    assert.deepEqual(r.acquisition.compatible,acquisitionComponents.filter((_,i)=>!(mask&(1<<i))));
  }
  const r=comparison();
  for(const bad of [{...r,acquisition:null},{...r,platform:'ios'},{...r,prepared:{operationId:OP,ownerGeneration:OWNER,statusRevision:1}},{...r,sources:{}},{...r,path:'/extra'}])assert.equal(parseToolSetupReview(bad),null);
  for(const field of ['prepared','sources','acquisition']){const bad=clone(r);delete bad[field];assert.equal(parseToolSetupReview(bad),null);}
  for(const kind of ['doctor','inspect-requirements','acquire-missing','inspect-picked-sources','register-reviewed-sources','inspect-saved-requirements']){
    const old={kind,platform:'android',draftRevision:1,baselineGeneration:1,prepared:['inspect-requirements','acquire-missing'].includes(kind)?{operationId:OP,ownerGeneration:OWNER,statusRevision:1}:null,
      sources:kind.includes('sources')?{registrationGeneration:1,sourceGeneration:2,reviewId:kind==='register-reviewed-sources'?REVIEW:null}:null};
    assert.equal(JSON.stringify(parseToolSetupReview(old)),JSON.stringify(old));
    assert.equal(parseToolSetupReview({...old,acquisition:r.acquisition}),null);assert.equal(parseToolSetupReview({...old,acquisition:null}),null);
    assert.notEqual(toolSetupConsent(kind),toolSetupConsent(r.kind));
  }
});

test('new comparison rejects aliases, mixed partitions, accessors, extra fields and terminal-LF IDs/hashes',()=>{
  const a=comparison().acquisition;
  for(const bad of [{...a,missing:['jdk','jdk'],compatible:['android-platform','android-build-tools']},{...a,missing:['sdk-platform'],compatible:['jdk','android-build-tools','gradle']},
    {...a,missing:[...a.missing].reverse()},{...a,missing:['jdk'],compatible:['jdk','android-platform','gradle']},{...a,missing:[],compatible:acquisitionComponents},{...a,url:'https://arbitrary'}])assert.equal(parseToolSetupAcquisition(bad),null);
  for(const field of ['operationId','ownerGeneration','requirementsSha256'])for(const suffix of ['\n','\r\n','\u2028'])assert.equal(parseToolSetupAcquisition({...a,[field]:a[field]+suffix}),null);
  let reads=0;const bad={...a};Object.defineProperty(bad,'missing',{enumerable:true,get(){reads++;return a.missing;}});
  assert.equal(parseToolSetupAcquisition(bad),null);assert.equal(reads,0);
});

test('MAIN acquisition requires exact native Acquire context, original inspection and native consent',()=>{
  const review=comparison(),c={...context(),action:'acquire',review:{operationId:INSPECT,ownerGeneration:INSPECT_OWNER,requirementsSha256:SHA}};
  const input={projectId:c.projectId,review,doctorDraft:null,sourceContext:c,nativeConsent:TOOL_ACQUISITION_CONSENT,licenseAcknowledged:false};
  assert.deepEqual(clone(copyToolSetupInput(input)),input);assert.ok(reviewedAcquisitionContext(c,review,c.projectId));
  for(const patch of [{action:'inspect',review:null},{review:null},{projectId:'other'},{draftRevision:2},{savedConfig:{bytes:0,sha256:SHA}}])assert.equal(copyToolSetupInput({...input,sourceContext:{...c,...patch}}),null);
  for(const field of ['operationId','ownerGeneration','requirementsSha256'])assert.equal(copyToolSetupInput({...input,sourceContext:{...c,review:{...c.review,[field]:field==='requirementsSha256'?'b'.repeat(64):ID(10)}}}),null);
  for(const patch of [{nativeConsent:toolSetupConsent('inspect-saved-requirements')},{doctorDraft:{}},{licenseAcknowledged:true},{sourceContext:null}])assert.equal(copyToolSetupInput({...input,...patch}),null);
});

test('only a returned current inspection offers acquisition; cold Status, compatible reuse and unknown hints do not',async t=>{
  const cold=harness(t);await cold.ready;cold.emit(status(3,terminal(prepared(context(),INSPECT,INSPECT_OWNER),requirements())));await cold.tool.checkStatus(true);
  assert.equal(cold.tool.reviewedAcquisitionReview(),null);
  for(const mode of ['all-compatible','protected','unknown']){
    const result=requirements(mode==='all-compatible'?0:15);
    if(mode==='protected'){result.protectedTools='reuse-selected';result.components={missing:[],compatible:[...nativeParts]};}
    if(mode==='unknown')result.requirements.android.jdk={state:'unknown',value:null};
    const h=harness(t,result);await h.inspect();assert.ok(h.tool.getSnapshot().inspection);assert.equal(h.tool.reviewedAcquisitionReview(),null);assert.notEqual(h.tool.reviewReason(),null);
    assert.deepEqual(h.calls.map(c=>c[0]),['gui-prepare','gui-start']);
  }
});

test('Allow retains the inspection selection but never calls GUI acquisition Prepare/Start or registration',async t=>{
  const h=harness(t,requirements(4));await allowed(h);assert.equal(h.input.sourceContext.action,'acquire');assert.equal(h.input.sourceContext.review.operationId,INSPECT);
  assert.deepEqual(h.input.review.acquisition.missing,['android-build-tools']);assert.deepEqual(h.input.sourceContext.savedConfig,CONTENT);
  assert.equal(h.tool.savedRequirementsReview(),null);assert.ok(h.tool.ownerReason());assert.equal(h.tool.delegateReviewedAcquisition(h.input.review),null);
  assert.equal(toolSetupCommands(h.agent.getSnapshot().access).length,1);assert.match(toolSetupCommands(h.agent.getSnapshot().access)[0],/^mrk tool-setup-submit /);
  await h.agent.allow();await h.tool.inspect();await h.tool.reviewDownload();assert.deepEqual(h.calls.map(c=>c[0]),['gui-prepare','gui-start','allow']);
});

test('terminal event before Allow and service caller return cannot release the staged result',async t=>{
  const h=harness(t),gate=deferred();await h.inspect();h.select();h.allowGate(gate);h.agent.acknowledge(true);const allowing=h.agent.allow();
  const p=prepared(h.input.sourceContext),end=status(5,terminal(p,staged()));h.emit(end);await h.tool.checkStatus(true);
  assert.equal(h.tool.getSnapshot().issue,null);assert.equal(h.tool.getSnapshot().presentation,'settling');assert.equal(h.agent.getSnapshot().pending,'allow');
  gate.resolve(h.access());await allowing;assert.equal(h.tool.getSnapshot().presentation,'settling');
  h.latest(h.access(false,h.done()));const read=deferred();h.readGates.push(read);const checking=h.agent.check();await flush();
  assert.equal(h.agent.getSnapshot().nativeReadJoined,false);assert.equal(h.tool.getSnapshot().presentation,'settling');
  read.resolve(end);await checking;assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.getSnapshot().presentation,'current-staged');
  assert.equal(h.calls.filter(c=>c[0]==='gui-prepare').length,1);
});

test('submitted Prepare then Revoke before Start retains the actual changed native identity until returns',async t=>{
  const h=harness(t);await allowed(h);const preparedReturn=deferred(),calls=[];let stop=false;
  const original=(async()=>{calls.push('prepare');const p=prepared(h.input.sourceContext);h.emit(status(4,p));await preparedReturn.promise;
    assert.equal(stop,true);h.emit(status(5,terminal(p,null,'cancelled')));return h.done('cancelled');})();
  const gate=deferred();h.revokeGate(gate);stop=true;const revoking=h.agent.revoke();await flush();assert.equal(h.agent.getSnapshot().nativeReadJoined,false);assert.ok(h.tool.ownerReason());
  preparedReturn.resolve();const returned=await original;assert.equal(parseToolSetupStatus(returned)?.operation.operationId,OP);h.latest(h.access(false,returned));gate.resolve(h.access(false,returned));await revoking;
  assert.deepEqual(calls,['prepare']);assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.ownerReason(),null);assert.equal(h.tool.getSnapshot().status.operation.operationId,OP);
  assert.equal(h.tool.reviewedAcquisitionReview(),null);assert.equal(h.calls.filter(c=>c[0]==='gui-start').length,1);
});

test('unsubmitted withdrawal requires its returned call plus unchanged inspection baseline, and no rearm',async t=>{
  const h=harness(t);await allowed(h);const baseline=clone(h.current),read=deferred();h.readGates.push(read);const p=h.agent.revoke();await flush();assert.ok(h.tool.ownerReason());
  read.resolve(baseline);await p;assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.ownerReason(),null);assert.equal(h.tool.reviewedAcquisitionReview(),null);
});

test('late Allow after Revoke joins the original in either return order and cannot replace it',async t=>{
  for(const first of [true,false]){
    const h=harness(t),ag=deferred(),rg=deferred();await h.inspect();h.select();h.allowGate(ag);h.revokeGate(rg);h.agent.acknowledge(true);const allowing=h.agent.allow();
    const p=prepared(h.input.sourceContext);h.emit(status(4,p));const revoking=h.agent.revoke();h.emit(status(5,terminal(p,null,'cancelled')));const result=h.access(false,h.done('cancelled'));h.latest(result);
    if(first){ag.resolve(h.access());await allowing;}rg.resolve(result);await revoking;
    if(!first){assert.equal(h.agent.getSnapshot().nativeReadJoined,false);ag.resolve(h.access());await allowing;}
    await h.agent.check();assert.equal(h.agent.getSnapshot().unknown,false);assert.equal(h.tool.getSnapshot().issue,null);assert.equal(h.tool.ownerReason(),null);
    assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);
  }
});

test('source reentry before Allow and identical-byte ABA cannot replace the original inspection',async t=>{
  const h=harness(t);await h.inspect();h.select();let changed=false;h.tool.subscribe(()=>{if(!changed&&h.tool.ownerReason()){changed=true;h.aba();}});
  h.agent.acknowledge(true);assert.equal(await h.agent.allow(),false);assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);assert.ok(h.tool.ownerReason());
  await h.agent.check();assert.equal(h.tool.ownerReason(),null);assert.equal(h.tool.reviewedAcquisitionReview(),null);
  const later=harness(t);await allowed(later);later.source();const p=prepared(later.input.sourceContext);later.emit(status(5,terminal(p,staged())));later.latest(later.access(false,later.done()));await later.agent.check();
  assert.equal(later.agent.getSnapshot().nativeReadJoined,true);assert.equal(later.tool.getSnapshot().presentation,'stale');assert.equal(later.tool.reviewedAcquisitionReview(),null);
});

test('lost Allow stays Unknown and a foreign candidate never gains automatic Cancel or another acquisition',async t=>{
  const lost=harness(t),gate=deferred();await lost.inspect();lost.select();lost.allowGate(gate);lost.agent.acknowledge(true);const call=lost.agent.allow();
  const p=prepared(lost.input.sourceContext);lost.emit(status(4,p));gate.reject(Error('lost ACK'));await call;lost.emit(status(5,terminal(p,staged())));lost.latest(lost.access(false,lost.done()));
  await lost.agent.check();await lost.agent.allow();assert.equal(lost.agent.getSnapshot().unknown,true);assert.equal(lost.calls.filter(c=>c[0]==='allow').length,1);
  const foreign=harness(t);await allowed(foreign);const fp=prepared(foreign.input.sourceContext);foreign.emit(status(4,fp));foreign.emit(status(5,{...fp,operationId:ID(10)}));foreign.source();
  assert.equal(foreign.tool.getSnapshot().issue,'protocol');assert.equal(foreign.calls.filter(c=>c[0]==='gui-cancel').length,0);
});

test('staged result and new operation must match the retained missing set, never the earlier Inspect',async t=>{
  const h=harness(t,requirements(4));await allowed(h);const done=h.done();assert.ok(parseToolSetupStatus(done));
  for(const patch of [{result:{kind:'acquire-missing',staged:['android-build-tools']}},{result:{kind:'acquire-reviewed-missing',staged:['jdk']}},
    {operation:{...done.operation,operationId:INSPECT}},{operation:{...done.operation,ownerGeneration:INSPECT_OWNER}}])assert.equal(parseToolSetupStatus({...done,...patch}),null);
  // Structurally valid native result for another partition must fail the real
  // controller's retained inspection comparison, not only its service codec.
  h.emit(status(5,terminal(prepared(h.input.sourceContext),staged(15))));h.latest(h.access(false,done));await h.agent.check();
  assert.equal(h.tool.getSnapshot().issue,'protocol');assert.equal(h.agent.getSnapshot().nativeReadJoined,false);
});

test('service pending and the actual status-return Promise both precede a usable native result',async t=>{
  const h=harness(t);await allowed(h);const p=prepared(h.input.sourceContext),done=h.done();h.emit(status(5,terminal(p,staged())));
  h.latest(h.access(false,{...done,state:'finishing',settlement:'pending',outcome:null,result:null}));await h.agent.check();assert.equal(h.tool.getSnapshot().presentation,'settling');
  const gate=deferred();h.statusGate(gate);const checking=h.agent.check();await flush();assert.equal(h.agent.getSnapshot().nativeReadJoined,false);
  gate.resolve(done);await checking;assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.getSnapshot().presentation,'current-staged');
});
