// Actual controllers with inert original-call ports. No native qualification,
// saved read, tool process, provider, download, protected copy or file access.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { AgentToolSetupController } from '../src/agentToolSetupController.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { copyToolSetupInput, parseToolSetupReview, parseToolSetupStatus, toolSetupCommands } from '../src/agentToolSetup.ts';
import { savedRequirementsContext, savedRequirementsReview } from '../src/toolSetupSavedRequirements.ts';
import { TOOL_ACQUISITION_CONSENT } from '../src/toolAcquisitionProtocol.ts';

const ID=n=>n.toString(16).padStart(32,'0'),PROJECT=ID(1),INSTANCE=ID(2),GRANT=ID(3),REVIEW=ID(4),REQUEST=ID(5),OP=ID(6),OWNER=ID(7);
const SHA='a'.repeat(64),CONTENT={bytes:120,sha256:SHA},clone=v=>structuredClone(v);
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
const context=()=>({projectId:'project-1',draftRevision:1,baselineGeneration:1,savedConfig:clone(CONTENT),action:'inspect',review:null});
const status=(revision=1,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:operation&&operation.phase!=='terminal'?'busy':'available',operation});
const prepared=c=>({operationId:OP,ownerGeneration:OWNER,context:clone(c),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const requirements=()=>({kind:'tool-requirements-observation',protectedTools:'none-in-supported-catalogue',components:{missing:['jdk','sdk-platform','sdk-build-tools','gradle'],compatible:[]},
  requirements:{schemaVersion:1,basis:'unverified-static-source-hints',sourcesSha256:SHA,complete:true,platform:'android',projectCodeExecuted:false,
    xcode:{version:'26.3',build:'17C529'},android:{jdk:{state:'literal',value:'17'},agp:{state:'literal',value:'8.9.2'},sdkPlatform:{state:'literal',value:'android-35'},
      sdkBuildTools:{state:'unspecified',value:null},gradle:{state:'literal',version:'8.14.5',distributionUrl:'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip',sha256:SHA}}}});
const terminal=(p,outcome='complete')=>({...clone(p),phase:'terminal',intentUsable:false,outcome,reason:outcome==='complete'?'none':'cancelled',result:outcome==='complete'?requirements():null});
function workspace(){let w=workspaceReducer(initialWorkspace,{type:'select',project:{id:'project-1',name:'Inert',path:'/never-opened'}});
  w=workspaceReducer(w,{type:'snapshot-start',projectId:'project-1',requestId:1});return workspaceReducer(w,{type:'snapshot-done',projectId:'project-1',requestId:1,observedAt:1,
    snapshot:{root:'/never-opened',config:{path:'release/mobile-release.json',state:'format-valid',data:{android:{enabled:true,module:':app'}},content:clone(CONTENT),issues:[]},discovery:{hints:{}},issues:[]}});}
function harness(t){
  let w=workspace(),known=[{},{},{}],native=status(),listener=null,input=null,latest=null,allowGate=null,revokeGate=null,statusGate=null;
  const calls=[],reads=[],readGates=[];const epoch={},session={};
  const api={mode:'native',subscribe:async f=>{listener=f;return()=>{listener=null;};},status:()=>{reads.push(clone(native));return readGates.shift()?.promise??Promise.resolve(clone(native));},
    prepare:async r=>{calls.push(['gui-prepare',clone(r)]);throw Error('not this route');},start:async r=>{calls.push(['gui-start',clone(r)]);throw Error('not this route');},
    cancel:async r=>{calls.push(['gui-cancel',clone(r)]);return clone(native);}};
  const tool=new ToolAcquisitionController({selectedProject:()=>w.projects[w.selectedId],otherOperationReason:()=>null,knownTools:()=>known});
  tool.setVisible(true);const ready=tool.connect(api);
  const access=(enabled=true,s=null)=>({serviceInstance:INSTANCE,projectId:PROJECT,grantId:GRANT,reviewId:REVIEW,review:clone(input.review),enabled,
    remainingMs:enabled?300000:0,consumed:s!==null,pending:s!==null&&s.settlement!=='settled',unknown:s?.state==='unknown',requestId:s?REQUEST:null,status:s});
  const done=(outcome='complete',hasOperation=true)=>({origin:{projectId:PROJECT,serviceInstance:INSTANCE,requestId:REQUEST},grantId:GRANT,reviewId:REVIEW,revision:3,
    review:clone(input.review),state:outcome==='complete'?'complete':'cancelled',settlement:'settled',reason:outcome==='complete'?'none':'permission-revoked',
    operation:hasOperation?{operationId:OP,ownerGeneration:OWNER,registrationGeneration:null}:null,outcome,
    result:outcome==='complete'?{kind:'inspect-saved-requirements',missing:['jdk','android-platform','android-build-tools','gradle']}:null});
  const port={allow:(id,body)=>{calls.push(['allow',id]);input=clone(body);return allowGate?.promise??Promise.resolve(latest=access());},
    access:async()=>{calls.push(['access']);return clone(latest);},revoke:()=>{calls.push(['revoke']);return revokeGate?.promise??Promise.resolve(latest=access(false));},
    requestStatus:()=>{calls.push(['service-status']);return statusGate?.promise??Promise.resolve(clone(latest.status));}};
  const agent=new AgentToolSetupController({current:()=>({port,nativeSession:session,projectId:'project-1',epoch:w.projects[w.selectedId]??epoch,preview:false,
    reviews:[tool.savedRequirementsReview()].filter(Boolean),blockedReason:null}),delegate:r=>tool.delegateSavedRequirements(r),nonce:()=>GRANT,now:()=>100,
    prepareRequirements:()=>tool.prepareForCli(),prepareReason:()=>tool.checkReason()});
  t.after(()=>{agent.dispose();tool.dispose();});
  return {tool,agent,ready,calls,reads,readGates,done,access,
    get input(){return input;},get current(){return native;},
    emit(s){native=clone(s);listener?.(clone(s));},setNative(s){native=clone(s);},latest(s){latest=clone(s);},
    allowGate(g){allowGate=g;},revokeGate(g){revokeGate=g;},statusGate(g){statusGate=g;},
    source(){known=[{},{},{}];tool.syncProject();agent.syncContext();},
    aba(){const p=w.projects[w.selectedId];tool.selectionIntent();w={...w,projects:{...w.projects,[p.project.id]:{...p}}};tool.syncProject();agent.syncContext();},
    select(){agent.choose('inspect-saved-requirements');agent.syncContext();assert.ok(agent.getSnapshot().review);},
  };
}
async function allowed(h){await h.ready;h.select();assert.equal(h.agent.acknowledge(true),true);assert.equal(await h.agent.allow(),true);}

test('new saved Inspect is exact required-null DATA; old five grammar and single ID-only submit remain',()=>{
  const c=context(),r=savedRequirementsReview(c),parsed=parseToolSetupReview(r);
  assert.equal(Object.getPrototypeOf(parsed),null);assert.deepEqual(clone(parsed),r);
  const input={projectId:c.projectId,review:r,doctorDraft:null,sourceContext:c,nativeConsent:TOOL_ACQUISITION_CONSENT,licenseAcknowledged:false};
  assert.deepEqual(clone(copyToolSetupInput(input)),input);
  for(const bad of [{...r,prepared:{operationId:OP,ownerGeneration:OWNER,statusRevision:1}},{...r,sources:{}},{...r,platform:'ios'},{...r,path:'/extra'}])assert.equal(parseToolSetupReview(bad),null);
  for(const field of ['prepared','sources']){const b=clone(r);delete b[field];assert.equal(parseToolSetupReview(b),null);}
  for(const patch of [{action:'acquire'},{review:{}},{projectId:'other'},{savedConfig:{bytes:0,sha256:SHA}},{path:'/extra'}])assert.equal(copyToolSetupInput({...input,sourceContext:{...c,...patch}}),null);
  assert.equal(savedRequirementsContext(c,{...r,draftRevision:2},c.projectId),null);
  for(const kind of ['inspect-requirements','acquire-missing'])assert.equal(parseToolSetupReview({...r,kind}),null);
  assert.equal(copyToolSetupInput({...input,sourceContext:null}),null);
  assert.equal(copyToolSetupInput({...input,licenseAcknowledged:true}),null);
  const extra=clone(input);Object.defineProperty(extra.sourceContext,'savedConfig',{get(){assert.fail('getter');},enumerable:true});assert.equal(copyToolSetupInput(extra),null);
});

test('new Allow only freezes current saved context and never calls GUI Prepare, Start or another tool action',async t=>{
  const h=harness(t);await allowed(h);assert.equal(h.input.sourceContext.action,'inspect');assert.equal(h.input.sourceContext.review,null);
  assert.deepEqual(h.input.sourceContext.savedConfig,CONTENT);assert.equal(h.input.review.prepared,null);assert.ok(h.tool.ownerReason());
  assert.deepEqual(h.calls.map(c=>c[0]),['allow']);assert.equal(h.tool.getSnapshot().inspection,null);
  assert.equal(h.tool.delegateSavedRequirements(h.input.review),null); // Even direct reentry cannot replace the pending origin.
  assert.equal(toolSetupCommands(h.agent.getSnapshot().access).length,1);assert.match(toolSetupCommands(h.agent.getSnapshot().access)[0],/^mrk tool-setup-submit /);
  await h.agent.allow();await h.tool.inspect();await h.tool.reviewDownload();assert.deepEqual(h.calls.map(c=>c[0]),['allow']);
});

test('terminal event before Allow return and before service retirement cannot become an inspection',async t=>{
  const h=harness(t),gate=deferred();await h.ready;h.select();h.allowGate(gate);h.agent.acknowledge(true);const allow=h.agent.allow();
  const p=prepared(h.input.sourceContext);h.emit(status(3,terminal(p)));await h.tool.checkStatus(true);
  assert.equal(h.tool.getSnapshot().issue,null);assert.equal(h.tool.getSnapshot().inspection,null);assert.equal(h.agent.getSnapshot().pending,'allow');
  assert.equal(await h.agent.check(),false);gate.resolve(h.access());await allow;assert.equal(h.tool.getSnapshot().inspection,null);
  h.latest(h.access(false,h.done()));const read=deferred();h.readGates.push(read);const checking=h.agent.check();await flush();
  assert.equal(h.tool.getSnapshot().inspection,null);assert.equal(h.agent.getSnapshot().nativeReadJoined,false);
  read.resolve(status(3,terminal(p)));await checking;assert.ok(h.tool.getSnapshot().inspection);assert.equal(h.agent.getSnapshot().nativeReadJoined,true);
  assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
});

test('submitted Prepare then Revoke before Start retires the changed original, not an unchanged-baseline shortcut',async t=>{
  const h=harness(t);await allowed(h);const prepareReturn=deferred(),calls=[];let stop=false;
  // Inert original native port deliberately pauses after creating Prepared.
  // This drives real service/controller ordering, not native qualification.
  const original=(async()=>{calls.push('prepare');const p=prepared(h.input.sourceContext);h.emit(status(2,p));await prepareReturn.promise;
    if(stop){h.emit(status(3,terminal(p,'cancelled')));return h.done('cancelled');}calls.push('start');assert.fail('revoke must prevent Start');})();
  const revoke=deferred();h.revokeGate(revoke);stop=true;const withdrawing=h.agent.revoke();await flush();
  assert.equal(h.agent.getSnapshot().nativeReadJoined,false);assert.ok(h.tool.ownerReason());assert.equal(h.tool.getSnapshot().status.operation.phase,'awaiting-consent');
  prepareReturn.resolve();const returned=await original;assert.equal(parseToolSetupStatus(returned)?.operation.operationId,OP);
  h.latest(h.access(false,returned));revoke.resolve(h.access(false,returned));await withdrawing;
  assert.deepEqual(calls,['prepare']);assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.ownerReason(),null);
  assert.equal(h.tool.getSnapshot().inspection,null);assert.equal(h.tool.getSnapshot().status.operation.operationId,OP);
  assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
});

test('unused withdrawal needs returned permission plus a new unchanged native read',async t=>{
  const h=harness(t);await allowed(h);const read=deferred();h.readGates.push(read);const p=h.agent.revoke();await flush();assert.ok(h.tool.ownerReason());
  read.resolve(status());await p;assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.ownerReason(),null);
});

test('concurrent Revoke retires display generation but a genuine late Allow caller still joins in either order',async t=>{
  for(const allowFirst of [false,true]) {
    const h=harness(t),allowGate=deferred(),revokeGate=deferred();await h.ready;h.select();h.allowGate(allowGate);h.revokeGate(revokeGate);
    h.agent.acknowledge(true);const allowing=h.agent.allow(),p=prepared(h.input.sourceContext);
    h.emit(status(2,p));const revoking=h.agent.revoke();h.emit(status(3,terminal(p,'cancelled')));
    const returned=h.access(false,h.done('cancelled'));h.latest(returned);
    if(allowFirst){allowGate.resolve(h.access());await allowing;assert.equal(h.agent.getSnapshot().revoking,true);}
    revokeGate.resolve(returned);await revoking;
    if(!allowFirst){assert.equal(h.agent.getSnapshot().nativeReadJoined,false);assert.ok(h.tool.ownerReason());allowGate.resolve(h.access());await allowing;}
    assert.equal(h.agent.getSnapshot().unknown,false);assert.equal(h.tool.getSnapshot().issue,null);
    await h.agent.check();assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.ownerReason(),null);
    assert.equal(h.agent.getSnapshot().access.enabled,false);assert.equal(h.tool.getSnapshot().inspection,null);
    assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
  }
});

test('source reentry after declaration prevents Allow; no prepared or foreign automatic cancellation is invented',async t=>{
  const h=harness(t);await h.ready;h.select();let switched=false;h.tool.subscribe(()=>{if(!switched&&h.tool.ownerReason()){switched=true;h.aba();}});
  h.agent.acknowledge(true);assert.equal(await h.agent.allow(),false);assert.equal(h.calls.length,0);assert.ok(h.tool.ownerReason());
  await h.agent.check();assert.equal(h.calls.length,0);assert.equal(h.tool.ownerReason(),null);
});

test('same bytes with a replaced source witness never restore an actionable inspection',async t=>{
  const h=harness(t);await allowed(h);const p=prepared(h.input.sourceContext);h.source();h.emit(status(3,terminal(p)));h.latest(h.access(false,h.done()));
  await h.agent.check();assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.equal(h.tool.getSnapshot().inspection,null);
  assert.notEqual(h.tool.reviewReason(),null);assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
});

test('lost Allow stays unknown after apparent completion; it cannot re-Prepare or adopt a cold Status',async t=>{
  const h=harness(t),gate=deferred();await h.ready;h.select();h.allowGate(gate);h.agent.acknowledge(true);const call=h.agent.allow();
  const p=prepared(h.input.sourceContext);h.emit(status(2,p));gate.reject(Error('lost ACK'));await call;h.emit(status(3,terminal(p)));h.latest(h.access(false,h.done()));
  await h.agent.check();await h.agent.allow();await h.tool.inspect();assert.equal(h.agent.getSnapshot().unknown,true);assert.equal(h.tool.getSnapshot().inspection,null);
  assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
});

test('foreign identity before exact service correlation refuses with zero automatic Cancel',async t=>{
  const h=harness(t);await allowed(h);const p=prepared(h.input.sourceContext);h.emit(status(2,p));h.emit(status(3,{...p,operationId:ID(8)}));
  h.source();h.latest(h.access(false,h.done()));await h.agent.check();assert.equal(h.tool.getSnapshot().issue,'protocol');assert.equal(h.tool.getSnapshot().inspection,null);
  assert.equal(h.calls.filter(c=>c[0]==='gui-cancel').length,0);
});

test('service settled response before its caller return cannot release the native view',async t=>{
  const h=harness(t);await allowed(h);const p=prepared(h.input.sourceContext),final=h.done();h.emit(status(3,terminal(p)));
  h.latest(h.access(false,{...final,state:'finishing',settlement:'pending',outcome:null,result:null}));await h.agent.check();
  const gate=deferred();h.statusGate(gate);const check=h.agent.check();await flush();assert.equal(h.tool.getSnapshot().inspection,null);
  gate.resolve(final);await check;assert.equal(h.agent.getSnapshot().nativeReadJoined,true);assert.ok(h.tool.getSnapshot().inspection);
  assert.equal(h.calls.filter(c=>c[0].startsWith('gui-')).length,0);
});
