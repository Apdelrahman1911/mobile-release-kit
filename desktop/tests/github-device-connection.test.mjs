// Actual controllers/bridge over explicit inert ports. No real browser, OAuth,
// HTTP, credential, timer, native process, clock or provider approval is tested.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { GitHubConnectionController } from '../src/githubConnectionController.ts';
import { GitHubDeviceConnectionController } from '../src/githubDeviceConnectionController.ts';
import { createGitHubDeviceApi,DEVICE_CONSENT,DEVICE_URI,encodeDeviceRequest,parseDeviceStatus,parseDeviceCompletion,deviceStartFailure } from '../src/githubDeviceConnectionProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';
const HELP=JSON.parse(readFileSync(new URL('../../src/mobile_release/api/data/github-connection-v1.json',import.meta.url),'utf8'));
const C={documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'Owner/App'};
const REQUEST={projectId:C.projectId,repository:C.repository,expectedDocumentRevision:7,expectedConnectionRevision:1,consentVersion:DEVICE_CONSENT};
const HTTP={sessionId:'session-a',operationId:'connect-a'},T='2026-10-19T12:00:00Z',E='2026-10-19T13:00:00Z';
const clone=v=>structuredClone(v);const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return{promise,resolve,reject}};
async function flush(){for(let i=0;i<32;i++)await Promise.resolve()}
const fact=(value=null)=>({state:value?'observed':'not-observed',value,observedAt:value?T:null,reason:value?'none':'not-connected'});
function idle(revision=1){return{schemaVersion:1,revision,capability:{readOnlySessionAvailable:true,reason:'none',deviceLogin:'publisher-unconfigured',storage:'session-only'},session:null,operation:null,account:fact(),repository:fact(),automation:fact(),
  facts:{remoteMutationAvailable:false,dispatchAvailable:false,repositoryActionsSettingsObservation:'not-run',environmentObservation:'not-run',secretObservation:'not-run',variableObservation:'not-run',protectionObservation:'not-run',runnerObservation:'not-run',templateCompatibility:'unknown',releaseReadiness:'unknown'}}}
function checking(){return{...idle(2),session:{id:HTTP.sessionId,projectId:C.projectId,targetRepository:C.repository,state:'checking',expiresAt:E},operation:{id:HTTP.operationId,kind:'connect',phase:'running',reason:'none'}}}
function connected(){return{...checking(),revision:3,session:{...checking().session,state:'connected'},operation:{...checking().operation,phase:'settled'},account:fact({id:'11',login:'Owner'}),repository:fact({id:'22',fullName:'Owner/App',defaultBranch:'main',visibility:'private',archived:false,permissions:{pull:'reported-allowed',push:'reported-denied',admin:'unknown'}}),automation:fact({coverage:'complete',workflows:GITHUB_WORKFLOWS.map(({id},i)=>({id,remoteId:String(i+100),presence:'listed',state:'active'}))})}}
function status(phase='idle',patch={}){return{schemaVersion:1,documentRevision:7,connectionRevision:1,available:true,operationId:phase==='idle'?null:'device-a',projectId:phase==='idle'?null:C.projectId,repository:phase==='idle'?null:C.repository,revision:phase==='idle'?1:phase==='pending'?2:4,phase,
  reason:phase==='pending'?'waiting':phase==='failed'?'cancelled':phase==='cleanup-unknown'?'cleanup-unknown':'none',code:phase==='pending'?{userCode:'ABCD-1234',verificationUri:DEVICE_URI,remainingSeconds:590,checkAfterSeconds:5}:null,http:phase==='settled'?HTTP:null,...patch}}
async function harness(){const calls=[],others=[],listeners=new Set();let entry,native=idle(),now=0;
 const h={calls,others,apiNow:null,portNow:null,blocked:null,onInvoke:null,count:n=>calls.filter(c=>c.name===n).length,last:n=>calls.filter(c=>c.name===n).at(-1),
   tick:ms=>{now+=ms},publish:v=>{native=clone(v);for(const fn of [...listeners])fn(clone(v))}};
 const port={mode:'native',subscribe:async fn=>{listeners.add(fn);return()=>listeners.delete(fn)},status:async()=>clone(native),refresh:r=>{others.push(['refresh',r]);return Promise.resolve(native)},disconnect:r=>{const d=deferred();others.push(['disconnect',r,d]);return d.promise}};
 const api=createGitHubDeviceApi('native',(name,raw)=>{const d=deferred();calls.push({name,request:JSON.parse(new TextDecoder().decode(raw)),...d});h.onInvoke?.(name);return d.promise});
 const connection=new GitHubConnectionController(()=>h.blocked??entry?.ownerReason()??null);h.connection=connection;h.apiNow=api;h.portNow=port;
 connection.setContext(C);connection.setHelp(HELP);await connection.attach(port);
 entry=new GitHubDeviceConnectionController(connection,{current:()=>({api:h.apiNow,port:h.portNow,context:connection.getSnapshot().context,blocked:h.blocked})},()=>now);h.entry=entry;entry.attach(api,port);
 h.read=async(v=status())=>{assert.equal(entry.read(),true);h.last('github_device_status').resolve(v);await flush()};
 h.start=async()=>{await h.read();assert.equal(entry.setConsent(true),true);assert.equal(entry.start(),true)};
 h.pending=async()=>{await h.start();h.last('github_device_start').resolve(status('pending'));await flush()};return h}

test('strict public DATA excludes private fields and malformed relations',()=>{
 assert.ok(parseDeviceStatus(status('pending')));assert.ok(parseDeviceStatus(status('cleanup-unknown')));
 for(const bad of [{...status(),deviceCode:'private'},status('pending',{code:{...status('pending').code,token:'private'}}),status('pending',{http:HTTP}),status('settled',{http:null}),status('idle',{operationId:'old'}),status('pending',{code:{...status('pending').code,verificationUri:DEVICE_URI+'?code=1234'}})])assert.equal(parseDeviceStatus(bad),null);
 assert.equal(parseDeviceCompletion({device:status('pending'),connection:connected()}),null);
 assert.ok(parseDeviceCompletion({device:status('settled'),connection:connected()}));
 assert.equal(encodeDeviceRequest('github_device_start',{...REQUEST,clientId:'foreign'}),null);
 assert.equal(encodeDeviceRequest('github_device_open',{operationId:'device-a',revision:2,url:'https://evil'}),null);
 assert.equal(deviceStartFailure({code:'cleanup_unknown'}).notAdmitted,false);
});
test('actual bridge sends only five exact RAW commands and no auth/token field',async()=>{
 const calls=[];const api=createNativeApi('native',async(name,raw)=>{calls.push([name,raw]);return null});
 assert.ok(api.githubDevice);await api.githubDevice.status();await api.githubDevice.start(REQUEST);await api.githubDevice.check({operationId:'device-a',revision:2});await api.githubDevice.open({operationId:'device-a',revision:2});await api.githubDevice.cancel({operationId:'device-a'});
 assert.deepEqual(calls.map(x=>x[0]),['github_device_status','github_device_start','github_device_check','github_device_open','github_device_cancel']);
 for(const[name,raw]of calls){assert.ok(raw instanceof Uint8Array);assert.ok(raw.length+name.length+32<=1024)}
 assert.equal(createGitHubDeviceApi('preview',()=>{throw Error('entry')}),null);
});
test('unconfigured publisher is visible and never starts or opens',async()=>{const h=await harness();await h.read(status('idle',{available:false,reason:'publisher-unconfigured'}));h.entry.setConsent(true);assert.match(h.entry.startReason(),/not configured/);assert.equal(h.entry.start(),false);assert.equal(h.entry.open(),false);assert.deepEqual(h.calls.map(c=>c.name),['github_device_status'])});
test('explicit consent and double click produce only one original Start',async()=>{const h=await harness();await h.read();assert.equal(h.entry.start(),false);h.entry.setConsent(true);assert.equal(h.entry.start(),true);assert.equal(h.entry.start(),false);assert.equal(h.count('github_device_start'),1);assert.equal(h.entry.getSnapshot().consent,false);h.last('github_device_start').resolve(status('pending'));await flush();assert.ok(h.entry.ownerReason());assert.equal(h.connection.getSnapshot().busy,'connect')});
test('healthy same-code pending and slow-down never become Unknown or reissue',async()=>{const h=await harness();await h.pending();assert.equal(h.entry.check(),false);h.tick(5000);assert.equal(h.entry.check(),true);assert.equal(h.entry.check(),false);
 h.last('github_device_check').resolve(status('pending',{revision:4,reason:'slow-down',code:{...status('pending').code,remainingSeconds:550,checkAfterSeconds:10}}));await flush();assert.equal(h.entry.getSnapshot().issue,null);assert.equal(h.entry.check(),false);h.tick(10000);assert.equal(h.entry.check(),true);h.last('github_device_check').resolve(status('pending',{revision:6,code:{...status('pending').code,remainingSeconds:530,checkAfterSeconds:10}}));await flush();assert.equal(h.count('github_device_start'),1);assert.equal(h.entry.getSnapshot().original.operationId,'device-a')});
test('Open is explicit fixed request only, never Connected',async()=>{const h=await harness();await h.pending();assert.equal(h.count('github_device_open'),0);assert.equal(h.entry.open(),true);assert.deepEqual(h.last('github_device_open').request,{operationId:'device-a',revision:2});h.last('github_device_open').resolve(null);await flush();assert.equal(h.entry.getSnapshot().browserRequested,true);assert.equal(h.connection.getSnapshot().status.session,null)});
test('code cannot admit HTTP when less than 24s remain',async()=>{const h=await harness();await h.start();h.last('github_device_start').resolve(status('pending',{code:{...status('pending').code,remainingSeconds:25,checkAfterSeconds:5}}));await flush();h.tick(5000);assert.equal(h.entry.check(),false);assert.match(h.entry.checkReason(),/too little time/);assert.equal(h.count('github_device_check'),0)});
test('real original promise blocks completion despite terminal HTTP event and Status',async()=>{const h=await harness();await h.pending();h.tick(5000);h.entry.check();h.publish(checking());h.publish(connected());await h.read(status('settled'));
 assert.equal(h.connection.getSnapshot().busy,'connect');assert.equal(h.entry.getSnapshot().pendingCount,1);h.last('github_device_check').resolve(status('settled'));await flush();assert.equal(h.connection.getSnapshot().busy,null);assert.equal(h.connection.getSnapshot().status.session.state,'connected');assert.equal(h.entry.ownerReason(),null)});
test('lost poll response never permits repoll/new code from a later status',async()=>{const h=await harness();await h.pending();h.tick(5000);h.entry.check();h.last('github_device_check').reject(new Error('private sentinel'));await flush();assert.equal(h.entry.getSnapshot().issue,'unconfirmed');await h.read(status('pending',{revision:4}));assert.equal(h.entry.check(),false);assert.equal(h.entry.start(),false);assert.equal(h.count('github_device_check'),1);assert.ok(h.connection.getSnapshot().uncertain);assert.ok(!JSON.stringify(h.entry.getSnapshot()).includes('private sentinel'))});
test('Stop before Start returns targets late original once and preserves caller',async()=>{const h=await harness();await h.start();assert.equal(h.entry.cancel(),true);assert.equal(h.count('github_device_cancel'),0);h.last('github_device_start').resolve(status('pending'));await flush();assert.equal(h.count('github_device_cancel'),1);h.last('github_device_cancel').resolve(status('failed',{revision:4}));await flush();assert.equal(h.entry.ownerReason(),null);assert.equal(h.connection.getSnapshot().busy,null);assert.equal(h.connection.getSnapshot().status.session,null)});
test('ABA/context switch cannot revive old consent or active original',async()=>{const h=await harness();await h.start();h.entry.beforeContextIntent();h.connection.setContext({...C,projectId:'other'});h.entry.syncContext();h.connection.setContext(C);h.entry.syncContext();h.last('github_device_start').resolve(status('pending'));await flush();assert.equal(h.entry.check(),false);assert.equal(h.count('github_device_cancel'),1);assert.equal(h.entry.getSnapshot().consent,false);assert.equal(h.entry.getSnapshot().fresh,false)});
test('reentrant Stop before native entry emits no Start or browser request',async()=>{const h=await harness();await h.read();h.entry.setConsent(true);let fired=false;h.entry.subscribe(()=>{if(!fired&&h.entry.getSnapshot().pendingCount){fired=true;h.entry.cancel()}});h.entry.start();await flush();assert.equal(h.count('github_device_start'),0);assert.equal(h.count('github_device_open'),0);assert.equal(h.connection.getSnapshot().busy,null)});
test('known pre-admission no-ID refuses without inventing HTTP; generic loss retains',async()=>{const h=await harness();await h.start();h.last('github_device_start').reject({code:'device_unconfigured'});await flush();assert.equal(h.entry.ownerReason(),null);assert.equal(h.connection.getSnapshot().busy,null);assert.equal(h.connection.getSnapshot().error,'publisher-unconfigured');const j=await harness();await j.start();j.last('github_device_start').reject({code:'unexpected'});await flush();assert.ok(j.entry.ownerReason());assert.equal(j.connection.getSnapshot().busy,'connect')});
test('foreign terminal and absorbing Unknown never release the original',async()=>{const h=await harness();await h.start();h.last('github_device_start').resolve(status('pending',{operationId:'foreign',repository:'Other/Repo'}));await flush();assert.equal(h.entry.getSnapshot().issue,'unconfirmed');const j=await harness();await j.pending();await j.read(status('cleanup-unknown',{revision:5}));await j.read(status('failed',{revision:6}));assert.equal(j.entry.getSnapshot().issue,'cleanup-unknown');assert.equal(j.entry.getSnapshot().original.phase,'cleanup-unknown')});
test('API replacement and dispose never discard an outstanding invoke',async()=>{const h=await harness();await h.start();assert.equal(h.entry.attach(null,null),false);h.entry.dispose();h.last('github_device_start').resolve(status('pending'));await flush();assert.equal(h.count('github_device_cancel'),1);assert.ok(h.entry.ownerReason());h.last('github_device_cancel').resolve(status('failed',{revision:4}));await flush();assert.equal(h.entry.ownerReason(),null)});
test('real native stopping status retains original callers and never looks terminal',async()=>{
 const h=await harness();await h.pending();assert.equal(h.entry.cancel(),true);
 h.last('github_device_cancel').resolve(status('stopping',{revision:3,reason:'cancelled'}));await flush();
 assert.equal(h.entry.getSnapshot().issue,null);assert.equal(h.entry.getSnapshot().original.phase,'stopping');
 assert.ok(h.entry.ownerReason());assert.equal(h.connection.getSnapshot().busy,'connect');assert.equal(h.entry.start(),false);
 await h.read(status('failed',{revision:4}));assert.equal(h.entry.ownerReason(),null);assert.equal(h.connection.getSnapshot().busy,null);
});
test('observed unknown original still offers exactly one Stop without reopening work',async()=>{
 const h=await harness();await h.read(status('cleanup-unknown',{revision:5}));
 assert.equal(h.entry.canCancel(),true);assert.equal(h.entry.cancel(),true);assert.equal(h.entry.cancel(),false);
 assert.deepEqual(h.last('github_device_cancel').request,{operationId:'device-a'});
 h.last('github_device_cancel').resolve(status('cleanup-unknown',{revision:6}));await flush();
 assert.equal(h.entry.getSnapshot().issue,'cleanup-unknown');assert.equal(h.entry.start(),false);assert.equal(h.entry.check(),false);
});
test('Stop overtaking a completed native login waits its actual caller and same HTTP verification',async()=>{
 const h=await harness();await h.pending();h.tick(5000);h.entry.check();h.publish(connected());
 assert.equal(h.entry.cancel(),true);h.last('github_device_cancel').resolve(status('settled'));await flush();
 assert.equal(h.connection.getSnapshot().busy,'connect');assert.equal(h.entry.getSnapshot().pendingCount,1);
 h.last('github_device_check').resolve(status('settled'));await flush();
 assert.equal(h.count('github_device_cancel'),1);assert.equal(h.connection.getSnapshot().busy,null);
 assert.equal(h.connection.getSnapshot().status.session.state,'connected');assert.equal(h.entry.ownerReason(),null);
 // A late local Stop is not a provider revocation or an automatic Disconnect.
 assert.equal(h.others.filter(c=>c[0]==='disconnect').length,0);
});
