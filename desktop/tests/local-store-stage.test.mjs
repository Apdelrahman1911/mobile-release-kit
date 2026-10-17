// Inert public DTO checks: no filesystem, native, credential or Store operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseStagePrepareRequest, parseStageExecuteRequest, parseStagePreparedSummary, parseStageExecutionSummary,
  nativeStageOperationId, STAGE_PREPARE_LIMITS, STAGE_EXECUTE_LIMITS } from '../src/localStoreStageProtocol.ts';

const candidate = '12345678-1234-4234-8234-123456789abc';
const external = '22345678-1234-4234-8234-123456789abc';
const production = '32345678-1234-4234-8234-123456789abc';
const authorization = '42345678-1234-4234-8234-123456789abc';
const copy = v => structuredClone(v);
const ref = c => ({ recordId: c.repeat(32), recordRevision: 3 });
function request(platform = 'android', stage = 'external-testing') {
  return { projectId: 'p1', draftRevision: 1, baselineGeneration: 2, savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
    savedVersion: { bytes: 40, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 42 },
    credentialContextRevision: 3, ...ref('c'), executionMode: 'local', platform, stage, candidateOperationId: candidate,
    candidateSha256: 'a'.repeat(64), predecessorOperationId: stage === 'external-testing' ? candidate : external,
    predecessorReceiptSha256: 'd'.repeat(64), confirmation: `${stage}:${platform}:1.2.3:42`,
    ...(platform === 'ios' ? { supplementalAssignments: { reviewContact: ref('e'), commitment: ref('f'), reviewDemo: null } } : {}) };
}
function prepared(platform = 'android', stage = 'external-testing') {
  return { operationId: stage === 'external-testing' ? external : production, stage, candidateOperationId: candidate,
    candidateSha256: 'a'.repeat(64), predecessorOperationId: stage === 'external-testing' ? candidate : external,
    predecessorReceiptSha256: 'd'.repeat(64), intentSha256: 'b'.repeat(64), storePreconditionSha256: 'c'.repeat(64),
    sourceCommit: 'b'.repeat(40), sourceTree: 'c'.repeat(40), version: { name: '1.2.3', build: 42 },
    observedAt: '2026-10-17T00:00:00Z', limitations: [...STAGE_PREPARE_LIMITS],
    ...(platform === 'ios' ? { bundleId: 'org.example.ios-app', appStoreAppId: '0012345', destination: stage === 'external-testing' ?
      { channel: 'testflight-external' } : { channel: 'app-store-review', automaticRelease: false } } :
      { applicationId: 'org.example.app', destination: stage === 'external-testing' ?
        { channel: 'Closed testing team', releaseStatus: 'completed' } : { channel: 'production', releaseStatus: 'draft' } }) };
}
function executed(platform, stage) {
  const v = prepared(platform, stage); delete v.storePreconditionSha256;
  return { ...v, receiptSha256: 'f'.repeat(64), authorizationId: authorization, result: 'accepted',
    state: platform === 'android' ? (stage === 'external-testing' ? 'available-to-testers' : 'draft') : 'submitted-for-review',
    limitations: [...STAGE_EXECUTE_LIMITS] };
}
test('both stage forms keep explicit platform, lineage and tools out of preparation/execution', () => {
  for (const platform of ['android', 'ios']) for (const stage of ['external-testing', 'production-submit']) {
    const v = request(platform, stage), stageOperationId = stage === 'external-testing' ? external : production;
    assert.deepEqual(copy(parseStagePrepareRequest(v)), v);
    const e = { ...v, stageOperationId, intentSha256: 'b'.repeat(64) };
    assert.deepEqual(copy(parseStageExecuteRequest(e)), e);
    for (const key of ['toolchainSelection', 'uploadSelection', 'signingTools', 'authorizationId']) {
      assert.equal(parseStagePrepareRequest({ ...v, [key]: {} }), null);
      assert.equal(parseStageExecuteRequest({ ...e, [key]: {} }), null);
    }
    assert.equal(parseStagePrepareRequest({ ...v, stageOperationId }), null);
    for (const id of [candidate, v.predecessorOperationId]) assert.equal(parseStageExecuteRequest({ ...e, stageOperationId: id }), null);
  }
});
test('candidate defaults, wrong predecessor, consent mismatch and malformed original assignment refs refuse', () => {
  for (const mutate of [v => delete v.stage, v => v.stage = 'candidate', v => delete v.platform,
    v => v.predecessorOperationId = external, v => v.confirmation = 'candidate:android:1.2.3:42',
    v => v.confirmation = 'external-testing:android:1.2.3:43', v => v.supplementalAssignments = null]) {
    const v = request(); mutate(v); assert.equal(parseStagePrepareRequest(v), null);
  }
  for (const mutate of [v => delete v.supplementalAssignments, v => v.supplementalAssignments.reviewDemo = {},
    v => v.supplementalAssignments.commitment.recordId = v.recordId, v => v.supplementalAssignments.reviewContact.recordRevision = 0,
    v => v.supplementalAssignments.reviewContact.privateKey = 'not-allowed']) {
    const v = request('ios'); mutate(v);
    assert.equal(parseStagePrepareRequest(v), null);
  }
  const ios = request('ios'); ios.supplementalAssignments.reviewDemo = ref('a'); assert.ok(parseStagePrepareRequest(ios));
});
test('native stage UUID must retain actual UUID4 bits; renderer IDs cannot replace the selected result', () => {
  assert.equal(nativeStageOperationId(external.replaceAll('-', '')), external);
  assert.equal(nativeStageOperationId('a'.repeat(32)), null);
  const v = prepared(); assert.ok(parseStagePreparedSummary(v, external, 'android'));
  assert.equal(parseStagePreparedSummary(v, production, 'android'), null);
  assert.equal(parseStagePreparedSummary({ ...v, operationId: candidate }, candidate, 'android'), null);
  assert.equal(parseStagePreparedSummary({ ...v, stageOperationId: external }, external, 'android'), null);
});
test('exact stage receipts distinguish manual review, beta review and nonserved Play draft', () => {
  for (const platform of ['android', 'ios']) for (const stage of ['external-testing', 'production-submit']) {
    const p = prepared(platform, stage), e = executed(platform, stage);
    assert.ok(parseStagePreparedSummary(p, p.operationId, platform));
    assert.ok(parseStageExecutionSummary(e, e.operationId, platform));
    assert.equal(parseStagePreparedSummary(p, p.operationId, platform === 'ios' ? 'android' : 'ios'), null);
    for (const mutate of [v => v.result = 'reconciled', v => v.state = 'released', v => v.observedAt = '2026-02-30T00:00:00Z',
      v => v.limitations = ['not-public-release'], v => v.predecessorReceiptSha256 = '0', v => v.destination.automaticRelease = true]) {
      const changed = copy(e); mutate(changed); assert.equal(parseStageExecutionSummary(changed, e.operationId, platform), null);
    }
  }
  const p = prepared('android', 'production-submit'); p.destination.releaseStatus = 'completed';
  assert.equal(parseStagePreparedSummary(p, production, 'android'), null);
  const e = executed('ios', 'external-testing'); e.state = 'pending-developer-release';
  assert.equal(parseStageExecutionSummary(e, external, 'ios'), null);
});
test('getter and oversized public DTO inputs never execute accessors or become accepted records', () => {
  let reads = 0; const v = request(); Object.defineProperty(v, 'stage', { enumerable: true, get() { reads++; return 'external-testing'; } });
  assert.equal(parseStagePrepareRequest(v), null); assert.equal(reads, 0);
  assert.equal(parseStagePrepareRequest({ ...request(), projectId: 'p'.repeat(20000) }), null);
  const p = prepared(); Object.defineProperty(p, 'destination', { enumerable: true, get() { reads++; return {}; } });
  assert.equal(parseStagePreparedSummary(p, external, 'android'), null); assert.equal(reads, 0);
});

import { parseLocalStorePrepareStatus, encodeLocalStorePrepareRequest } from '../src/localStorePrepareProtocol.ts';
import { parseLocalStoreExecuteStatus, encodeLocalStoreExecuteRequest } from '../src/localStoreExecuteProtocol.ts';
import { parseLocalHistoryStatus, parseLocalHistoryRequest } from '../src/localReleaseHistoryProtocol.ts';
import { localStorePrepareRequest, LocalStorePrepareController } from '../src/localStorePrepare.ts';
import { localStoreExecuteRequest, LocalStoreExecuteController } from '../src/localStoreExecute.ts';
import { localStoreReconcileRequest } from '../src/localStoreReconcile.ts';
const status = (revision=0, operation=null) => ({schemaVersion:1,statusRevision:revision,availability:'available',operation});
function operation(r, kind, complete=false) {
  const p = prepared(r.platform,r.stage), e = executed(r.platform,r.stage), prepare = kind === 'prepare';
  return {operationId:prepare?p.operationId.replaceAll('-',''):'a'.repeat(32),ownerGeneration:'b'.repeat(32),
    context:{...copy(r),operation:`local-store-${kind}`},phase:complete?'terminal':'awaiting-consent',
    intentUsable:!complete,outcome:complete?'complete':null,reason:'none',result:complete?{
      schemaVersion:1,scope:`local-${r.platform}-store-stage-${kind}`,headSequence:(r.stage==='external-testing'?9:13)+(prepare?0:2),
      [prepare?'preparedIntent':'executionReceipt']:prepare?p:e}:null};
}
function stageProject(platform='android') {
  const r=request(platform);
  return {projectId:r.projectId,draftRevision:r.draftRevision,baselineGeneration:r.baselineGeneration,observationGeneration:3,
    savedConfig:r.savedConfig,savedVersion:r.savedVersion,inputIssue:null,dirtyDraft:false,snapshotPending:false,
    versionPending:false,saveRecoveryRequired:false,iosDemoRequired:false};
}
function stageAssets(platform='android', stage='external-testing') {
  const r=request(platform,stage), scope={executionMode:'local',platform,stage:stage==='production-submit'?'production':stage,purpose:'store'};
  const pairs=[[platform==='ios'?'asc-p8':'google-service-account',{recordId:r.recordId,recordRevision:r.recordRevision}],
    ...(platform==='ios'?[['apple-review-contact',r.supplementalAssignments.reviewContact],['operation-commitment',r.supplementalAssignments.commitment]]:[])];
  return {mode:'native',scope,contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,
    status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{...scope,revision:3,projectId:'p1'},operation:null,
      assignments:pairs.map(([kind,row])=>({...row,kind,contextRevision:3,availability:'available'})),
      records:pairs.map(([kind,row])=>({recordId:row.recordId,revision:row.recordRevision,kind,availability:'assigned'}))}};
}
function stageHistory(platform='android', stage='external-testing', prepare=false) {
  let receipt=prepare?prepared(platform,stage):executed(platform,stage);
  const id=receipt.operationId, action=prepare?'review-stage-prepared':'review-stage-execution';
  receipt={...receipt,observation:prepare?'current-prepared-files-only':'current-execution-files-only',
    [prepare?'priorPrepareFinality':'priorExecutionFinality']:'not-established'};
  const rows=[{operationId:candidate,phase:'settled-success',recoveryRequired:false},
    {operationId:external,phase:stage==='external-testing'&&prepare?'prepared':'settled-success',recoveryRequired:stage==='external-testing'&&prepare}];
  if(stage==='production-submit')rows.push({operationId:production,phase:prepare?'prepared':'settled-success',recoveryRequired:prepare});
  return {mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:status(1,{
    operationId:'e'.repeat(32),ownerGeneration:'b'.repeat(32),context:{projectId:'p1',executionMode:'local',platform,action,stageOperationId:id},
    phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,
      headSequence:(stage==='external-testing'?9:13)+(prepare?0:2),history:rows,
      limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],[prepare?'preparedIntent':'executionReceipt']:receipt}})};
}
function candidateHistory(platform='android') {
  const h=stageHistory(platform), op=h.status.operation, r=op.result.executionReceipt;
  for(const k of ['stage','candidateOperationId','predecessorOperationId','predecessorReceiptSha256','state'])delete r[k];
  r.operationId=candidate;r.destination=platform==='ios'?{channel:'testflight-internal'}:{channel:'internal',releaseStatus:'completed'};
  r.limitations=['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic'];
  op.context={projectId:'p1',executionMode:'local',action:'review-execution',candidateOperationId:candidate,...(platform==='ios'?{platform}: {})};
  op.result.headSequence=7;op.result.history.splice(1);
  return h;
}
test('integrated Prepare and Execute envelopes enforce stage, owner UUID, lineage and consent',()=>{
  for(const platform of ['android','ios']) for(const stage of ['external-testing','production-submit']) {
    const r=request(platform,stage), p=operation(r,'prepare',true);
    assert.ok(encodeLocalStorePrepareRequest('prepare_local_store_prepare',r));assert.ok(parseLocalStorePrepareStatus(status(1,p)));
    for(const change of [v=>v.operationId='a'.repeat(32),v=>v.result.preparedIntent.predecessorReceiptSha256='a'.repeat(64),
      v=>v.result.scope=`local-${platform}-store-prepare`,v=>v.result.headSequence=513,v=>v.context.stageOperationId=external]) {
      const bad=copy(p);change(bad);assert.equal(parseLocalStorePrepareStatus(status(1,bad)),null);
    }
    const x={...r,stageOperationId:p.result.preparedIntent.operationId,intentSha256:'b'.repeat(64)}, e=operation(x,'execute',true);
    assert.ok(encodeLocalStoreExecuteRequest('prepare_local_store_execute',x));assert.ok(parseLocalStoreExecuteStatus(status(1,e)));
    const bad=copy(e);bad.result.executionReceipt.stage=stage==='external-testing'?'production-submit':'external-testing';
    assert.equal(parseLocalStoreExecuteStatus(status(1,bad)),null);
    for(const kind of ['prepare','execute'])assert.ok((kind==='prepare'?encodeLocalStorePrepareRequest:encodeLocalStoreExecuteRequest)(`start_local_store_${kind}`,{
      operationId:'a'.repeat(32),ownerGeneration:'b'.repeat(32),consentVersion:`local-${platform}-store-stage-${kind}-v1`}));
  }
  const p=prepared();p.destination.channel='😀'.repeat(100);assert.ok(parseStagePreparedSummary(p,external,'android'));
  p.destination.channel+='😀';assert.equal(parseStagePreparedSummary(p,external,'android'),null);
});
test('History preserves exact stage actions and accepts promotion-pending without granting retry',()=>{
  for(const platform of ['android','ios'])for(const stage of ['external-testing','production-submit'])for(const prepare of [true,false]){
    const h=stageHistory(platform,stage,prepare);assert.ok(parseLocalHistoryStatus(h.status));
    const c=h.status.operation.context;assert.ok(parseLocalHistoryRequest(c));assert.equal(parseLocalHistoryRequest({...c,candidateOperationId:candidate}),null);
    const bad=copy(h);bad.status.operation.result.history.at(-1).phase='settled-failure';bad.status.operation.result.history.at(-1).recoveryRequired=false;
    assert.equal(parseLocalHistoryStatus(bad.status),null);
  }
  const h=stageHistory();h.status.operation.context={projectId:'p1',executionMode:'local',action:'verify'};delete h.status.operation.result.executionReceipt;
  h.status.operation.result.history.at(-1).phase='promotion-pending';h.status.operation.result.history.at(-1).recoveryRequired=true;
  assert.ok(parseLocalHistoryStatus(h.status));
});
test('current-last successful history and stage-specific Apple references select promotion, never another build',()=>{
  for(const platform of ['android','ios']) {
    const p=stageProject(platform),a=stageAssets(platform),h=candidateHistory(platform);
    assert.ok(parseLocalHistoryStatus(h.status));assert.ok(localStorePrepareRequest(p,a,h));
    for(const change of [(_p,_a,h)=>h.historical=true,(_p,a)=>a.status.context.stage='candidate',
      (_p,_a,h)=>h.status.operation.result.history.push({operationId:external,phase:'settled-failure',recoveryRequired:false}),
      (p)=>p.savedVersion.build++,(_p,a)=>a.status.assignments[0].recordRevision++]){
      const pp=copy(p),aa=copy(a),hh=copy(h);change(pp,aa,hh);assert.equal(localStorePrepareRequest(pp,aa,hh),null);
    }
    const preparedHistory=stageHistory(platform,'external-testing',true);
    const x=localStoreExecuteRequest(p,a,preparedHistory,null);assert.ok(x);assert.equal('toolchainSelection' in x,false);
    assert.equal(localStoreReconcileRequest(p,a,preparedHistory,false),null);
    const prodAssets=stageAssets(platform,'production-submit'), externalHistory=stageHistory(platform);
    if(platform==='ios') {
      assert.equal(localStorePrepareRequest(p,prodAssets,externalHistory),null);
      externalHistory.status.operation.result.executionReceipt.state='approved';assert.equal(localStorePrepareRequest(p,prodAssets,externalHistory),null);
      externalHistory.status.operation.result.executionReceipt.state='available-to-testers';
      for(const change of [p=>delete p.iosDemoRequired,p=>p.iosDemoRequired=true,(_p,a)=>a.status.assignments.splice(1,1),
        (_p,a)=>a.status.assignments[1].contextRevision++]) {
        const pp=copy(p),aa=copy(a);change(pp,aa);assert.equal(localStorePrepareRequest(pp,aa,h),null);
      }
    }
    assert.ok(localStorePrepareRequest(p,prodAssets,externalHistory));
  }
});
test('existing controllers send stage-specific consent, no tools, and retire consent on supplemental revision change',async()=>{
  for(const kind of ['prepare','execute'])for(const invalidate of [false,true]) {
    const p=stageProject('ios'),a=stageAssets('ios'),h=kind==='prepare'?candidateHistory('ios'):stageHistory('ios','external-testing',true);
    const Controller=kind==='prepare'?LocalStorePrepareController:LocalStoreExecuteController;
    const c=new Controller({project:()=>p,assets:()=>a,history:()=>h,tools:()=>{throw new Error('stage must not inspect tools');},otherOperationReason:()=>null});
    let revision=0,last=status(),start=0,cancel=0;
    const suffix=kind==='prepare'?'Prepare':'Execute';
    const api={mode:'native', [`subscribeLocalStore${suffix}`]:async()=>()=>{},[`localStore${suffix}Status`]:async()=>last,
      [`prepareLocalStore${suffix}`]:async r=>last=status(++revision,operation(r,kind)),
      [`startLocalStore${suffix}`]:async v=>{start++;assert.equal(v.consentVersion,`local-ios-store-stage-${kind}-v1`);return last=status(++revision,{...last.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});},
      [`cancelLocalStore${suffix}`]:async()=>{cancel++;return last=status(++revision,{...last.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});}};
    try {
      await c.connect(api);c.syncProject();assert.ok(c.getSnapshot().request);await c.prepare();c.acknowledge(true);
      if(invalidate)a.status.assignments[1].recordRevision++;
      await c.start();assert.equal(start,invalidate?0:1);assert.equal(cancel,invalidate?1:0);
    }finally{c.dispose();}
  }
});

import { parseExternalReadinessRequest, parseExternalReadinessSummary, EXTERNAL_READINESS_CONSENT } from '../src/localExternalReadinessProtocol.ts';
import { parseLocalStoreReconcileRequest, parseLocalStoreReconcileStatus, reconcileRequestContext, reconcileConsent, encodeLocalStoreReconcileRequest } from '../src/localStoreReconcileProtocol.ts';
import { LocalStoreReconcileController } from '../src/localStoreReconcile.ts';
import { LocalReleaseHistoryController } from '../src/localReleaseHistory.ts';
function readinessRequest() {
  const v=request('ios');
  for(const k of ['stage','predecessorOperationId','predecessorReceiptSha256'])delete v[k];
  return {...v,action:'external-readiness',stageOperationId:external,intentSha256:'b'.repeat(64),executionReceiptSha256:'f'.repeat(64)};
}
function readinessReceipt(offline=false) {
  return {operationId:external,candidateOperationId:candidate,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),
    executionReceiptSha256:'f'.repeat(64),receiptSha256:'e'.repeat(64),authorizationId:authorization,sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),
    bundleId:'org.example.ios-app',appStoreAppId:'0012345',version:{name:'1.2.3',build:42},destination:{channel:'testflight-external'},
    observedAt:'2026-10-17T00:00:00Z',result:'ready',state:'available-to-testers',limitations:['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic'],
    observation:offline?'current-external-readiness-files-only':'current-external-target-only',priorExecutionFinality:'not-established'};
}
function readinessHistory() {
  const h=stageHistory('ios'),op=h.status.operation;
  op.context.action='review-external-readiness';op.result.headSequence=12;op.result.history.at(-1).phase='external-ready';
  delete op.result.executionReceipt;op.result.readinessReceipt=readinessReceipt(true);return h;
}
function readinessOperation(r=readinessRequest(),complete=false) {
  return {operationId:'a'.repeat(32),ownerGeneration:'b'.repeat(32),context:reconcileRequestContext(r),phase:complete?'terminal':'awaiting-consent',
    intentUsable:!complete,outcome:complete?'complete':null,reason:'none',result:complete?{
      schemaVersion:1,scope:'local-ios-external-readiness',headSequence:12,readinessReceipt:readinessReceipt()}:null};
}
test('external readiness is explicit iOS-only same Reconcile API, never recovery, stage Execute or an unbound assignment',()=>{
  const r=readinessRequest();assert.deepEqual(copy(parseExternalReadinessRequest(r)),r);assert.ok(parseLocalStoreReconcileRequest(r));
  assert.equal(reconcileConsent(r),EXTERNAL_READINESS_CONSENT);
  assert.ok(encodeLocalStoreReconcileRequest('start_local_store_reconcile',{operationId:'a'.repeat(32),ownerGeneration:'b'.repeat(32),consentVersion:EXTERNAL_READINESS_CONSENT}));
  for(const mutate of [v=>delete v.action,v=>v.action=null,v=>v.platform='android',v=>v.stage='external-testing',v=>v.settlement='record-current-target',
    v=>v.stageOperationId=candidate,v=>v.executionReceiptSha256='0',v=>v.confirmation='candidate:ios:1.2.3:42',v=>delete v.supplementalAssignments,
    v=>v.supplementalAssignments.commitment.recordId=v.recordId,v=>v.externalReadinessReceiptSha256='e'.repeat(64),v=>v.uploadSelection={}]) {
    const bad=copy(r);mutate(bad);assert.equal(parseLocalStoreReconcileRequest(bad),null);
  }
  let reads=0;Object.defineProperty(r,'action',{enumerable:true,get(){reads++;return'external-readiness';}});
  assert.equal(parseExternalReadinessRequest(r),null);assert.equal(reads,0);
});
test('readiness receipts bind original external execution and remain distinct from live/offline old receipts',()=>{
  const op=readinessOperation(undefined,true);assert.ok(parseLocalStoreReconcileStatus(status(1,op)));
  assert.ok(parseExternalReadinessSummary(readinessReceipt(),external));assert.ok(parseExternalReadinessSummary(readinessReceipt(true),external,true));
  assert.equal(parseExternalReadinessSummary(readinessReceipt(true),external),null);
  for(const mutate of [v=>v.result.headSequence=11,v=>v.result.headSequence=510,v=>v.result.scope='local-ios-store-reconcile',
    v=>v.result.readinessReceipt.operationId=candidate,v=>v.result.readinessReceipt.candidateOperationId=production,
    v=>v.result.readinessReceipt.intentSha256='c'.repeat(64),v=>v.result.readinessReceipt.executionReceiptSha256='e'.repeat(64),
    v=>v.result.readinessReceipt.version.build++,v=>v.result.readinessReceipt.state='approved',v=>v.result.readinessReceipt.result='accepted',
    v=>v.result.readinessReceipt.priorExecutionFinality='established',v=>v.result.readinessReceipt.observedAt='2026-02-30T00:00:00Z',
    v=>v.result.reconciliationReceipt=copy(v.result.readinessReceipt)]) {
    const bad=copy(op);mutate(bad);assert.equal(parseLocalStoreReconcileStatus(status(1,bad)),null);
  }
});
test('refresh UI requires current-last successful external history, original stage credentials and exact saved version',()=>{
  const p=stageProject('ios'),a=stageAssets('ios'),h=stageHistory('ios');
  assert.deepEqual(copy(localStoreReconcileRequest(p,a,h,false,true)),readinessRequest());
  assert.equal(localStoreReconcileRequest(p,a,h),null);
  for(const mutate of [(p)=>p.savedVersion.build++,(_p,a)=>a.status.assignments[1].recordRevision++,(_p,a)=>a.status.context.stage='candidate',
    (_p,_a,h)=>h.historical=true,(_p,_a,h)=>h.status.operation.result.history.at(-1).phase='reconciliation-required',
    (_p,_a,h)=>h.status.operation.result.history.push({operationId:production,phase:'settled-success',recoveryRequired:false}),
    (_p,_a,h)=>h.status.operation.result.headSequence=509]) {
    const pp=copy(p),aa=copy(a),hh=copy(h);mutate(pp,aa,hh);assert.equal(localStoreReconcileRequest(pp,aa,hh,false,true),null);
  }
});
test('offline readiness review preserves original execution hash and selects production without renderer readiness authority',()=>{
  const h=readinessHistory(),p=stageProject('ios'),a=stageAssets('ios','production-submit');
  assert.ok(parseLocalHistoryStatus(h.status));
  const r=localStorePrepareRequest(p,a,h);assert.ok(r);assert.equal(r.predecessorReceiptSha256,'f'.repeat(64));
  assert.equal(r.predecessorOperationId,external);assert.equal(Object.hasOwn(r,'externalReadinessReceiptSha256'),false);
  assert.equal(localStoreReconcileRequest(p,stageAssets('ios'),h,false,true),null);
  const older=copy(h);older.status.operation.result.history.push({operationId:production,phase:'settled-success',recoveryRequired:false});
  assert.ok(parseLocalHistoryStatus(older.status));assert.equal(localStorePrepareRequest(p,a,older),null);
  for(const mutate of [v=>v.operation.context.platform='android',v=>v.operation.result.readinessReceipt.observation='current-external-target-only',
    v=>v.operation.result.history.at(-1).recoveryRequired=true,v=>v.operation.result.executionReceipt=executed('ios','external-testing'),
    v=>v.operation.result.headSequence=11]) {const bad=copy(h.status);mutate(bad);assert.equal(parseLocalHistoryStatus(bad),null);}
});
test('same Reconcile controller starts readiness once, retires stale supplemental consent and rejects wrong live receipt/head bindings',async()=>{
  for(const fault of ['none','assignment','head','source','bundle']) {
    const p=stageProject('ios'),a=stageAssets('ios'),h=stageHistory('ios');let start=0,cancel=0,revision=0,last=status();
    const c=new LocalStoreReconcileController({project:()=>p,assets:()=>a,history:()=>h,otherOperationReason:()=>null,now:()=>1000});
    const api={mode:'native',subscribeLocalStoreReconcile:async()=>()=>{},localStoreReconcileStatus:async()=>last,
      prepareLocalStoreReconcile:async r=>(last=status(++revision,readinessOperation(r))),
      startLocalStoreReconcile:async r=>{start++;assert.equal(r.consentVersion,EXTERNAL_READINESS_CONSENT);const op=readinessOperation(undefined,true);
        if(fault==='head')op.result.headSequence=13;if(fault==='source')op.result.readinessReceipt.sourceTree='a'.repeat(40);if(fault==='bundle')op.result.readinessReceipt.bundleId='wrong.example.app';
        return last=status(++revision,op);},
      cancelLocalStoreReconcile:async()=>{cancel++;return last=status(++revision,{...last.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});}};
    try {
      await c.connect(api);c.syncProject();assert.equal(c.setExternalReadiness(true),true);await c.prepare();c.acknowledge(true);
      if(fault==='assignment')a.status.assignments[1].recordRevision++;
      await c.start();await c.start();assert.equal(start,fault==='assignment'?0:1);
      if(fault==='none')assert.equal(c.getSnapshot().status.operation.outcome,'complete');
      if(['head','source','bundle'].includes(fault))assert.equal(c.getSnapshot().blocked,true);
      if(fault==='assignment')assert.equal(cancel,1);
    }finally{c.dispose();}
  }
});
test('offline readiness History uses existing one-use iOS consent and rejects wrong-platform selection',async()=>{
  let revision=1,last=readinessHistory().status,start=0,prepared=null;
  last.operation.context={projectId:'p1',executionMode:'local',action:'verify'};delete last.operation.result.readinessReceipt;
  const c=new LocalReleaseHistoryController({projectId:()=> 'p1',otherOperationReason:()=>null,now:()=>1000});
  const api={mode:'native',subscribeLocalReleaseHistory:async()=>()=>{},localReleaseHistoryStatus:async()=>last,
    prepareLocalReleaseHistory:async r=>{prepared=r;return last=status(++revision,{...last.operation,operationId:'f'.repeat(32),context:r,phase:'awaiting-consent',intentUsable:true,outcome:null,result:null});},
    startLocalReleaseHistory:async r=>{start++;assert.equal(r.consentVersion,'local-ios-candidate-inputs-v1');return last=status(++revision,{...readinessHistory().status.operation,operationId:'f'.repeat(32),context:prepared});},
    cancelLocalReleaseHistory:async()=>last};
  try{c.syncProject();await c.connect(api);assert.equal(c.selectStage('review-external-readiness',external),false);
    assert.equal(c.setInputPlatform('ios'),true);assert.equal(c.selectStage('review-external-readiness',external),true);
    await c.prepare();c.acknowledge(true);await c.start();await c.start();assert.equal(start,1);
    assert.equal(c.getSnapshot().status.operation.result.readinessReceipt.executionReceiptSha256,'f'.repeat(64));
  }finally{c.dispose();}
});
