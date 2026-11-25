import { parseExternalReadinessSummary } from './localExternalReadinessProtocol.ts';
import { parseStagePreparedSummary, parseStageExecutionSummary } from './localStoreStageProtocol.ts';
import { iosCandidateInputs, IOS_CANDIDATE_CONSENT } from './iosArchiveProtocol.ts';
import type { LocalExecutionReceipt, IOSExecutionReceipt } from './localStoreExecuteTypes.ts';
import type { LocalPreparedIntent, IOSPreparedIntent } from './localStorePrepareTypes.ts';
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalHistoryStatus, PrepareLocalHistory } from './localReleaseHistoryTypes.ts';
export const LOCAL_HISTORY_EVENT='local-release-history-state-changed';
export const LOCAL_HISTORY_CONSENT='local-release-history-v1' as const;
export const LOCAL_CANDIDATE_CONSENT='local-android-candidate-inputs-v1' as const;
export type LocalHistoryCommand='prepare_local_release_history'|'start_local_release_history'|'local_release_history_status'|'cancel_local_release_history';
const limits=['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'];
const journalPhases=['promotion-pending','inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending','settled-success','settled-failure','reconciliation-required','target-reconciled','external-ready'];
const phases=['awaiting-consent','starting','running','stopping','terminal','unknown'];
const outcomes=['complete','refused','cancelled','timed-out','failed','unknown'];
const reasons=['none','cancelled','context-changed','document-lost','shutdown','timed-out','protocol-error','runtime-unavailable','intent-expired','stale-intent','saved-source-changed','saved-source-invalid','credentials-unavailable','query-prerequisites','command-incomplete','cleanup-unknown','journal-unavailable','enrollment-exists','recovery-required','project-busy'];
const counter=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<4294967295;
const token=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,names:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===names.length&&names.every(n=>Object.hasOwn(v,n));
const member=(values:string[],v:unknown)=>typeof v==='string'&&values.includes(v);
const contextKeys=['projectId','executionMode','action'];
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const hex=(v:unknown,n:number)=>typeof v==='string'&&new RegExp(`^[0-9a-f]{${n}}$`).test(v);
const bounded=(v:unknown,max:number)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=1&&v<=max;
export const candidateHistoryAction=(action:unknown)=>action==='review-inputs'||action==='abandon-inputs'||action==='review-prepared'||action==='review-execution'||action==='review-reconcile'||action==='review-recovery';
export const stageHistoryAction=(action:unknown)=>action==='review-stage-prepared'||action==='review-stage-execution'||action==='review-external-readiness';
export function localHistoryConsent(request:PrepareLocalHistory){return request.platform==='ios'?IOS_CANDIDATE_CONSENT:(candidateHistoryAction(request.action)||stageHistoryAction(request.action))?LOCAL_CANDIDATE_CONSENT:LOCAL_HISTORY_CONSENT;}
// Predicate for already copied bounded DATA; both callers own descriptor-safe copying.
export function candidateInputs(v:unknown,operationId:unknown):boolean {
 if(!keys(v,['operationId','candidateSha256','sourceCommit','sourceTree','applicationId','version','files','observation','priorCreateFinality'])||!uuid(v.operationId)||v.operationId!==operationId||!hex(v.candidateSha256,64)||!hex(v.sourceCommit,40)||!hex(v.sourceTree,40)||v.observation!=='current-bundle-only'||v.priorCreateFinality!=='not-established')return false;
 if(typeof v.applicationId!=='string'||v.applicationId.length>255||!/^([A-Za-z][A-Za-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*$/.test(v.applicationId)||!keys(v.version,['name','build'])||typeof v.version.name!=='string'||!/^[0-9A-Za-z.+-]{1,64}$/.test(v.version.name)||!bounded(v.version.build,2100000000))return false;
 if(!Array.isArray(v.files)||v.files.length!==3)return false;
 const names=['app-release.aab','store-metadata.zip','validation-report.json'],bounds=[1073741824,536870912,65536];
 return v.files.every((file,index)=>keys(file,['fileName','bytes','sha256'])&&file.fileName===names[index]&&bounded(file.bytes,bounds[index]!)&&hex(file.sha256,64));
}
const preparedLimits = ['non-publishing', 'prepare-not-execute', 'temporary-edit-may-expire',
  'current-bundle-not-historical-finality', 'saved-inputs-not-atomic'];
// Predicate for already copied bounded DATA; no native/file/Store authority.
// Both callers retain their own exact envelope. These are actual shared fields,
// never a fabricated Prepare record or authority grant.
export function localStoreSummaryIdentity(i: Record<string, unknown>, operationId: unknown): boolean {
  if (!uuid(i.operationId) || i.operationId !== operationId || !hex(i.candidateSha256, 64) || !hex(i.intentSha256, 64) || !hex(i.sourceCommit, 40) || !hex(i.sourceTree, 40) ||
    typeof i.applicationId !== 'string' || i.applicationId.length > 255 || !/^([A-Za-z][A-Za-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*$/.test(i.applicationId) ||
    !keys(i.version, ['name', 'build']) || typeof i.version.name !== 'string' || !/^[0-9A-Za-z.+-]{1,64}$/.test(i.version.name) ||
    !counter(i.version.build) || i.version.build < 1 || i.version.build > 2100000000 ||
    !sameOfflineData(i.destination, { channel: 'internal', releaseStatus: 'completed' }) ||
    typeof i.observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(i.observedAt) || !Number.isFinite(Date.parse(i.observedAt))) return false;
  return new Date(i.observedAt).toISOString() === i.observedAt.replace('Z', '.000Z');
}
export function preparedIntentSummary(i: unknown, operationId: unknown): i is LocalPreparedIntent {
  return keys(i, ['operationId', 'candidateSha256', 'intentSha256', 'storePreconditionSha256', 'sourceCommit', 'sourceTree', 'applicationId', 'version', 'destination', 'observedAt', 'limitations']) &&
    hex(i.storePreconditionSha256, 64) && sameOfflineData(i.limitations, preparedLimits) && localStoreSummaryIdentity(i, operationId);
}
export function iosPreparedIntentSummary(i: unknown, operationId: unknown): i is IOSPreparedIntent {
  if (!keys(i, ['operationId', 'candidateSha256', 'intentSha256', 'storePreconditionSha256', 'sourceCommit', 'sourceTree', 'bundleId', 'appStoreAppId', 'version', 'destination', 'observedAt', 'limitations']) ||
    !uuid(i.operationId) || i.operationId !== operationId || !hex(i.candidateSha256, 64) || !hex(i.intentSha256, 64) || !hex(i.storePreconditionSha256, 64) || !hex(i.sourceCommit, 40) || !hex(i.sourceTree, 40) ||
    typeof i.bundleId !== 'string' || i.bundleId.length > 255 || !/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/.test(i.bundleId) ||
    typeof i.appStoreAppId !== 'string' || !/^[0-9]{1,20}$/.test(i.appStoreAppId) ||
    !keys(i.version, ['name', 'build']) || typeof i.version.name !== 'string' || !/^[0-9A-Za-z.+-]{1,64}$/.test(i.version.name) || !bounded(i.version.build, 2100000000) ||
    !sameOfflineData(i.destination, {channel:'testflight-internal'}) ||
    !sameOfflineData(i.limitations, ['non-publishing','prepare-not-execute','current-asc-snapshot-may-change','current-bundle-not-historical-finality','saved-inputs-not-atomic']) ||
    typeof i.observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(i.observedAt) || !Number.isFinite(Date.parse(i.observedAt))) return false;
  return new Date(i.observedAt).toISOString() === i.observedAt.replace('Z', '.000Z');
}
// Shared exact13-field DATA, not an Execute context or previous finality.
export function executionReceiptSummary(i: unknown, operationId: unknown): i is LocalExecutionReceipt {
  return keys(i, ['operationId', 'candidateSha256', 'intentSha256', 'receiptSha256', 'authorizationId', 'sourceCommit', 'sourceTree', 'applicationId', 'version', 'destination', 'observedAt', 'result', 'limitations']) &&
    uuid(i.authorizationId) && hex(i.receiptSha256, 64) && member(['accepted', 'reconciled'], i.result) &&
    sameOfflineData(i.limitations, ['internal-testing-only', 'not-public-release', 'prior-prepare-finality-not-established', 'saved-inputs-not-atomic']) &&
    localStoreSummaryIdentity(i, operationId);
}
// Same-invocation TestFlight result DATA, not a Store upload/recovery grant.
export function iosExecutionReceiptSummary(i: unknown, operationId: unknown): i is IOSExecutionReceipt {
  if (!keys(i, ['operationId','candidateSha256','intentSha256','receiptSha256','authorizationId','sourceCommit','sourceTree','bundleId','appStoreAppId','version','destination','observedAt','result','limitations']) ||
    !uuid(i.operationId) || i.operationId !== operationId || !uuid(i.authorizationId) ||
    !hex(i.candidateSha256,64) || !hex(i.intentSha256,64) || !hex(i.receiptSha256,64) || !hex(i.sourceCommit,40) || !hex(i.sourceTree,40) ||
    typeof i.bundleId !== 'string' || i.bundleId.length > 255 || !/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/.test(i.bundleId) ||
    typeof i.appStoreAppId !== 'string' || !/^[0-9]{1,20}$/.test(i.appStoreAppId) ||
    !keys(i.version,['name','build']) || typeof i.version.name !== 'string' || !/^[0-9A-Za-z.+-]{1,64}$/.test(i.version.name) || !bounded(i.version.build,2100000000) ||
    !sameOfflineData(i.destination,{channel:'testflight-internal'}) || !member(['accepted','reconciled'],i.result) ||
    !sameOfflineData(i.limitations,['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic']) ||
    typeof i.observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(i.observedAt) || !Number.isFinite(Date.parse(i.observedAt))) return false;
  return new Date(i.observedAt).toISOString() === i.observedAt.replace('Z','.000Z');
}
// Shared exact13-field recovery receipt DATA. Each caller separately validates
// its live/offline observation and original finality fields; no synthetic owner.
export function recoveryReceiptFields(i: unknown, operationId: unknown): boolean {
  return keys(i, ['operationId', 'candidateSha256', 'intentSha256', 'receiptSha256', 'authorizationId', 'sourceCommit', 'sourceTree', 'applicationId', 'version', 'destination', 'observedAt', 'result', 'limitations']) &&
    uuid(i.authorizationId) && hex(i.receiptSha256, 64) && i.result === 'reconciled' &&
    sameOfflineData(i.limitations, ['non-publishing', 'not-retry-permission', 'old-evidence-preserved', 'saved-inputs-not-atomic']) &&
    localStoreSummaryIdentity(i, operationId);
}
function request(v:unknown):boolean{
 if(object(v)&&stageHistoryAction(v.action))return keys(v,[...contextKeys,'platform','stageOperationId'])&&typeof v.projectId==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v.projectId)&&v.executionMode==='local'&&member(v.action==='review-external-readiness'?['ios']:['android','ios'],v.platform)&&uuid(v.stageOperationId);
 const candidate=object(v)&&candidateHistoryAction(v.action),ios=object(v)&&Object.hasOwn(v,'platform');
 return (!ios||v.platform==='ios'&&['review-inputs','abandon-inputs','review-prepared','review-execution','review-reconcile'].includes(v.action as string))&&keys(v,[...contextKeys,...(candidate?['candidateOperationId']:[]),...(ios?['platform']:[])])&&typeof v.projectId==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v.projectId)&&v.executionMode==='local'&&(candidate?uuid(v.candidateOperationId):member(['enroll','verify'],v.action));
}
export function parseLocalHistoryRequest(input:unknown):PrepareLocalHistory|null{
 try{const v=copyBoundedComparisonData(input,8192);return request(v)?v as PrepareLocalHistory:null;}catch{return null;}
}
export function encodeLocalHistoryRequest(command:LocalHistoryCommand,input:unknown):Uint8Array|null{
 try{const v=copyBoundedComparisonData(input,8192);
 const valid=command==='prepare_local_release_history'?request(v):command==='local_release_history_status'?keys(v,[]):keys(v,command==='start_local_release_history'?['operationId','ownerGeneration','consentVersion']:['operationId','ownerGeneration'])&&token(v.operationId)&&token(v.ownerGeneration)&&(command!=='start_local_release_history'||member([LOCAL_HISTORY_CONSENT,LOCAL_CANDIDATE_CONSENT,IOS_CANDIDATE_CONSENT],v.consentVersion));
 if(!valid)return null;const bytes=new TextEncoder().encode(JSON.stringify(v));return bytes.length<=8192?bytes:null;
 }catch{return null;}
}
export function parseLocalHistoryStatus(input:unknown):LocalHistoryStatus|null{
 try{const v=copyBoundedComparisonData(input,16384);
 if(!keys(v,['schemaVersion','statusRevision','availability','operation'])||v.schemaVersion!==1||!counter(v.statusRevision)||!member(['available','busy','shutdown','cleanup-unknown','document-lost','unsupported-platform','runtime-unqualified'],v.availability))return null;
 const op=v.operation;if(op===null)return v as unknown as LocalHistoryStatus;
 if(!keys(op,['operationId','ownerGeneration','context','phase','intentUsable','outcome','reason','result'])||!token(op.operationId)||!token(op.ownerGeneration)||!member(phases,op.phase)||typeof op.intentUsable!=='boolean'||!member(reasons,op.reason))return null;
 if(!request(op.context))return null;
 const context=op.context as PrepareLocalHistory,candidate=candidateHistoryAction(context.action);
 if(op.phase==='terminal'){if(!member(outcomes,op.outcome)||op.outcome==='unknown'||op.intentUsable)return null;}
 else if(op.phase==='unknown'){if(op.outcome!=='unknown'||op.reason!=='cleanup-unknown'||op.intentUsable||op.result!==null)return null;}
 else if(op.outcome!==null||op.result!==null||op.intentUsable&&op.phase!=='awaiting-consent')return null;
 if(op.result!==null){const r=op.result;
  if(op.phase!=='terminal'||op.outcome!=='complete'||op.reason!=='none'||!keys(r,['schemaVersion','scope','enrolled','headSequence','history','limitations',...((context.action==='review-prepared'||context.action==='review-reconcile'||context.action==='review-stage-prepared')?['preparedIntent']:(context.action==='review-execution'||context.action==='review-stage-execution')?['executionReceipt']:context.action==='review-external-readiness'?['readinessReceipt']:context.action==='review-recovery'?['reconciliationReceipt']:candidate?['candidateInputs']:[])])||r.schemaVersion!==1||r.scope!=='local-release-history'||r.enrolled!==true||!counter(r.headSequence)||r.headSequence<1||r.headSequence>513||!sameOfflineData(r.limitations,limits)||!Array.isArray(r.history)||r.history.length>64||r.history.length>r.headSequence-1)return null;
  const ids=new Set<string>();
  for(const row of r.history){
   if(!keys(row,['operationId','phase','recoveryRequired'])||typeof row.operationId!=='string'||!/^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(row.operationId)||ids.has(row.operationId)||!member(journalPhases,row.phase)||row.recoveryRequired!==!['settled-success','settled-failure','target-reconciled','external-ready'].includes(row.phase as string))return null;
   ids.add(row.operationId);
  }
  if(context.action==='review-external-readiness'){
   const selected=r.history.find(row=>row.operationId===context.stageOperationId);
   if(!selected||selected.phase!=='external-ready'||(r.headSequence as number)<12||!parseExternalReadinessSummary(r.readinessReceipt,context.stageOperationId,true))return null;
  }
  if(context.action==='review-stage-prepared'||context.action==='review-stage-execution'){
   const selected=r.history.find(row=>row.operationId===context.stageOperationId),prepared=context.action==='review-stage-prepared';
   const i=prepared?r.preparedIntent:r.executionReceipt;
   if(!selected||selected.phase!==(prepared?'prepared':'settled-success')||!object(i))return null;
   let summary;
   if(prepared){
    if(i.observation!=='current-prepared-files-only'||i.priorPrepareFinality!=='not-established')return null;
    const {observation:_,priorPrepareFinality:__,...body}=i;
    summary=parseStagePreparedSummary(body,context.stageOperationId,context.platform);
   }else{
    if(i.observation!=='current-execution-files-only'||i.priorExecutionFinality!=='not-established')return null;
    const {observation:_,priorExecutionFinality:__,...body}=i;
    summary=parseStageExecutionSummary(body,context.stageOperationId,context.platform);
   }
   if(!summary||(r.headSequence as number)<(summary.stage==='external-testing'?9:13)+(prepared?0:2))return null;
  }
  if(candidate){
   const selected=r.history.find(row=>row.operationId===context.candidateOperationId);
   if(!selected)return null;
   if(context.action==='review-prepared'||context.action==='review-reconcile'){
    const prepared=r.preparedIntent;
    const allowed=context.action==='review-prepared'?(r.headSequence as number)>=5&&selected.phase==='prepared':(r.headSequence as number)>=6&&r.history.at(-1)===selected&&member(['execute-pending','settled-success','settled-failure','reconciliation-required'],selected.phase);
    if(!allowed||!object(prepared)||prepared.observation!=='current-prepared-files-only'||prepared.priorPrepareFinality!=='not-established')return null;
    const {observation:_,priorPrepareFinality:__,...summary}=prepared;
    if(!(context.platform==='ios'?iosPreparedIntentSummary(summary,context.candidateOperationId):preparedIntentSummary(summary,context.candidateOperationId)))return null;
   }else if(context.action==='review-execution'){
    const receipt=r.executionReceipt;
    if((r.headSequence as number)<7||selected.phase!=='settled-success'||!object(receipt)||receipt.observation!=='current-execution-files-only'||receipt.priorExecutionFinality!=='not-established')return null;
    const {observation:_,priorExecutionFinality:__,...summary}=receipt;
    if(!(context.platform==='ios'?iosExecutionReceiptSummary(summary,context.candidateOperationId):executionReceiptSummary(summary,context.candidateOperationId)))return null;
   }else if(context.action==='review-recovery'){
    const receipt=r.reconciliationReceipt;
    if((r.headSequence as number)<7||selected.phase!=='target-reconciled'||!object(receipt)||receipt.observation!=='current-recovery-files-only'||receipt.priorExecutionFinality!=='not-established')return null;
    const {observation:_,priorExecutionFinality:__,...summary}=receipt;
    if(!recoveryReceiptFields(summary,context.candidateOperationId))return null;
   }else if(context.action==='abandon-inputs'){
    if(selected.phase!=='settled-failure'||r.history.at(-1)!==selected||r.candidateInputs!==null)return null;
   }else if(selected.phase==='inputs-ready'){
    if(!(context.platform==='ios'?iosCandidateInputs(r.candidateInputs,context.candidateOperationId):candidateInputs(r.candidateInputs,context.candidateOperationId)))return null;
   }else if(!['inputs-pending','settled-failure'].includes(selected.phase as string)||r.candidateInputs!==null)return null;
  }
 }else if(op.outcome==='complete')return null;
 return v as unknown as LocalHistoryStatus;
 }catch{return null;}
}
export function localHistoryError(_value?:unknown):ApiError{return{code:'local_release_history_unavailable',retryable:false,message:'The original local history operation is unavailable or unverified. Refresh its status; do not retry until cleanup is confirmed.'};}
