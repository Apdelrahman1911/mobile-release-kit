// Closed comparison DATA only. No native material, journal, prepared owner or
// Start authority can be reconstructed from one of these objects.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
export type LocalHistoryKind='enroll'|'verify'|'review-inputs'|'review-prepared'|'review-execution'|'review-reconcile'|'review-recovery'|'review-stage-prepared'|'review-stage-execution'|'review-external-readiness';
export interface LocalHistorySelection {readonly kind:LocalHistoryKind;readonly platform?:'android'|'ios';readonly candidateOperationId?:string;readonly stageOperationId?:string}
export interface LocalHistoryReview extends LocalHistorySelection {readonly operationId:string;readonly ownerGeneration:string;readonly statusRevision:number}
export interface LocalHistoryOrigin {readonly projectId:string;readonly serviceInstance:string;readonly requestId:string}
export interface LocalHistoryPreparationStatus {readonly origin:LocalHistoryOrigin;readonly selection:LocalHistorySelection;readonly revision:number;
 readonly phase:'queued'|'preparing'|'prepared'|'handed-off'|'refused'|'cancelled'|'expired'|'unknown';readonly settlement:'pending'|'settled'|'unknown';readonly reason:string;
 readonly review:LocalHistoryReview|null;readonly remainingMs:number}
export interface LocalHistoryPreparationComparison {readonly runtimeProjectId:string;readonly request:LocalHistoryPreparationStatus;readonly live:LocalHistoryReview|null}
const id=(v:unknown):v is string=>typeof v==='string'&&v.length===32&&/^[a-f0-9]{32}$/.test(v)&&v!=='0'.repeat(32);
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&/^[a-f0-9]+$(?![\s\S])/.test(v);
const uuid=(v:unknown):v is string=>typeof v==='string'&&v.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const int=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,k:readonly string[]):v is Record<string,unknown>=>obj(v)&&Object.keys(v).length===k.length&&k.every(x=>Object.hasOwn(v,x));
const one=(v:unknown,choices:readonly string[])=>typeof v==='string'&&choices.includes(v);
const stage=(v:unknown)=>one(v,['review-stage-prepared','review-stage-execution','review-external-readiness']);
const candidate=(v:unknown)=>one(v,['review-inputs','review-prepared','review-execution','review-reconcile','review-recovery']);
export const localHistoryPreparationReasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'] as const;
/** Only call on the bounded getter-free copy, never arbitrary renderer objects. */
export function validLocalHistorySelection(v:unknown,extra:readonly string[]=[]):v is LocalHistorySelection {
 if(!obj(v))return false;
 if(one(v.kind,['enroll','verify']))return keys(v,['kind',...extra]);
 if(candidate(v.kind))return keys(v,['kind','candidateOperationId',...(v.platform==='ios'?['platform']:[]),...extra])&&uuid(v.candidateOperationId)&&(v.kind!=='review-recovery'||v.platform===undefined);
 return stage(v.kind)&&keys(v,['kind','stageOperationId','platform',...extra])&&uuid(v.stageOperationId)&&one(v.platform,v.kind==='review-external-readiness'?['ios']:['android','ios']);
}
export function validLocalHistoryReview(v:unknown):v is LocalHistoryReview {
 return validLocalHistorySelection(v,['operationId','ownerGeneration','statusRevision'])&&id((v as unknown as Record<string,unknown>).operationId)&&id((v as unknown as Record<string,unknown>).ownerGeneration)&&int((v as unknown as Record<string,unknown>).statusRevision,1,0xffff_fffe);
}
export const sameLocalHistorySelection=(a:LocalHistorySelection,b:LocalHistorySelection)=>a.kind===b.kind&&a.platform===b.platform&&a.candidateOperationId===b.candidateOperationId&&a.stageOperationId===b.stageOperationId;
export const sameLocalHistoryOriginal=(a:LocalHistoryReview|null,b:LocalHistoryReview|null)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration&&sameLocalHistorySelection(a,b);
export const validLocalHistoryOrigin=(v:unknown):v is LocalHistoryOrigin=>keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(id);
export const sameLocalHistoryOrigin=(a:LocalHistoryOrigin,b:LocalHistoryOrigin)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.requestId===b.requestId;
export function validLocalHistoryPreparation(v:unknown):v is LocalHistoryPreparationStatus {
 if(!keys(v,['origin','selection','revision','phase','settlement','reason','review','remainingMs'])||!validLocalHistoryOrigin(v.origin)||!validLocalHistorySelection(v.selection)||!int(v.revision,1,0xffff_fffe)||!int(v.remainingMs,0,300000)||!one(v.reason,localHistoryPreparationReasons)||!(v.review===null||validLocalHistoryReview(v.review)&&sameLocalHistorySelection(v.selection,v.review)))return false;
 if(v.phase==='queued')return v.settlement==='pending'&&v.review===null&&v.remainingMs===0&&v.reason==='none';
 if(v.phase==='preparing')return v.settlement==='pending'&&v.remainingMs===0&&!one(v.reason,['cleanup-unknown','history-unavailable']);
 if(v.phase==='prepared')return v.settlement==='settled'&&v.review!==null&&v.reason==='none'&&v.remainingMs>0;
 if(v.phase==='handed-off')return v.settlement==='settled'&&v.review!==null&&v.reason==='none'&&v.remainingMs===0;
 if(v.phase==='unknown')return v.settlement==='unknown'&&v.remainingMs===0&&one(v.reason,['cleanup-unknown','history-unavailable']);
 return one(v.phase,['refused','cancelled','expired'])&&v.settlement==='settled'&&v.remainingMs===0&&!one(v.reason,['none','cleanup-unknown','history-unavailable']);
}
export function validLocalHistoryComparison(v:unknown):v is LocalHistoryPreparationComparison {
 return keys(v,['runtimeProjectId','request','live'])&&typeof v.runtimeProjectId==='string'&&/^[A-Za-z0-9_-]{1,64}$(?![\s\S])/.test(v.runtimeProjectId)&&validLocalHistoryPreparation(v.request)&&
  (v.live===null||v.request.phase==='prepared'&&validLocalHistoryReview(v.live)&&sameLocalHistorySelection(v.live,v.request.selection)&&sameLocalHistoryOriginal(v.request.review,v.live)&&v.live.statusRevision>=v.request.review!.statusRevision);
}
const freeze=<T>(v:T):T=>{if(v&&typeof v==='object'){for(const value of Object.values(v))freeze(value);Object.freeze(v);}return v;};
export function parseLocalHistoryPreparation(raw:unknown):LocalHistoryPreparationComparison|null {try{const v=copyBoundedComparisonData(raw,2048,96);return validLocalHistoryComparison(v)?freeze(v):null;}catch{return null;}}
export function parseLocalHistoryOrigin(raw:unknown):LocalHistoryOrigin|null {try{const v=copyBoundedComparisonData(raw,256,8);return validLocalHistoryOrigin(v)?freeze(v):null;}catch{return null;}}
export const localHistoryPreparationHeld=(v:LocalHistoryPreparationComparison)=>one(v.request.phase,['queued','preparing','prepared','unknown']);
/** Mirrors the closed native summary. These current-file labels are explicitly
 * not provider/readiness authority or proof that an earlier process returned. */
export function validLocalHistoryReviewedFiles(v:unknown,r:LocalHistoryReview):boolean {
 const k=r.kind,prepared=one(k,['review-prepared','review-reconcile','review-stage-prepared']);
 const execution=one(k,['review-execution','review-stage-execution']),recovery=k==='review-recovery',readiness=k==='review-external-readiness';
 if(!(prepared||execution||recovery||readiness)||!keys(v,['kind','operationId','candidateSha256','intentSha256','receiptSha256','sourceCommit','sourceTree','application','version','destination','stage','candidateOperationId','predecessorOperationId','predecessorReceiptSha256','executionReceiptSha256','observation','priorFinality']))return false;
 const ios=r.platform==='ios',isStage=stage(k),selected=r.stageOperationId??r.candidateOperationId;
 if(v.kind!==(prepared?'prepared':execution?'execution':recovery?'reconciliation':'external-readiness')||v.observation!==(prepared?'current-prepared-files-only':execution?'current-execution-files-only':recovery?'current-recovery-files-only':'current-external-readiness-files-only')||v.priorFinality!=='not-established'||v.operationId!==selected||!uuid(v.operationId)||!hex(v.candidateSha256,64)||!hex(v.intentSha256,64)||!(prepared?v.receiptSha256===null:hex(v.receiptSha256,64))||!hex(v.sourceCommit,40)||!hex(v.sourceTree,40))return false;
 if(typeof v.application!=='string'||v.application.length>255||!(ios?/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$(?![\s\S])/:/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$(?![\s\S])/).test(v.application)||!keys(v.version,['name','build'])||typeof v.version.name!=='string'||!/^[A-Za-z0-9.+-]{1,64}$(?![\s\S])/.test(v.version.name)||!int(v.version.build,1,2100000000)||!keys(v.destination,['channel','releaseStatus','automaticRelease']))return false;
 const d=v.destination;
 if(isStage?!one(v.stage,['external-testing','production-submit'])||!uuid(v.candidateOperationId)||v.candidateOperationId===v.operationId:v.stage!==null||v.candidateOperationId!==null)return false;
 if(ios){if(d.releaseStatus!==null||d.channel!==(v.stage===null?'testflight-internal':v.stage==='external-testing'?'testflight-external':'app-store-review')||d.automaticRelease!==(v.stage==='production-submit'?false:null))return false;}
 else if(d.automaticRelease!==null||d.releaseStatus!==(v.stage==='production-submit'?'draft':'completed')||(v.stage===null?d.channel!=='internal':v.stage==='production-submit'?d.channel!=='production':typeof d.channel!=='string'||d.channel.trim().length===0||[...d.channel].length>100||/[\0\r\n]/.test(d.channel)||one(d.channel,['internal','production'])))return false;
 if(readiness)return ios&&v.stage==='external-testing'&&v.predecessorOperationId===null&&v.predecessorReceiptSha256===null&&hex(v.executionReceiptSha256,64);
 if(isStage)return v.executionReceiptSha256===null&&hex(v.predecessorReceiptSha256,64)&&uuid(v.predecessorOperationId)&&v.predecessorOperationId!==v.operationId&&(v.stage==='external-testing'?v.predecessorOperationId===v.candidateOperationId:v.predecessorOperationId!==v.candidateOperationId);
 return v.predecessorOperationId===null&&v.predecessorReceiptSha256===null&&v.executionReceiptSha256===null;
}
