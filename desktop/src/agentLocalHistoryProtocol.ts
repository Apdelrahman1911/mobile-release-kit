import { validStorePermissionRevision } from './agentStorePermissionRevision.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
export type LocalHistoryKind='enroll'|'verify'|'review-inputs';
export interface LocalHistoryReview {readonly kind:LocalHistoryKind;readonly operationId:string;readonly ownerGeneration:string;readonly statusRevision:number;readonly platform?:'ios';readonly candidateOperationId?:string}
export interface LocalHistoryRequestStatus {
  readonly origin: { readonly projectId: string; readonly serviceInstance: string; readonly requestId: string };
  readonly grantId: string; readonly reviewId: string; readonly revision: number; readonly review: LocalHistoryReview;
  readonly state: 'queued' | 'starting' | 'running' | 'stopping' | 'finishing' | 'complete' | 'failed' | 'refused' | 'cancelled' | 'expired' | 'unknown';
  readonly settlement: 'pending' | 'settled' | 'unknown'; readonly reason: string;
  readonly operation: { readonly operationId: string; readonly ownerGeneration: string; readonly statusRevision: number } | null;
  readonly outcome: 'complete' | 'failed' | 'refused' | 'cancelled' | 'timed-out' | 'unknown' | null;
  readonly result: Readonly<Record<string, unknown>> | null;
}
export interface AgentLocalHistoryAccess {
  readonly permissionRevision:string; // MAIN comparison only; not CLI request authority.
  readonly serviceInstance: string | null; readonly projectId: string | null; readonly grantId: string | null; readonly reviewId: string | null;
  readonly review: LocalHistoryReview | null; readonly enabled: boolean; readonly remainingMs: number; readonly consumed: boolean;
  readonly pending: boolean; readonly unknown: boolean; readonly requestId: string | null; readonly status: LocalHistoryRequestStatus | null;
}
export interface AgentLocalHistoryPort { status(): Promise<unknown>; allow(review: LocalHistoryReview, expectedPermissionRevision:string): Promise<unknown>; revoke(): Promise<unknown> }
const id = (v: unknown): v is string => typeof v === 'string' && v.length === 32 && /^[a-f0-9]{32}$/.test(v) && v !== '0'.repeat(32);
const sha = (v: unknown): v is string => typeof v === 'string' && v.length === 64 && /^[a-f0-9]{64}$/.test(v);
const uuid = (v: unknown) => typeof v === 'string' && v.length === 36 && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v) && v !== '00000000-0000-0000-0000-000000000000';
const number = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min && v <= max;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const oneOf = (v: unknown, a: readonly string[]) => typeof v === 'string' && a.includes(v);
export const localHistoryDelegateConsent=(r:LocalHistoryReview):string=>r.kind==='review-inputs'?`agent-local-history-${r.platform==='ios'?'ios':'android'}-inputs-once-v1`:`agent-local-history-${r.kind}-once-v1`;
function review(v:unknown):v is LocalHistoryReview{
 if(!record(v)||!oneOf(v.kind,['enroll','verify','review-inputs']))return false;
 const input=v.kind==='review-inputs';
 return keys(v,['kind','operationId','ownerGeneration','statusRevision',...(input?['candidateOperationId']:[]),...(input&&v.platform==='ios'?['platform']:[])])&&
  id(v.operationId)&&id(v.ownerGeneration)&&number(v.statusRevision,1,0xffff_fffe)&&(!input||uuid(v.candidateOperationId));
}
// Only after the bounded copy has removed accessors/prototypes/cycles.
function freeze<T>(v:T):T {if(v&&typeof v==='object'){for(const item of Object.values(v))freeze(item);Object.freeze(v);}return v;}
export function parseLocalHistoryReview(raw: unknown): LocalHistoryReview | null { try { const v=copyBoundedComparisonData(raw,1024,24); return review(v) ? freeze(v) : null; } catch { return null; } }
export const sameLocalHistoryReview = (a: LocalHistoryReview | null, b: LocalHistoryReview | null) => !!a && !!b && a.kind===b.kind && a.operationId===b.operationId && a.ownerGeneration===b.ownerGeneration && a.statusRevision===b.statusRevision && a.platform===b.platform && a.candidateOperationId===b.candidateOperationId;
const historyPhases=['inputs-pending','inputs-ready','prepare-pending','promotion-pending','prepared','execute-pending','settled-success','settled-failure','reconciliation-required','target-reconciled','external-ready'];
const limits=['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'];
function result(v:unknown,r:LocalHistoryReview):boolean{
 if(!keys(v,['enrolled','headSequence','history','candidateInputs','limitations'])||v.enrolled!==true||!number(v.headSequence,1,513)||!Array.isArray(v.history)||v.history.length>64||v.history.length>=v.headSequence||JSON.stringify(v.limitations)!==JSON.stringify(limits))return false;
 if(!v.history.every(row=>keys(row,['operationId','phase','recoveryRequired'])&&uuid(row.operationId)&&oneOf(row.phase,historyPhases)&&typeof row.recoveryRequired==='boolean'&&row.recoveryRequired!==oneOf(row.phase,['settled-success','settled-failure','target-reconciled','external-ready']))||new Set(v.history.map(row=>row.operationId)).size!==v.history.length)return false;
 if(r.kind!=='review-inputs')return v.candidateInputs===null;
 const row=v.history.find(row=>row.operationId===r.candidateOperationId);if(!row)return false;
 if(['inputs-pending','settled-failure'].includes(row.phase))return v.candidateInputs===null;
 const c=v.candidateInputs,ios=r.platform==='ios';
 if(row.phase!=='inputs-ready'||!keys(c,['operationId','candidateSha256','sourceCommit','sourceTree','application','version','files','archive','observation','priorCreateFinality'])||c.operationId!==r.candidateOperationId||!sha(c.candidateSha256)||![c.sourceCommit,c.sourceTree].every(v=>typeof v==='string'&&/^[a-f0-9]{40}$(?![\s\S])/.test(v))||typeof c.application!=='string'||c.application.length>255||!(ios?/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$(?![\s\S])/:/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$(?![\s\S])/).test(c.application)||!keys(c.version,['name','build'])||typeof c.version.name!=='string'||!/^[A-Za-z0-9.+-]{1,64}$(?![\s\S])/.test(c.version.name)||!number(c.version.build,1,2100000000)||!Array.isArray(c.files)||c.files.length!==3||c.observation!=='current-bundle-only'||c.priorCreateFinality!=='not-established')return false;
 if(!c.files.every(f=>keys(f,['fileName','bytes','sha256'])&&sha(f.sha256)&&number(f.bytes,1,4294967296)))return false;
 const name=c.files[0].fileName;
 if(ios?typeof name!=='string'||!/^export\/[^/\\:\x00-\x1f\x7f]+\.ipa$(?![\s\S])/.test(name)||new TextEncoder().encode(name.slice(7)).length>255:name!=='app-release.aab'||c.files[0].bytes>1073741824)return false;
 if(c.files[1].fileName!=='store-metadata.zip'||c.files[1].bytes>536870912||c.files[2].fileName!=='validation-report.json'||c.files[2].bytes>65536)return false;
 return ios?keys(c.archive,['directory','entries','bytes','sha256'])&&c.archive.directory==='archive.xcarchive'&&number(c.archive.entries,1,100000)&&number(c.archive.bytes,1,8589934592)&&sha(c.archive.sha256):c.archive===null;
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'];
function status(v: unknown): v is LocalHistoryRequestStatus {
  if (!keys(v,['origin','grantId','reviewId','revision','review','state','settlement','reason','operation','outcome','result']) || !keys(v.origin,['projectId','serviceInstance','requestId']) ||
      !Object.values(v.origin).every(id) || !id(v.grantId) || !id(v.reviewId) || !number(v.revision,1,0xffff_fffe) || !review(v.review) || !oneOf(v.reason,reasons) ||
      !(v.operation===null || keys(v.operation,['operationId','ownerGeneration','statusRevision']) && v.operation.operationId===v.review.operationId && v.operation.ownerGeneration===v.review.ownerGeneration && number(v.operation.statusRevision,v.review.statusRevision,0xffff_fffe)) ||
      !(v.result===null || result(v.result,v.review))) return false;
  if (v.state==='unknown') return v.settlement==='unknown' && v.outcome==='unknown' && v.result===null && oneOf(v.reason,['cleanup-unknown','history-unavailable']);
  if (oneOf(v.state,['complete','failed','refused','cancelled','expired'])) {
    if(v.settlement!=='settled'||v.operation===null)return false;
    if(v.state==='complete')return v.outcome==='complete'&&v.reason==='none'&&v.result!==null;
    return !oneOf(v.reason,['none','cleanup-unknown','history-unavailable'])&&v.result===null&&(v.state==='failed'?oneOf(v.outcome,['failed','timed-out']):v.state==='cancelled'?oneOf(v.outcome,['cancelled','refused']):v.outcome==='refused');
  }
  return oneOf(v.state,['queued','starting','running','stopping','finishing'])&&v.settlement==='pending'&&v.outcome===null&&v.result===null&&!oneOf(v.reason,['cleanup-unknown','history-unavailable']);
}
export function parseAgentLocalHistoryAccess(raw: unknown): AgentLocalHistoryAccess | null {
  try {
    const v=copyBoundedComparisonData(raw,24576,1024);
    if(!keys(v,['permissionRevision','serviceInstance','projectId','grantId','reviewId','review','enabled','remainingMs','consumed','pending','unknown','requestId','status']) ||
      !validStorePermissionRevision(v.permissionRevision) || !['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean') || !number(v.remainingMs,0,300000) || !(v.requestId===null||id(v.requestId)))return null;
    const present=['serviceInstance','projectId','grantId','reviewId'].every(k=>id(v[k])) && review(v.review);
    if(!present && !['serviceInstance','projectId','grantId','reviewId','review'].every(k=>v[k]===null))return null;
    if(v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||!v.enabled&&v.remainingMs!==0||v.consumed!==(v.requestId!==null)||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
    if(v.status!==null){
      if(!status(v.status)||v.status.origin.projectId!==v.projectId||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.requestId!==v.requestId||
        v.status.grantId!==v.grantId||v.status.reviewId!==v.reviewId||!sameLocalHistoryReview(v.status.review,v.review as LocalHistoryReview)||
        v.pending!==(v.status.settlement!=='settled')||v.unknown!==(v.status.state==='unknown'))return null;
    }
    return freeze(v) as unknown as AgentLocalHistoryAccess;
  }catch{return null;}
}
export function createAgentLocalHistoryPort(invoke:(name:string,body:Uint8Array)=>Promise<unknown>):AgentLocalHistoryPort {
  const send=(name:string,body:object)=>{const bytes=new TextEncoder().encode(JSON.stringify(body));return bytes.length<=1024?invoke(name,bytes):Promise.reject({code:'agent_local_history_invalid'});};
  return Object.freeze({status:()=>send('agent_local_history_access',{}),revoke:()=>send('revoke_agent_local_history',{}),allow:(raw:LocalHistoryReview,expectedPermissionRevision:string)=>{
    const r=parseLocalHistoryReview(raw);return r&&validStorePermissionRevision(expectedPermissionRevision)?send('allow_agent_local_history',{expectedPermissionRevision,kind:r.kind,operationId:r.operationId,ownerGeneration:r.ownerGeneration,expectedStatusRevision:r.statusRevision,consentVersion:localHistoryDelegateConsent(r)}):Promise.reject({code:'agent_local_history_invalid'});
  }});
}
export function localHistoryCommands(raw:AgentLocalHistoryAccess|null):readonly string[]{const s=parseAgentLocalHistoryAccess(raw);if(!s?.grantId)return [];
  const ids=`${s.projectId} ${s.serviceInstance}`;return s.requestId?[`mrk local-history-status ${ids} ${s.requestId}`,`mrk local-history-cancel ${ids} ${s.requestId}`]:s.enabled?[`mrk local-history-submit ${ids} ${s.grantId} ${s.reviewId} --reviewed`]:[];
}
