import { validStorePermissionRevision } from './agentStorePermissionRevision.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { validStoreReleaseReview, validStoreReleaseResult, storeReleaseFromContext } from './agentStoreRelease.ts';
import type { StoreReleaseReview } from './agentStoreRelease.ts';
export type StoreKind = 'access-check' | 'candidate-prepare' | 'execute' | 'reconcile';
export type StorePlatform = 'android' | 'ios';
export interface StoreReview {
  readonly kind: StoreKind; readonly platform: StorePlatform; readonly operationId: string; readonly ownerGeneration: string; readonly statusRevision: number;
  readonly savedConfig: { readonly bytes: number; readonly sha256: string };
  readonly savedVersion: { readonly bytes: number; readonly sha256: string; readonly name: string; readonly build: number };
  readonly candidate: { readonly operationId: string; readonly sha256: string } | null;
  readonly release?: StoreReleaseReview;
}
export interface StoreRequestStatus {
  readonly origin: { readonly projectId: string; readonly serviceInstance: string; readonly requestId: string };
  readonly grantId: string; readonly reviewId: string; readonly revision: number; readonly review: StoreReview;
  readonly state: 'queued' | 'starting' | 'running' | 'stopping' | 'finishing' | 'complete' | 'failed' | 'refused' | 'cancelled' | 'expired' | 'unknown';
  readonly settlement: 'pending' | 'settled' | 'unknown'; readonly reason: string;
  readonly operation: { readonly operationId: string; readonly ownerGeneration: string; readonly statusRevision: number } | null;
  readonly outcome: 'complete' | 'failed' | 'refused' | 'cancelled' | 'timed-out' | 'unknown' | null;
  readonly result: Readonly<Record<string, unknown>> | null;
}
export interface AgentStoreAccess {
  readonly permissionRevision:string; // MAIN comparison only; not CLI request authority.
  readonly serviceInstance: string | null; readonly projectId: string | null; readonly grantId: string | null; readonly reviewId: string | null;
  readonly review: StoreReview | null; readonly enabled: boolean; readonly remainingMs: number; readonly consumed: boolean;
  readonly pending: boolean; readonly unknown: boolean; readonly requestId: string | null; readonly status: StoreRequestStatus | null;
}
export interface AgentStoreAccessPort { status(): Promise<unknown>; allow(review: StoreReview, expectedPermissionRevision:string): Promise<unknown>; revoke(): Promise<unknown> }
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v) && v !== '0'.repeat(32);
const sha = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const uuid = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v) && v !== '00000000-0000-0000-0000-000000000000';
const number = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min && v <= max;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const oneOf = (v: unknown, a: readonly string[]) => typeof v === 'string' && a.includes(v);
export const storeConsent = (r: StoreReview): string => r.kind==='execute'||r.kind==='reconcile' ?
  validStoreReleaseReview(r.release,r.kind,r.platform,r.candidate)?`agent-${r.platform}-store-${r.kind}-${r.release.mode}-once-v1`:'' :
  `agent-${r.platform}-store-${r.kind === 'access-check' ? 'access' : 'candidate-prepare'}-once-v1`;
function review(v: unknown): v is StoreReview {
  const release=record(v)&&(v.kind==='execute'||v.kind==='reconcile');
  return keys(v, ['kind','platform','operationId','ownerGeneration','statusRevision','savedConfig','savedVersion','candidate',...(release?['release']:[])]) &&
    oneOf(v.kind, ['access-check','candidate-prepare','execute','reconcile']) && oneOf(v.platform, ['android','ios']) && id(v.operationId) && id(v.ownerGeneration) && number(v.statusRevision,1,0xffff_fffe) &&
    keys(v.savedConfig,['bytes','sha256']) && number(v.savedConfig.bytes,1,524288) && sha(v.savedConfig.sha256) &&
    keys(v.savedVersion,['bytes','sha256','name','build']) && number(v.savedVersion.bytes,1,65536) && sha(v.savedVersion.sha256) && number(v.savedVersion.build,1,2100000000) &&
    typeof v.savedVersion.name === 'string' && /^[A-Za-z0-9.+-]{1,64}$/.test(v.savedVersion.name) &&
    (v.kind === 'access-check' ? v.candidate === null : keys(v.candidate,['operationId','sha256']) && uuid(v.candidate.operationId) && sha(v.candidate.sha256)) &&
    (!release || validStoreReleaseReview(v.release,v.kind as StoreKind,v.platform as StorePlatform,v.candidate as StoreReview['candidate']));
}
// Only after the bounded copy has removed accessors/prototypes/cycles.
function freeze<T>(v:T):T {if(v&&typeof v==='object'){for(const item of Object.values(v))freeze(item);Object.freeze(v);}return v;}
export function parseStoreReview(raw: unknown): StoreReview | null { try { const v=copyBoundedComparisonData(raw,2048,52); return review(v) ? freeze(v) : null; } catch { return null; } }
export const sameStoreReview = (a: StoreReview | null, b: StoreReview | null) => !!a && !!b && JSON.stringify(a) === JSON.stringify(b);
const accessLimits=['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic'];
export { result as validStoreReport };
function result(v: unknown, r: StoreReview): boolean {
  if (!record(v) || v.kind !== r.kind) return false;
  if(r.kind==='execute'||r.kind==='reconcile')return validStoreReleaseResult(v,r);
  if (r.kind === 'access-check') return keys(v,['kind','findings','limitations']) && Array.isArray(v.findings) && v.findings.length<=16 &&
    v.findings.every(f=>keys(f,['check','status']) && oneOf(f.check,['credential-format','query-prerequisites','runtime-unavailable','bundle-unavailable','store-access']) &&
      oneOf(f.status,['PASS','FAIL','MISSING','BLOCKED','INVALID','SKIP','MANUAL','CONFIGURED','NOT_APPLICABLE'])) && JSON.stringify(v.limitations)===JSON.stringify(accessLimits);
  return keys(v,['kind','headSequence','operationId','candidateSha256','intentSha256','storePreconditionSha256','limitations']) &&
    number(v.headSequence,r.platform==='ios'?5:1,513) && r.candidate?.operationId===v.operationId && r.candidate?.sha256===v.candidateSha256 && sha(v.intentSha256) && sha(v.storePreconditionSha256) &&
    JSON.stringify(v.limitations)===JSON.stringify(['non-publishing','prepare-not-execute',r.platform==='android'?'temporary-edit-may-expire':'current-asc-snapshot-may-change','current-bundle-not-historical-finality','saved-inputs-not-atomic']);
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'];
function status(v: unknown): v is StoreRequestStatus {
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
export function parseAgentStoreAccess(raw: unknown): AgentStoreAccess | null {
  try {
    const v=copyBoundedComparisonData(raw,16384,320);
    if(!keys(v,['permissionRevision','serviceInstance','projectId','grantId','reviewId','review','enabled','remainingMs','consumed','pending','unknown','requestId','status']) ||
      !validStorePermissionRevision(v.permissionRevision) || !['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean') || !number(v.remainingMs,0,300000) || !(v.requestId===null||id(v.requestId)))return null;
    const present=['serviceInstance','projectId','grantId','reviewId'].every(k=>id(v[k])) && review(v.review);
    if(!present && !['serviceInstance','projectId','grantId','reviewId','review'].every(k=>v[k]===null))return null;
    if(v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||!v.enabled&&v.remainingMs!==0||v.consumed!==(v.requestId!==null)||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
    if(v.status!==null){
      if(!status(v.status)||v.status.origin.projectId!==v.projectId||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.requestId!==v.requestId||
        v.status.grantId!==v.grantId||v.status.reviewId!==v.reviewId||!sameStoreReview(v.status.review,v.review as StoreReview)||
        v.pending!==(v.status.settlement!=='settled')||v.unknown!==(v.status.state==='unknown'))return null;
    }
    return freeze(v) as unknown as AgentStoreAccess;
  }catch{return null;}
}
export function createAgentStoreAccessPort(invoke:(name:string,body:Uint8Array)=>Promise<unknown>):AgentStoreAccessPort {
  const send=(name:string,body:object)=>{const bytes=new TextEncoder().encode(JSON.stringify(body));return bytes.length<=1024?invoke(name,bytes):Promise.reject({code:'agent_store_invalid'});};
  return Object.freeze({status:()=>send('agent_store_access',{}),revoke:()=>send('revoke_agent_store',{}),allow:(raw:StoreReview,expectedPermissionRevision:string)=>{
    const r=parseStoreReview(raw);return r&&validStorePermissionRevision(expectedPermissionRevision)?send('allow_agent_store',{expectedPermissionRevision,kind:r.kind,operationId:r.operationId,ownerGeneration:r.ownerGeneration,expectedStatusRevision:r.statusRevision,consentVersion:storeConsent(r)}):Promise.reject({code:'agent_store_invalid'});
  }});
}
export function storeCommands(raw:AgentStoreAccess|null):readonly string[]{const s=parseAgentStoreAccess(raw);if(!s?.grantId)return [];
  const ids=`${s.projectId} ${s.serviceInstance}`;return s.requestId?[`mrk store-status ${ids} ${s.requestId}`,`mrk store-cancel ${ids} ${s.requestId}`]:s.enabled?[`mrk store-submit ${ids} ${s.grantId} ${s.reviewId} --reviewed`]:[];
}
// Called only with the already-validated current Store controller status. It
// selects small review DATA; neither a foreign context nor a query is eligible.
export function storeReviewFromState(raw:unknown,kind:StoreKind,projectId:string|null):StoreReview|null {
  try {
    const s=copyBoundedComparisonData(raw,65536,2048);
    if(!record(s)||s.mode!=='native'||s.pending||s.callersPending||s.historical||s.blocked||s.unconfirmed||s.consentUntil===null||!record(s.status))return null;
    const op=s.status.operation;if(!record(op)||op.phase!=='awaiting-consent'||op.intentUsable!==true||!record(op.context)||op.context.projectId!==projectId)return null;
    const c=op.context;if(!oneOf(c.platform,['android','ios'])||c.query!==undefined||c.iosRecord!==undefined||c.later!==undefined)return null;
    if(kind==='execute'||kind==='reconcile'){
      const release=storeReleaseFromContext(c,kind),v=c.savedVersion;
      if(!release||c.executionMode!=='local'||!record(v))return null;
      return parseStoreReview({kind,platform:c.platform,operationId:op.operationId,ownerGeneration:op.ownerGeneration,statusRevision:s.status.statusRevision,
        savedConfig:c.savedConfig,savedVersion:{bytes:v.bytes,sha256:v.sha256,name:v.name,build:v.build},
        candidate:{operationId:c.candidateOperationId,sha256:c.candidateSha256},release});
    }
    if(c.stage!==undefined)return null;
    if(c.operation!==(kind==='access-check'?'local-store-preflight':'local-store-prepare')||c.executionMode!=='local')return null;
    const v=c.savedVersion;if(!record(v))return null;
    return parseStoreReview({kind,platform:c.platform,operationId:op.operationId,ownerGeneration:op.ownerGeneration,statusRevision:s.status.statusRevision,
      savedConfig:c.savedConfig,savedVersion:{bytes:v.bytes,sha256:v.sha256,name:v.name,build:v.build},
      candidate:kind==='candidate-prepare'?{operationId:c.candidateOperationId,sha256:c.candidateSha256}:null});
  }catch{return null;}
}
