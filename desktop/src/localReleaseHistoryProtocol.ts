import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalHistoryStatus, PrepareLocalHistory } from './localReleaseHistoryTypes.ts';
export const LOCAL_HISTORY_EVENT='local-release-history-state-changed';
export const LOCAL_HISTORY_CONSENT='local-release-history-v1' as const;
export type LocalHistoryCommand='prepare_local_release_history'|'start_local_release_history'|'local_release_history_status'|'cancel_local_release_history';
const limits=['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'];
const journalPhases=['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending','settled-success','settled-failure','reconciliation-required'];
const phases=['awaiting-consent','starting','running','stopping','terminal','unknown'];
const outcomes=['complete','refused','cancelled','timed-out','failed','unknown'];
const reasons=['none','cancelled','context-changed','document-lost','shutdown','timed-out','protocol-error','runtime-unavailable','intent-expired','stale-intent','saved-source-changed','saved-source-invalid','credentials-unavailable','query-prerequisites','command-incomplete','cleanup-unknown','journal-unavailable','enrollment-exists','recovery-required','project-busy'];
const counter=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<4294967295;
const token=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,names:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===names.length&&names.every(n=>Object.hasOwn(v,n));
const member=(values:string[],v:unknown)=>typeof v==='string'&&values.includes(v);
const contextKeys=['projectId','executionMode','action'];
function request(v:unknown):boolean{
 return keys(v,contextKeys)&&typeof v.projectId==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v.projectId)&&v.executionMode==='local'&&member(['enroll','verify'],v.action);
}
export function parseLocalHistoryRequest(input:unknown):PrepareLocalHistory|null{
 try{const v=copyBoundedComparisonData(input,8192);return request(v)?v as PrepareLocalHistory:null;}catch{return null;}
}
export function encodeLocalHistoryRequest(command:LocalHistoryCommand,input:unknown):Uint8Array|null{
 try{const v=copyBoundedComparisonData(input,8192);
 const valid=command==='prepare_local_release_history'?request(v):command==='local_release_history_status'?keys(v,[]):keys(v,command==='start_local_release_history'?['operationId','ownerGeneration','consentVersion']:['operationId','ownerGeneration'])&&token(v.operationId)&&token(v.ownerGeneration)&&(command!=='start_local_release_history'||v.consentVersion===LOCAL_HISTORY_CONSENT);
 if(!valid)return null;const bytes=new TextEncoder().encode(JSON.stringify(v));return bytes.length<=8192?bytes:null;
 }catch{return null;}
}
export function parseLocalHistoryStatus(input:unknown):LocalHistoryStatus|null{
 try{const v=copyBoundedComparisonData(input,16384);
 if(!keys(v,['schemaVersion','statusRevision','availability','operation'])||v.schemaVersion!==1||!counter(v.statusRevision)||!member(['available','busy','shutdown','cleanup-unknown','document-lost','unsupported-platform','runtime-unqualified'],v.availability))return null;
 const op=v.operation;if(op===null)return v as unknown as LocalHistoryStatus;
 if(!keys(op,['operationId','ownerGeneration','context','phase','intentUsable','outcome','reason','result'])||!token(op.operationId)||!token(op.ownerGeneration)||!member(phases,op.phase)||typeof op.intentUsable!=='boolean'||!member(reasons,op.reason))return null;
 if(!request(op.context))return null;
 if(op.phase==='terminal'){if(!member(outcomes,op.outcome)||op.outcome==='unknown'||op.intentUsable)return null;}
 else if(op.phase==='unknown'){if(op.outcome!=='unknown'||op.reason!=='cleanup-unknown'||op.intentUsable||op.result!==null)return null;}
 else if(op.outcome!==null||op.result!==null||op.intentUsable&&op.phase!=='awaiting-consent')return null;
 if(op.result!==null){const r=op.result;
  if(op.phase!=='terminal'||op.outcome!=='complete'||op.reason!=='none'||!keys(r,['schemaVersion','scope','enrolled','headSequence','history','limitations'])||r.schemaVersion!==1||r.scope!=='local-release-history'||r.enrolled!==true||!counter(r.headSequence)||r.headSequence<1||r.headSequence>513||!sameOfflineData(r.limitations,limits)||!Array.isArray(r.history)||r.history.length>64||r.history.length>r.headSequence-1)return null;
  const ids=new Set<string>();
  for(const row of r.history){
   if(!keys(row,['operationId','phase','recoveryRequired'])||typeof row.operationId!=='string'||!/^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(row.operationId)||ids.has(row.operationId)||!member(journalPhases,row.phase)||row.recoveryRequired!==!['settled-success','settled-failure'].includes(row.phase as string))return null;
   ids.add(row.operationId);
  }
 }else if(op.outcome==='complete')return null;
 return v as unknown as LocalHistoryStatus;
 }catch{return null;}
}
export function localHistoryError(_value?:unknown):ApiError{return{code:'local_release_history_unavailable',retryable:false,message:'The original local history operation is unavailable or unverified. Refresh its status; do not retry until cleanup is confirmed.'};}
