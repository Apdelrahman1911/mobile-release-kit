import { copyBoundedComparisonData, parseSavedConfigContent, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseAndroidBuildSavedVersion } from './androidBuildProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalStoreStatus, PrepareLocalStorePreflight } from './localStorePreflightTypes.ts';
export const STORE_EVENT='local-store-preflight-state-changed';
export const STORE_CONSENT='local-android-store-access-v1' as const;
export type StoreCommand='prepare_local_store_preflight'|'start_local_store_preflight'|'local_store_preflight_status'|'cancel_local_store_preflight';
const limits=['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic'];
const checks=['credential-format','query-prerequisites','runtime-unavailable','bundle-unavailable','store-access'];
const core=['PASS','FAIL','MISSING','BLOCKED','INVALID','SKIP','MANUAL','CONFIGURED','NOT_APPLICABLE'];
const phases=['awaiting-consent','starting','running','stopping','terminal','unknown'];
const outcomes=['complete','refused','cancelled','timed-out','failed','unknown'];
const reasons=['none','cancelled','context-changed','document-lost','shutdown','timed-out','protocol-error','runtime-unavailable','intent-expired','stale-intent','saved-source-changed','saved-source-invalid','credentials-unavailable','query-prerequisites','command-incomplete','cleanup-unknown'];
const counter=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<4294967295;
const token=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,names:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===names.length&&names.every(n=>Object.hasOwn(v,n));
const member=(values:string[],v:unknown)=>typeof v==='string'&&values.includes(v);
const contextKeys=['projectId','draftRevision','baselineGeneration','savedConfig','savedVersion','credentialContextRevision','recordId','recordRevision','executionMode'];
function request(v:unknown):boolean{
 return keys(v,contextKeys)&&typeof v.projectId==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v.projectId)&&counter(v.draftRevision)&&counter(v.baselineGeneration)&&!!parseSavedConfigContent(v.savedConfig)&&!!parseAndroidBuildSavedVersion(v.savedVersion)&&counter(v.credentialContextRevision)&&v.credentialContextRevision>0&&counter(v.recordRevision)&&v.recordRevision>0&&token(v.recordId)&&v.executionMode==='local';
}
export function parseLocalStoreRequest(input:unknown):PrepareLocalStorePreflight|null{
 try{const v=copyBoundedComparisonData(input,8192);return request(v)?v as PrepareLocalStorePreflight:null;}catch{return null;}
}
export function encodeLocalStoreRequest(command:StoreCommand,input:unknown):Uint8Array|null{
 try{const v=copyBoundedComparisonData(input,8192);
 const valid=command==='prepare_local_store_preflight'?request(v):command==='local_store_preflight_status'?keys(v,[]):keys(v,command==='start_local_store_preflight'?['operationId','ownerGeneration','consentVersion']:['operationId','ownerGeneration'])&&token(v.operationId)&&token(v.ownerGeneration)&&(command!=='start_local_store_preflight'||v.consentVersion===STORE_CONSENT);
 if(!valid)return null;const bytes=new TextEncoder().encode(JSON.stringify(v));return bytes.length<=8192?bytes:null;
 }catch{return null;}
}
export function parseLocalStoreStatus(input:unknown):LocalStoreStatus|null{
 try{const v=copyBoundedComparisonData(input,16384);
 if(!keys(v,['schemaVersion','statusRevision','availability','operation'])||v.schemaVersion!==1||!counter(v.statusRevision)||!member(['available','busy','shutdown','cleanup-unknown','document-lost','unsupported-platform','runtime-unqualified'],v.availability))return null;
 const op=v.operation;if(op===null)return v as unknown as LocalStoreStatus;
 if(!keys(op,['operationId','ownerGeneration','context','phase','intentUsable','outcome','reason','result'])||!token(op.operationId)||!token(op.ownerGeneration)||!member(phases,op.phase)||typeof op.intentUsable!=='boolean'||!member(reasons,op.reason))return null;
 const c=op.context;if(!keys(c,[...contextKeys,'platform','operation'])||c.platform!=='android'||c.operation!=='local-store-preflight')return null;
 const prepared={...c};delete prepared.platform;delete prepared.operation;if(!request(prepared))return null;
 if(op.phase==='terminal'){if(!member(outcomes,op.outcome)||op.outcome==='unknown'||op.intentUsable)return null;}
 else if(op.phase==='unknown'){if(op.outcome!=='unknown'||op.reason!=='cleanup-unknown'||op.intentUsable||op.result!==null)return null;}
 else if(op.outcome!==null||op.result!==null||op.intentUsable&&op.phase!=='awaiting-consent')return null;
 if(op.result!==null){const r=op.result;
  if(op.phase!=='terminal'||op.outcome!=='complete'||!keys(r,['schemaVersion','scope','findings','limitations'])||r.schemaVersion!==1||r.scope!=='local-android-store-access-no-publishing'||!sameOfflineData(r.limitations,limits)||!Array.isArray(r.findings)||r.findings.length>16||r.findings.some(f=>!keys(f,['check','status'])||!member(checks,f.check)||!member(core,f.status)))return null;
 }else if(op.outcome==='complete')return null;
 return v as unknown as LocalStoreStatus;
 }catch{return null;}
}
export function localStoreError(_value?:unknown):ApiError{return{code:'local_store_preflight_unavailable',retryable:false,message:'The original local Store check is unavailable or unverified. Refresh its status; do not retry until cleanup is confirmed.'};}
