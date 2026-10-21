// Public comparison DATA only. Native owns the same Prepared/Review, consent,
// private draft, clocks and all three retirement cuts. CLI receives IDs only.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { startEnvironmentDiagnosticsFits } from './environmentDiagnosticsProtocol.ts';
import { copyAndroidBuildRequest } from './androidBuildProtocol.ts';
import { TOOL_ACQUISITION_CONSENT } from './toolAcquisitionProtocol.ts';
import { ANDROID_TOOL_REGISTRATION_CONSENT } from './androidToolRegistration.ts';
import type { JsonObject } from './types.ts';
export const TOOL_SETUP_KINDS = ['doctor','inspect-requirements','acquire-missing','inspect-picked-sources','register-reviewed-sources'] as const;
export type ToolSetupKind = typeof TOOL_SETUP_KINDS[number];
export interface ToolSetupReview {
  readonly kind: ToolSetupKind; readonly platform: 'android'|'ios'; readonly draftRevision: number; readonly baselineGeneration: number;
  readonly prepared: { readonly operationId: string; readonly ownerGeneration: string; readonly statusRevision: number } | null;
  readonly sources: { readonly registrationGeneration: number; readonly sourceGeneration: number; readonly reviewId: string|null } | null;
}
export interface ToolSetupQuery { readonly projectId:string; readonly serviceInstance:string; readonly requestId:string }
export interface ToolSetupOperation { readonly operationId:string; readonly ownerGeneration:string|null; readonly registrationGeneration:number|null }
export interface ToolSetupStatus {
  readonly origin:ToolSetupQuery; readonly grantId:string; readonly reviewId:string; readonly revision:number; readonly review:ToolSetupReview;
  readonly state:'queued'|'starting'|'running'|'stopping'|'finishing'|'complete'|'failed'|'refused'|'cancelled'|'expired'|'unknown';
  readonly settlement:'pending'|'settled'|'unknown'; readonly reason:string; readonly operation:ToolSetupOperation|null;
  readonly outcome:'complete'|'failed'|'refused'|'cancelled'|'timed-out'|'unknown'|null; readonly result:Readonly<Record<string,unknown>>|null;
}
export interface AgentToolSetupAccess {
  readonly serviceInstance:string|null; readonly projectId:string|null; readonly grantId:string|null; readonly reviewId:string|null; readonly review:ToolSetupReview|null;
  readonly enabled:boolean; readonly remainingMs:number; readonly consumed:boolean; readonly pending:boolean; readonly unknown:boolean;
  readonly requestId:string|null; readonly status:ToolSetupStatus|null;
}
// This input is produced only by the original Desktop controller. It never
// becomes a CLI argument or service history. Only one pending Allow retains it.
export interface ToolSetupInput {
  readonly projectId:string; readonly review:ToolSetupReview; readonly doctorDraft:JsonObject|null;
  readonly sourceContext:Readonly<Record<string,unknown>>|null; readonly nativeConsent:string|null; readonly licenseAcknowledged:boolean;
}
export interface AgentToolSetupPort {
  access():Promise<unknown>; allow(consentId:string,input:ToolSetupInput):Promise<unknown>;
  revoke(consentId:string):Promise<unknown>; requestStatus(query:ToolSetupQuery):Promise<unknown>;
}
export interface ToolSetupDelegation {
  readonly input:ToolSetupInput;
  current():boolean;
  // Only after the original permission/query returned known retirement. A new
  // original native read must independently match; never invent GUI StartJoined.
  readAfterReturned(status:ToolSetupStatus|null):Promise<boolean>;
}
const encoder=new TextEncoder();
export const toolSetupId=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v)&&v!=='0'.repeat(32);
const uint=(v:unknown,min=0,max=0xffff_fffe):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,n:readonly string[]):v is Record<string,unknown>=>record(v)&&Object.keys(v).length===n.length&&n.every(k=>Object.hasOwn(v,k));
const one=(v:unknown,a:readonly string[])=>typeof v==='string'&&a.includes(v);
export function freezeToolSetup<T>(v:T):T{if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.values(v).forEach(freezeToolSetup);Object.freeze(v);}return v;}
function review(v:unknown):v is ToolSetupReview {
  if(!keys(v,['kind','platform','draftRevision','baselineGeneration','prepared','sources'])||!one(v.kind,TOOL_SETUP_KINDS)||!one(v.platform,['android','ios'])||
      !uint(v.draftRevision)||!uint(v.baselineGeneration)||v.kind!=='doctor'&&v.platform!=='android')return false;
  if(v.kind==='doctor')return v.prepared===null&&v.sources===null;
  if(v.kind==='inspect-requirements'||v.kind==='acquire-missing')return v.sources===null&&keys(v.prepared,['operationId','ownerGeneration','statusRevision'])&&
    toolSetupId(v.prepared.operationId)&&toolSetupId(v.prepared.ownerGeneration)&&uint(v.prepared.statusRevision,1);
  return v.prepared===null&&keys(v.sources,['registrationGeneration','sourceGeneration','reviewId'])&&uint(v.sources.registrationGeneration)&&uint(v.sources.sourceGeneration)&&
    (v.kind==='inspect-picked-sources'?v.sources.reviewId===null:toolSetupId(v.sources.reviewId));
}
export function parseToolSetupReview(raw:unknown):ToolSetupReview|null{try{const v=copyBoundedComparisonData(raw,1024,48);return review(v)?freezeToolSetup(v):null;}catch{return null;}}
export const sameToolSetupReview=(a:ToolSetupReview|null,b:ToolSetupReview|null):boolean=>a===null||b===null?a===b:JSON.stringify(a)===JSON.stringify(b);
export const toolSetupConsent=(kind:ToolSetupKind):string=>({doctor:'agent-tool-doctor-once-v1','inspect-requirements':'agent-tool-requirements-once-v1',
  'acquire-missing':'agent-tool-acquire-missing-once-v1','inspect-picked-sources':'agent-tool-inspect-picked-once-v1','register-reviewed-sources':'agent-tool-register-reviewed-once-v1'})[kind];
const query=(v:unknown):v is ToolSetupQuery=>keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(toolSetupId);
const components=['jdk','gradle','android-platform','android-build-tools'];
const unique=(v:unknown,max:number,values:readonly string[])=>Array.isArray(v)&&v.length<=max&&v.every(x=>one(x,values))&&new Set(v).size===v.length;
function sources(v:unknown):v is unknown[]{return Array.isArray(v)&&v.length<=3&&v.every(s=>keys(s,['role','logicalBytes','files','entries','aliases','complete','compatible'])&&
  one(s.role,['jdk','sdk','gradle'])&&uint(s.logicalBytes,0,1024*1024*1024)&&uint(s.files,0,16384)&&uint(s.entries,0,32768)&&uint(s.aliases,0,128)&&
  typeof s.complete==='boolean'&&typeof s.compatible==='boolean')&&new Set(v.map(s=>s.role)).size===v.length;}
function report(v:unknown,r:ToolSetupReview):boolean {
  if(!record(v)||v.kind!==r.kind||encoder.encode(JSON.stringify(v)).length>4096)return false;
  switch(r.kind){
    case 'doctor':return keys(v,['kind','checks'])&&Array.isArray(v.checks)&&v.checks.length<=5&&v.checks.every(c=>keys(c,['check','status'])&&
      one(c.check,['developer-selection','git','java','javac','xcode'])&&one(c.status,['ok','failed','unavailable','skipped']))&&new Set(v.checks.map(c=>c.check)).size===v.checks.length;
    case 'inspect-requirements':return keys(v,['kind','missing'])&&unique(v.missing,4,components);
    case 'acquire-missing':return keys(v,['kind','staged'])&&unique(v.staged,4,components)&&(v.staged as unknown[]).length>0;
    case 'inspect-picked-sources':return keys(v,['kind','sources'])&&sources(v.sources)&&v.sources.length===3;
    case 'register-reviewed-sources':return keys(v,['kind','copy','sources'])&&one(v.copy,['not-created','published','retained-partial'])&&sources(v.sources);
  }
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','timed-out','cleanup-unknown','history-unavailable'];
function status(v:unknown):v is ToolSetupStatus {
  if(!keys(v,['origin','grantId','reviewId','revision','review','state','settlement','reason','operation','outcome','result'])||!query(v.origin)||!toolSetupId(v.grantId)||!toolSetupId(v.reviewId)||
      !uint(v.revision,1)||!review(v.review)||!one(v.reason,reasons)||v.result!==null&&!report(v.result,v.review))return false;
  if(v.operation!==null){const o=v.operation,r=v.review;if(!keys(o,['operationId','ownerGeneration','registrationGeneration'])||!toolSetupId(o.operationId))return false;
    if(r.sources){if(o.ownerGeneration!==null||!uint(o.registrationGeneration)||o.registrationGeneration!==r.sources.registrationGeneration+1)return false;}
    else if(!toolSetupId(o.ownerGeneration)||o.registrationGeneration!==null||r.prepared&&(o.operationId!==r.prepared.operationId||o.ownerGeneration!==r.prepared.ownerGeneration))return false;
  }
  if(v.state==='unknown')return v.settlement==='unknown'&&v.outcome==='unknown'&&v.result===null&&one(v.reason,['cleanup-unknown','history-unavailable']);
  if(one(v.state,['complete','failed','refused','cancelled','expired'])){
    if(v.settlement!=='settled')return false;
    if(v.state==='complete')return v.operation!==null&&v.outcome==='complete'&&v.reason==='none'&&v.result!==null;
    return v.result===null&&!one(v.reason,['none','cleanup-unknown','history-unavailable'])&&
      (v.state==='failed'?one(v.outcome,['failed','timed-out']):v.state==='cancelled'?one(v.outcome,['cancelled','refused']):v.outcome==='refused');
  }
  return one(v.state,['queued','starting','running','stopping','finishing'])&&v.settlement==='pending'&&v.outcome===null&&v.result===null&&!one(v.reason,['cleanup-unknown','history-unavailable']);
}
export function parseToolSetupStatus(raw:unknown):ToolSetupStatus|null{try{const v=copyBoundedComparisonData(raw,8192,320);return status(v)?freezeToolSetup(v):null;}catch{return null;}}
export function parseAgentToolSetupAccess(raw:unknown):AgentToolSetupAccess|null{try{
  const v=copyBoundedComparisonData(raw,8192,384);
  if(!keys(v,['serviceInstance','projectId','grantId','reviewId','review','enabled','remainingMs','consumed','pending','unknown','requestId','status'])||
      !['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean')||!uint(v.remainingMs,0,300000)||!(v.requestId===null||toolSetupId(v.requestId)))return null;
  const present=['serviceInstance','projectId','grantId','reviewId'].every(k=>toolSetupId(v[k]))&&review(v.review);
  if(!present&&!['serviceInstance','projectId','grantId','reviewId','review'].every(k=>v[k]===null)||v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||
      !v.enabled&&v.remainingMs!==0||v.consumed!==(v.requestId!==null)||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
  if(v.status!==null){const s=v.status;if(!status(s)||s.origin.projectId!==v.projectId||s.origin.serviceInstance!==v.serviceInstance||s.origin.requestId!==v.requestId||s.grantId!==v.grantId||
      s.reviewId!==v.reviewId||!sameToolSetupReview(s.review,v.review as ToolSetupReview)||v.pending!==(s.settlement!=='settled')||v.unknown!==(s.state==='unknown'))return null;}
  return freezeToolSetup(v) as unknown as AgentToolSetupAccess;
}catch{return null;}}
// Original controller creates this fixed payload. Revalidate before any encoding;
// draft getters, extra fields and arbitrary source paths never reach invoke.
export function copyToolSetupInput(raw:unknown):ToolSetupInput|null{try{
  if(!record(raw)||!keys(Object.fromEntries(Object.keys(raw).map(k=>[k,null])),['projectId','review','doctorDraft','sourceContext','nativeConsent','licenseAcknowledged']))return null;
  if(Object.getPrototypeOf(raw)!==Object.prototype&&Object.getPrototypeOf(raw)!==null)return null;
  for(const k of Reflect.ownKeys(raw)){const d=Object.getOwnPropertyDescriptor(raw,k);if(typeof k!=='string'||!d?.enumerable||!Object.hasOwn(d,'value'))return null;}
  const r=parseToolSetupReview(raw.review);if(!r||typeof raw.projectId!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(raw.projectId))return null;
  if(r.kind==='doctor'){
    if(raw.sourceContext!==null||raw.nativeConsent!==null||raw.licenseAcknowledged!==false||!startEnvironmentDiagnosticsFits({projectId:raw.projectId,draft:raw.doctorDraft,draftRevision:r.draftRevision,baselineGeneration:r.baselineGeneration,platform:r.platform,operation:'build'}))return null;
    if(encoder.encode(JSON.stringify(raw.doctorDraft)).length>512*1024)return null;
    return freezeToolSetup({projectId:raw.projectId,review:r,doctorDraft:structuredClone(raw.doctorDraft) as JsonObject,sourceContext:null,nativeConsent:null,licenseAcknowledged:false});
  }
  if(raw.doctorDraft!==null)return null;
  if(r.prepared){if(raw.sourceContext!==null||raw.nativeConsent!==TOOL_ACQUISITION_CONSENT||raw.licenseAcknowledged!==false)return null;
    return freezeToolSetup({projectId:raw.projectId,review:r,doctorDraft:null,sourceContext:null,nativeConsent:TOOL_ACQUISITION_CONSENT,licenseAcknowledged:false});}
  const context=copyAndroidBuildRequest('prepare_android_build',raw.sourceContext);
  if(!context||!('projectId' in context)||context.projectId!==raw.projectId||context.draftRevision!==r.draftRevision||context.baselineGeneration!==r.baselineGeneration)return null;
  const register=r.kind==='register-reviewed-sources';if(raw.nativeConsent!==(register?ANDROID_TOOL_REGISTRATION_CONSENT:null)||raw.licenseAcknowledged!==register)return null;
  return freezeToolSetup({projectId:raw.projectId,review:r,doctorDraft:null,sourceContext:context as unknown as Record<string,unknown>,nativeConsent:register?ANDROID_TOOL_REGISTRATION_CONSENT:null,licenseAcknowledged:register});
}catch{return null;}}
export function createAgentToolSetupPort(invoke:(name:string,raw:Uint8Array)=>Promise<unknown>):AgentToolSetupPort{
  const send=(name:string,body:object,max=1024)=>{const raw=encoder.encode(JSON.stringify(body));return raw.length<=max?invoke(name,raw):Promise.reject({code:'tool_setup_invalid'});};
  return Object.freeze({access:()=>send('agent_tool_setup_access',{}),revoke:(id:string)=>toolSetupId(id)?send('revoke_agent_tool_setup',{consentId:id}):Promise.reject({code:'tool_setup_invalid'}),
    requestStatus:(raw:ToolSetupQuery)=>{try{const v=copyBoundedComparisonData(raw,256,8);return query(v)?send('agent_tool_setup_request_status',v):Promise.reject({code:'tool_setup_invalid'});}catch{return Promise.reject({code:'tool_setup_invalid'});}},
    allow:(id:string,input:ToolSetupInput)=>{const v=copyToolSetupInput(input);return toolSetupId(id)&&v?send('allow_agent_tool_setup',{consentId:id,...v,consentVersion:toolSetupConsent(v.review.kind)},1024*1024):Promise.reject({code:'tool_setup_invalid'});}});
}
export function toolSetupCommands(raw:AgentToolSetupAccess|null):readonly string[]{const a=parseAgentToolSetupAccess(raw);if(!a?.grantId)return [];const ids=`${a.projectId} ${a.serviceInstance}`;
  return a.requestId?[`mrk tool-setup-status ${ids} ${a.requestId}`,`mrk tool-setup-cancel ${ids} ${a.requestId}`]:a.enabled?[`mrk tool-setup-submit ${ids} ${a.grantId} ${a.reviewId} --reviewed`]:[];}
export const toolSetupLabel:Readonly<Record<ToolSetupKind,string>>=Object.freeze({doctor:'Check tools for the approved draft','inspect-requirements':'Inspect saved project requirements','acquire-missing':'Download only the reviewed missing tools','inspect-picked-sources':'Inspect the three chosen tool folders','register-reviewed-sources':'Make the reviewed protected tool copy'});
export const toolSetupEffect:Readonly<Record<ToolSetupKind,string>>=Object.freeze({doctor:'Runs the existing fixed tool probes against an immutable copy of the draft approved below. Later edits do not change that copy. It is not a saved-file or build-readiness check.',
  'inspect-requirements':'Starts only the original prepared requirements inspection. It does not download, select or register tools.',
  'acquire-missing':'Uses the original missing-component review and pinned public downloads. Existing compatible tools are not replaced. Staged folders still require the ordinary picker and inspection.',
  'inspect-picked-sources':'Checks the three folders already chosen in Desktop, with the original saved project inputs. It does not make a protected copy.',
  'register-reviewed-sources':'Consumes the current native inspection review and vendor-license approval to make the protected copy. Catalogue recovery/selection and build checks remain separate.'});
