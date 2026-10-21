// Closed DATA for one actual Desktop Prepared. No public material or Prepare.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
export const appleCliModes = ['review','register','reconcile','profile-review','profile-reuse','profile-create','profile-reconcile',
  'key-review','key-prepare','certificate-review','certificate-create','certificate-reconcile','p12-review','p12-reuse','p12-save'] as const;
type AppleCliMode = typeof appleCliModes[number];
export interface AppleCliReview { readonly mode:AppleCliMode; readonly operationId:string; readonly ownerGeneration:string; readonly statusRevision:number;
  readonly savedConfig:{readonly bytes:number;readonly sha256:string}; readonly savedVersion:{readonly bytes:number;readonly sha256:string;readonly name:string;readonly build:number} }
export interface AppleCliQuery {readonly projectId:string;readonly serviceInstance:string;readonly requestId:string}
export interface AppleCliRecord {readonly kind:'apple-profile'|'apple-distribution-key'|'apple-p12'; readonly reference:{readonly vaultId:string;readonly generationId:string;readonly recordId:string;readonly revisionId:string;readonly revisionCounter:1}}
export interface AppleCliStatus {
  readonly origin:AppleCliQuery;readonly grantId:string;readonly reviewId:string;readonly revision:number;readonly review:AppleCliReview;
  readonly state:'queued'|'starting'|'running'|'stopping'|'finishing'|'complete'|'failed'|'refused'|'cancelled'|'expired'|'unknown';
  readonly settlement:'pending'|'settled'|'unknown';readonly reason:string;
  readonly operation:{readonly operationId:string;readonly ownerGeneration:string;readonly statusRevision:number}|null;
  readonly outcome:'complete'|'failed'|'refused'|'cancelled'|'timed-out'|'unknown'|null;
  readonly result:Readonly<Record<string,unknown>>|null;readonly recordAtCompletion:AppleCliRecord|null;
}
export interface AppleCliAccess {readonly serviceInstance:string|null;readonly projectId:string|null;readonly grantId:string|null;readonly reviewId:string|null;
  readonly review:AppleCliReview|null;readonly enabled:boolean;readonly remainingMs:number;readonly consumed:boolean;readonly pending:boolean;readonly unknown:boolean;
  readonly requestId:string|null;readonly status:AppleCliStatus|null}
export interface AppleCliPort {access():Promise<unknown>;allow(review:AppleCliReview,nonce:string):Promise<unknown>;revoke(nonce:string):Promise<unknown>;request(query:AppleCliQuery):Promise<unknown>}
export const appleCliId=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v)&&v!=='0'.repeat(32);
const sha=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const num=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,names:readonly string[]):v is Record<string,unknown>=>obj(v)&&Object.keys(v).length===names.length&&names.every(k=>Object.hasOwn(v,k));
const one=(v:unknown,values:readonly string[])=>typeof v==='string'&&values.includes(v);
export const appleCliConsent=(mode:AppleCliMode)=>`agent-apple-${mode}-once-v1`;
function review(v:unknown):v is AppleCliReview{return keys(v,['mode','operationId','ownerGeneration','statusRevision','savedConfig','savedVersion'])&&one(v.mode,appleCliModes)&&
  appleCliId(v.operationId)&&appleCliId(v.ownerGeneration)&&num(v.statusRevision,1,0xffff_fffe)&&keys(v.savedConfig,['bytes','sha256'])&&num(v.savedConfig.bytes,1,524288)&&sha(v.savedConfig.sha256)&&
  keys(v.savedVersion,['bytes','sha256','name','build'])&&num(v.savedVersion.bytes,1,65536)&&sha(v.savedVersion.sha256)&&num(v.savedVersion.build,1,2100000000)&&typeof v.savedVersion.name==='string'&&/^[A-Za-z0-9.+-]{1,64}$/.test(v.savedVersion.name);}
function freeze<T>(v:T):T{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
export function parseAppleCliReview(raw:unknown):AppleCliReview|null{try{const v=copyBoundedComparisonData(raw,2048,48);return review(v)?freeze(v):null;}catch{return null;}}
export const sameAppleCliReview=(a:AppleCliReview|null,b:AppleCliReview|null)=>!!a&&!!b&&JSON.stringify(a)===JSON.stringify(b);
const decisions:Record<AppleCliMode,readonly string[]>={
  review:['reuse','review-required','blocked'],register:['reuse','review-required','blocked','registration-confirmed','registration-unconfirmed'],reconcile:['comparison-only'],
  'profile-review':['reuse-available','create-available','blocked'],'profile-reuse':['download-returned','creation-unconfirmed','blocked'],'profile-create':['download-returned','creation-unconfirmed','blocked'],'profile-reconcile':['comparison-only'],
  'key-review':['prepare-review','recover-existing-key','reuse-existing-identity','bundle-required','blocked'],'key-prepare':['produced','blocked'],
  'certificate-review':['reuse','request-review','blocked'],'certificate-create':['reuse','request-confirmed','request-unconfirmed','blocked'],'certificate-reconcile':['comparison-only'],
  'p12-review':['assemble-review','reuse-review','blocked'],'p12-reuse':['reused','blocked'],'p12-save':['assembled','blocked']};
function result(v:unknown,r:AppleCliReview):boolean{
  if(!keys(v,['decision','comparison','attempt','certificateId','certificateSha256','doNotReplay','credentialReady'])||!one(v.decision,decisions[r.mode])||v.doNotReplay!==true||v.credentialReady!==false)return false;
  const recon=['reconcile','profile-reconcile','certificate-reconcile'].includes(r.mode);
  if(recon?!one(v.comparison,['same-response','different-response','unattributed','not-returned','inconclusive']):v.comparison!==null)return false;
  if(v.attempt!==null&&(!['register','certificate-create'].includes(r.mode)||!keys(v.attempt,['operationId','status','cancellationRequested'])||v.attempt.operationId!==r.operationId||typeof v.attempt.cancellationRequested!=='boolean'||
    !one(v.attempt.status,['running','cancellation_requested','succeeded','failed','cancelled','recovery_required','unknown'])))return false;
  return (v.certificateId===null||/^(certificate|p12)-/.test(r.mode)&&typeof v.certificateId==='string'&&/^[A-Za-z0-9._-]{1,200}$/.test(v.certificateId))&&
    (v.certificateSha256===null||r.mode.startsWith('p12-')&&sha(v.certificateSha256));
}
function saved(v:unknown,r:AppleCliReview):v is AppleCliRecord {
  const kind=r.mode==='key-prepare'?'apple-distribution-key':r.mode==='p12-save'?'apple-p12':['profile-reuse','profile-create'].includes(r.mode)?'apple-profile':null;
  return keys(v,['kind','reference'])&&v.kind===kind&&kind!==null&&keys(v.reference,['vaultId','generationId','recordId','revisionId','revisionCounter'])&&
    ['vaultId','generationId','recordId','revisionId'].every(k=>appleCliId((v.reference as Record<string,unknown>)[k]))&&
    new Set([v.reference.vaultId,v.reference.generationId,v.reference.recordId,v.reference.revisionId]).size===4&&v.reference.revisionCounter===1;
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'];
function status(v:unknown):v is AppleCliStatus {
  if(!keys(v,['origin','grantId','reviewId','revision','review','state','settlement','reason','operation','outcome','result','recordAtCompletion'])||!keys(v.origin,['projectId','serviceInstance','requestId'])||!Object.values(v.origin).every(appleCliId)||
    !appleCliId(v.grantId)||!appleCliId(v.reviewId)||!num(v.revision,1,0xffff_fffe)||!review(v.review)||v.reviewId!==v.review.operationId||!one(v.reason,reasons)||
    !(v.operation===null||keys(v.operation,['operationId','ownerGeneration','statusRevision'])&&v.operation.operationId===v.review.operationId&&v.operation.ownerGeneration===v.review.ownerGeneration&&num(v.operation.statusRevision,v.review.statusRevision,0xffff_fffe))||
    !(v.result===null||result(v.result,v.review))||!(v.recordAtCompletion===null||v.settlement==='settled'&&saved(v.recordAtCompletion,v.review)))return false;
  if(v.state==='unknown')return v.settlement==='unknown'&&v.outcome==='unknown'&&v.result===null&&v.recordAtCompletion===null&&one(v.reason,['cleanup-unknown','history-unavailable']);
  if(one(v.state,['complete','failed','refused','cancelled','expired'])){
    if(v.settlement!=='settled'||v.operation===null)return false;
    if(v.state==='complete')return v.outcome==='complete'&&v.reason==='none'&&v.result!==null;
    return !one(v.reason,['none','cleanup-unknown','history-unavailable'])&&v.result===null&&(v.state==='failed'?one(v.outcome,['failed','timed-out']):v.state==='cancelled'?one(v.outcome,['cancelled','refused']):v.outcome==='refused');
  }
  return one(v.state,['queued','starting','running','stopping','finishing'])&&v.settlement==='pending'&&v.outcome===null&&v.result===null&&v.recordAtCompletion===null&&!one(v.reason,['cleanup-unknown','history-unavailable']);
}
export function parseAppleCliStatus(raw:unknown):AppleCliStatus|null{try{const v=copyBoundedComparisonData(raw,8192,200);return status(v)?freeze(v):null;}catch{return null;}}
export function parseAppleCliAccess(raw:unknown):AppleCliAccess|null{try{
  const v=copyBoundedComparisonData(raw,16384,280);
  if(!keys(v,['serviceInstance','projectId','grantId','reviewId','review','enabled','remainingMs','consumed','pending','unknown','requestId','status'])||
    !['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean')||!num(v.remainingMs,0,300000)||!(v.requestId===null||appleCliId(v.requestId)))return null;
  const present=['serviceInstance','projectId','grantId','reviewId'].every(k=>appleCliId(v[k]))&&review(v.review)&&v.reviewId===v.review.operationId;
  if(!present&&!['serviceInstance','projectId','grantId','reviewId','review'].every(k=>v[k]===null))return null;
  if(v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||!v.enabled&&v.remainingMs!==0||v.consumed!==(v.requestId!==null)||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
  if(v.status!==null&&(!status(v.status)||v.status.origin.projectId!==v.projectId||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.requestId!==v.requestId||v.status.grantId!==v.grantId||v.status.reviewId!==v.reviewId||
    !sameAppleCliReview(v.status.review,v.review as AppleCliReview)||v.pending!==(v.status.settlement!=='settled')||v.unknown!==(v.status.state==='unknown')))return null;
  return freeze(v) as unknown as AppleCliAccess;
}catch{return null;}}
export function createAppleCliPort(invoke:(command:string,body:Uint8Array)=>Promise<unknown>):AppleCliPort {
  const send=(name:string,body:object)=>{const bytes=new TextEncoder().encode(JSON.stringify(body));return bytes.length<=1024?invoke(name,bytes):Promise.reject({code:'agent_apple_invalid'});};
  return Object.freeze({access:()=>send('agent_apple_provisioning_access',{}),allow:(raw:AppleCliReview,nonce:string)=>{
    const r=parseAppleCliReview(raw);return r&&appleCliId(nonce)?send('allow_agent_apple_provisioning',{consentId:nonce,mode:r.mode,operationId:r.operationId,ownerGeneration:r.ownerGeneration,expectedStatusRevision:r.statusRevision,consentVersion:appleCliConsent(r.mode)}):Promise.reject({code:'agent_apple_invalid'});},
    revoke:(nonce:string)=>appleCliId(nonce)?send('revoke_agent_apple_provisioning',{consentId:nonce}):Promise.reject({code:'agent_apple_invalid'}),
    request:(q:AppleCliQuery)=>keys(q,['projectId','serviceInstance','requestId'])&&Object.values(q).every(appleCliId)?send('agent_apple_provisioning_request_status',q):Promise.reject({code:'agent_apple_invalid'})});
}
export function appleCliCommands(value:AppleCliAccess|null):readonly string[]{const a=parseAppleCliAccess(value);if(!a?.grantId)return [];
  const prefix=`${a.projectId} ${a.serviceInstance}`;return a.requestId?[`mrk apple-provisioning-status ${prefix} ${a.requestId}`,`mrk apple-provisioning-cancel ${prefix} ${a.requestId}`]:
    a.enabled?[`mrk apple-provisioning-submit ${prefix} ${a.grantId} ${a.reviewId} --reviewed`]:[];
}
export function appleCliEffect(mode:AppleCliMode):string {
  if(mode==='register')return 'May register one new Bundle ID after the existing reuse-first checks. No automatic retry.';
  if(mode==='profile-create')return 'May request one profile and save the returned profile encrypted. No assignment or build.';
  if(mode==='certificate-create')return 'May request one Distribution certificate for the current saved key. No replacement key, P12, or retry.';
  if(mode==='key-prepare')return 'Generates and saves a local private key and CSR encrypted. No certificate request or public key export.';
  if(mode==='p12-save')return 'Uses the current key and fresh read-only certificate checks to assemble and save an encrypted P12. No assignment.';
  if(mode==='profile-reuse')return 'Downloads the reviewed existing profile and saves it encrypted. No new profile or assignment.';
  return 'Runs only this existing reviewed read/comparison step. May update local journal history; does not authorize the next step or clear earlier uncertainty.';
}
