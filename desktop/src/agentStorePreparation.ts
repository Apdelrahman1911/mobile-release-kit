// Comparison DATA and fixed RAW calls only. No native receipt, credential or
// inventory-to-allocation conversion exists in this renderer facet.
import {copyBoundedComparisonData,sameOfflineData} from './offlinePreflightProtocol.ts';
import {localStoreRequest,type LocalStoreProject} from './localStorePreflight.ts';
import {localStorePrepareRequest} from './localStorePrepare.ts';
import {parseLocalStoreRequest} from './localStorePreflightProtocol.ts';
import {parseLocalStorePrepareRequest} from './localStorePrepareProtocol.ts';
import {nativeStageOperationId,STAGE_PREPARE_LIMITS,type LocalStoreStage,type StagePreparedIntent} from './localStoreStageProtocol.ts';
import {validStoreReport,type StoreReview} from './agentStoreAccess.ts';
import {parseIOSCurrentVersions,type IOSCurrentVersions} from './iosStoreVersions.ts';
import {parseAndroidCurrentVersions,type AndroidCurrentVersions} from './androidStoreVersions.ts';
import type {AssetDisplayState} from './assetSessionTypes.ts';
import type {LocalHistoryState} from './localReleaseHistory.ts';
import type {PrepareLocalStorePreflight} from './localStorePreflightTypes.ts';
import type {PrepareLocalStoreIntent} from './localStorePrepareTypes.ts';
export const storePreparationKinds=['android-access','ios-access','android-candidate','ios-candidate','android-versions','ios-versions','paired-versions','android-external-testing','ios-external-testing','android-production-submit','ios-production-submit'] as const;
export type PreparationKind=typeof storePreparationKinds[number];
export interface StorePreparationInput {readonly kind:PreparationKind;readonly prepare:PrepareLocalStorePreflight|PrepareLocalStoreIntent}
export interface StageSelection {readonly stage:LocalStoreStage;readonly predecessorOperationId:string;readonly predecessorReceiptSha256:string}
export interface StoreSelection {readonly kind:PreparationKind;readonly savedConfig:StoreReview['savedConfig'];readonly savedVersion:StoreReview['savedVersion'];readonly candidate:StoreReview['candidate'];readonly later?:StageSelection}
export interface StoreOperation {readonly operationId:string;readonly ownerGeneration:string;readonly statusRevision:number}
export interface PreparationReview {readonly reviewId:string;readonly operation:StoreOperation}
export interface PreparationOrigin {readonly projectId:string;readonly serviceInstance:string;readonly requestId:string}
export type CurrentInventory={readonly platform:'ios';readonly current:IOSCurrentVersions}|{readonly platform:'android';readonly current:AndroidCurrentVersions}|{readonly platform:'both';readonly ios:IOSCurrentVersions;readonly android:AndroidCurrentVersions};
export interface StoreStageReport {
 readonly platform:'android'|'ios';readonly stage:LocalStoreStage;readonly operationId:string;readonly headSequence:number;
 readonly candidateOperationId:string;readonly candidateSha256:string;readonly predecessorOperationId:string;readonly predecessorReceiptSha256:string;
 readonly intentSha256:string;readonly storePreconditionSha256:string;readonly destination:StagePreparedIntent['destination'];readonly limitations:typeof STAGE_PREPARE_LIMITS;
}
export interface PreparationStatus {
 readonly schemaVersion:1;readonly origin:PreparationOrigin;readonly prepareGrantId:string;readonly selectionId:string;readonly revision:number;readonly selection:StoreSelection;
 readonly phase:'queued'|'preparing'|'prepared'|'starting'|'running'|'stopping'|'finishing'|'final'|'unknown';readonly settlement:'pending'|'settled'|'unknown';readonly reason:string;
 readonly prepared:PreparationReview|null;readonly operation:StoreOperation|null;readonly startGrantId:string|null;readonly prepareReturned:boolean;readonly startSubmitted:boolean;
 readonly outcome:'complete'|'failed'|'refused'|'cancelled'|'timed-out'|'unknown'|null;
 readonly result:{readonly kind:'ordinary';readonly report:Readonly<Record<string,unknown>>}|{readonly kind:'current-versions';readonly inventory:CurrentInventory}|{readonly kind:'stage-prepare';readonly report:StoreStageReport}|null;readonly doNotReplay:true;
}
export interface StorePreparationAccess {
 readonly schemaVersion:1;readonly serviceInstance:string|null;readonly projectId:string|null;readonly permission:'prepare'|'start'|null;readonly grantId:string|null;readonly reviewId:string|null;
 readonly selection:StoreSelection|null;readonly requestId:string|null;readonly enabled:boolean;readonly consumed:boolean;readonly pending:boolean;readonly unknown:boolean;readonly remainingMs:number;readonly status:PreparationStatus|null;
}
export interface StorePreparationPort {status():Promise<unknown>;allowPrepare(input:StorePreparationInput):Promise<unknown>;allowStart(status:PreparationStatus):Promise<unknown>;revoke():Promise<unknown>}
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v)&&v!=='0'.repeat(32);
const sha=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const n=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
const keys=(v:unknown,k:readonly string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===k.length&&k.every(p=>Object.hasOwn(v,p));
const one=(v:unknown,ss:readonly string[])=>typeof v==='string'&&ss.includes(v);
function freeze<T>(v:T):T{if(v&&typeof v==='object'){for(const item of Object.values(v))freeze(item);Object.freeze(v);}return v;}
const candidate=(k:PreparationKind)=>k==='android-candidate'||k==='ios-candidate';
export const storePreparationStage=(k:PreparationKind):LocalStoreStage|null=>k==='android-external-testing'||k==='ios-external-testing'?'external-testing':k==='android-production-submit'||k==='ios-production-submit'?'production-submit':null;
export const storePreparationPreparesIntent=(k:PreparationKind)=>candidate(k)||storePreparationStage(k)!==null;
const kind=(v:unknown):v is PreparationKind=>one(v,storePreparationKinds);
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v)&&v!=='00000000-0000-0000-0000-000000000000';
const uuid4=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
function selection(v:unknown):v is StoreSelection{
 if(!(keys(v,['kind','savedConfig','savedVersion','candidate'])||keys(v,['kind','savedConfig','savedVersion','candidate','later']))||!kind(v.kind))return false;
 const stage=storePreparationStage(v.kind);
 return keys(v,['kind','savedConfig','savedVersion','candidate',...(stage?['later']:[])])
 &&keys(v.savedConfig,['bytes','sha256'])&&n(v.savedConfig.bytes,1,524288)&&sha(v.savedConfig.sha256)
 &&keys(v.savedVersion,['bytes','sha256','name','build'])&&n(v.savedVersion.bytes,1,65536)&&sha(v.savedVersion.sha256)&&n(v.savedVersion.build,1,2100000000)&&typeof v.savedVersion.name==='string'&&/^[A-Za-z0-9.+-]{1,64}$/.test(v.savedVersion.name)
 &&(storePreparationPreparesIntent(v.kind)?keys(v.candidate,['operationId','sha256'])&&uuid(v.candidate.operationId)&&sha(v.candidate.sha256):v.candidate===null)
 &&(!stage||keys(v.candidate,['operationId','sha256'])&&uuid4(v.candidate.operationId)&&keys(v.later,['stage','predecessorOperationId','predecessorReceiptSha256'])&&v.later.stage===stage&&uuid4(v.later.predecessorOperationId)&&sha(v.later.predecessorReceiptSha256)&&(stage==='external-testing'?v.later.predecessorOperationId===v.candidate.operationId:v.later.predecessorOperationId!==v.candidate.operationId));}
const operation=(v:unknown):v is StoreOperation=>keys(v,['operationId','ownerGeneration','statusRevision'])&&id(v.operationId)&&id(v.ownerGeneration)&&n(v.statusRevision,1,0xffff_fffe);
const review=(v:unknown):v is PreparationReview=>keys(v,['reviewId','operation'])&&id(v.reviewId)&&operation(v.operation);
const origin=(v:unknown):v is PreparationOrigin=>keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(id);
function stageReport(v:unknown,s:StoreSelection,r:PreparationReview):boolean{
 const stage=storePreparationStage(s.kind),later=s.later,c=s.candidate,ios=s.kind.startsWith('ios-');
 if(!stage||!later||!c||!keys(v,['platform','stage','operationId','headSequence','candidateOperationId','candidateSha256','predecessorOperationId','predecessorReceiptSha256','intentSha256','storePreconditionSha256','destination','limitations'])
  ||v.platform!==(ios?'ios':'android')||v.stage!==stage||!uuid4(v.operationId)||v.operationId!==nativeStageOperationId(r.operation.operationId)||v.operationId===c.operationId||v.operationId===later.predecessorOperationId
  ||v.candidateOperationId!==c.operationId||v.candidateSha256!==c.sha256||v.predecessorOperationId!==later.predecessorOperationId||v.predecessorReceiptSha256!==later.predecessorReceiptSha256
  ||!sha(v.intentSha256)||!sha(v.storePreconditionSha256)||!n(v.headSequence,stage==='external-testing'?9:13,511)||!sameOfflineData(v.limitations,STAGE_PREPARE_LIMITS))return false;
 if(ios)return sameOfflineData(v.destination,stage==='external-testing'?{channel:'testflight-external'}:{channel:'app-store-review',automaticRelease:false});
 return keys(v.destination,['channel','releaseStatus'])&&(stage==='production-submit'?sameOfflineData(v.destination,{channel:'production',releaseStatus:'draft'}):
  typeof v.destination.channel==='string'&&v.destination.channel.trim().length>0&&[...v.destination.channel].length<=100&&!/[\0\r\n]/.test(v.destination.channel)&&!['internal','production'].includes(v.destination.channel)&&v.destination.releaseStatus==='completed');
}
function report(v:unknown,s:StoreSelection,r:PreparationReview):boolean{
 if(keys(v,['kind','report'])&&v.kind==='stage-prepare')return stageReport(v.report,s,r);
 if(keys(v,['kind','inventory'])&&v.kind==='current-versions'){
  const i=v.inventory;
  if(keys(i,['platform','current']))return s.kind==='ios-versions'&&i.platform==='ios'&&!!parseIOSCurrentVersions(i.current)||s.kind==='android-versions'&&i.platform==='android'&&!!parseAndroidCurrentVersions(i.current);
  return s.kind==='paired-versions'&&keys(i,['platform','android','ios'])&&i.platform==='both'&&!!parseIOSCurrentVersions(i.ios)&&!!parseAndroidCurrentVersions(i.android);
 }
 if(!keys(v,['kind','report'])||v.kind!=='ordinary'||s.kind.endsWith('-versions')||storePreparationStage(s.kind)!==null)return false;
 return validStoreReport(v.report,{kind:candidate(s.kind)?'candidate-prepare':'access-check',platform:s.kind.startsWith('ios-')?'ios':'android',...r.operation,savedConfig:s.savedConfig,savedVersion:s.savedVersion,candidate:s.candidate});
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'];
function status(v:unknown):v is PreparationStatus{
 if(!keys(v,['schemaVersion','origin','prepareGrantId','selectionId','revision','selection','phase','settlement','reason','prepared','operation','startGrantId','prepareReturned','startSubmitted','outcome','result','doNotReplay'])
 ||v.schemaVersion!==1||v.doNotReplay!==true||!origin(v.origin)||!id(v.prepareGrantId)||!id(v.selectionId)||!n(v.revision,1,0xffff_fffe)||!selection(v.selection)||!one(v.reason,reasons)
 ||typeof v.prepareReturned!=='boolean'||typeof v.startSubmitted!=='boolean'||!(v.prepared===null||review(v.prepared))||!(v.startGrantId===null||id(v.startGrantId))
 ||v.startSubmitted&&(!v.prepared||!v.startGrantId)||v.startGrantId!==null&&(!v.prepared||!v.prepareReturned)
 ||!(v.operation===null||operation(v.operation)&&review(v.prepared)&&v.operation.operationId===v.prepared.operation.operationId&&v.operation.ownerGeneration===v.prepared.operation.ownerGeneration&&v.operation.statusRevision>=v.prepared.operation.statusRevision)
 ||!(v.result===null||review(v.prepared)&&report(v.result,v.selection,v.prepared)))return false;
 if(v.phase==='unknown')return v.settlement==='unknown'&&v.outcome==='unknown'&&v.result===null&&one(v.reason,['cleanup-unknown','history-unavailable']);
 if(v.phase==='final')return v.settlement==='settled'&&v.prepareReturned&&(v.outcome==='complete'?v.startSubmitted&&v.reason==='none'&&v.result!==null&&v.operation!==null:one(v.outcome,['failed','refused','cancelled','timed-out'])&&!one(v.reason,['none','cleanup-unknown','history-unavailable'])&&v.result===null&&(v.prepared===null||v.operation!==null));
 return one(v.phase,['queued','preparing','prepared','starting','running','stopping','finishing'])&&v.settlement==='pending'&&v.outcome===null&&v.result===null&&!one(v.reason,['cleanup-unknown','history-unavailable'])&&(v.phase!=='prepared'||v.prepareReturned&&v.prepared!==null&&!v.startSubmitted);
}
export function parseStorePreparationStatus(raw:unknown):PreparationStatus|null{try{const v=copyBoundedComparisonData(raw,8192,400);return status(v)?freeze(v):null;}catch{return null;}}
export function parseStorePreparationAccess(raw:unknown):StorePreparationAccess|null{try{
 const v=copyBoundedComparisonData(raw,16384,512);
 if(!keys(v,['schemaVersion','serviceInstance','projectId','permission','grantId','reviewId','selection','requestId','enabled','consumed','pending','unknown','remainingMs','status'])||v.schemaVersion!==1||!['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean')||!n(v.remainingMs,0,300000)||!(v.requestId===null||id(v.requestId)))return null;
 if(v.permission===null)return ['serviceInstance','projectId','grantId','reviewId','selection','requestId','status'].every(k=>v[k]===null)&&!v.enabled&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs===0?freeze(v) as unknown as StorePreparationAccess:null;
 if(!one(v.permission,['prepare','start'])||!id(v.serviceInstance)||!id(v.projectId)||!id(v.grantId)||!id(v.reviewId)||!selection(v.selection)||v.enabled!==(v.remainingMs>0)||v.enabled&&(v.consumed||v.unknown)||!(v.status===null||status(v.status))||(v.requestId===null)!==(v.status===null))return null;
 if(v.status!==null){const s=v.status as unknown as PreparationStatus;
  if(s.origin.serviceInstance!==v.serviceInstance||s.origin.projectId!==v.projectId||s.origin.requestId!==v.requestId||!sameOfflineData(s.selection,v.selection)||v.pending!==(s.settlement!=='settled')||v.unknown!==(s.phase==='unknown'))return null;
  if(v.permission==='start'){if(!s.prepared||s.prepared.reviewId!==v.reviewId||s.startGrantId!==v.grantId||v.consumed!==s.startSubmitted||v.enabled&&s.phase!=='prepared')return null;}
  else if(s.prepareGrantId!==v.grantId||s.selectionId!==v.reviewId||!v.consumed)return null;
 }else if(v.permission!=='prepare'||v.consumed||v.pending)return null;
 return freeze(v) as unknown as StorePreparationAccess;
}catch{return null;}}
export function storePreparationSelection(input:StorePreparationInput):StoreSelection{
 const p=input.prepare,v=p.savedVersion;
 return {kind:input.kind,savedConfig:p.savedConfig,savedVersion:{bytes:v.bytes,sha256:v.sha256,name:v.name,build:v.build},candidate:'candidateOperationId' in p?{operationId:p.candidateOperationId,sha256:p.candidateSha256}:null,
  ...('stage' in p?{later:{stage:p.stage,predecessorOperationId:p.predecessorOperationId,predecessorReceiptSha256:p.predecessorReceiptSha256}}:{})};
}
export function parseStorePreparationInput(raw:unknown):StorePreparationInput|null{try{
 const v=copyBoundedComparisonData(raw,8192,256);if(!keys(v,['kind','prepare'])||!kind(v.kind))return null;
 const p=storePreparationPreparesIntent(v.kind)?parseLocalStorePrepareRequest(v.prepare):parseLocalStoreRequest(v.prepare);if(!p)return null;
 if(storePreparationPreparesIntent(v.kind)){
  const stage=storePreparationStage(v.kind);
  if(!('candidateOperationId'in p)||(p.platform??'android')!==(v.kind.startsWith('ios-')?'ios':'android')||(stage?'stage' in p?p.stage!==stage:true:'stage' in p))return null;
 }else{
  const q='query' in p?p.query:undefined,platform=p.platform??'android';
  if(v.kind==='android-access'&&(platform!=='android'||q!==undefined)||v.kind==='ios-access'&&(platform!=='ios'||q!==undefined)
   ||v.kind==='android-versions'&&(platform!=='android'||q!=='android-current-versions')||v.kind==='ios-versions'&&(platform!=='ios'||q!=='ios-current-versions')||v.kind==='paired-versions'&&(platform!=='both'||q!=='paired-current-versions'))return null;
 }
 const input={kind:v.kind,prepare:p} as StorePreparationInput;return selection(storePreparationSelection(input))?freeze(input):null;
}catch{return null;}}
export function storePreparationInput(k:PreparationKind,project:LocalStoreProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null):StorePreparationInput|null{
 if(!kind(k))return null;
 if(storePreparationPreparesIntent(k))return parseStorePreparationInput({kind:k,prepare:localStorePrepareRequest(project,assets,history)});
 const base=localStoreRequest(project,assets);if(!base)return null;
 return parseStorePreparationInput({kind:k,prepare:k==='android-versions'?{...base,platform:'android',query:'android-current-versions'}:k==='ios-versions'?{...base,query:'ios-current-versions'}:base});
}
export const storePreparationConsent=(k:PreparationKind)=>({
 'android-access':'agent-android-store-access-once-v1','ios-access':'agent-ios-store-access-once-v1','android-candidate':'agent-android-store-candidate-prepare-once-v1','ios-candidate':'agent-ios-store-candidate-prepare-once-v1',
 'android-versions':'agent-android-current-versions-edit-once-v1','ios-versions':'agent-ios-current-versions-read-once-v1','paired-versions':'agent-paired-current-versions-edit-once-v1',
 'android-external-testing':'agent-android-external-testing-prepare-once-v1','ios-external-testing':'agent-ios-external-testing-prepare-once-v1',
 'android-production-submit':'agent-android-production-submit-prepare-once-v1','ios-production-submit':'agent-ios-production-submit-prepare-once-v1',
}[k]);
export function createStorePreparationPort(invoke:(name:string,body:Uint8Array)=>Promise<unknown>):StorePreparationPort{
 const send=(name:string,body:object)=>{const b=new TextEncoder().encode(JSON.stringify(body));return b.length<=8192?invoke(name,b):Promise.reject({code:'invalid-input'});};
 return Object.freeze({status:()=>send('agent_store_preparation_access',{}),revoke:()=>send('revoke_agent_store_preparation',{}),allowPrepare:(raw:StorePreparationInput)=>{
  const v=parseStorePreparationInput(raw);return v?send('allow_agent_store_prepare',{...v,consentVersion:'agent-store-native-prepare-once-v1'}):Promise.reject({code:'invalid-input'});
 },allowStart:(raw:PreparationStatus)=>{const s=parseStorePreparationStatus(raw);return s?.prepared&&s.prepareReturned&&s.phase==='prepared'&&!s.startSubmitted&&!s.startGrantId?send('allow_agent_store_preparation_start',{origin:s.origin,review:s.prepared,consentVersion:storePreparationConsent(s.selection.kind)}):Promise.reject({code:'invalid-input'});}});
}
export function storePreparationCommands(a:StorePreparationAccess|null):readonly string[]{if(!a?.projectId||!a.serviceInstance)return[];const base=`${a.projectId} ${a.serviceInstance}`,out:string[]=[];
 if(a.requestId)out.push(`mrk store-status ${base} ${a.requestId} --json`,`mrk store-cancel ${base} ${a.requestId} --json`);
 if(a.enabled)out.unshift(a.permission==='prepare'?`mrk store-prepare ${base} ${a.grantId} ${a.reviewId} --reviewed --json`:`mrk store-start ${base} ${a.requestId} ${a.grantId} ${a.reviewId} --reviewed --json`);return out;
}
/** App peer exemption only for DATA from this same granted preparation. It
 * cannot supply a GUI Attempt, clear a pending Promise, or authorize Start. */
export function storePreparationPeerReason(input:StorePreparationInput|null,r:PreparationReview|null,raw:unknown,reason:string|null):string|null{
 if(!reason||!input||!r)return reason;
 try{const s=copyBoundedComparisonData(raw,65536,2048) as Record<string,unknown>|null;
  if(!s||s.mode!=='native'||s.pending||s.callersPending||s.blocked||s.unconfirmed||s.acknowledged||s.consentUntil!==null||!s.status||typeof s.status!=='object')return reason;
  const state=s.status as Record<string,unknown>,op=state.operation as Record<string,unknown>|null;
  if(!op||op.operationId!==r.operation.operationId||op.ownerGeneration!==r.operation.ownerGeneration||op.phase!=='awaiting-consent'||op.intentUsable!==true)return reason;
  return sameOfflineData(op.context,{...input.prepare,platform:input.prepare.platform??'android',operation:storePreparationPreparesIntent(input.kind)?'local-store-prepare':'local-store-preflight'})?null:reason;
 }catch{return reason;}
}
