// Bounded comparison DATA. Prepare invokes the SAME Apple owner; this port has
// no native Start, provider, credential discovery or material constructor.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { appleCliId, appleCliModes, parseAppleCliReview } from './agentAppleProvisioning.ts';
import type { AppleCliQuery, AppleCliReview } from './agentAppleProvisioning.ts';
import { parseAppleProvisioningRequest } from './appleProvisioningProtocol.ts';
import type { PrepareAppleProvisioning } from './appleProvisioningTypes.ts';
export type ApplePreparationMode = typeof appleCliModes[number];
export const APPLE_PREPARATION_EVENT = 'mrk-agent-apple-preparation';
export interface ApplePreparationStatus {readonly origin:AppleCliQuery;readonly grantId:string;readonly scopeId:string;readonly mode:ApplePreparationMode;readonly revision:number;
  readonly phase:'queued'|'preparing'|'finishing'|'prepared'|'refused'|'unknown';readonly settlement:'pending'|'settled'|'unknown';readonly reason:string;readonly prepared:AppleCliReview|null;readonly usable:boolean;readonly handedOff:boolean}
export interface ApplePreparationAccess {readonly serviceInstance:string|null;readonly projectId:string|null;readonly grantId:string|null;readonly scopeId:string|null;readonly mode:ApplePreparationMode|null;readonly enabled:boolean;readonly remainingMs:number;readonly status:ApplePreparationStatus|null}
export interface ApplePreparationPort {access():Promise<unknown>;allow(selection:PrepareAppleProvisioning,nonce:string):Promise<unknown>;revoke(nonce:string):Promise<unknown>;request(query:AppleCliQuery):Promise<unknown>;subscribe(listener:(value:unknown)=>void):Promise<()=>void>}
export interface ApplePreparationDelegate {current():boolean;allowReturned():void;run(query:AppleCliQuery,closing:boolean):Promise<boolean>;observe(status:ApplePreparationStatus):Promise<void>;withdrawn(query:AppleCliQuery|null):void;notSent():void;uncertain():void}
const keys=(v:unknown,n:readonly string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===n.length&&n.every(k=>Object.hasOwn(v,k));
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
const mode=(v:unknown):v is ApplePreparationMode=>typeof v==='string'&&(appleCliModes as readonly string[]).includes(v);
export const sameApplePreparationQuery=(a:AppleCliQuery,b:AppleCliQuery)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.requestId===b.requestId;
export const applePreparationQuery=(v:unknown):v is AppleCliQuery=>keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(appleCliId);
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','command-failed','command-incomplete','timed-out','cleanup-unknown','history-unavailable'];
function frozen<T>(v:T):T{if(v&&typeof v==='object'){Object.values(v).forEach(frozen);Object.freeze(v);}return v;}
function status(v:unknown):v is ApplePreparationStatus {
  if(!keys(v,['origin','grantId','scopeId','mode','revision','phase','settlement','reason','prepared','usable','handedOff'])||!applePreparationQuery(v.origin)||!appleCliId(v.grantId)||!appleCliId(v.scopeId)||!mode(v.mode)||!integer(v.revision,1,0xffff_fffe)||typeof v.usable!=='boolean'||typeof v.handedOff!=='boolean'||!reasons.includes(String(v.reason)))return false;
  const r=v.prepared===null?null:parseAppleCliReview(v.prepared);
  if(v.prepared!==null&&(!r||r.mode!==v.mode)||v.usable&&(v.phase!=='prepared'||v.handedOff||v.reason!=='none')||v.handedOff&&v.phase!=='prepared')return false;
  const unknown=['cleanup-unknown','history-unavailable'].includes(String(v.reason));
  if(v.phase==='unknown')return v.settlement==='unknown'&&unknown&&!v.usable&&!v.handedOff&&v.prepared===null;
  if(unknown)return false;
  if(v.phase==='prepared')return v.settlement==='settled'&&r!==null;
  if(v.phase==='refused')return v.settlement==='settled'&&v.prepared===null&&!v.usable&&!v.handedOff&&v.reason!=='none';
  return ['queued','preparing','finishing'].includes(String(v.phase))&&v.settlement==='pending'&&v.prepared===null&&!v.usable&&!v.handedOff;
}
export function parseApplePreparationStatus(raw:unknown):ApplePreparationStatus|null{try{const v=copyBoundedComparisonData(raw,8192,180);return status(v)?frozen(v):null;}catch{return null;}}
export function parseApplePreparationAccess(raw:unknown):ApplePreparationAccess|null{try{
  const v=copyBoundedComparisonData(raw,12288,220);
  if(!keys(v,['serviceInstance','projectId','grantId','scopeId','mode','enabled','remainingMs','status'])||typeof v.enabled!=='boolean'||!integer(v.remainingMs,0,300000))return null;
  const all=['serviceInstance','projectId','grantId','scopeId'].every(k=>appleCliId(v[k]))&&mode(v.mode),none=['serviceInstance','projectId','grantId','scopeId','mode'].every(k=>v[k]===null);
  if(!all&&!none||v.enabled!==(all&&v.status===null&&v.remainingMs>0)||!v.enabled&&v.remainingMs!==0)return null;
  if(v.status!==null&&(!status(v.status)||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.projectId!==v.projectId||v.status.grantId!==v.grantId||v.status.scopeId!==v.scopeId||v.status.mode!==v.mode))return null;
  return frozen(v) as unknown as ApplePreparationAccess;
}catch{return null;}}
export function applePreparationSelection(raw:unknown):PrepareAppleProvisioning|null{try{const copy=copyBoundedComparisonData(raw,8192,150),v=parseAppleProvisioningRequest(copy);return v&&mode(v.mode)?frozen(v):null;}catch{return null;}}
export function createApplePreparationPort(invoke:(command:string,body:Uint8Array)=>Promise<unknown>,listen:(event:typeof APPLE_PREPARATION_EVENT,listener:(value:unknown)=>void)=>Promise<()=>void>):ApplePreparationPort {
  const send=(name:string,value:object)=>{const bytes=new TextEncoder().encode(JSON.stringify(value));return bytes.length<=8192?invoke(name,bytes):Promise.reject({code:'agent_apple_invalid'});};
  return Object.freeze({access:()=>send('agent_apple_provisioning_access',{intent:'preparation'}),
    allow:(raw:PrepareAppleProvisioning,nonce:string)=>{const selection=applePreparationSelection(raw);return selection&&appleCliId(nonce)?send('allow_agent_apple_provisioning',{intent:'preparation',consentId:nonce,consentVersion:'agent-apple-prepare-once-v1',selection}):Promise.reject({code:'agent_apple_invalid'});},
    revoke:(nonce:string)=>appleCliId(nonce)?send('revoke_agent_apple_provisioning',{intent:'preparation',consentId:nonce}):Promise.reject({code:'agent_apple_invalid'}),
    request:(q:AppleCliQuery)=>applePreparationQuery(q)?send('agent_apple_provisioning_request_status',{intent:'agent-apple-prepare',origin:q}):Promise.reject({code:'agent_apple_invalid'}),
    subscribe:(listener:(value:unknown)=>void)=>listen(APPLE_PREPARATION_EVENT,listener)});
}
export function applePreparationCommands(raw:ApplePreparationAccess|null):readonly string[]{const a=parseApplePreparationAccess(raw);if(!a)return[];
  if(a.status){const q=a.status.origin;return[`mrk apple-provisioning-status ${q.projectId} ${q.serviceInstance} ${q.requestId}`,`mrk apple-provisioning-cancel ${q.projectId} ${q.serviceInstance} ${q.requestId}`];}
  return a.enabled?[`mrk apple-provisioning-prepare ${a.projectId} ${a.serviceInstance} ${a.grantId} ${a.scopeId} --reviewed`]:[];
}
