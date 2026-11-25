import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseReserveOptions, reserveId, reserveProject } from './versionReserve.ts';
import type { VersionReserveOptions } from './versionReserve.ts';
export interface ReserveReviewOrigin { readonly projectId:string; readonly serviceInstance:string; readonly requestId:string }
export interface ReserveReviewStatus {
  readonly schemaVersion:1; readonly origin:ReserveReviewOrigin; readonly runtimeProjectId:string; readonly options:VersionReserveOptions;
  readonly revision:number; readonly phase:'queued'|'reading'|'finishing'|'review-ready'|'refused'|'stopping'|'unknown';
  readonly settlement:'pending'|'settled'|'unknown'; readonly operationId:string|null;
  readonly review:{readonly id:string;readonly revision:number}|null; readonly remainingMs:number; readonly reason:string|null; readonly doNotReplay:true;
}
const exact=(v:unknown,keys:readonly string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const integer=(v:unknown,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=0&&v<=max;
const revision=(v:unknown):v is number=>integer(v,0xffff_fffe)&&v>0;
export function reviewOrigin(v:unknown):v is ReserveReviewOrigin{return exact(v,['projectId','serviceInstance','requestId'])&&reserveId(v.projectId)&&reserveId(v.serviceInstance)&&reserveId(v.requestId)}
export const sameReviewOrigin=(a:ReserveReviewOrigin,b:ReserveReviewOrigin)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.requestId===b.requestId;
export function parseReserveReviewStatus(raw:unknown):ReserveReviewStatus|null{
  try{
    const v=copyBoundedComparisonData(raw,2048,64);
    if(!exact(v,['schemaVersion','origin','runtimeProjectId','options','revision','phase','settlement','operationId','review','remainingMs','reason','doNotReplay'])||v.schemaVersion!==1||!reviewOrigin(v.origin)||!reserveProject(v.runtimeProjectId)||!revision(v.revision)||v.doNotReplay!==true)return null;
    const options=parseReserveOptions(v.options);if(!options||!['queued','reading','finishing','review-ready','refused','stopping','unknown'].includes(v.phase as string)||!['pending','settled','unknown'].includes(v.settlement as string)||!(v.operationId===null||reserveId(v.operationId))||!integer(v.remainingMs,120000))return null;
    if((v.phase==='unknown')!==(v.settlement==='unknown')||(['review-ready','refused'].includes(v.phase as string))!==(v.settlement==='settled')||v.phase!=='review-ready'&&v.remainingMs!==0)return null;
    if(v.phase==='review-ready'? !exact(v.review,['id','revision'])||!reserveId(v.review.id)||!revision(v.review.revision)||v.review.id!==v.operationId||v.reason!==null : v.review!==null)return null;
    if(!(v.reason===null||['user-cancelled','permission-revoked','expired','context-changed','native-refused','cleanup-unknown','shutdown','busy','unavailable'].includes(v.reason as string))||v.phase==='unknown'&&v.reason!=='cleanup-unknown')return null;
    return Object.freeze({...v,origin:Object.freeze({...v.origin}),options,review:v.review?Object.freeze({...v.review}):null}) as unknown as ReserveReviewStatus;
  }catch{return null}
}
export interface ReserveReviewPort {
  status(origin:ReserveReviewOrigin|null):Promise<unknown>; cancel(origin:ReserveReviewOrigin):Promise<unknown>;
  review(origin:ReserveReviewOrigin):Promise<unknown>; subscribe(listener:(hint:unknown)=>void):Promise<()=>void>;
}
export function createReserveReviewPort(invoke:(name:string,raw:Uint8Array)=>Promise<unknown>,listen:(event:'mrk:agent-version-reserve-review',listener:(v:unknown)=>void)=>Promise<()=>void>):ReserveReviewPort{
  const send=(name:string,origin:ReserveReviewOrigin|null,start=false)=>{
    if(origin!==null&&!reviewOrigin(origin)||start&&origin===null)return Promise.reject({code:'version_reserve_invalid_request'});
    const bytes=new TextEncoder().encode(JSON.stringify(start?{intent:'agent-version-reserve-review',origin}:{origin}));
    return bytes.length+96<=1024?invoke(name,bytes):Promise.reject({code:'version_reserve_invalid_request'});
  };
  return Object.freeze({status:(q:ReserveReviewOrigin|null)=>send('agent_version_reserve_review_status',q),cancel:(q:ReserveReviewOrigin)=>send('cancel_agent_version_reserve_review',q),
    review:(q:ReserveReviewOrigin)=>send('version_reserve_review',q,true),subscribe:(fn:(v:unknown)=>void)=>listen('mrk:agent-version-reserve-review',fn)});
}
