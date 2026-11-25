// Fixed comparison-only inspection of one already native-opened image Import.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseMetadataImagesEditStatus } from './metadataImagesProtocol.ts';
import { isImagesAgentReview, sameImagesAgentOrigin } from './serviceMetadataImagesProtocol.ts';
import type { ImagesAgentOrigin, ImagesAgentReview } from './serviceMetadataImagesProtocol.ts';
import type { MetadataImagesEditStatus } from './metadataImages.ts';
export const IMAGES_PREPARE_EVENT = 'mrk:agent-metadata-images-prepare';
export interface ImagesReadOriginal { sessionId:string; ownerGeneration:string; revision:string; nativeStatusRevision:number; baselineGeneration:number }
export interface ImagesReadItem { itemId:string; displayName:string; selectedBytes:number; selectedSha256:string; beforeSha256:string|null; canReplace:boolean; replaceExisting:false }
export interface ImagesReadObservation { original:ImagesReadOriginal; platform:'android'|'ios'; locale:string; assetType:string; openedSha256:string; items:ImagesReadItem[] }
export interface ImagesPrepareChoice { itemId:string; replaceExisting:boolean }
export interface ImagesPreparationStatus {
  schemaVersion:1; origin:ImagesAgentOrigin; runtimeProjectId:string; revision:number;
  phase:'queued-read'|'reading'|'editing'|'queued-prepare'|'preparing'|'reviewing'|'transferred'|'stopping'|'final'|'unknown';
  settlement:'pending'|'settled'|'unknown'; observation:ImagesReadObservation|null; choices:ImagesPrepareChoice[]|null;
  review:ImagesAgentReview|null; remainingMs:number; cancelRequested:boolean;
  result:{prepared:boolean;transferred:boolean;gui:boolean}|null; doNotReplay:true;
}
export interface MetadataImagesPrepareApi {
  status(q?:ImagesAgentOrigin):Promise<ImagesPreparationStatus|null>;
  inspect(q:ImagesAgentOrigin,original:ImagesReadOriginal):Promise<ImagesPreparationStatus>;
  prepare(q:ImagesAgentOrigin):Promise<MetadataImagesEditStatus>;
  cancel(q:ImagesAgentOrigin):Promise<ImagesPreparationStatus>;
  subscribe(fn:(v:unknown)=>void):Promise<()=>void>;
}
const keys=(v:unknown,n:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===n.length&&n.every(k=>Object.hasOwn(v,k));
const id=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{32}(?![\s\S])/.test(v)&&!/^0+$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}(?![\s\S])/.test(v);
const uint=(v:unknown,max=0xfffffffe,min=0):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>=min&&v<=max;
const origin=(v:unknown):v is ImagesAgentOrigin=>keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(id);
export const sameImagesReadOriginal=(a:ImagesReadOriginal,b:ImagesReadOriginal):boolean=>
 a.sessionId===b.sessionId&&a.ownerGeneration===b.ownerGeneration&&a.revision===b.revision&&a.nativeStatusRevision===b.nativeStatusRevision&&a.baselineGeneration===b.baselineGeneration;
function original(v:unknown):v is ImagesReadOriginal{return keys(v,['sessionId','ownerGeneration','revision','nativeStatusRevision','baselineGeneration'])&&[v.sessionId,v.ownerGeneration,v.revision].every(id)&&uint(v.nativeStatusRevision)&&uint(v.baselineGeneration);}
function observation(v:unknown):v is ImagesReadObservation {
 if(!keys(v,['original','platform','locale','assetType','openedSha256','items'])||!original(v.original)||(v.platform!=='android'&&v.platform!=='ios')||
 typeof v.locale!=='string'||!/^[A-Za-z0-9-]{2,12}(?![\s\S])/.test(v.locale)||typeof v.assetType!=='string'||!/^[A-Za-z0-9_]{1,64}(?![\s\S])/.test(v.assetType)||!hash(v.openedSha256)||!Array.isArray(v.items)||v.items.length<1||v.items.length>10)return false;
 let total=0;const ids=new Set<string>();
 for(const x of v.items){if(!keys(x,['itemId','displayName','selectedBytes','selectedSha256','beforeSha256','canReplace','replaceExisting'])||!id(x.itemId)||ids.has(x.itemId)||
 typeof x.displayName!=='string'||!x.displayName||new TextEncoder().encode(x.displayName).length>255||['.','..'].includes(x.displayName)||/[\p{Cc}/\\]/u.test(x.displayName)||
 !uint(x.selectedBytes,10485760,1)||!hash(x.selectedSha256)||x.beforeSha256!==null&&!hash(x.beforeSha256)||typeof x.canReplace!=='boolean'||x.canReplace&&x.beforeSha256===null||x.replaceExisting!==false)return false;
 ids.add(x.itemId);total+=x.selectedBytes;}
 return total<=25165824&&new TextEncoder().encode(JSON.stringify(v)).length<=6144;
}
function status(v:unknown):v is ImagesPreparationStatus {
 if(!keys(v,['schemaVersion','origin','runtimeProjectId','revision','phase','settlement','observation','choices','review','remainingMs','cancelRequested','result','doNotReplay'])||v.schemaVersion!==1||!origin(v.origin)||
 typeof v.runtimeProjectId!=='string'||!/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(v.runtimeProjectId)||!uint(v.revision,0xfffffffe,1)||
 !['queued-read','reading','editing','queued-prepare','preparing','reviewing','transferred','stopping','final','unknown'].includes(String(v.phase))||
 !['pending','settled','unknown'].includes(String(v.settlement))||(v.phase==='unknown')!==(v.settlement==='unknown')||(v.phase==='final')!==(v.settlement==='settled')||
 !uint(v.remainingMs,900000)||typeof v.cancelRequested!=='boolean'||v.doNotReplay!==true||v.observation!==null&&!observation(v.observation))return false;
 const o=v.observation;
 if(v.choices!==null&&(!o||!Array.isArray(v.choices)||v.choices.length!==o.items.length||!v.choices.every((c,i)=>{const item=o.items[i];return !!item&&keys(c,['itemId','replaceExisting'])&&c.itemId===item.itemId&&typeof c.replaceExisting==='boolean'&&(!c.replaceExisting||item.canReplace&&item.beforeSha256!==null);})))return false;
 if(v.review!==null){const r=v.review;if(!isImagesAgentReview(r)||!o||v.choices===null||r.original.sessionId!==o.original.sessionId||r.original.ownerGeneration!==o.original.ownerGeneration||r.original.revision!==o.original.revision||r.original.baselineGeneration!==o.original.baselineGeneration||r.original.draftRevision!==1||r.platform!==o.platform||r.locale!==o.locale||r.assetType!==o.assetType||r.fileCount!==o.items.length)return false;}
 if(['editing','queued-prepare','preparing','reviewing','transferred'].includes(String(v.phase))&&!o||['queued-prepare','preparing','reviewing','transferred'].includes(String(v.phase))&&v.choices===null||['reviewing','transferred'].includes(String(v.phase))&&v.review===null)return false;
 return v.phase==='final'?keys(v.result,['prepared','transferred','gui'])&&Object.values(v.result).every(x=>typeof x==='boolean'):v.result===null;
}
function freeze<T>(v:T):T{if(v&&typeof v==='object'){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;}
export function parseImagesPreparationStatus(raw:unknown):ImagesPreparationStatus|null {try{const v=copyBoundedComparisonData(raw,8192,1024);return status(v)?freeze(v):null;}catch{return null;}}
type Invoke=<T>(c:string,args?:Record<string,unknown>|Uint8Array)=>Promise<T>;
export function createImagesPrepareApi(mode:string,invoke:Invoke,listen?: (e:typeof IMAGES_PREPARE_EVENT,fn:(v:unknown)=>void)=>Promise<()=>void>):MetadataImagesPrepareApi|undefined {
 if(mode!=='native'||!listen)return undefined;
 const fail=()=>({code:'image_preparation_unconfirmed',message:'Keep this original image request. Do not repeat Prepare.',retryable:false});
 const raw=(v:unknown)=>{const b=new TextEncoder().encode(JSON.stringify(v));if(b.length+96>4096)throw fail();return b;};
 const call=async<T>(c:string,v:unknown,parse:(v:unknown)=>T|null):Promise<T>=>{const value=parse(await invoke(c,raw(v)));if(value===null)throw fail();return value;};
 return {status:async(q)=>{const v=await invoke('agent_metadata_images_prepare_status',raw(q??{}));if(v===null)return null;const s=parseImagesPreparationStatus(v);if(!s||q&&!sameImagesAgentOrigin(s.origin,q))throw fail();return s;},
 inspect:(q,o)=>call('agent_metadata_images_inspect',{origin:q,original:o},parseImagesPreparationStatus),
 prepare:(q)=>call('metadata_images_edit_prepare',{intent:'agent-metadata-images-prepare',origin:q},parseMetadataImagesEditStatus),
 cancel:(q)=>call('agent_metadata_images_prepare_cancel',q,parseImagesPreparationStatus),subscribe:(fn)=>listen(IMAGES_PREPARE_EVENT,fn)};
}
