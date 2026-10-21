// Bounded preparation DATA; only the existing native Open/Prepare owns source
// access, selected reservation values and the original immutable review.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseVersionEditStatus } from './releaseVersionEdit.ts';
import type { VersionCheckout, VersionEditStatus, VersionValues } from './releaseVersionEdit.ts';
import { validVersionEditReview } from './serviceVersionEditProtocol.ts';
import type { VersionEditOrigin, VersionEditRequest, VersionEditReview } from './serviceVersionEditProtocol.ts';

export type VersionPrepareSelection = {kind:'manual'; values:VersionValues} | {kind:'reserved'; reservationId:string};
export interface VersionPrepareCheckout {
  revision:string; source:string; iosEnabled:boolean; values:VersionValues;
  configBytes:number; configSha256:string; versionBytes:number; versionSha256:string;
}
export interface VersionPreparation {
  schemaVersion:1; origin:VersionEditOrigin; runtimeProjectId:string; selection:VersionPrepareSelection; revision:number;
  phase:'queued'|'opening'|'opened'|'preparing'|'reviewing'|'applying'|'stopping'|'final'|'unknown';
  settlement:'pending'|'settled'|'unknown'; original:{sessionId:string; ownerGeneration:string}|null;
  checkout:VersionPrepareCheckout|null; proposed:VersionValues|null; review:VersionEditReview|null;
  applyRequest:VersionEditOrigin|null; guiOwned:boolean; cancelRequested:boolean; result:VersionEditRequest['result']; doNotReplay:true;
}
export interface VersionPrepareApi {
  status(origin?:VersionEditOrigin):Promise<VersionPreparation|null>;
  open(origin:VersionEditOrigin):Promise<VersionEditStatus>;
  prepare(origin:VersionEditOrigin, draftRevision:number, baselineGeneration:number):Promise<VersionEditStatus>;
  cancel(origin:VersionEditOrigin):Promise<VersionPreparation|null>;
}
const keys=(v:unknown,n:string[]):v is Record<string,unknown> => !!v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===n.length && n.every(k=>Object.hasOwn(v,k));
const id=(v:unknown):v is string => typeof v==='string' && /^[0-9a-f]{32}(?![\s\S])/.test(v) && !/^0+$/.test(v);
const hash=(v:unknown):v is string => typeof v==='string' && /^[0-9a-f]{64}(?![\s\S])/.test(v);
const uint=(v:unknown,max=0xfffffffe,min=0):v is number => typeof v==='number' && Number.isInteger(v) && v>=min && v<=max;
const text=(v:unknown,n:number):v is string => typeof v==='string' && v.length>0 && v.length<=n && /^[\x20-\x7e]+(?![\s\S])/.test(v);
const values=(v:unknown):v is VersionValues => keys(v,['name','build']) && text(v.name,64) && typeof v.build==='string' && /^[0-9]{1,10}(?![\s\S])/.test(v.build);
const origin=(v:unknown):v is VersionEditOrigin => keys(v,['projectId','serviceInstance','requestId']) && Object.values(v).every(id);
const selection=(v:unknown):v is VersionPrepareSelection => keys(v,['kind','values']) && v.kind==='manual' && values(v.values) || keys(v,['kind','reservationId']) && v.kind==='reserved' && id(v.reservationId);
export const sameVersionPrepareOrigin=(a:VersionEditOrigin,b:VersionEditOrigin):boolean => a.projectId===b.projectId && a.serviceInstance===b.serviceInstance && a.requestId===b.requestId;
export function versionPreparationCheckoutMatches(c:VersionPrepareCheckout, actual:VersionCheckout):boolean {
  return c.revision===actual.revision && c.source===actual.source && c.iosEnabled===actual.iosEnabled && actual.values!==null &&
    c.values.name===actual.values.name && c.values.build===actual.values.build && c.configBytes===actual.baseline.savedConfig.bytes &&
    c.configSha256===actual.baseline.savedConfig.sha256 && actual.baseline.savedVersion.state==='present' &&
    c.versionBytes===actual.baseline.savedVersion.bytes && c.versionSha256===actual.baseline.savedVersion.sha256;
}
export function parseVersionPreparation(raw:unknown):VersionPreparation|null {
  try {
    const v=copyBoundedComparisonData(raw,8192,256);
    if (!keys(v,['schemaVersion','origin','runtimeProjectId','selection','revision','phase','settlement','original','checkout','proposed','review','applyRequest','guiOwned','cancelRequested','result','doNotReplay']) ||
      v.schemaVersion!==1 || !origin(v.origin) || typeof v.runtimeProjectId!=='string' || !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(v.runtimeProjectId) ||
      !selection(v.selection) || !uint(v.revision,0xfffffffe,1) || !['queued','opening','opened','preparing','reviewing','applying','stopping','final','unknown'].includes(String(v.phase)) ||
      !['pending','settled','unknown'].includes(String(v.settlement)) || (v.phase==='final')!==(v.settlement==='settled') || (v.phase==='unknown')!==(v.settlement==='unknown') ||
      (v.phase==='final')!==(v.result!==null) || v.doNotReplay!==true || typeof v.guiOwned!=='boolean' || typeof v.cancelRequested!=='boolean' ||
      !(v.original===null || keys(v.original,['sessionId','ownerGeneration']) && Object.values(v.original).every(id))) return null;
    const c=v.checkout;
    if (c!==null && (!keys(c,['revision','source','iosEnabled','values','configBytes','configSha256','versionBytes','versionSha256']) || !id(c.revision) || !text(c.source,512) ||
      c.source.startsWith('/') || /[\\:]/.test(c.source) || !c.source.split('/').every(p=>p!=='' && p!=='.' && p!=='..') || typeof c.iosEnabled!=='boolean' || !values(c.values) ||
      !uint(c.configBytes,512*1024,1) || !hash(c.configSha256) || !uint(c.versionBytes,65536,1) || !hash(c.versionSha256))) return null;
    if ((c!==null)!==(v.proposed!==null) || !(v.proposed===null || values(v.proposed)) || c!==null && v.original===null ||
      ['opened','preparing'].includes(String(v.phase)) && c===null || ['reviewing','applying'].includes(String(v.phase)) && v.review===null ||
      !(v.applyRequest===null || origin(v.applyRequest) && v.applyRequest.projectId===v.origin.projectId && v.applyRequest.serviceInstance===v.origin.serviceInstance && v.applyRequest.requestId!==v.origin.requestId) ||
      v.guiOwned && v.applyRequest!==null) return null;
    if (v.selection.kind==='manual' && v.proposed!==null && (v.proposed.name!==v.selection.values.name || v.proposed.build!==v.selection.values.build)) return null;
    if (v.review!==null) {
      if (!validVersionEditReview(v.review) || !c || !v.proposed || !v.original || v.review.original.sessionId!==v.original.sessionId ||
        v.review.original.ownerGeneration!==v.original.ownerGeneration || v.review.original.revision!==c.revision || v.review.source!==c.source ||
        v.review.beforeBytes!==c.versionBytes || v.review.beforeSha256!==c.versionSha256 || v.review.name!==v.proposed.name || v.review.build!==v.proposed.build ||
        (v.selection.kind==='reserved')!==(v.review.candidateId!==null)) return null;
    }
    if (v.result!==null && (!keys(v.result,['effect','journal','cancelled','applySubmitted']) || !['not-started','unchanged','rolled-back','committed'].includes(String(v.result.effect)) ||
      !['not-created','clean','recovery-required'].includes(String(v.result.journal)) || typeof v.result.cancelled!=='boolean' || typeof v.result.applySubmitted!=='boolean')) return null;
    const freeze=(x:unknown):void => {if(x && typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}};
    freeze(v);return v as unknown as VersionPreparation;
  } catch { return null; }
}
type Invoke=<T>(command:string,args?:Record<string,unknown>|Uint8Array)=>Promise<T>;
export function createVersionPrepareApi(invoke:Invoke):VersionPrepareApi {
  const error=()=>({code:'agent_version_prepare_unconfirmed',message:'Keep the same version preparation. Check or cancel it; do not resend.',retryable:false});
  const raw=(v:unknown)=>{const b=new TextEncoder().encode(JSON.stringify(v));if(b.length>1024)throw error();return b;};
  const status=async(command:string,v:unknown)=>{const r=await invoke(command,raw(v));if(r===null)return null;const p=parseVersionPreparation(r);if(!p)throw error();return p;};
  const call=async(command:string,v:unknown)=>{const p=parseVersionEditStatus(await invoke(command,raw(v)));if(!p)throw error();return p;};
  return Object.freeze({status:(origin?:VersionEditOrigin)=>status('agent_version_edit_status',{intent:'preparation',origin:origin??null}),
    cancel:(origin:VersionEditOrigin)=>status('revoke_agent_version_edit',{intent:'agent-version-prepare',origin}),
    open:(origin:VersionEditOrigin)=>call('release_version_edit_open',{intent:'agent-version-prepare',origin}),
    prepare:(origin:VersionEditOrigin,draftRevision:number,baselineGeneration:number)=>call('release_version_edit_prepare',{intent:'agent-version-prepare',origin,draftRevision,baselineGeneration})});
}
