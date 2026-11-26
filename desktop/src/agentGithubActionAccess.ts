import { GITHUB_OPERATION_KINDS, isGithubOperationKind, parseGithubOperationSelection, parseGithubOperationReference, sameGithubOperationSelection, parseGithubOperationSnapshot, githubOperationResultMatches, githubOperationEffect } from './githubOperationDelegation.ts';
import type { GithubOperationSelection, GithubOperationReference, GithubOperationSnapshot } from './githubOperationDelegation.ts';
import { GITHUB_REMOTE_SETTINGS_KINDS, isGithubRemoteSettingsKind, parseGithubRemoteSettingsSelection, parseGithubRemoteSettingsReference, sameGithubRemoteSettingsSelection, parseGithubRemoteSettingsResult, githubRemoteSettingsRow, githubRemoteSettingsInitial, githubRemoteSettingsEffect } from './githubRemoteSetupDelegation.ts';
import type { GithubRemoteSettingsSelection, GithubRemoteSettingsReference, GithubRemoteSettingsResult } from './githubRemoteSetupDelegation.ts';
import { GITHUB_DISPATCH_KINDS, isGithubDispatchKind, parseGithubDispatchSelection, parseGithubDispatchReference, parseGithubDispatchSnapshot, githubDispatchReferenceMatches, githubDispatchEffect, githubDispatchInitial } from './githubDispatchDelegation.ts';
import { ENROLLMENT_ACTION_KINDS, isEnrollmentActionKind, enrollmentActionId, parseEnrollmentActionSelection, parseEnrollmentActionReference, sameEnrollmentActionSelection, parseEnrollmentActionResult } from './agentVersionEnrollment.ts';
import type { EnrollmentActionSelection, EnrollmentActionReference, EnrollmentActionResult } from './agentVersionEnrollment.ts';
import type { GithubDispatchSelection, GithubDispatchReference, GithubDispatchSnapshot } from './githubDispatchDelegation.ts';
// Closed comparison DATA, never native consent.
import { permissionRevision, parseGithubActivitySelection, parseGithubActivityReference, sameGithubActivitySelection, parseGithubActivitySnapshot } from './githubActivityDelegation.ts';
import type { GithubActivitySelection, GithubActivityReference, GithubActivitySnapshot } from './githubActivityDelegation.ts';
import { parseGithubPublicationSelection, parseGithubPublicationReference, sameGithubPublicationSelection, githubPublicationEffect } from './githubPublicationDelegation.ts';
import type { GithubPublicationSelection, GithubPublicationReference } from './githubPublicationDelegation.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, sameConnectionData as same } from './githubConnectionProtocol.ts';
export const GITHUB_ACTION_KINDS = ['repository-create','draft-pr-create','pr-create','failed-jobs-retry','setup-publish','setup-reconcile','activity-overview',...GITHUB_DISPATCH_KINDS,...ENROLLMENT_ACTION_KINDS,...GITHUB_REMOTE_SETTINGS_KINDS,...GITHUB_OPERATION_KINDS] as const;
export type GithubActionKind = typeof GITHUB_ACTION_KINDS[number];
interface PreparedSelection { readonly kind:'repository-create'|'draft-pr-create'|'pr-create'|'failed-jobs-retry'; readonly sessionId:string; readonly consentId:string; readonly expectedRevision:number }
export type GithubActionSelection = PreparedSelection | GithubPublicationSelection | GithubActivitySelection | GithubDispatchSelection | EnrollmentActionSelection | GithubRemoteSettingsSelection | GithubOperationSelection;
export type GithubActionReview = (PreparedSelection & { readonly preparedSha256:string }) | GithubPublicationReference | GithubActivityReference | GithubDispatchReference | EnrollmentActionReference | GithubRemoteSettingsReference | GithubOperationReference;
export interface GithubActionQuery { readonly projectId:string; readonly serviceInstance:string; readonly requestId:string }
export interface GithubActionStatus {
  readonly origin:GithubActionQuery; readonly grantId:string; readonly review:GithubActionReview; readonly revision:number;
  readonly state:'queued'|'starting'|'running'|'stopping'|'finishing'|'complete'|'refused'|'cancelled'|'unknown';
  readonly settlement:'pending'|'settled'|'unknown'; readonly operationId:string|null; readonly reason:string;
  readonly effect:'none'|'branch-observed'|'draft-pr-observed'|'not-sent'|'potentially-applied'|'acknowledged-unconfirmed'|'created-observed'|'unresolved'|'found-unattributed'|'accepted-unconfirmed'|'accepted'|'advanced-unattributed'|'counter-observed'|'local-mapping-observed'|'settings-readback-observed'|'closed-confirmed';
  readonly neverAdmitted:boolean; readonly doNotReplay:true; readonly snapshot?:GithubActivitySnapshot; readonly result?:GithubDispatchSnapshot|EnrollmentActionResult|GithubRemoteSettingsResult|GithubOperationSnapshot;
}
export interface AgentGithubActionAccess {
  readonly permissionRevision:string;
  readonly serviceInstance:string|null; readonly projectId:string|null; readonly grantId:string|null; readonly review:GithubActionReview|null;
  readonly enabled:boolean; readonly remainingMs:number; readonly consumed:boolean; readonly pending:boolean; readonly unknown:boolean; readonly status:GithubActionStatus|null;
}
export interface AgentGithubActionPort {access():Promise<unknown>;allow(selection:GithubActionSelection,expectedPermissionRevision:string):Promise<unknown>;revoke():Promise<unknown>;request(query:GithubActionQuery):Promise<unknown>}
// Each method closes over the SAME existing controller Review/Original. This
// interface cannot manufacture a native Start, retirement or provider receipt.
export interface GithubActionDelegate {
  current():boolean; allowReturned():void; observe(status:GithubActionStatus):void; unusedReturned():void;
  notSubmitted():void; uncertain():void; released():boolean;
}
const one=(v:unknown,a:readonly string[]):v is string=>typeof v==='string'&&a.includes(v);
export const githubActionId=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v)&&v!=='0'.repeat(32);
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^a-f0-9]/.test(v);
const number=(v:unknown,a:number,b:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=a&&v<=b;
function selection(v:unknown,review:true):v is GithubActionReview;
function selection(v:unknown,review?:false):v is GithubActionSelection;
function selection(v:unknown,review=false):boolean {
  if(v&&typeof v==='object'&&'kind'in v&&isGithubRemoteSettingsKind(v.kind))return !!(review?parseGithubRemoteSettingsReference(v):parseGithubRemoteSettingsSelection(v));
  if(v&&typeof v==='object'&&'kind'in v&&isGithubOperationKind(v.kind))return !!(review?parseGithubOperationReference(v):parseGithubOperationSelection(v));
  if(v&&typeof v==='object'&&'kind'in v&&isEnrollmentActionKind(v.kind))return !!(review?parseEnrollmentActionReference(v):parseEnrollmentActionSelection(v));
  if(v&&typeof v==='object'&&'kind'in v&&isGithubDispatchKind(v.kind))return !!(review?parseGithubDispatchReference(v):parseGithubDispatchSelection(v));
  if(v&&typeof v==='object'&&('kind' in v)&&v.kind==='activity-overview')return !!(review?parseGithubActivityReference(v):parseGithubActivitySelection(v));
  if(v&&typeof v==='object'&&('kind' in v)&&(v.kind==='setup-publish'||v.kind==='setup-reconcile'))return !!(review?parseGithubPublicationReference(v):parseGithubPublicationSelection(v));
  return keys(v,['kind','sessionId','consentId','expectedRevision',...(review?['preparedSha256']:[])])&&one(v.kind,['repository-create','draft-pr-create','pr-create','failed-jobs-retry'])&&
    typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&hex(v.consentId,32)&&number(v.expectedRevision,1,0xffff_fffe)&&(!review||hex(v.preparedSha256,64));
}
function query(v:unknown):v is GithubActionQuery {return keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(githubActionId);}
function freeze<T>(v:T):T {if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
export function parseGithubActionSelection(raw:unknown):GithubActionSelection|null {try{const v=copyBoundedComparisonData(raw,16896,80);if(v&&typeof v==='object'&&'kind'in v&&isGithubOperationKind(v.kind))return parseGithubOperationSelection(v);return selection(v)&&new TextEncoder().encode(JSON.stringify(v)).length<=4096?freeze(v):null;}catch{return null;}}
export function sameGithubActionSelection(a:GithubActionSelection|GithubActionReview|null,b:GithubActionSelection|GithubActionReview|null):boolean {
  if(!a||!b||a.kind!==b.kind)return false;
  if(isGithubRemoteSettingsKind(a.kind))return sameGithubRemoteSettingsSelection(a,b);
  if(isGithubOperationKind(a.kind))return sameGithubOperationSelection(a,b);
  if(isEnrollmentActionKind(a.kind)||isEnrollmentActionKind(b.kind))return isEnrollmentActionKind(a.kind)&&isEnrollmentActionKind(b.kind)&&sameEnrollmentActionSelection(a as EnrollmentActionSelection,b as EnrollmentActionSelection);
  if(isGithubDispatchKind(a.kind)){
    const ar=parseGithubDispatchReference(a),br=parseGithubDispatchReference(b),sa=parseGithubDispatchSelection(a),bs=parseGithubDispatchSelection(b);
    return ar&&bs?githubDispatchReferenceMatches(ar,bs):br&&sa?githubDispatchReferenceMatches(br,sa):ar&&br?same(ar,br):!!sa&&!!bs&&same(sa,bs);
  }
  if(a.kind==='activity-overview'||b.kind==='activity-overview')return a.kind==='activity-overview'&&b.kind==='activity-overview'&&sameGithubActivitySelection(a,b);
  if(a.kind==='setup-reconcile'||a.kind==='setup-publish')return b.kind==='setup-reconcile'||b.kind==='setup-publish'?sameGithubPublicationSelection(a,b):false;
  return 'consentId'in a&&'consentId'in b&&a.sessionId===b.sessionId&&a.consentId===b.consentId&&a.expectedRevision===b.expectedRevision;
}
export const sameGithubActionReview=(a:GithubActionReview|null,b:GithubActionReview|null):boolean=>!!a&&!!b&&same(a,b);
const prefixes:Readonly<Record<Exclude<GithubActionKind,import('./agentVersionEnrollment.ts').EnrollmentActionKind>,string>>={'repository-create':'repository-create-','draft-pr-create':'github-pull-request-','pr-create':'github-pull-request-','failed-jobs-retry':'github-actions-retry-','setup-publish':'github-publication-','setup-reconcile':'github-publication-','activity-overview':'github-activity-','preflight-prepare':'github-preflight-','preflight-dispatch':'github-preflight-','preflight-pending':'github-preflight-','preflight-observe':'github-preflight-','release-prepare':'github-release-','release-dispatch':'github-release-','release-pending':'github-release-','release-observe':'github-release-','setup-prepare':'github-publication-','counter-prepare':'github-publication-','counter-create':'github-publication-','publication-pending':'github-publication-','counter-reconcile':'github-publication-','remote-setup-prepare':'github-setup-','remote-setup-apply':'github-setup-','repository-prepare':'repository-create-','repository-pending':'repository-create-','repository-reconcile':'repository-create-','pr-prepare':'github-pull-request-','pr-pending':'github-pull-request-','pr-reconcile':'github-pull-request-','failed-jobs-prepare':'github-actions-retry-','failed-jobs-pending':'github-actions-retry-','failed-jobs-reconcile':'github-actions-retry-'};
function operation(v:unknown,k:GithubActionKind):v is string {
  if(isEnrollmentActionKind(k))return enrollmentActionId(v);
  if(typeof v!=='string'||!v.startsWith(prefixes[k]))return false;const n=v.slice(prefixes[k].length);
  return /^[1-9][0-9]{0,19}$/.test(n)&&BigInt(n)<=18446744073709551615n;
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','cleanup-unknown','history-unavailable'];
function status(v:unknown):v is GithubActionStatus {
  if(!keys(v,['origin','grantId','review','revision','state','settlement','operationId','reason','effect','neverAdmitted','doNotReplay',...(v&&typeof v==='object'&&'snapshot' in v?['snapshot']:[]),...(v&&typeof v==='object'&&'result'in v?['result']:[])])||!query(v.origin)||!githubActionId(v.grantId)||
    !selection(v.review,true)||!number(v.revision,1,0xffff_fffe)||v.doNotReplay!==true||typeof v.neverAdmitted!=='boolean'||!one(v.reason,reasons)||
    !one(v.state,['queued','starting','running','stopping','finishing','complete','refused','cancelled','unknown'])||!one(v.settlement,['pending','settled','unknown'])||
    v.operationId!==null&&!operation(v.operationId,v.review.kind))return false;
  const activity=v.review.kind==='activity-overview',dispatch=isGithubDispatchKind(v.review.kind),enrollment=isEnrollmentActionKind(v.review.kind),remote=isGithubRemoteSettingsKind(v.review.kind),opFamily=isGithubOperationKind(v.review.kind);
  if(activity){
    if(v.state==='complete'){if(!parseGithubActivitySnapshot(v.snapshot,v.review as GithubActivityReference))return false;}
    else if('snapshot' in v)return false;
  }else if('snapshot' in v||!dispatch&&!remote&&!opFamily&&new TextEncoder().encode(JSON.stringify(v)).length>2048)return false;
  if(remote){
    const k=v.review.kind as import('./githubRemoteSetupDelegation.ts').GithubRemoteSettingsKind, result='result'in v?parseGithubRemoteSettingsResult(v.result,k):null;
    if('result'in v&&(!result||v.neverAdmitted||!githubRemoteSettingsRow(k,v.state,v.reason,v.effect,result))||v.state==='complete'&&!result||v.effect==='settings-readback-observed'&&v.state!=='complete')return false;
  }else if(opFamily){
    const result='result'in v?parseGithubOperationSnapshot(v.result,v.review.kind as import('./githubOperationDelegation.ts').GithubOperationKind):null;
    if('result'in v&&(!result||v.neverAdmitted||!githubOperationResultMatches(v.review.kind as import('./githubOperationDelegation.ts').GithubOperationKind,String(v.state),String(v.reason),String(v.effect),result))||v.state==='complete'&&!result)return false;
  }else if(enrollment){
    const result='result'in v?parseEnrollmentActionResult(v.result,v.review.kind as import('./agentVersionEnrollment.ts').EnrollmentActionKind,v.operationId):null;
    if('result'in v&&(!result||v.neverAdmitted||!one(v.state,['complete','refused','cancelled']))||
      v.state==='complete'&&(!result||result.phase!==(v.review.kind==='counter-enrollment-review'?'reviewed':'connected'))||
      one(v.state,['refused','cancelled'])&&result&&result.phase!=='refused')return false;
    if(v.review.kind==='counter-enrollment-review'?v.effect!=='none':v.state==='complete'?v.effect!=='local-mapping-observed':!one(v.effect,['not-sent','potentially-applied']))return false;
  }else if(dispatch){if(v.state==='complete'&&!['preflight-dispatch','release-dispatch'].includes(v.review.kind)){if(!parseGithubDispatchSnapshot(v.result,v.review.kind as import('./githubDispatchDelegation.ts').GithubDispatchKind))return false;}
    else if('result'in v)return false;}else if('result'in v)return false;
  const initial=opFamily?'none':remote?githubRemoteSettingsInitial(v.review.kind as import('./githubRemoteSetupDelegation.ts').GithubRemoteSettingsKind):dispatch?githubDispatchInitial(v.review.kind as import('./githubDispatchDelegation.ts').GithubDispatchKind):v.review.kind==='setup-reconcile'||activity||v.review.kind==='counter-enrollment-review'?'none':'not-sent';
  const effects=['not-sent','potentially-applied','unresolved',...(v.review.kind==='failed-jobs-retry'?['accepted-unconfirmed','accepted','advanced-unattributed']:['created-observed','found-unattributed']),...((v.review.kind==='draft-pr-create'||v.review.kind==='pr-create')?['acknowledged-unconfirmed']:[])];
  const effectValid=opFamily?githubOperationEffect(v.review.kind as import('./githubOperationDelegation.ts').GithubOperationKind,v.effect):remote?githubRemoteSettingsEffect(v.review.kind as import('./githubRemoteSetupDelegation.ts').GithubRemoteSettingsKind,v.effect):enrollment?true:dispatch?githubDispatchEffect(v.review.kind as import('./githubDispatchDelegation.ts').GithubDispatchKind,v.effect):activity?v.effect==='none':v.review.kind==='setup-publish'||v.review.kind==='setup-reconcile'?githubPublicationEffect(v.review.kind,v.effect):one(v.effect,effects);
  if(!effectValid||v.effect!==initial&&v.operationId===null)return false;
  const terminal=one(v.state,['complete','refused','cancelled']);
  if(terminal!==(v.settlement==='settled')||(v.state==='unknown')!==(v.settlement==='unknown')||
    (v.state==='unknown')!==one(v.reason,['cleanup-unknown','history-unavailable'])||
    v.neverAdmitted&&(v.operationId!==null||v.effect!==initial||!one(v.state,['finishing','refused','cancelled']))||
    v.state==='complete'&&(v.reason!=='none'||v.operationId===null||v.neverAdmitted)||one(v.state,['refused','cancelled'])&&v.reason==='none')return false;
  return true;
}
export function parseGithubActionStatus(raw:unknown):GithubActionStatus|null {try{const v=copyBoundedComparisonData(raw,8192,700);return status(v)?freeze(v):null;}catch{return null;}}
export function parseAgentGithubActionAccess(raw:unknown):AgentGithubActionAccess|null {
  try{
    const v=copyBoundedComparisonData(raw,8192,750);
    if(!keys(v,['serviceInstance','projectId','grantId','review','enabled','remainingMs','consumed','pending','unknown','status','permissionRevision'])||!permissionRevision(v.permissionRevision)||!['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean')||!number(v.remainingMs,0,120000))return null;
    const present=[v.serviceInstance,v.projectId,v.grantId].every(githubActionId)&&selection(v.review,true);
    if(!present&&![v.serviceInstance,v.projectId,v.grantId,v.review].every(x=>x===null)||v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||
      !v.enabled&&v.remainingMs!==0||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
    if(v.status!==null&&(!status(v.status)||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.projectId!==v.projectId||v.status.grantId!==v.grantId||
      !same(v.status.review,v.review)||v.pending!==(v.status.settlement!=='settled')||v.unknown!==(v.status.state==='unknown')))return null;
    return freeze(v) as unknown as AgentGithubActionAccess;
  }catch{return null;}
}
const consents:Readonly<Record<GithubActionKind,string>>={'repository-create':'agent-repository-create-once-v1','draft-pr-create':'agent-draft-pr-create-once-v1','pr-create':'agent-pr-create-once-v1','failed-jobs-retry':'agent-failed-jobs-retry-once-v1','setup-publish':'agent-setup-publish-once-v1','setup-reconcile':'agent-setup-reconcile-once-v1','activity-overview':'agent-activity-overview-once-v1','preflight-prepare':'agent-preflight-prepare-once-v1','preflight-dispatch':'agent-preflight-dispatch-once-v1','preflight-pending':'agent-preflight-pending-once-v1','preflight-observe':'agent-preflight-observe-once-v1','release-prepare':'agent-release-prepare-once-v1','release-dispatch':'agent-release-dispatch-once-v1','release-pending':'agent-release-pending-once-v1','release-observe':'agent-release-observe-once-v1','setup-prepare':'agent-setup-prepare-once-v1','counter-prepare':'agent-counter-prepare-once-v1','counter-create':'agent-counter-create-once-v1','publication-pending':'agent-publication-pending-once-v1','counter-reconcile':'agent-counter-reconcile-once-v1','counter-enrollment-review':'agent-counter-enrollment-review-once-v1','counter-enrollment-connect':'agent-counter-enrollment-connect-once-v1','remote-setup-prepare':'agent-remote-setup-prepare-once-v1','remote-setup-apply':'agent-remote-setup-apply-once-v1','repository-prepare':'agent-repository-prepare-once-v1','repository-pending':'agent-repository-pending-once-v1','repository-reconcile':'agent-repository-reconcile-once-v1','pr-prepare':'agent-pr-prepare-once-v1','pr-pending':'agent-pr-pending-once-v1','pr-reconcile':'agent-pr-reconcile-once-v1','failed-jobs-prepare':'agent-failed-jobs-prepare-once-v1','failed-jobs-pending':'agent-failed-jobs-pending-once-v1','failed-jobs-reconcile':'agent-failed-jobs-reconcile-once-v1'};
export function createAgentGithubActionPort(invoke:(name:string,body:Uint8Array)=>Promise<unknown>):AgentGithubActionPort {
  const send=(name:string,body:object,limit=1024)=>{const bytes=new TextEncoder().encode(JSON.stringify(body));if(bytes.length>limit)throw new Error('Invalid GitHub delegation DATA');return invoke(name,bytes);};
  return Object.freeze({access:()=>send('agent_github_action_access',{}),revoke:()=>send('revoke_agent_github_action',{}),allow:(raw:GithubActionSelection,revision:string)=>{
    const s=parseGithubActionSelection(raw);if(!s||!permissionRevision(revision)||revision==='18446744073709551615')throw new Error('Invalid GitHub selection');return send('allow_agent_github_action',{selection:s,consentVersion:consents[s.kind],expectedPermissionRevision:revision},s.kind==='pr-prepare'?16896:(isGithubDispatchKind(s.kind)||isGithubRemoteSettingsKind(s.kind))&&s.kind.endsWith('-prepare')?4096:1024);
  },request:(raw:GithubActionQuery)=>{const q=copyBoundedComparisonData(raw,512,8);if(!query(q))throw new Error('Invalid GitHub request address');return send('agent_github_action_request_status',q);}});
}
export function githubActionCommands(a:AgentGithubActionAccess|null,s:GithubActionStatus|null):readonly string[] {
  if(s)return [`mrk github-status ${s.origin.projectId} ${s.origin.serviceInstance} ${s.origin.requestId}`,`mrk github-cancel ${s.origin.projectId} ${s.origin.serviceInstance} ${s.origin.requestId}`];
  return a?.enabled?[`mrk github-submit ${a.projectId} ${a.serviceInstance} ${a.grantId} --reviewed`]:[];
}
