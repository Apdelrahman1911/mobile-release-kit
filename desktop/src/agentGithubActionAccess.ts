// Closed comparison DATA for three existing mutations, never native consent.
import { parseGithubPublicationSelection, parseGithubPublicationReference, sameGithubPublicationSelection, sameGithubPublicationReference, githubPublicationEffect } from './githubPublicationDelegation.ts';
import type { GithubPublicationSelection, GithubPublicationReference } from './githubPublicationDelegation.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, sameConnectionData as same } from './githubConnectionProtocol.ts';
export const GITHUB_ACTION_KINDS = ['repository-create','draft-pr-create','failed-jobs-retry','setup-publish','setup-reconcile'] as const;
export type GithubActionKind = typeof GITHUB_ACTION_KINDS[number];
interface PreparedSelection { readonly kind:'repository-create'|'draft-pr-create'|'failed-jobs-retry'; readonly sessionId:string; readonly consentId:string; readonly expectedRevision:number }
export type GithubActionSelection = PreparedSelection | GithubPublicationSelection;
export type GithubActionReview = (PreparedSelection & { readonly preparedSha256:string }) | GithubPublicationReference;
export interface GithubActionQuery { readonly projectId:string; readonly serviceInstance:string; readonly requestId:string }
export interface GithubActionStatus {
  readonly origin:GithubActionQuery; readonly grantId:string; readonly review:GithubActionReview; readonly revision:number;
  readonly state:'queued'|'starting'|'running'|'stopping'|'finishing'|'complete'|'refused'|'cancelled'|'unknown';
  readonly settlement:'pending'|'settled'|'unknown'; readonly operationId:string|null; readonly reason:string;
  readonly effect:'none'|'branch-observed'|'draft-pr-observed'|'not-sent'|'potentially-applied'|'acknowledged-unconfirmed'|'created-observed'|'unresolved'|'found-unattributed'|'accepted-unconfirmed'|'accepted'|'advanced-unattributed';
  readonly neverAdmitted:boolean; readonly doNotReplay:true;
}
export interface AgentGithubActionAccess {
  readonly serviceInstance:string|null; readonly projectId:string|null; readonly grantId:string|null; readonly review:GithubActionReview|null;
  readonly enabled:boolean; readonly remainingMs:number; readonly consumed:boolean; readonly pending:boolean; readonly unknown:boolean; readonly status:GithubActionStatus|null;
}
export interface AgentGithubActionPort {access():Promise<unknown>;allow(selection:GithubActionSelection):Promise<unknown>;revoke():Promise<unknown>;request(query:GithubActionQuery):Promise<unknown>}
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
function selection(v:unknown,review=false):v is GithubActionSelection {
  if(v&&typeof v==='object'&&('kind' in v)&&(v.kind==='setup-publish'||v.kind==='setup-reconcile'))return !!(review?parseGithubPublicationReference(v):parseGithubPublicationSelection(v));
  return keys(v,['kind','sessionId','consentId','expectedRevision',...(review?['preparedSha256']:[])])&&one(v.kind,['repository-create','draft-pr-create','failed-jobs-retry'])&&
    typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&hex(v.consentId,32)&&number(v.expectedRevision,1,0xffff_fffe)&&(!review||hex(v.preparedSha256,64));
}
function query(v:unknown):v is GithubActionQuery {return keys(v,['projectId','serviceInstance','requestId'])&&Object.values(v).every(githubActionId);}
function freeze<T>(v:T):T {if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
export function parseGithubActionSelection(raw:unknown):GithubActionSelection|null {try{const v=copyBoundedComparisonData(raw,512,16);return selection(v)?freeze(v):null;}catch{return null;}}
export function sameGithubActionSelection(a:GithubActionSelection|null,b:GithubActionSelection|null):boolean {
  if(a?.kind==='setup-reconcile'||a?.kind==='setup-publish')return b?.kind==='setup-reconcile'||b?.kind==='setup-publish'?sameGithubPublicationSelection(a,b):false;
  return !!a&&!!b&&b.kind!=='setup-reconcile'&&a.kind===b.kind&&a.sessionId===b.sessionId&&a.consentId===b.consentId&&a.expectedRevision===b.expectedRevision;
}
export const sameGithubActionReview=(a:GithubActionReview|null,b:GithubActionReview|null):boolean=>{
  if(a?.kind==='setup-reconcile'||a?.kind==='setup-publish')return b?.kind==='setup-reconcile'||b?.kind==='setup-publish'?sameGithubPublicationReference(a,b):false;
  return sameGithubActionSelection(a,b)&&!!a&&!!b&&b.kind!=='setup-reconcile'&&a.preparedSha256===b.preparedSha256;
};
const prefixes:Readonly<Record<GithubActionKind,string>>={'repository-create':'repository-create-','draft-pr-create':'github-pull-request-','failed-jobs-retry':'github-actions-retry-','setup-publish':'github-publication-','setup-reconcile':'github-publication-'};
function operation(v:unknown,k:GithubActionKind):v is string {
  if(typeof v!=='string'||!v.startsWith(prefixes[k]))return false;const n=v.slice(prefixes[k].length);
  return /^[1-9][0-9]{0,19}$/.test(n)&&BigInt(n)<=18446744073709551615n;
}
const reasons=['none','user-cancelled','permission-revoked','expired','context-changed','shutdown','busy','unavailable','native-refused','cleanup-unknown','history-unavailable'];
function status(v:unknown):v is GithubActionStatus {
  if(!keys(v,['origin','grantId','review','revision','state','settlement','operationId','reason','effect','neverAdmitted','doNotReplay'])||!query(v.origin)||!githubActionId(v.grantId)||
    !selection(v.review,true)||!number(v.revision,1,0xffff_fffe)||v.doNotReplay!==true||typeof v.neverAdmitted!=='boolean'||!one(v.reason,reasons)||
    !one(v.state,['queued','starting','running','stopping','finishing','complete','refused','cancelled','unknown'])||!one(v.settlement,['pending','settled','unknown'])||
    v.operationId!==null&&!operation(v.operationId,v.review.kind))return false;
  const initial=v.review.kind==='setup-reconcile'?'none':'not-sent';
  const effects=['not-sent','potentially-applied','unresolved',...(v.review.kind==='failed-jobs-retry'?['accepted-unconfirmed','accepted','advanced-unattributed']:['created-observed','found-unattributed']),...(v.review.kind==='draft-pr-create'?['acknowledged-unconfirmed']:[])];
  const effectValid=v.review.kind==='setup-publish'||v.review.kind==='setup-reconcile'?githubPublicationEffect(v.review.kind,v.effect):one(v.effect,effects);
  if(!effectValid||v.effect!==initial&&v.operationId===null)return false;
  const terminal=one(v.state,['complete','refused','cancelled']);
  if(terminal!==(v.settlement==='settled')||(v.state==='unknown')!==(v.settlement==='unknown')||
    (v.state==='unknown')!==one(v.reason,['cleanup-unknown','history-unavailable'])||
    v.neverAdmitted&&(v.operationId!==null||v.effect!==initial||!one(v.state,['finishing','refused','cancelled']))||
    v.state==='complete'&&(v.reason!=='none'||v.operationId===null||v.neverAdmitted)||one(v.state,['refused','cancelled'])&&v.reason==='none')return false;
  return true;
}
export function parseGithubActionStatus(raw:unknown):GithubActionStatus|null {try{const v=copyBoundedComparisonData(raw,2048,64);return status(v)?freeze(v):null;}catch{return null;}}
export function parseAgentGithubActionAccess(raw:unknown):AgentGithubActionAccess|null {
  try{
    const v=copyBoundedComparisonData(raw,4096,96);
    if(!keys(v,['serviceInstance','projectId','grantId','review','enabled','remainingMs','consumed','pending','unknown','status'])||!['enabled','consumed','pending','unknown'].every(k=>typeof v[k]==='boolean')||!number(v.remainingMs,0,120000))return null;
    const present=[v.serviceInstance,v.projectId,v.grantId].every(githubActionId)&&selection(v.review,true);
    if(!present&&![v.serviceInstance,v.projectId,v.grantId,v.review].every(x=>x===null)||v.enabled!==(present&&!v.consumed&&!v.pending&&!v.unknown&&v.remainingMs>0)||
      !v.enabled&&v.remainingMs!==0||v.consumed!==(v.status!==null)||!present&&(v.pending||v.unknown||v.consumed))return null;
    if(v.status!==null&&(!status(v.status)||v.status.origin.serviceInstance!==v.serviceInstance||v.status.origin.projectId!==v.projectId||v.status.grantId!==v.grantId||
      !same(v.status.review,v.review)||v.pending!==(v.status.settlement!=='settled')||v.unknown!==(v.status.state==='unknown')))return null;
    return freeze(v) as unknown as AgentGithubActionAccess;
  }catch{return null;}
}
const consents:Readonly<Record<GithubActionKind,string>>={'repository-create':'agent-repository-create-once-v1','draft-pr-create':'agent-draft-pr-create-once-v1','failed-jobs-retry':'agent-failed-jobs-retry-once-v1','setup-publish':'agent-setup-publish-once-v1','setup-reconcile':'agent-setup-reconcile-once-v1'};
export function createAgentGithubActionPort(invoke:(name:string,body:Uint8Array)=>Promise<unknown>):AgentGithubActionPort {
  const send=(name:string,body:object)=>{const bytes=new TextEncoder().encode(JSON.stringify(body));if(bytes.length>1024)throw new Error('Invalid GitHub delegation DATA');return invoke(name,bytes);};
  return Object.freeze({access:()=>send('agent_github_action_access',{}),revoke:()=>send('revoke_agent_github_action',{}),allow:(raw:GithubActionSelection)=>{
    const s=parseGithubActionSelection(raw);if(!s)throw new Error('Invalid GitHub selection');return send('allow_agent_github_action',{selection:s,consentVersion:consents[s.kind]});
  },request:(raw:GithubActionQuery)=>{const q=copyBoundedComparisonData(raw,512,8);if(!query(q))throw new Error('Invalid GitHub request address');return send('agent_github_action_request_status',q);}});
}
export function githubActionCommands(a:AgentGithubActionAccess|null,s:GithubActionStatus|null):readonly string[] {
  if(s)return [`mrk github-status ${s.origin.projectId} ${s.origin.serviceInstance} ${s.origin.requestId}`,`mrk github-cancel ${s.origin.projectId} ${s.origin.serviceInstance} ${s.origin.requestId}`];
  return a?.enabled?[`mrk github-submit ${a.projectId} ${a.serviceInstance} ${a.grantId} --reviewed`]:[];
}
