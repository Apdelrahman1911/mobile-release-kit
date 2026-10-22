// Closed comparison DATA for the three existing repository/PR/retry owners.
// No provider, native command, promise owner, permission or source is made here.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { githubDispatchHash } from './githubDispatchDelegation.ts';
import { encodeRepositoryCreateRequest } from './githubRepositoryCreateProtocol.ts';
import { encodePullRequestRequest } from './githubPullRequestProtocol.ts';
import { encodeActionsRetryRequest } from './githubActionsRetryProtocol.ts';
import type { RepositoryCreatePrepare, RepositoryCreatePrepared, RepositoryCreatePending } from './githubRepositoryCreateProtocol.ts';
import type { PullRequestPrepare, PullRequestPrepared, PullRequestPending } from './githubPullRequestProtocol.ts';
import type { ActionsRetryPrepare, ActionsRetryPrepared, ActionsRetryPending } from './githubActionsRetryProtocol.ts';
export const GITHUB_OPERATION_KINDS = ['repository-prepare','repository-pending','repository-reconcile','pr-prepare','pr-pending','pr-reconcile','failed-jobs-prepare','failed-jobs-pending','failed-jobs-reconcile'] as const;
export type GithubOperationKind = typeof GITHUB_OPERATION_KINDS[number];
interface Original { readonly sessionId:string; readonly expectedRevision:number }
export type GithubOperationSelection =
 ({readonly kind:'repository-prepare'} & RepositoryCreatePrepare) | ({readonly kind:'pr-prepare'} & PullRequestPrepare) |
 ({readonly kind:'failed-jobs-prepare'} & ActionsRetryPrepare) |
 (Original & {readonly kind:'repository-pending'|'pr-pending'|'failed-jobs-pending'; readonly expectedConnectionRevision:number}) |
 (Original & {readonly kind:'repository-reconcile'|'pr-reconcile'|'failed-jobs-reconcile'; readonly marker:string});
export type GithubOperationReference =
 (Original & {readonly kind:'repository-prepare'|'pr-prepare'|'failed-jobs-prepare'|'repository-pending'|'pr-pending'|'failed-jobs-pending'; readonly requestSha256:string}) |
 (Original & {readonly kind:'repository-reconcile'|'pr-reconcile'|'failed-jobs-reconcile'; readonly marker:string; readonly recordSha256:string});
export type GithubOperationObservation = {readonly target:'repository';readonly id:string} | {readonly target:'pr';readonly id:string;readonly number:string} |
 {readonly target:'failed-jobs';readonly runId:string;readonly attempt:number};
export interface GithubOperationRecord {readonly marker:string;readonly recordSha256:string;readonly claimed:boolean;readonly acknowledged:boolean;readonly closed:boolean}
export type GithubOperationSnapshot = {readonly type:'operation';readonly phase:'prepared';readonly consentId:string;readonly preparedSha256:string;readonly next:'repository-create'|'draft-pr-create'|'pr-create'|'failed-jobs-retry'} |
 {readonly type:'operation';readonly phase:'pending';readonly rows:readonly GithubOperationRecord[]} |
 {readonly type:'operation';readonly phase:'reconciled';readonly marker:string;readonly effect:string;readonly observed:GithubOperationObservation|null};
export const isGithubOperationKind = (v:unknown):v is GithubOperationKind => typeof v==='string' && (GITHUB_OPERATION_KINDS as readonly string[]).includes(v);
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const revision=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0&&v<=0xffff_fffe;
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const original=(v:Record<string,unknown>)=>typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&revision(v.expectedRevision);
function freeze<T>(v:T):T {if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
function pick(v:object,names:readonly string[]):Record<string,unknown> {const a=v as Record<string,unknown>,o:Record<string,unknown>={};for(const k of names)if(Object.hasOwn(a,k))o[k]=a[k];return o;}
/** Match native Args declaration order, not user property order. This contains
 * private PR text only in the already approved MAIN input, never result/Review. */
function orderedInput(s:GithubOperationSelection):GithubOperationSelection {
 const names=['kind','sessionId','expectedRevision'];
 if(s.kind==='repository-prepare')names.push('expectedConnectionRevision','ownerKind','visibility');
 else if(s.kind==='pr-prepare')names.push('expectedConnectionRevision','draft');
 else if(s.kind==='failed-jobs-prepare')names.push('expectedConnectionRevision','activityRevision','runId','attempt');
 else if('marker'in s)names.push('marker');else names.push('expectedConnectionRevision');
 const result=pick(s,names);if(s.kind==='pr-prepare')result.draft=pick(s.draft,['base','head','title','body','creationMode']);
 return freeze(result) as unknown as GithubOperationSelection;
}
export function parseGithubOperationSelection(raw:unknown):GithubOperationSelection|null {
 try {
  const v=copyBoundedComparisonData(raw,16896,80);
  if(!record(v)||!('kind'in v)||!isGithubOperationKind(v.kind))return null;
  const {kind,...args}=v;let bytes:Uint8Array|null=null;
  switch(kind){
   case 'repository-prepare':bytes=encodeRepositoryCreateRequest('github_repository_create_prepare',args);break;
   case 'repository-pending':bytes=encodeRepositoryCreateRequest('github_repository_create_pending',args);break;
   case 'repository-reconcile':bytes=encodeRepositoryCreateRequest('github_repository_create_reconcile',args);break;
   case 'pr-prepare':bytes=encodePullRequestRequest('github_pull_request_prepare',args);break;
   case 'pr-pending':bytes=encodePullRequestRequest('github_pull_request_pending',args);break;
   case 'pr-reconcile':bytes=encodePullRequestRequest('github_pull_request_reconcile',args);break;
   case 'failed-jobs-prepare':bytes=encodeActionsRetryRequest('github_actions_retry_prepare',args);break;
   case 'failed-jobs-pending':bytes=encodeActionsRetryRequest('github_actions_retry_pending',args);break;
   case 'failed-jobs-reconcile':bytes=encodeActionsRetryRequest('github_actions_retry_reconcile',args);break;
  }
  if(!bytes)return null;
  return orderedInput(v as unknown as GithubOperationSelection);
 }catch{return null;}
}
export function parseGithubOperationReference(raw:unknown):GithubOperationReference|null {
 try {const v=copyBoundedComparisonData(raw,768,24);if(!record(v)||!('kind'in v)||!isGithubOperationKind(v.kind)||!original(v))return null;
  const valid=v.kind.endsWith('-reconcile')?keys(v,['kind','sessionId','expectedRevision','marker','recordSha256'])&&hex(v.marker,32)&&hex(v.recordSha256,64):
   keys(v,['kind','sessionId','expectedRevision','requestSha256'])&&hex(v.requestSha256,64);
  return valid?freeze(v) as unknown as GithubOperationReference:null;
 }catch{return null;}
}
export function githubOperationReferenceMatches(r:GithubOperationReference,s:GithubOperationSelection):boolean {
 if(r.kind!==s.kind||r.sessionId!==s.sessionId||r.expectedRevision!==s.expectedRevision)return false;
 return 'requestSha256'in r?r.requestSha256===githubDispatchHash(orderedInput(s)):'marker'in s&&s.marker===r.marker;
}
export function sameGithubOperationSelection(a:unknown,b:unknown):boolean {
 const ar=parseGithubOperationReference(a),br=parseGithubOperationReference(b),sa=parseGithubOperationSelection(a),sb=parseGithubOperationSelection(b);
 return ar&&sb?githubOperationReferenceMatches(ar,sb):br&&sa?githubOperationReferenceMatches(br,sa):ar&&br?same(ar,br):!!sa&&!!sb&&same(sa,sb);
}
export function githubOperationEffect(k:GithubOperationKind,e:unknown):boolean {
 return typeof e==='string'&&(k==='repository-reconcile'?['none','potentially-applied','unresolved','created-observed','found-unattributed']:
 k==='pr-reconcile'?['none','potentially-applied','acknowledged-unconfirmed','unresolved','created-observed','closed-confirmed','found-unattributed']:
 k==='failed-jobs-reconcile'?['none','potentially-applied','accepted-unconfirmed','unresolved','accepted','advanced-unattributed']:['none']).includes(e);
}
export function parseGithubOperationSnapshot(raw:unknown,k:GithubOperationKind):GithubOperationSnapshot|null {
 try {const v=copyBoundedComparisonData(raw,8192,540);if(!record(v)||!('phase'in v)||!('type'in v)||v.type!=='operation')return null;
 let valid=false;
 if(v.phase==='prepared')valid=keys(v,['type','phase','consentId','preparedSha256','next'])&&hex(v.consentId,32)&&hex(v.preparedSha256,64)&&
  (k==='repository-prepare'?v.next==='repository-create':k==='pr-prepare'?v.next==='draft-pr-create'||v.next==='pr-create':k==='failed-jobs-prepare'&&v.next==='failed-jobs-retry');
 else if(v.phase==='pending')valid=keys(v,['type','phase','rows'])&&['repository-pending','pr-pending','failed-jobs-pending'].includes(k)&&Array.isArray(v.rows)&&v.rows.length<=32&&v.rows.every((r,i,rs)=>
  keys(r,['marker','recordSha256','claimed','acknowledged','closed'])&&hex(r.marker,32)&&hex(r.recordSha256,64)&&[r.claimed,r.acknowledged,r.closed].every(x=>typeof x==='boolean')&&
  (!r.acknowledged||r.claimed)&&(!r.closed||k==='pr-pending'&&r.claimed&&r.acknowledged)&&!rs.slice(0,i).some(old=>old.marker===r.marker));
 else if(v.phase==='reconciled'){
  const o=v.observed;
  valid=keys(v,['type','phase','marker','effect','observed'])&&k.endsWith('-reconcile')&&hex(v.marker,32)&&githubOperationEffect(k,v.effect)&&
   (o===null?v.effect==='unresolved':k==='repository-reconcile'?keys(o,['target','id'])&&o.target==='repository'&&numeric(o.id)&&['created-observed','found-unattributed'].includes(String(v.effect)):
    k==='pr-reconcile'?keys(o,['target','id','number'])&&o.target==='pr'&&numeric(o.id)&&numeric(o.number)&&['created-observed','closed-confirmed','found-unattributed'].includes(String(v.effect)):
    keys(o,['target','runId','attempt'])&&o.target==='failed-jobs'&&numeric(o.runId)&&typeof o.attempt==='number'&&Number.isInteger(o.attempt)&&o.attempt>=1&&o.attempt<=1000&&['accepted','advanced-unattributed'].includes(String(v.effect)));
 }
 return valid?freeze(v) as unknown as GithubOperationSnapshot:null;
 }catch{return null;}
}
export function githubOperationResultMatches(k:GithubOperationKind,state:string,reason:string,effect:string,s:GithubOperationSnapshot):boolean {
 if(!parseGithubOperationSnapshot(s,k))return false;
 if(s.phase!=='reconciled')return state==='complete'&&reason==='none'&&effect==='none';
 const inconclusive=['unresolved','found-unattributed','advanced-unattributed'].includes(s.effect);
 return effect===s.effect&&(state==='complete'&&reason==='none'||state==='refused'&&reason==='native-refused'&&inconclusive);
}
// Below only strict original native parsers' returned typed objects are used.
// Keep native Serialize declaration order in the bounded comparison hash.
const scopeKeys=['projectBinding','repository','accountId','repositoryId'];
function prepared(p:RepositoryCreatePrepared|PullRequestPrepared|ActionsRetryPrepared):object {
 if('ownerId'in p)return {...pick(p,['target','ownerId','membership','repositoryObservation','creationPermission','autoInit','confirmation']),target:pick(p.target,['projectBinding','repository','accountId','accountLogin','ownerKind','visibility','marker'])};
 if('baseSha'in p){const target={scope:pick(p.target.scope,scopeKeys),intent:p.target.intent===null?null:pick(p.target.intent,['base','head','marker','titleSha256','bodySha256','creationMode'])};
  const comparison={...pick(p.comparison,['aheadBy','behindBy','totalCommits','reportedFiles','coverage','files']),files:p.comparison.files.map(f=>pick(f,['path','change']))};
  return {...pick(p,['target','baseSha','headSha','comparison','draft','creationPermission','confirmation']),target,comparison};}
 const target={scope:pick(p.target.scope,scopeKeys),selection:p.target.selection===null?null:pick(p.target.selection,['runId','attempt','headSha','marker'])};
 const run=pick(p.run,['id','attempt','name','workflowId','workflowPath','status','conclusion','headSha','headBranch','headRepository','headRepositoryId','event','createdAt','updatedAt']);
 return {...pick(p,['target','accountLogin','run','retryPermission','confirmation']),target,run};
}
export function githubOperationPreparedHash(p:RepositoryCreatePrepared|PullRequestPrepared|ActionsRetryPrepared):string {return githubDispatchHash(prepared(p));}
export function githubOperationRecordHash(r:RepositoryCreatePending|PullRequestPending|ActionsRetryPending):string {
 let ack:unknown=r.acknowledged;
 if(ack&&typeof ack==='object')ack='fullName'in ack?pick(ack,['id','fullName','ownerId','visibility','url']):pick(ack,['id','number','url']);
 const row:Record<string,unknown>={prepared:prepared(r.prepared),claimed:r.claimed,acknowledged:ack};
 if('closed'in r&&r.closed)row.closed=pick(r.closed,['id','number','closedAt','merged']);
 return githubDispatchHash(row);
}
export function githubOperationRecord(r:RepositoryCreatePending|PullRequestPending|ActionsRetryPending):GithubOperationRecord {
 const t=r.prepared.target,marker='marker'in t?t.marker:'intent'in t?t.intent?.marker:t.selection?.marker;
 if(!marker)throw new Error('Missing original journal marker');
 return {marker,recordSha256:githubOperationRecordHash(r),claimed:r.claimed,acknowledged:typeof r.acknowledged==='boolean'?r.acknowledged:r.acknowledged!==null,closed:'closed'in r&&r.closed!==undefined};
}
