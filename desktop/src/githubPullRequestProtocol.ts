// One closed draft-PR route on the existing native connection. No token, push,
// merge, ready-for-review, workflow dispatch or provider URL crosses this port.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, connectionOpaqueId as id,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { repositoryCreateCoordinate as coordinate } from './githubRepositoryCreateProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';
export const PULL_REQUEST_EVENT = 'github-pull-request-status';
export const PULL_REQUEST_REASONS = ['none','invalid-input','target-changed','branches-changed','pull-request-exists','no-changes',
  'permission-unconfirmed','unauthorized','forbidden','not-found-or-inaccessible','rate-limited','network-unavailable','tls-failed',
  'response-invalid','response-limit','expired','cancelled','journal-unavailable','previous-attempt','unresolved','unattributed',
  'resources-unavailable','runtime-unavailable','unqualified','not-connected','busy','cleanup-unknown','consent-expired'] as const;
export type PullRequestReason = typeof PULL_REQUEST_REASONS[number];
export type PullRequestKind = 'prepare'|'create'|'pending'|'reconcile';
export type PullRequestEffect = 'none'|'not-sent'|'potentially-applied'|'acknowledged-unconfirmed'|'created-observed'|'unresolved'|'found-unattributed';
export interface PullRequestDraft {base:string;head:string;title:string;body:string}
export interface PullRequestScope {projectBinding:string;repository:string;accountId:string;repositoryId:string}
export interface PullRequestIntent {base:string;head:string;marker:string;titleSha256:string;bodySha256:string}
export interface PullRequestTarget {scope:PullRequestScope;intent:PullRequestIntent|null}
export interface PullRequestPrepared {target:PullRequestTarget;baseSha:string;headSha:string;comparison:{aheadBy:number;behindBy:number;totalCommits:number;reportedFiles:number;coverage:'windowed';files:{path:string;change:string}[]};draft:true;creationPermission:'not-proven';confirmation:string}
export interface PullRequestAcknowledgement {id:string;number:string;url:string}
export interface PullRequestPending {prepared:PullRequestPrepared;claimed:boolean;acknowledged:PullRequestAcknowledgement|null}
export interface PullRequestConsent {id:string;expiresAt:string;prepared:PullRequestPrepared}
export interface PullRequestOperation {id:string;projectId:string;kind:PullRequestKind;target:PullRequestTarget;phase:'running'|'stopping'|'settled'|'cleanup-unknown';reason:PullRequestReason;effect:PullRequestEffect}
export interface PullRequestStatus {schemaVersion:1;revision:number;sessionId:string|null;available:boolean;reason:PullRequestReason;operation:PullRequestOperation|null;consent:PullRequestConsent|null;pending:PullRequestPending[];observed:PullRequestAcknowledgement|null;acknowledged:PullRequestAcknowledgement|null}
export interface PullRequestPrepare {sessionId:string;expectedRevision:number;expectedConnectionRevision:number;draft:PullRequestDraft}
export interface PullRequestCreate {sessionId:string;expectedRevision:number;consentId:string;confirm:true}
export interface PullRequestPort {readonly mode:'native';status():Promise<unknown>;prepare(a:PullRequestPrepare):Promise<unknown>;create(a:PullRequestCreate):Promise<unknown>;pending(a:{sessionId:string;expectedRevision:number;expectedConnectionRevision:number}):Promise<unknown>;reconcile(a:{sessionId:string;expectedRevision:number;marker:string}):Promise<unknown>;discard(a:{sessionId:string;expectedRevision:number;consentId:string}):Promise<unknown>;cancel(a:{operationId:string}):Promise<unknown>;subscribe(f:(value:unknown)=>void):Promise<()=>void>}
export type PullRequestCommand = `github_pull_request_${'status'|'prepare'|'create'|'pending'|'reconcile'|'discard'|'cancel'}`;
const one=<T extends string>(v:unknown,items:readonly T[]):v is T=>typeof v==='string'&&(items as readonly string[]).includes(v);
const rev=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>0&&v<=0xffff_fffe;
const count=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>=0&&v<=0x7fff_ffff;
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const text=(v:unknown,n:number,multiline=false,empty=false):v is string=>typeof v==='string'&&(empty||!!v.trim())&&new TextEncoder().encode(v).length<=n&&!/[\p{Cc}\p{Cf}\p{Cs}]/u.test(multiline?v.replaceAll('\n',''):v)&&!v.includes('mrk-draft-pr:');
function draft(v:unknown):v is PullRequestDraft{return keys(v,['base','head','title','body'])&&branch(v.base)&&branch(v.head)&&v.base!==v.head&&text(v.title,256)&&text(v.body,4096,true,true);}
export function parsePullRequestDraft(raw:unknown):PullRequestDraft|null{try{const v=copyBoundedComparisonData(raw,16*1024,16);return draft(v)?v:null;}catch{return null;}}
function target(v:unknown):v is PullRequestTarget{
  if(!keys(v,['scope','intent'])||!keys(v.scope,['projectBinding','repository','accountId','repositoryId'])||!hex(v.scope.projectBinding,64)||!coordinate(v.scope.repository)||!numeric(v.scope.accountId)||!numeric(v.scope.repositoryId))return false;
  const i=v.intent;return i===null||keys(i,['base','head','marker','titleSha256','bodySha256'])&&branch(i.base)&&branch(i.head)&&i.base!==i.head&&hex(i.marker,32)&&hex(i.titleSha256,64)&&hex(i.bodySha256,64);
}
export function pullRequestConfirmation(t:PullRequestTarget):string{return t.intent?`Create a draft pull request in ${t.scope.repository} from ${t.intent.head} into ${t.intent.base} with the text you reviewed? Existing GitHub workflows may run. No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.`:'';}
function prepared(v:unknown):v is PullRequestPrepared{
  if(!keys(v,['target','baseSha','headSha','comparison','draft','creationPermission','confirmation'])||!target(v.target)||!v.target.intent||!hex(v.baseSha,40)||!hex(v.headSha,40)||v.baseSha===v.headSha||v.draft!==true||v.creationPermission!=='not-proven'||v.confirmation!==pullRequestConfirmation(v.target))return false;
  const c=v.comparison;if(!keys(c,['aheadBy','behindBy','totalCommits','reportedFiles','coverage','files'])||!count(c.aheadBy)||c.aheadBy<1||!count(c.behindBy)||!count(c.totalCommits)||!count(c.reportedFiles)||c.coverage!=='windowed'||!Array.isArray(c.files)||c.files.length>4||c.reportedFiles<c.files.length)return false;
  const paths=new Set<string>();return c.files.every(f=>{if(!keys(f,['path','change'])||!text(f.path,192)||!one(f.change,['added','removed','modified','renamed','copied','changed','unchanged'])||paths.has(f.path))return false;paths.add(f.path);return true;})&&new TextEncoder().encode(JSON.stringify(v)).length<=4096-64;
}
function acknowledgement(v:unknown,t:PullRequestTarget):v is PullRequestAcknowledgement{return keys(v,['id','number','url'])&&numeric(v.id)&&numeric(v.number)&&v.url===`https://github.com/${t.scope.repository}/pull/${v.number}`;}
function pending(v:unknown):v is PullRequestPending{return keys(v,['prepared','claimed','acknowledged'])&&prepared(v.prepared)&&typeof v.claimed==='boolean'&&(v.acknowledged===null||v.claimed&&acknowledgement(v.acknowledged,v.prepared.target));}
export function parsePullRequestStatus(raw:unknown):PullRequestStatus|null{
  try{const v=copyBoundedComparisonData(raw,192*1024,8192);
    if(!keys(v,['schemaVersion','revision','sessionId','available','reason','operation','consent','pending','observed','acknowledged'])||v.schemaVersion!==1||!rev(v.revision)||(v.sessionId!==null&&!id(v.sessionId))||typeof v.available!=='boolean'||!one(v.reason,PULL_REQUEST_REASONS)||v.available!==(v.reason==='none'))return null;
    const o=v.operation;
    if(o!==null&&(!keys(o,['id','projectId','kind','target','phase','reason','effect'])||!id(o.id)||!id(o.projectId)||!one(o.kind,['prepare','create','pending','reconcile'])||!target(o.target)||(o.kind==='pending')!==(o.target.intent===null)||!one(o.phase,['running','stopping','settled','cleanup-unknown'])||!one(o.reason,PULL_REQUEST_REASONS)||!one(o.effect,['none','not-sent','potentially-applied','acknowledged-unconfirmed','created-observed','unresolved','found-unattributed'])||v.sessionId===null||o.phase!=='settled'&&v.available||o.phase==='cleanup-unknown'&&o.reason!=='cleanup-unknown'||(o.kind==='prepare'||o.kind==='pending')&&o.effect!=='none'))return null;
    const c=v.consent;if(c!==null&&(!keys(c,['id','expiresAt','prepared'])||!hex(c.id,32)||!utc(c.expiresAt)||!prepared(c.prepared)||!o||o.kind!=='prepare'||o.phase!=='settled'||o.reason!=='none'||!same(c.prepared.target,o.target)))return null;
    if(!Array.isArray(v.pending)||v.pending.length>32)return null;
    const markers=new Set<string>();for(const r of v.pending){if(!pending(r)||!r.prepared.target.intent||markers.has(r.prepared.target.intent.marker))return null;markers.add(r.prepared.target.intent.marker);}
    const selectedTarget=o===null?null:o.target;if(selectedTarget!==null&&!target(selectedTarget))return null;
    if(v.acknowledged!==null&&(!o||!selectedTarget||o.phase!=='settled'||!one(o.kind,['create','reconcile'])||!acknowledgement(v.acknowledged,selectedTarget)))return null;
    if(v.observed!==null&&(!o||!selectedTarget||o.phase!=='settled'||!acknowledgement(v.observed,selectedTarget)||!(o.effect==='created-observed'&&o.reason==='none'&&same(v.acknowledged,v.observed)||o.effect==='found-unattributed'&&o.reason==='unattributed'&&v.acknowledged===null)))return null;
    if(o?.effect==='created-observed'&&(v.acknowledged===null||v.observed===null)||o?.effect==='acknowledged-unconfirmed'&&v.acknowledged===null||o?.effect==='found-unattributed'&&v.observed===null)return null;
    return v as unknown as PullRequestStatus;
  }catch{return null;}
}
export function encodePullRequestRequest(command:PullRequestCommand,raw:unknown):Uint8Array|null{
  try{const max=command==='github_pull_request_prepare'?16*1024:1024,v=copyBoundedComparisonData(raw,max,48);
    const ok=command==='github_pull_request_status'?keys(v,[]):command==='github_pull_request_cancel'?keys(v,['operationId'])&&id(v.operationId):
      command==='github_pull_request_prepare'?keys(v,['sessionId','expectedRevision','expectedConnectionRevision','draft'])&&id(v.sessionId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision)&&draft(v.draft):
      command==='github_pull_request_create'?keys(v,['sessionId','expectedRevision','consentId','confirm'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32)&&v.confirm===true:
      command==='github_pull_request_discard'?keys(v,['sessionId','expectedRevision','consentId'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32):
      command==='github_pull_request_pending'?keys(v,['sessionId','expectedRevision','expectedConnectionRevision'])&&id(v.sessionId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision):
      command==='github_pull_request_reconcile'&&keys(v,['sessionId','expectedRevision','marker'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.marker,32);
    if(!ok)return null;const b=new TextEncoder().encode(JSON.stringify(v));return b.length<=max?b:null;
  }catch{return null;}
}
export function createGitHubPullRequestPort(mode:string,invoke:(name:PullRequestCommand,bytes:Uint8Array)=>Promise<unknown>,listen:((event:typeof PULL_REQUEST_EVENT,f:(value:unknown)=>void)=>Promise<()=>void>)|null):PullRequestPort|null{
  if(mode!=='native'||!listen)return null;
  const call=(name:PullRequestCommand,v:unknown)=>{const bytes=encodePullRequestRequest(name,v);if(!bytes)throw {code:'github_pull_request_refused_invalid_input'};return invoke(name,bytes);};
  return Object.freeze({mode:'native',status:()=>call('github_pull_request_status',{}),prepare:(a)=>call('github_pull_request_prepare',a),create:(a)=>call('github_pull_request_create',a),pending:(a)=>call('github_pull_request_pending',a),reconcile:(a)=>call('github_pull_request_reconcile',a),discard:(a)=>call('github_pull_request_discard',a),cancel:(a)=>call('github_pull_request_cancel',a),subscribe:(f)=>listen(PULL_REQUEST_EVENT,f)} satisfies PullRequestPort);
}
export function pullRequestError(raw:unknown):{reason:PullRequestReason;notAdmitted:boolean}{
  try{const d=raw&&typeof raw==='object'?Object.getOwnPropertyDescriptor(raw,'code'):null,code=d&&Object.hasOwn(d,'value')?d.value:null;
    if(typeof code==='string'&&code.startsWith('github_pull_request_refused_')){const r=code.slice('github_pull_request_refused_'.length).replaceAll('_','-');if(one(r,PULL_REQUEST_REASONS))return {reason:r,notAdmitted:one(r,['invalid-input','target-changed','not-connected','busy','expired','rate-limited','unqualified','runtime-unavailable','resources-unavailable','consent-expired'])};}
  }catch{/* Do not call getters or display private exception text. */}return {reason:'response-invalid',notAdmitted:false};
}
export const PULL_REQUEST_HELP:Readonly<Record<PullRequestReason,string>>=Object.freeze({
  none:'Review two existing branches, then explicitly create a draft pull request.',
  'invalid-input':'Choose two different branch names, not URLs or refs/ paths. Add a short title and optionally a description; do not include secrets.',
  'target-changed':'The selected project, GitHub account or repository changed. Your text is kept; finish the original task before reviewing again.',
  'branches-changed':'A branch or the pull-request details changed. Do not repeat a sent request. Check previous attempts, then review the actual GitHub page.',
  'pull-request-exists':'An open pull request already uses these branches. Open GitHub to review it instead of creating a duplicate.',
  'no-changes':'The selected head branch has no reviewed changes for this base. Push your changes separately before preparing a pull request.',
  'permission-unconfirmed':'GitHub permissions or repository rules were not confirmed. This route requires the selected account to have repository write access; checking it does not grant permission.',
  unauthorized:'GitHub rejected this account session. Finish the original task before reconnecting.',
  forbidden:'GitHub denied access. Check repository Pull requests read/write permissions and organization SSO rules.',
  'not-found-or-inaccessible':'GitHub did not return this item. It may be missing or inaccessible; this is not permission to create or repeat anything.',
  'rate-limited':'GitHub requested a pause. No automatic retry or cooldown bypass is used.',
  'network-unavailable':'The original request could not finish. If Create was sent, check previous attempts instead of repeating it.',
  'tls-failed':'The secure GitHub connection failed. No insecure or alternate endpoint is used.',
  'response-invalid':'The original response could not be verified. Keep the original status; partial data cannot authorize a second Create.',
  'response-limit':'This response exceeded the small review window. Open GitHub for the full comparison; no partial response is treated as complete.',
  expired:'The original session or review expired. Status does not extend its deadline.',
  cancelled:'The original task was stopped. A pull request already sent to GitHub is not undone.',
  'journal-unavailable':'The original attempt could not be safely recorded or read. Keep the app’s files; do not start another Create to bypass it.',
  'previous-attempt':'A saved attempt already protects this repository and branch pair from a duplicate. Use its original GitHub account to load and check it below; a new review or account cannot authorize another Create.',
  unresolved:'No exact acknowledged result was confirmed. Missing or inaccessible results do not authorize another Create.',
  unattributed:'A matching draft was found, but the original creation acknowledgement was not retained. This is not proof this app created it; no repeat is authorized.',
  'resources-unavailable':'The original task could not be safely retained. No replacement was started.',
  'runtime-unavailable':'Draft pull requests are unavailable in this application runtime.',
  unqualified:'This installed runtime has not admitted draft-PR creation. Preview never contacts GitHub.',
  'not-connected':'Connect and verify this existing repository and GitHub account first.',
  busy:'An original task is still active or closing. Check status and Stop remain available.',
  'cleanup-unknown':'Original cleanup is unconfirmed. Keep the app and its files; do not reconnect or repeat Create to dismiss this warning.',
  'consent-expired':'This exact review expired or was already used. Check previous attempts before making a new review.',
});
