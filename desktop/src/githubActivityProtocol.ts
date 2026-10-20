// Bounded read-only PR/Actions DATA. No workflow dispatch, approval or token.
import { encodeGitHubBrowserRequest } from './githubPullRequestManagement.ts';
import type { GitHubBrowserRequest } from './githubPullRequestManagement.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, connectionOpaqueId as id,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { repositoryCreateCoordinate as coordinate, repositoryCreateLogin as login } from './githubRepositoryCreateProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';
export const ACTIVITY_EVENT = 'github-activity-status';
export const ACTIVITY_REASONS = ['none','invalid-input','target-changed','selection-changed','unauthorized','forbidden',
  'not-found-or-inaccessible','rate-limited','network-unavailable','tls-failed','response-invalid','response-limit',
  'expired','cancelled','resources-unavailable','runtime-unavailable','unqualified','not-connected','busy','cleanup-unknown'] as const;
export type ActivityReason = typeof ACTIVITY_REASONS[number];
export type ActivitySelection = {kind:'overview';branch:string|null}|{kind:'pull-request';number:string}|{kind:'workflow-run';runId:string;attempt:number};
export interface ActivityTarget {projectBinding:string;repository:string;accountId:string;repositoryId:string}
export interface ActivitySection<T> {state:'read'|'unavailable';reason:'none'|'forbidden'|'not-found-or-inaccessible';coverage:'complete'|'windowed'|'unknown';total:number|null;rows:T[]}
export interface ActivityPull {id:string;number:string;title:string;state:'open'|'closed';draft:boolean;headSha:string;headBranch:string;headRepository:string|null;baseSha:string;baseBranch:string;updatedAt:string}
export type ActivityRunStatus = 'queued'|'in_progress'|'completed'|'waiting'|'pending'|'requested';
export type ActivityConclusion = 'success'|'failure'|'neutral'|'cancelled'|'skipped'|'timed_out'|'action_required'|'stale'|'startup_failure';
export interface ActivityJob {id:string;name:string;status:ActivityRunStatus;conclusion:ActivityConclusion|null}
export interface ActivityRun extends ActivityJob {attempt:number;headSha:string;headBranch:string|null;headRepository:string|null;event:string;createdAt:string;updatedAt:string}
export interface ActivityFile {path:string;change:'added'|'removed'|'modified'|'renamed'|'copied'|'changed'|'unchanged';additions:number;deletions:number}
export interface ActivityReview {id:string;reviewer:string|null;state:'APPROVED'|'CHANGES_REQUESTED'|'COMMENTED'|'DISMISSED'|'PENDING';commitSha:string|null;submittedAt:string|null}
export interface ActivityCommitStatus {id:string;name:string;state:'error'|'failure'|'pending'|'success';updatedAt:string}
export type ActivityData = {kind:'overview';branchHead:string|null;pullRequests:ActivitySection<ActivityPull>;workflowRuns:ActivitySection<ActivityRun>}|
  {kind:'pull-request';pullRequest:ActivityPull;changedFiles:ActivitySection<ActivityFile>;reviews:ActivitySection<ActivityReview>;commitStatuses:ActivitySection<ActivityCommitStatus>;checkRuns:ActivitySection<ActivityJob>;headChecked:true}|
  {kind:'workflow-run';run:ActivityRun;jobs:ActivitySection<ActivityJob>;attemptChecked:true};
export interface ActivityObservation {target:ActivityTarget;selection:ActivitySelection;observedAt:string;data:ActivityData}
export interface ActivityOperation {id:string;projectId:string;target:ActivityTarget;selection:ActivitySelection;phase:'running'|'stopping'|'settled'|'cleanup-unknown';reason:ActivityReason}
export interface ActivityStatus {schemaVersion:1;revision:number;sessionId:string|null;available:boolean;reason:ActivityReason;operation:ActivityOperation|null;result:ActivityObservation|null}
export interface ActivityRead {sessionId:string;projectId:string;expectedRevision:number;expectedConnectionRevision:number;selection:ActivitySelection}
export interface GitHubActivityPort {readonly mode:'native';openBrowser?(request:GitHubBrowserRequest):Promise<unknown>;status():Promise<unknown>;read(args:ActivityRead):Promise<unknown>;cancel(args:{operationId:string}):Promise<unknown>;subscribe(f:(value:unknown)=>void):Promise<()=>void>}
export type ActivityCommand = `github_activity_${'status'|'read'|'cancel'}`;
const one = <T extends string>(v:unknown,items:readonly T[]):v is T=>typeof v==='string'&&(items as readonly string[]).includes(v);
const rev = (v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>0&&v<=0xffff_fffe;
const count = (v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>=0&&v<=0x7fff_ffff;
const hex = (v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const txt = (v:unknown,n=512):v is string=>typeof v==='string'&&!!v.trim()&&new TextEncoder().encode(v).length<=n&&!/[\p{Cc}\p{Cf}\p{Cs}]/u.test(v);
function target(v:unknown):v is ActivityTarget{return keys(v,['projectBinding','repository','accountId','repositoryId'])&&hex(v.projectBinding,64)&&coordinate(v.repository)&&numeric(v.accountId)&&numeric(v.repositoryId);}
export function activitySelection(v:unknown):v is ActivitySelection {
  return keys(v,['kind','branch'])&&v.kind==='overview'&&(v.branch===null||branch(v.branch))||keys(v,['kind','number'])&&v.kind==='pull-request'&&numeric(v.number)||
    keys(v,['kind','runId','attempt'])&&v.kind==='workflow-run'&&numeric(v.runId)&&count(v.attempt)&&v.attempt>=1&&v.attempt<=1000;
}
export function parseActivitySelection(raw:unknown):ActivitySelection|null{try{const v=copyBoundedComparisonData(raw,1024,16);return activitySelection(v)?v:null;}catch{return null;}}
const runStatuses:readonly ActivityRunStatus[]=['queued','in_progress','completed','waiting','pending','requested'];
const conclusions:readonly ActivityConclusion[]=['success','failure','neutral','cancelled','skipped','timed_out','action_required','stale','startup_failure'];
function disposition(v:Record<string,unknown>):boolean{return one(v.status,runStatuses)&&(v.conclusion===null||one(v.conclusion,conclusions))&&(v.status==='completed'||v.conclusion===null);}
function pull(v:unknown):v is ActivityPull{return keys(v,['id','number','title','state','draft','headSha','headBranch','headRepository','baseSha','baseBranch','updatedAt'])&&
  numeric(v.id)&&numeric(v.number)&&txt(v.title)&&one(v.state,['open','closed'])&&typeof v.draft==='boolean'&&hex(v.headSha,40)&&txt(v.headBranch,200)&&
  (v.headRepository===null||coordinate(v.headRepository))&&hex(v.baseSha,40)&&txt(v.baseBranch,200)&&utc(v.updatedAt);}
function run(v:unknown):v is ActivityRun{return keys(v,['id','attempt','name','status','conclusion','headSha','headBranch','headRepository','event','createdAt','updatedAt'])&&numeric(v.id)&&
  count(v.attempt)&&v.attempt>=1&&v.attempt<=1000&&txt(v.name)&&disposition(v)&&hex(v.headSha,40)&&(v.headBranch===null||txt(v.headBranch,200))&&
  (v.headRepository===null||coordinate(v.headRepository))&&txt(v.event,64)&&utc(v.createdAt)&&utc(v.updatedAt);}
function file(v:unknown):v is ActivityFile{return keys(v,['path','change','additions','deletions'])&&txt(v.path,1024)&&one(v.change,['added','removed','modified','renamed','copied','changed','unchanged'])&&count(v.additions)&&count(v.deletions);}
function review(v:unknown):v is ActivityReview{return keys(v,['id','reviewer','state','commitSha','submittedAt'])&&numeric(v.id)&&(v.reviewer===null||login(v.reviewer))&&
  one(v.state,['APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED','PENDING'])&&(v.commitSha===null||hex(v.commitSha,40))&&(v.submittedAt===null||utc(v.submittedAt));}
function commitStatus(v:unknown):v is ActivityCommitStatus{return keys(v,['id','name','state','updatedAt'])&&numeric(v.id)&&txt(v.name)&&one(v.state,['error','failure','pending','success'])&&utc(v.updatedAt);}
function job(v:unknown):v is ActivityJob{return keys(v,['id','name','status','conclusion'])&&numeric(v.id)&&txt(v.name)&&disposition(v);}
function section<T>(v:unknown,check:(row:unknown)=>row is T,identity:keyof T):v is ActivitySection<T>{
  if(!keys(v,['state','reason','coverage','total','rows'])||!Array.isArray(v.rows)||v.rows.length>30)return false;
  if(v.state==='unavailable')return one(v.reason,['forbidden','not-found-or-inaccessible'])&&v.coverage==='unknown'&&v.total===null&&v.rows.length===0;
  if(v.state!=='read'||v.reason!=='none'||!(v.total===null||count(v.total)&&v.total>=v.rows.length)||v.coverage!==(v.total===v.rows.length?'complete':'windowed'))return false;
  const ids=new Set<unknown>();return v.rows.every((row)=>{if(!check(row)||ids.has(row[identity]))return false;ids.add(row[identity]);return true;});
}
function data(v:unknown,s:ActivitySelection,t:ActivityTarget):v is ActivityData{
  if(s.kind==='overview')return keys(v,['kind','branchHead','pullRequests','workflowRuns'])&&v.kind===s.kind&&(s.branch===null?v.branchHead===null:hex(v.branchHead,40))&&
    section(v.pullRequests,pull,'id')&&section(v.workflowRuns,run,'id')&&(s.branch===null||v.pullRequests.rows.every(p=>p.headBranch===s.branch&&p.headRepository?.toLowerCase()===t.repository.toLowerCase())&&
    v.workflowRuns.rows.every(r=>r.headBranch===s.branch&&r.headRepository?.toLowerCase()===t.repository.toLowerCase()));
  if(s.kind==='pull-request')return keys(v,['kind','pullRequest','changedFiles','reviews','commitStatuses','checkRuns','headChecked'])&&v.kind===s.kind&&v.headChecked===true&&pull(v.pullRequest)&&v.pullRequest.number===s.number&&
    section(v.changedFiles,file,'path')&&section(v.reviews,review,'id')&&section(v.commitStatuses,commitStatus,'id')&&section(v.checkRuns,job,'id');
  return keys(v,['kind','run','jobs','attemptChecked'])&&v.kind===s.kind&&v.attemptChecked===true&&run(v.run)&&v.run.id===s.runId&&v.run.attempt===s.attempt&&section(v.jobs,job,'id');
}
export function parseActivityStatus(raw:unknown):ActivityStatus|null {
  try{
    const v=copyBoundedComparisonData(raw,128*1024,8192);
    if(!keys(v,['schemaVersion','revision','sessionId','available','reason','operation','result'])||v.schemaVersion!==1||!rev(v.revision)||(v.sessionId!==null&&!id(v.sessionId))||
      typeof v.available!=='boolean'||!one(v.reason,ACTIVITY_REASONS)||v.available!==(v.reason==='none'))return null;
    const o=v.operation;
    if(o!==null&&(!keys(o,['id','projectId','target','selection','phase','reason'])||!id(o.id)||!id(o.projectId)||!target(o.target)||!activitySelection(o.selection)||
      !one(o.phase,['running','stopping','settled','cleanup-unknown'])||!one(o.reason,ACTIVITY_REASONS)||v.sessionId===null||o.phase!=='settled'&&v.available||o.phase==='cleanup-unknown'&&o.reason!=='cleanup-unknown'))return null;
    const r=v.result;
    if(r!==null&&(!keys(r,['target','selection','observedAt','data'])||!target(r.target)||!activitySelection(r.selection)||!utc(r.observedAt)||!data(r.data,r.selection,r.target)||
      !o||o.phase!=='settled'||o.reason!=='none'||!same(o.target,r.target)||!same(o.selection,r.selection)))return null;
    return v as unknown as ActivityStatus;
  }catch{return null;}
}
export function encodeActivityRequest(command:ActivityCommand,raw:unknown):Uint8Array|null{
  try{const v=copyBoundedComparisonData(raw,1024,32);const ok=command==='github_activity_status'?keys(v,[]):command==='github_activity_cancel'?keys(v,['operationId'])&&id(v.operationId):
    command==='github_activity_read'&&keys(v,['sessionId','projectId','expectedRevision','expectedConnectionRevision','selection'])&&id(v.sessionId)&&id(v.projectId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision)&&activitySelection(v.selection);
    if(!ok)return null;const b=new TextEncoder().encode(JSON.stringify(v));return b.length<=1024?b:null;}catch{return null;}
}
export function createGitHubActivityPort(mode:string,invoke:(name:ActivityCommand|'github_browser_open',bytes:Uint8Array)=>Promise<unknown>,listen:((event:typeof ACTIVITY_EVENT,f:(value:unknown)=>void)=>Promise<()=>void>)|null):GitHubActivityPort|null{
  if(mode!=='native'||!listen)return null;
  const call=(name:ActivityCommand,v:unknown)=>{const bytes=encodeActivityRequest(name,v);if(!bytes)throw {code:'github_activity_refused_invalid_input'};return invoke(name,bytes);};
  return Object.freeze({mode:'native',openBrowser:(request:GitHubBrowserRequest)=>{const bytes=encodeGitHubBrowserRequest(request);if(!bytes)throw {code:'github_browser_refused'};return invoke('github_browser_open',bytes);},status:()=>call('github_activity_status',{}),read:(v)=>call('github_activity_read',v),cancel:(v)=>call('github_activity_cancel',v),subscribe:(f)=>listen(ACTIVITY_EVENT,f)} satisfies GitHubActivityPort);
}
export function activityError(raw:unknown):{reason:ActivityReason;notAdmitted:boolean}{
  try{const d=raw&&typeof raw==='object'?Object.getOwnPropertyDescriptor(raw,'code'):null;const code=d&&Object.hasOwn(d,'value')?d.value:null;
    if(typeof code==='string'&&code.startsWith('github_activity_refused_')){const r=code.slice('github_activity_refused_'.length).replaceAll('_','-');
      if(one(r,ACTIVITY_REASONS))return {reason:r,notAdmitted:one(r,['invalid-input','target-changed','not-connected','busy','expired','rate-limited','unqualified','runtime-unavailable','resources-unavailable'])};}
  }catch{/* Never render raw exception text or invoke a getter. */}return {reason:'response-invalid',notAdmitted:false};
}
export function activityLink(repository:string,kind:'pull'|'run',number:string):string|null{
  return coordinate(repository)&&numeric(number)?`https://github.com/${repository}/${kind==='pull'?'pull':'actions/runs'}/${number}`:null;
}
export const ACTIVITY_HELP:Readonly<Record<ActivityReason,string>>=Object.freeze({
  none:'Read pull requests and workflow results from the selected GitHub repository.',
  'invalid-input':'Use a branch name, not a URL or full refs/ path. Repository and account come from the connection above.',
  'target-changed':'The project, account or repository changed. Check status, then read again explicitly when the original task finishes.',
  'selection-changed':'The branch, pull-request head or workflow attempt changed during the read. No replacement result was adopted; read it again after this task finishes.',
  unauthorized:'GitHub rejected this account session. Finish the original read before reconnecting.',
  forbidden:'GitHub denied this read. Check the account’s repository, Pull requests, Actions, Checks and commit-status read permissions and organization SSO rules.',
  'not-found-or-inaccessible':'GitHub did not return the item. It may be missing or inaccessible; this is not an empty successful result.',
  'rate-limited':'GitHub requested a pause. No automatic retry or cooldown bypass is used.',
  'network-unavailable':'The bounded read could not finish. No workflow or pull request was changed.',
  'tls-failed':'The secure GitHub connection failed. No insecure or alternate endpoint is used.',
  'response-invalid':'The original response could not be verified. Check its status; partial data is not trusted.',
  'response-limit':'This response exceeded the bounded read window. Open GitHub for the full view; partial rows are not treated as complete.',
  expired:'The original session or read expired. Status never extends its deadline.',
  cancelled:'The original read was stopped. No workflow or pull request was changed.',
  'resources-unavailable':'The original read could not be safely retained. No replacement operation was started.',
  'runtime-unavailable':'Activity reads are unavailable in this application runtime.',
  unqualified:'This installed build has not admitted Activity reads. Preview does not contact GitHub.',
  'not-connected':'Connect and verify this existing repository and GitHub account above first.',
  busy:'An original task is still active or closing. Status and Stop remain available.',
  'cleanup-unknown':'Original cleanup is unconfirmed. Keep the app and its files; do not reconnect or repeat a task to dismiss this warning.',
});
