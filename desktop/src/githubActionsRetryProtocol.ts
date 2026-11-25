// A closed run-specific retry route, not a scheduler, token transport or release permission.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, connectionOpaqueId as id,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { repositoryCreateCoordinate as coordinate } from './githubRepositoryCreateProtocol.ts';
import type { ActivityRun } from './githubActivityProtocol.ts';

export const ACTIONS_RETRY_EVENT = 'github-actions-retry-status';
export const ACTIONS_RETRY_REASONS = ['none','invalid-input','target-changed','selection-changed','not-retryable','permission-unconfirmed',
  'unauthorized','forbidden','not-found-or-inaccessible','rate-limited','network-unavailable','tls-failed','response-invalid','response-limit',
  'expired','cancelled','journal-unavailable','previous-attempt','journal-full','unresolved','unattributed','resources-unavailable',
  'runtime-unavailable','unqualified','not-connected','busy','cleanup-unknown','consent-expired'] as const;
export type ActionsRetryReason = typeof ACTIONS_RETRY_REASONS[number];
export type ActionsRetryKind = 'prepare'|'retry'|'pending'|'reconcile';
export type ActionsRetryEffect = 'none'|'not-sent'|'potentially-applied'|'accepted-unconfirmed'|'accepted'|'unresolved'|'advanced-unattributed';
export interface ActionsRetryScope {projectBinding:string;repository:string;accountId:string;repositoryId:string}
export interface ActionsRetrySelection {runId:string;attempt:number;headSha:string;marker:string}
export interface ActionsRetryTarget {scope:ActionsRetryScope;selection:ActionsRetrySelection|null}
export interface ActionsRetryRun extends ActivityRun {workflowId:string;workflowPath:string;headRepositoryId:string|null}
export interface ActionsRetryPrepared {target:ActionsRetryTarget;accountLogin:string;run:ActionsRetryRun;retryPermission:'not-proven';confirmation:string}
export interface ActionsRetryPending {prepared:ActionsRetryPrepared;claimed:boolean;acknowledged:boolean}
export interface ActionsRetryConsent {id:string;expiresAt:string;prepared:ActionsRetryPrepared}
export interface ActionsRetryOperation {id:string;projectId:string;kind:ActionsRetryKind;target:ActionsRetryTarget;phase:'running'|'stopping'|'settled'|'cleanup-unknown';reason:ActionsRetryReason;effect:ActionsRetryEffect}
export interface ActionsRetryStatus {schemaVersion:1;revision:number;sessionId:string|null;available:boolean;reason:ActionsRetryReason;operation:ActionsRetryOperation|null;consent:ActionsRetryConsent|null;pending:ActionsRetryPending[];observed:ActionsRetryRun|null;acknowledged:boolean}
export interface ActionsRetryPrepare {sessionId:string;expectedRevision:number;expectedConnectionRevision:number;activityRevision:number;runId:string;attempt:number}
export interface ActionsRetryStart {sessionId:string;expectedRevision:number;consentId:string;confirm:true}
export interface ActionsRetryPort {
  readonly mode:'native';status():Promise<unknown>;prepare(a:ActionsRetryPrepare):Promise<unknown>;start(a:ActionsRetryStart):Promise<unknown>;
  pending(a:{sessionId:string;expectedRevision:number;expectedConnectionRevision:number}):Promise<unknown>;
  reconcile(a:{sessionId:string;expectedRevision:number;marker:string}):Promise<unknown>;
  discard(a:{sessionId:string;expectedRevision:number;consentId:string}):Promise<unknown>;cancel(a:{operationId:string}):Promise<unknown>;
  subscribe(f:(value:unknown)=>void):Promise<()=>void>;
}
export type ActionsRetryCommand = `github_actions_retry_${'status'|'prepare'|'start'|'pending'|'reconcile'|'discard'|'cancel'}`;
const one=<T extends string>(v:unknown,items:readonly T[]):v is T=>typeof v==='string'&&(items as readonly string[]).includes(v);
const rev=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>0&&v<=0xffff_fffe;
const attempt=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>=1&&v<=1000;
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const text=(v:unknown,n:number):v is string=>typeof v==='string'&&!!v.trim()&&new TextEncoder().encode(v).length<=n&&!/[\p{Cc}\p{Cf}\p{Cs}]/u.test(v);
const login=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(v)&&!v.includes('--');
function target(v:unknown):v is ActionsRetryTarget {
  if(!keys(v,['scope','selection'])||!keys(v.scope,['projectBinding','repository','accountId','repositoryId'])||!hex(v.scope.projectBinding,64)||!coordinate(v.scope.repository)||!numeric(v.scope.accountId)||!numeric(v.scope.repositoryId))return false;
  const s=v.selection;return s===null||keys(s,['runId','attempt','headSha','marker'])&&numeric(s.runId)&&attempt(s.attempt)&&hex(s.headSha,40)&&hex(s.marker,32);
}
function run(v:unknown):v is ActionsRetryRun {
  return keys(v,['id','attempt','name','workflowId','workflowPath','status','conclusion','headSha','headBranch','headRepository','headRepositoryId','event','createdAt','updatedAt'])&&
    numeric(v.id)&&attempt(v.attempt)&&text(v.name,512)&&numeric(v.workflowId)&&text(v.workflowPath,512)&&
    one(v.status,['queued','in_progress','completed','waiting','pending','requested'])&&
    (v.conclusion===null||one(v.conclusion,['success','failure','neutral','cancelled','skipped','timed_out','action_required','stale','startup_failure']))&&
    (v.status==='completed'||v.conclusion===null)&&hex(v.headSha,40)&&(v.headBranch===null||text(v.headBranch,200))&&
    (v.headRepository===null)===(v.headRepositoryId===null)&&(v.headRepository===null||coordinate(v.headRepository)&&numeric(v.headRepositoryId))&&text(v.event,64)&&utc(v.createdAt)&&utc(v.updatedAt);
}
export function actionsRetryConfirmation(t:ActionsRetryTarget,r:ActionsRetryRun):string {
  return `Retry failed and dependent jobs for run ${r.id} in ${t.scope.repository}? Observed attempt ${r.attempt}. GitHub may select its latest attempt when it receives this request. This approval is for the same immutable run, workflow ${r.workflowId} and source ${r.headSha}, not another run. Dependent jobs may run again, and the workflow may publish or change external services using its existing privileges. Stopping cannot undo an accepted request.`;
}
function prepared(v:unknown):v is ActionsRetryPrepared {
  return keys(v,['target','accountLogin','run','retryPermission','confirmation'])&&target(v.target)&&v.target.selection!==null&&login(v.accountLogin)&&run(v.run)&&
    v.run.id===v.target.selection.runId&&v.run.attempt===v.target.selection.attempt&&v.run.headSha===v.target.selection.headSha&&v.run.status==='completed'&&
    one(v.run.conclusion,['failure','timed_out'])&&(v.run.headRepository?.toLowerCase()!==v.target.scope.repository.toLowerCase()||v.run.headRepositoryId===v.target.scope.repositoryId)&&
    v.retryPermission==='not-proven'&&v.confirmation===actionsRetryConfirmation(v.target,v.run)&&new TextEncoder().encode(JSON.stringify(v)).length<=4096-128;
}
function pending(v:unknown):v is ActionsRetryPending {return keys(v,['prepared','claimed','acknowledged'])&&prepared(v.prepared)&&typeof v.claimed==='boolean'&&typeof v.acknowledged==='boolean'&&(!v.acknowledged||v.claimed);}
export function parseActionsRetryStatus(raw:unknown):ActionsRetryStatus|null {
  try {
    const v=copyBoundedComparisonData(raw,192*1024,8192);
    if(!keys(v,['schemaVersion','revision','sessionId','available','reason','operation','consent','pending','observed','acknowledged'])||v.schemaVersion!==1||!rev(v.revision)||(v.sessionId!==null&&!id(v.sessionId))||typeof v.available!=='boolean'||!one(v.reason,ACTIONS_RETRY_REASONS)||v.available!==(v.reason==='none')||typeof v.acknowledged!=='boolean')return null;
    const o=v.operation;
    if(o!==null&&(!keys(o,['id','projectId','kind','target','phase','reason','effect'])||!id(o.id)||!id(o.projectId)||!one(o.kind,['prepare','retry','pending','reconcile'])||!target(o.target)||(o.kind==='pending')!==(o.target.selection===null)||
      !one(o.phase,['running','stopping','settled','cleanup-unknown'])||!one(o.reason,ACTIONS_RETRY_REASONS)||!one(o.effect,['none','not-sent','potentially-applied','accepted-unconfirmed','accepted','unresolved','advanced-unattributed'])||
      v.sessionId===null||o.phase!=='settled'&&v.available||o.phase==='cleanup-unknown'&&o.reason!=='cleanup-unknown'||one(o.kind,['prepare','pending'])&&o.effect!=='none'))return null;
    const c=v.consent;
    if(c!==null&&(!keys(c,['id','expiresAt','prepared'])||!hex(c.id,32)||!utc(c.expiresAt)||!prepared(c.prepared)||!o||o.kind!=='prepare'||o.phase!=='settled'||o.reason!=='none'||!same(c.prepared.target,o.target)))return null;
    if(!Array.isArray(v.pending)||v.pending.length>32)return null;
    const markers=new Set<string>(), attempts=new Set<string>();
    for(const p of v.pending){if(!pending(p)||!p.prepared.target.selection)return null;const s=p.prepared.target.selection,key=`${p.prepared.target.scope.repositoryId}:${s.runId}:${s.attempt}`;
      if(markers.has(s.marker)||attempts.has(key))return null;markers.add(s.marker);attempts.add(key);}
    // The operation's closed shape/target was checked above; this local typed
    // view does not treat a nested unknown from the raw renderer as authority.
    const op=o as unknown as ActionsRetryOperation|null;
    if(v.acknowledged&&(!op||op.phase!=='settled'||!one(op.kind,['retry','reconcile'])))return null;
    if(v.observed!==null&&(!op||op.phase!=='settled'||!one(op.kind,['retry','reconcile'])||!op.target.selection||!run(v.observed)||v.observed.id!==op.target.selection.runId||v.observed.attempt<op.target.selection.attempt||v.observed.headSha!==op.target.selection.headSha||
      !(op.effect==='accepted'&&op.reason==='none'&&v.acknowledged||op.effect==='advanced-unattributed'&&op.reason==='unattributed'&&!v.acknowledged&&v.observed.attempt>op.target.selection.attempt)))return null;
    if(o?.effect==='accepted'&&(!v.acknowledged||v.observed===null)||o?.effect==='accepted-unconfirmed'&&!v.acknowledged||o?.effect==='advanced-unattributed'&&v.observed===null||
      o?.effect==='not-sent'&&(o.kind!=='retry'||v.acknowledged||v.observed!==null)||o?.effect==='potentially-applied'&&(o.kind!=='retry'||v.acknowledged||v.observed!==null))return null;
    return v as unknown as ActionsRetryStatus;
  }catch{return null;}
}
export function encodeActionsRetryRequest(name:ActionsRetryCommand,raw:unknown):Uint8Array|null {
  try {
    const v=copyBoundedComparisonData(raw,1024,48);
    const ok=name==='github_actions_retry_status'?keys(v,[]):name==='github_actions_retry_cancel'?keys(v,['operationId'])&&id(v.operationId):
      name==='github_actions_retry_prepare'?keys(v,['sessionId','expectedRevision','expectedConnectionRevision','activityRevision','runId','attempt'])&&id(v.sessionId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision)&&rev(v.activityRevision)&&numeric(v.runId)&&attempt(v.attempt):
      name==='github_actions_retry_start'?keys(v,['sessionId','expectedRevision','consentId','confirm'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32)&&v.confirm===true:
      name==='github_actions_retry_discard'?keys(v,['sessionId','expectedRevision','consentId'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32):
      name==='github_actions_retry_pending'?keys(v,['sessionId','expectedRevision','expectedConnectionRevision'])&&id(v.sessionId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision):
      name==='github_actions_retry_reconcile'&&keys(v,['sessionId','expectedRevision','marker'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.marker,32);
    if(!ok)return null;const b=new TextEncoder().encode(JSON.stringify(v));return b.length<=1024?b:null;
  }catch{return null;}
}
export function createGitHubActionsRetryPort(mode:string,invoke:(name:ActionsRetryCommand,raw:Uint8Array)=>Promise<unknown>,listen:((event:typeof ACTIONS_RETRY_EVENT,f:(value:unknown)=>void)=>Promise<()=>void>)|null):ActionsRetryPort|null {
  if(mode!=='native'||!listen)return null;
  const call=(name:ActionsRetryCommand,v:unknown)=>{const bytes=encodeActionsRetryRequest(name,v);if(!bytes)throw {code:'github_actions_retry_refused_invalid_input'};return invoke(name,bytes);};
  return Object.freeze({mode:'native',status:()=>call('github_actions_retry_status',{}),prepare:a=>call('github_actions_retry_prepare',a),start:a=>call('github_actions_retry_start',a),pending:a=>call('github_actions_retry_pending',a),reconcile:a=>call('github_actions_retry_reconcile',a),discard:a=>call('github_actions_retry_discard',a),cancel:a=>call('github_actions_retry_cancel',a),subscribe:f=>listen(ACTIONS_RETRY_EVENT,f)} satisfies ActionsRetryPort);
}
export function actionsRetryError(raw:unknown):{reason:ActionsRetryReason;notAdmitted:boolean} {
  try {const d=raw&&typeof raw==='object'?Object.getOwnPropertyDescriptor(raw,'code'):null,code=d&&Object.hasOwn(d,'value')?d.value:null;
    if(typeof code==='string'&&code.startsWith('github_actions_retry_refused_')){const r=code.slice('github_actions_retry_refused_'.length).replaceAll('_','-');
      if(one(r,ACTIONS_RETRY_REASONS))return {reason:r,notAdmitted:one(r,['invalid-input','target-changed','selection-changed','not-connected','busy','expired','rate-limited','unqualified','runtime-unavailable','resources-unavailable','consent-expired'])};}
  }catch{/* Never call exception getters or display private diagnostics. */}return {reason:'response-invalid',notAdmitted:false};
}
export const ACTIONS_RETRY_HELP:Readonly<Record<ActionsRetryReason,string>>=Object.freeze({
  none:'Review this run before explicitly retrying failed and dependent jobs.',
  'invalid-input':'Select an actual completed failed run from Activity, then review it. Paths, tokens, workflow commands and debug options are not accepted.',
  'target-changed':'The project, account or repository changed. Finish the original task before reviewing again.',
  'selection-changed':'The run, attempt or source changed. Check the original attempt first; a sent request must not be repeated automatically.',
  'not-retryable':'Only completed failed or timed-out runs are supported. GitHub may reject an expired or otherwise unavailable run; open its page for guidance.',
  'permission-unconfirmed':'The selected account needs repository write access and Actions write permission. A review cannot prove every token, SSO or organization restriction.',
  unauthorized:'GitHub rejected this account. Finish the original task before reconnecting.',
  forbidden:'GitHub denied the action. Check Actions write permissions, organization SSO and repository restrictions.',
  'not-found-or-inaccessible':'The run or repository is missing or inaccessible. This is not permission to retry another run.',
  'rate-limited':'GitHub requested a pause. No automatic retry or cooldown bypass is used.',
  'network-unavailable':'The request could not finish. If it may have been sent, check the retained attempt instead of repeating it.',
  'tls-failed':'The secure GitHub connection failed. No insecure or alternative endpoint is used.',
  'response-invalid':'The original response could not be verified. Keep its task and attempt files; partial data cannot authorize another retry.',
  'response-limit':'The response exceeded this bounded review. Open the run on GitHub; an incomplete observation is not success.',
  expired:'The original session or review expired. Checking status does not extend it.',
  cancelled:'The original task was stopped. An accepted retry may still run and cannot be undone here.',
  'journal-unavailable':'The attempt could not be safely recorded or read. Preserve its files; do not delete them or reconnect to bypass this uncertainty.',
  'previous-attempt':'This run has a protected earlier attempt. Check it below. An acknowledged older attempt permits a genuinely newer explicit review; an unresolved send remains blocked.',
  'journal-full':'All 32 local retry records are retained. Keep this evidence and use GitHub directly for further work; automatic deletion or reset is not supported.',
  unresolved:'The original retry remains unresolved. No changed attempt does not prove that nothing was sent. Read-only checking cannot rearm it.',
  unattributed:'A newer attempt was observed, but it cannot be attributed to the lost request. The local uncertainty remains protected.',
  'resources-unavailable':'There is not enough bounded operation capacity. Finish other tasks before reviewing again.',
  'runtime-unavailable':'The verified installed GitHub runtime is unavailable. No alternate executable is used.',
  unqualified:'This installed build has not enabled the required GitHub operation runtime. Use GitHub directly until it is qualified.',
  'not-connected':'Connect the intended verified GitHub account and repository first.',
  busy:'Finish the original task first. Its status and Stop controls remain available.',
  'cleanup-unknown':'Original cleanup is unconfirmed. Keep the app and task evidence; another response cannot clear it or authorize a second send.',
  'consent-expired':'The one-use review expired or was consumed. Check previous attempts before a genuinely new review.',
});
