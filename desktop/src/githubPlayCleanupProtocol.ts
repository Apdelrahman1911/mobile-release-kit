// Closed comparison DATA for the existing Connection/Setup owner. No edit ID,
// encrypted capsule, token, workflow input or provider target comes from UI.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, connectionOpaqueId as id,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { repositoryCreateCoordinate as coordinate, repositoryCreateLogin as login } from './githubRepositoryCreateProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';

export const PLAY_CLEANUP_EVENT = 'github-play-cleanup-status';
export const PLAY_CLEANUP_REASONS = ['none','invalid-input','target-changed','selection-changed','source-changed',
  'source-tree-unavailable','source-unsupported','configuration-invalid','caller-mismatch','workflow-unavailable',
  'permission-unconfirmed','counter-unavailable','protection-unsupported','authority-changed','authority-rewound',
  'ledger-invalid','journal-invalid','cleanup-unavailable','cleanup-claimed','review-changed','unauthorized','forbidden',
  'not-found-or-inaccessible','rate-limited','network-unavailable','tls-failed','response-invalid','response-limit',
  'expired','cancelled','journal-unavailable','previous-attempt','journal-full','unresolved','resources-unavailable',
  'runtime-unavailable','unqualified','publisher-unconfigured','not-connected','busy','cleanup-unknown','consent-expired'] as const;
export type PlayCleanupReason = typeof PLAY_CLEANUP_REASONS[number];
export type PlayCleanupKind = 'prepare'|'dispatch'|'pending'|'observe';
export type PlayCleanupEffect = 'none'|'not-sent'|'potentially-applied'|'acknowledged-unconfirmed'|'unresolved'|'observed-unconfirmed';
export interface PlayCleanupTarget {
  scope:{projectBinding:string;repository:string;accountId:string;repositoryId:string};
  toolingRepository:string;toolingSha:string;marker:string;
}
export interface PlayCleanupCandidate {
  candidateId:string;attemptId:string;requestSha256:string;localProjectId:string;platform:'android'|'both';
  source:{commit:string;tree:string;ref:string;configurationSha256:string;versionSha256:string};
  identityRevision:string;baseVersion:{name:string;build:number};capsuleSha256:string;
}
export interface PlayCleanupPrepared {
  target:PlayCleanupTarget;accountLogin:string;branch:string;sourceSha:string;sourceTree:string;savedConfigSha256:string;
  workflowId:string;callerSha256:string;
  authority:{projectId:string;repository:string;repositoryId:string;ledgerId:string;genesisSha256:string;protectedBranch:true};
  checkpoint:{sequence:number;headSha256:string;commit:string};ledgerBlob:string;journalBlob:string;journalSha256:string;
  journalRevision:number;candidate:PlayCleanupCandidate;confirmation:string;
}
export interface PlayCleanupPending {prepared:PlayCleanupPrepared;claimed:boolean;acknowledged:boolean}
export interface PlayCleanupConsent {id:string;expiresAt:string;prepared:PlayCleanupPrepared;agentAllowed:boolean}
export interface PlayCleanupAgentAccess {serviceInstance:string;projectId:string;consentId:string;enabled:boolean;remainingMs:number}
export interface PlayCleanupObservation {counterCommit:string;journalSha256:string;journalRevision:number;
  pendingTuple:'same-unclaimed'|'same-claimed'|'different'|'not-present';assurance:'later-journal-read-not-cleanup-proof'}
export interface PlayCleanupOperation {id:string;projectId:string;kind:PlayCleanupKind;target:PlayCleanupTarget;
  phase:'running'|'stopping'|'settled'|'cleanup-unknown';reason:PlayCleanupReason;effect:PlayCleanupEffect}
export interface PlayCleanupStatus {schemaVersion:1;revision:number;sessionId:string|null;available:boolean;reason:PlayCleanupReason;
  operation:PlayCleanupOperation|null;consent:PlayCleanupConsent|null;pending:PlayCleanupPending[];
  observed:PlayCleanupObservation|null;acknowledged:boolean;agentAccess:PlayCleanupAgentAccess|null}
export interface PlayCleanupPrepare {sessionId:string;expectedRevision:number;expectedConnectionRevision:number}
export interface PlayCleanupStart {sessionId:string;expectedRevision:number;consentId:string;confirm:true}
export interface PlayCleanupPort {
  readonly mode:'native';status():Promise<unknown>;prepare(a:PlayCleanupPrepare):Promise<unknown>;start(a:PlayCleanupStart):Promise<unknown>;
  pending(a:PlayCleanupPrepare):Promise<unknown>;observe(a:{sessionId:string;expectedRevision:number;marker:string}):Promise<unknown>;
  allowAgent(a:PlayCleanupStart):Promise<unknown>;discard(a:{sessionId:string;expectedRevision:number;consentId:string}):Promise<unknown>;
  cancel(a:{operationId:string}):Promise<unknown>;subscribe(f:(value:unknown)=>void):Promise<()=>void>;
}
export type PlayCleanupCommand = `github_play_cleanup_${'status'|'prepare'|'start'|'pending'|'observe'|'allow_agent'|'discard'|'cancel'}`;
const one=<T extends string>(v:unknown,items:readonly T[]):v is T=>typeof v==='string'&&(items as readonly string[]).includes(v);
const integer=(v:unknown,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=0&&v<=max;
const rev=(v:unknown):v is number=>integer(v,0xffff_fffe)&&v>0;
const positive=(v:unknown):v is number=>integer(v,Number.MAX_SAFE_INTEGER)&&v>0;
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const serviceId=(v:unknown):v is string=>hex(v,32)&&v!=='0'.repeat(32);
const uuid=(v:unknown):v is string=>typeof v==='string'&&v.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
function target(v:unknown):v is PlayCleanupTarget {
  return keys(v,['scope','toolingRepository','toolingSha','marker'])&&keys(v.scope,['projectBinding','repository','accountId','repositoryId'])&&
    hex(v.scope.projectBinding,64)&&coordinate(v.scope.repository)&&numeric(v.scope.accountId)&&numeric(v.scope.repositoryId)&&
    v.toolingRepository==='Apdelrahman1911/mobile-release-kit'&&hex(v.toolingSha,40)&&hex(v.marker,32);
}
function candidate(v:unknown):v is PlayCleanupCandidate {
  if(!keys(v,['candidateId','attemptId','requestSha256','localProjectId','platform','source','identityRevision','baseVersion','capsuleSha256'])||
    !uuid(v.candidateId)||!uuid(v.attemptId)||!hex(v.requestSha256,64)||!serviceId(v.localProjectId)||!one(v.platform,['android','both'])||
    !hex(v.identityRevision,64)||!hex(v.capsuleSha256,64)||!keys(v.source,['commit','tree','ref','configurationSha256','versionSha256'])||
    !hex(v.source.commit,40)||!hex(v.source.tree,40)||typeof v.source.ref!=='string'||!v.source.ref.startsWith('refs/heads/')||
    !branch(v.source.ref.slice(11))||!hex(v.source.configurationSha256,64)||!hex(v.source.versionSha256,64))return false;
  const b=v.baseVersion;return keys(b,['name','build'])&&typeof b.name==='string'&&b.name.length>0&&b.name.length<=64&&
    !/[^A-Za-z0-9.+-]/.test(b.name)&&integer(b.build,2_100_000_000)&&b.build>0;
}
export function playCleanupConfirmation(p:Pick<PlayCleanupPrepared,'candidate'|'target'|'branch'>):string {
  return `Dispatch one hosted Play edit cleanup for candidate ${p.candidate.candidateId} in ${p.target.scope.repository}? This is nonpublishing but mutating: the protected workflow may decrypt its retained edit ID, consume its one-use cleanup claim and delete that Play edit. It does not reserve a version or build, sign or release. The configured branch ${p.branch} is mutable; authorized writers can replace its workflow after review. Its actual dispatch head may differ from the reviewed head; the workflow must separately validate the original candidate source. A dispatch acknowledgement does not prove cleanup or identify a run. Stopping cannot undo a sent request.`;
}
function prepared(v:unknown):v is PlayCleanupPrepared {
  if(!keys(v,['target','accountLogin','branch','sourceSha','sourceTree','savedConfigSha256','workflowId','callerSha256','authority','checkpoint','ledgerBlob','journalBlob','journalSha256','journalRevision','candidate','confirmation'])||
    !target(v.target)||!login(v.accountLogin)||!branch(v.branch)||!candidate(v.candidate)||v.candidate.source.ref!==`refs/heads/${v.branch}`||
    ![v.sourceSha,v.sourceTree,v.ledgerBlob,v.journalBlob].every(s=>hex(s,40))||
    ![v.savedConfigSha256,v.callerSha256,v.journalSha256].every(s=>hex(s,64))||!numeric(v.workflowId)||!positive(v.journalRevision))return false;
  const a=v.authority,c=v.checkpoint;
  return keys(a,['projectId','repository','repositoryId','ledgerId','genesisSha256','protectedBranch'])&&(serviceId(a.projectId)||uuid(a.projectId))&&
    coordinate(a.repository)&&numeric(a.repositoryId)&&uuid(a.ledgerId)&&hex(a.genesisSha256,64)&&a.protectedBranch===true&&
    a.repository.toLowerCase()===v.target.scope.repository.toLowerCase()&&a.repositoryId===v.target.scope.repositoryId&&
    keys(c,['sequence','headSha256','commit'])&&integer(c.sequence,64)&&hex(c.headSha256,64)&&hex(c.commit,40)&&
    (c.sequence!==0||c.headSha256===a.genesisSha256)&&v.confirmation===playCleanupConfirmation(v as unknown as PlayCleanupPrepared)&&
    new TextEncoder().encode(JSON.stringify(v)).length<=4096;
}
function pending(v:unknown):v is PlayCleanupPending {
  return keys(v,['prepared','claimed','acknowledged'])&&prepared(v.prepared)&&typeof v.claimed==='boolean'&&typeof v.acknowledged==='boolean'&&(!v.acknowledged||v.claimed);
}
export function parsePlayCleanupStatus(raw:unknown):PlayCleanupStatus|null {
  try {
    const v=copyBoundedComparisonData(raw,192*1024,8192);
    if(!keys(v,['schemaVersion','revision','sessionId','available','reason','operation','consent','pending','observed','acknowledged','agentAccess'])||
      v.schemaVersion!==1||!rev(v.revision)||(v.sessionId!==null&&!id(v.sessionId))||typeof v.available!=='boolean'||!one(v.reason,PLAY_CLEANUP_REASONS)||
      v.available!==(v.reason==='none')||typeof v.acknowledged!=='boolean')return null;
    const o=v.operation;
    if(o!==null&&(!keys(o,['id','projectId','kind','target','phase','reason','effect'])||!id(o.id)||!id(o.projectId)||
      !one(o.kind,['prepare','dispatch','pending','observe'])||!target(o.target)||!one(o.phase,['running','stopping','settled','cleanup-unknown'])||
      !one(o.reason,PLAY_CLEANUP_REASONS)||!one(o.effect,['none','not-sent','potentially-applied','acknowledged-unconfirmed','unresolved','observed-unconfirmed'])||
      v.sessionId===null||o.phase!=='settled'&&v.available||o.phase==='cleanup-unknown'&&o.reason!=='cleanup-unknown'||
      one(o.kind,['prepare','pending'])&&o.effect!=='none'))return null;
    const c=v.consent;
    if(c!==null&&(!keys(c,['id','expiresAt','prepared','agentAllowed'])||!hex(c.id,32)||!utc(c.expiresAt)||!prepared(c.prepared)||
      typeof c.agentAllowed!=='boolean'||!o||o.kind!=='prepare'||o.phase!=='settled'||o.reason!=='none'||!same(c.prepared.target,o.target)))return null;
    const a=v.agentAccess;
    if(a!==null&&(!keys(a,['serviceInstance','projectId','consentId','enabled','remainingMs'])||!serviceId(a.serviceInstance)||!serviceId(a.projectId)||
      !serviceId(a.consentId)||typeof a.enabled!=='boolean'||!integer(a.remainingMs,120000)||a.enabled!==(a.remainingMs>0)||
      !c||!c.agentAllowed||a.consentId!==c.id))return null;
    if((a!==null)!==(c!==null&&c.agentAllowed===true))return null;
    if(!Array.isArray(v.pending)||v.pending.length>32)return null;
    const markers=new Set<string>(),tuples=new Set<string>();
    for(const p of v.pending){if(!pending(p))return null;const t=p.prepared.target,au=p.prepared.authority,ca=p.prepared.candidate;
      const tuple=[t.scope.repositoryId,au.projectId,au.ledgerId,au.genesisSha256,ca.candidateId,ca.attemptId].join(':');
      if(markers.has(t.marker)||tuples.has(tuple))return null;markers.add(t.marker);tuples.add(tuple);}
    const op=o as unknown as PlayCleanupOperation|null;
    if(v.acknowledged&&(!op||op.phase!=='settled'||!one(op.kind,['dispatch','observe'])))return null;
    if(v.observed!==null&&(!op||op.kind!=='observe'||op.phase!=='settled'||op.effect!=='observed-unconfirmed'||op.reason!=='none'||
      !keys(v.observed,['counterCommit','journalSha256','journalRevision','pendingTuple','assurance'])||!hex(v.observed.counterCommit,40)||
      !hex(v.observed.journalSha256,64)||!positive(v.observed.journalRevision)||!one(v.observed.pendingTuple,['same-unclaimed','same-claimed','different','not-present'])||
      v.observed.assurance!=='later-journal-read-not-cleanup-proof'))return null;
    if(op?.effect==='observed-unconfirmed'&&v.observed===null||op?.effect==='acknowledged-unconfirmed'&&!v.acknowledged||
      one(op?.effect,['not-sent','potentially-applied'])&&(op?.kind!=='dispatch'||v.acknowledged||v.observed!==null)||
      op?.effect==='unresolved'&&(op.kind!=='observe'||v.observed!==null)||op?.kind==='dispatch'&&op.effect==='none')return null;
    return v as unknown as PlayCleanupStatus;
  }catch{return null;}
}
export function encodePlayCleanupRequest(name:PlayCleanupCommand,raw:unknown):Uint8Array|null {
  try {
    const v=copyBoundedComparisonData(raw,1024,48);
    const ok=name==='github_play_cleanup_status'?keys(v,[]):name==='github_play_cleanup_cancel'?keys(v,['operationId'])&&id(v.operationId):
      one(name,['github_play_cleanup_prepare','github_play_cleanup_pending'])?keys(v,['sessionId','expectedRevision','expectedConnectionRevision'])&&id(v.sessionId)&&rev(v.expectedRevision)&&rev(v.expectedConnectionRevision):
      one(name,['github_play_cleanup_start','github_play_cleanup_allow_agent'])?keys(v,['sessionId','expectedRevision','consentId','confirm'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32)&&v.confirm===true:
      name==='github_play_cleanup_discard'?keys(v,['sessionId','expectedRevision','consentId'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.consentId,32):
      name==='github_play_cleanup_observe'&&keys(v,['sessionId','expectedRevision','marker'])&&id(v.sessionId)&&rev(v.expectedRevision)&&hex(v.marker,32);
    if(!ok)return null;const b=new TextEncoder().encode(JSON.stringify(v));return b.length<=1024?b:null;
  }catch{return null;}
}
export function createGitHubPlayCleanupPort(mode:string,invoke:(name:PlayCleanupCommand,raw:Uint8Array)=>Promise<unknown>,
  listen:((event:typeof PLAY_CLEANUP_EVENT,f:(value:unknown)=>void)=>Promise<()=>void>)|null):PlayCleanupPort|null {
  if(mode!=='native'||!listen)return null;
  const call=(name:PlayCleanupCommand,v:unknown)=>{const bytes=encodePlayCleanupRequest(name,v);if(!bytes)throw {code:'github_play_cleanup_refused_invalid_input'};return invoke(name,bytes);};
  return Object.freeze({mode:'native',status:()=>call('github_play_cleanup_status',{}),prepare:a=>call('github_play_cleanup_prepare',a),
    start:a=>call('github_play_cleanup_start',a),pending:a=>call('github_play_cleanup_pending',a),observe:a=>call('github_play_cleanup_observe',a),
    allowAgent:a=>call('github_play_cleanup_allow_agent',a),discard:a=>call('github_play_cleanup_discard',a),cancel:a=>call('github_play_cleanup_cancel',a),
    subscribe:f=>listen(PLAY_CLEANUP_EVENT,f)} satisfies PlayCleanupPort);
}
export function playCleanupError(raw:unknown):{reason:PlayCleanupReason;notAdmitted:boolean} {
  try {const d=raw&&typeof raw==='object'?Object.getOwnPropertyDescriptor(raw,'code'):null,code=d&&Object.hasOwn(d,'value')?d.value:null;
    if(typeof code==='string'&&code.startsWith('github_play_cleanup_refused_')){const r=code.slice('github_play_cleanup_refused_'.length).replaceAll('_','-');
      if(one(r,PLAY_CLEANUP_REASONS))return {reason:r,notAdmitted:one(r,['invalid-input','target-changed','selection-changed','not-connected','busy',
        'expired','rate-limited','unqualified','publisher-unconfigured','runtime-unavailable','resources-unavailable','consent-expired'])};}
  }catch{/* No exception getters, private diagnostics or raw response logging. */}
  return {reason:'response-invalid',notAdmitted:false};
}
export const PLAY_CLEANUP_HELP:Readonly<Record<PlayCleanupReason,string>>=Object.freeze({
  none:'Review a previous hosted Google Play draft before deciding whether to clean it up.',
  'invalid-input':'Use the current saved project and its reviewed cleanup. No edit ID, key, path or workflow input can be entered here.',
  'target-changed':'The project, account or repository changed. Finish the original task, then review the current project.',
  'selection-changed':'The retained candidate changed. Keep the original attempt and check it without sending again.',
  'source-changed':'The reviewed branch changed. No replacement source was silently approved.',
  'source-tree-unavailable':'The original candidate source is unavailable. Restore access to its retained Git history; do not rerun allocation.',
  'source-unsupported':'This source layout cannot use the supported hosted cleanup. Keep the previous attempt for manual recovery.',
  'configuration-invalid':'Correct and save the project configuration through Settings before a new review.',
  'caller-mismatch':'The repository needs the supported protected candidate workflow. Review workflow changes through the existing GitHub setup.',
  'workflow-unavailable':'The protected candidate workflow could not be read. Check repository access and its configured branch.',
  'permission-unconfirmed':'The selected account needs repository and Actions write access. Organization restrictions still apply.',
  'counter-unavailable':'The enrolled shared version counter is unavailable. Keep manual versions unchanged; do not reset the counter.',
  'protection-unsupported':'The shared counter needs readable protection against deletion and force pushes. Ask the repository administrator.',
  'authority-changed':'The saved counter connection changed. Keep its history; do not reset it or reuse numbers.',
  'authority-rewound':'The counter moved behind its retained history. Stop and check with the repository administrator.',
  'ledger-invalid':'The shared version history could not be verified. Preserve it; no cleanup or version was assumed.',
  'journal-invalid':'The retained cleanup record could not be verified. Keep its files and do not repeat a possibly sent request.',
  'cleanup-unavailable':'No single supported previous Google Play draft was found for this project. Nothing will be created to make one.',
  'cleanup-claimed':'Cleanup was already claimed for this draft. Check the original attempt; it cannot be claimed again here.',
  'review-changed':'The reviewed cleanup changed or expired. Close it and check previous attempts before reviewing again.',
  unauthorized:'GitHub rejected the selected account. Finish the original task before reconnecting.',
  forbidden:'GitHub denied access. Check repository permissions, Actions write access and organization SSO.',
  'not-found-or-inaccessible':'The workflow or repository is missing or inaccessible. This does not prove that no cleanup was sent.',
  'rate-limited':'GitHub requested a pause. No automatic retry or cooldown bypass is used.',
  'network-unavailable':'The request could not finish. If it may have been sent, check the retained attempt instead of repeating it.',
  'tls-failed':'The secure GitHub connection failed. No insecure or alternative endpoint is used.',
  'response-invalid':'The original response could not be verified. Keep this task; partial data cannot authorize another request.',
  'response-limit':'The response exceeded this bounded review. No partial list or observation is treated as completion.',
  expired:'The original session or review expired. Checking status does not extend it.',
  cancelled:'The original task was stopped. A sent workflow request cannot be undone here.',
  'journal-unavailable':'The local attempt could not be recorded or read safely. Keep its files; do not delete them to retry.',
  'previous-attempt':'This draft has a protected earlier attempt. Read it below instead of sending another request.',
  'journal-full':'The 32 retained cleanup records are full. Preserve them; automatic deletion or reset is not supported.',
  unresolved:'The original cleanup request remains unresolved. A later journal read cannot prove completion or authorize another send.',
  'resources-unavailable':'Finish other tasks before reviewing cleanup; the original operation has a fixed capacity limit.',
  'runtime-unavailable':'The verified installed GitHub runtime is unavailable. No alternate executable will be used.',
  unqualified:'This installed build has not enabled the required cleanup runtime. No request will be sent.',
  'publisher-unconfigured':'This installed build has no supported protected workflow pin. No arbitrary workflow can be selected.',
  'not-connected':'Connect the intended GitHub account and repository first.',
  busy:'Finish the original task first. Its status and Stop controls remain available.',
  'cleanup-unknown':'Original cleanup is unconfirmed. Keep the app and task evidence; no later response can authorize a second send.',
  'consent-expired':'The one-use review expired, changed or was consumed. Check previous attempts before a genuinely new review.',
});
