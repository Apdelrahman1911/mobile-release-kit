// UI coordination only. The native saved-command Session owns work and cleanup.
import type { AndroidBuildProject } from './androidBuild.ts';
import { isDirty, type ProjectSession } from './drafts.ts';
import { parseReleaseVersionObservation, type ReleaseVersionState } from './releaseVersion.ts';
import { savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import { parseAndroidBuildSavedConfig, parseAndroidBuildSavedVersion, sameAndroidBuildData, androidBuildCounter } from './androidBuildProtocol.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { assetStorageWritable } from './assetSessionProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { ANDROID_VERSIONS_QUERY } from './androidStoreVersions.ts';
import { PAIRED_VERSIONS_QUERY, pairedVersionScope } from './pairedStoreVersions.ts';
import { IOS_VERSIONS_QUERY } from './iosStoreVersions.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, storeConsent, APPLE_BUNDLE_QUERY, APPLE_PROFILE_QUERY } from './localStorePreflightProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalStoreIdentity, LocalStorePreflightApi, LocalStoreStatus, PrepareLocalStorePreflight } from './localStorePreflightTypes.ts';
type Port=LocalStorePreflightApi&{mode:BridgeMode};
export interface LocalStoreState {mode:BridgeMode;platform:'android'|'ios'|'both';request:PrepareLocalStorePreflight|null;status:LocalStoreStatus|null;pending:boolean;callersPending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
export type LocalStoreProject=Pick<AndroidBuildProject,'projectId'|'draftRevision'|'baselineGeneration'|'observationGeneration'|'savedConfig'|'savedVersion'|'dirtyDraft'|'snapshotPending'|'versionPending'|'saveRecoveryRequired'|'inputIssue'> & { iosDemoRequired?: boolean | null; versionPlatforms?: readonly ('android'|'ios')[] | null };
interface Source {project:()=>LocalStoreProject|null;assets:()=>AssetDisplayState|null;otherOperationReason:()=>string|null;now?:()=>number}
interface Attempt {delegated?:boolean;request:PrepareLocalStorePreflight;epoch:number;after:number;previous:LocalStoreIdentity|null;id:LocalStoreIdentity|null;retired:boolean;started:boolean}
const active=(s:LocalStoreStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalStoreIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalStoreIdentity|null|undefined,b:LocalStoreIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original Store check is unverified. Keep its status and cancel; another run is not safe until native cleanup is confirmed.';
export function localStoreOwnerReason(s:LocalStoreState):string|null{return s.blocked||s.unconfirmed||s.pending||s.callersPending||active(s.status)?'A local Store access-check intent or operation is retained. Cancel or finish it before other work.':null;}
export function localStoreRequest(project:LocalStoreProject|null,assets:AssetDisplayState|null):PrepareLocalStorePreflight|null{
 const status=assets?.status,c=status?.context;
 const pair=!!c&&pairedVersionScope(c);
 if(!project||project.inputIssue||project.dirtyDraft||project.snapshotPending||project.versionPending||project.saveRecoveryRequired||!project.savedConfig||!project.savedVersion||!assets||assets.mode!=='native'||assets.blocked||assets.busy||assets.updatingContext||assets.observationFailed||assets.originPending||!assets.contextCurrent||!status||!status.capability.available||!assetStorageWritable(status)||status.operation&&(status.operation.phase!=='idle'||status.operation.settlement!=='known')||!c||c.projectId!==project.projectId||!['android','ios','both'].includes(c.platform)||assets.scope.platform!==c.platform||c.executionMode!=='local'||(!pair&&!['full','store'].includes(c.purpose))||assets.scope.executionMode!=='local')return null;
 if((c.platform==='both'||c.purpose==='version-inventory')&&!pair||pair&&(!pairedVersionScope(assets.scope)||!sameOfflineData(project.versionPlatforms,['android','ios'])))return null;
 const kind=c.platform==='ios'?'asc-p8':'google-service-account';
 const rows=status.assignments.filter(r=>r.kind===kind&&r.availability==='available'&&r.contextRevision===c.revision);
 if(rows.length!==1)return null;const row=rows[0]!;
 if(!status.records.some(r=>r.kind===kind&&r.recordId===row.recordId&&r.revision===row.recordRevision&&r.availability==='assigned'))return null;
 let iosRecord: {recordId:string;recordRevision:number}|undefined;
 if(pair){const matches=status.assignments.filter(r=>r.kind==='asc-p8'&&r.availability==='available'&&r.contextRevision===c.revision);if(matches.length!==1)return null;const p8=matches[0]!;if(p8.recordId===row.recordId||!status.records.some(r=>r.kind==='asc-p8'&&r.recordId===p8.recordId&&r.revision===p8.recordRevision&&r.availability==='assigned'))return null;iosRecord={recordId:p8.recordId,recordRevision:p8.recordRevision};}
 return parseLocalStoreRequest({projectId:project.projectId,draftRevision:project.draftRevision,baselineGeneration:project.baselineGeneration,savedConfig:project.savedConfig,savedVersion:project.savedVersion,credentialContextRevision:c.revision,recordId:row.recordId,recordRevision:row.recordRevision,executionMode:'local',...(pair?{platform:'both',query:PAIRED_VERSIONS_QUERY,iosRecord}:c.platform==='ios'?{platform:'ios'}:{})});
}
export class LocalStorePreflightController {
 private state:LocalStoreState={mode:'unavailable',platform:'android',request:null,status:null,pending:false,callersPending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;private pendingGuiSubmissions=0;
 private attempt:Attempt|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalStoreState>){this.state=Object.freeze({...this.state,...patch,callersPending:this.hasPendingGuiSubmission()});if(!this.disposed)for(const listener of this.listeners){try{listener();}catch{/* An observer cannot release an original call. */}}}
 // Actual JavaScript callers, separate from native status/finality. A terminal
 // event cannot retire an outstanding invocation or its original listener.
 hasPendingGuiSubmission():boolean{return this.pendingGuiSubmissions!==0;}
 private enterGuiSubmission():boolean{const first=!this.hasPendingGuiSubmission();this.pendingGuiSubmissions=Number.isSafeInteger(this.pendingGuiSubmissions)&&this.pendingGuiSubmissions>=0&&this.pendingGuiSubmissions<Number.MAX_SAFE_INTEGER?this.pendingGuiSubmissions+1:Infinity;return first;}
 private returnedGuiSubmission():void{const held=this.hasPendingGuiSubmission();if(Number.isSafeInteger(this.pendingGuiSubmissions)&&this.pendingGuiSubmissions>0)this.pendingGuiSubmissions--;if(held!==this.hasPendingGuiSubmission())this.update({});this.detachIfDisposed();}
 private detachIfDisposed():void{if(!this.disposed||this.hasPendingGuiSubmission()||localStoreOwnerReason(this.state)||!this.unlisten)return;const original=this.unlisten;this.unlisten=null;try{original();}catch{this.update({blocked:true,unconfirmed:true,error});}}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const assets=this.source.assets(),next=localStoreRequest(this.source.project(),assets),platform=assets?.scope.platform==='both'?'both':assets?.scope.platform==='ios'?'ios':'android';if(!sameOfflineData(next,this.state.request)||platform!==this.state.platform){this.invalidate();this.update({request:next,platform});}};
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{if(pending)this.invalidate();else this.syncProject();};
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started&&!this.attempt.delegated)this.invalidate();};
 delegatePrepared(id:LocalStoreIdentity,revision:number):(()=>boolean)|null{
  this.syncProject();const a=this.attempt,api=this.api;
  const exact=()=>!!a&&this.attempt===a&&this.api===api&&api?.mode==='native'&&!this.disposed&&!a.retired&&!a.started&&a.epoch===this.epoch&&!this.reading&&!this.state.pending&&!this.state.blocked&&!this.state.unconfirmed&&!(this.hasPendingGuiSubmission()||false)&&sameId(a.id,id)&&sameId(a.id,this.state.status?.operation)&&this.state.status?.statusRevision===revision&&this.state.status.operation?.phase==='awaiting-consent'&&this.state.status.operation.intentUsable&&a.request.query===undefined&&(a.request.platform===undefined||a.request.platform==='android'||a.request.platform==='ios');
  if(!exact()||!a||a.delegated||this.state.consentUntil===null||this.now()>=this.state.consentUntil)return null;
  a.delegated=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  // Survives removal of ordinary consent, not context/native-identity changes.
  return ()=>exact()&&a.delegated===true;
 }
 beginConnection=()=>{this.invalidate();if(localStoreOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalStorePreflight(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalStoreStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,{...a.request,platform:a.request.platform??'android',operation:'local-store-preflight'}))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,{...a!.request,platform:a!.request.platform??'android',operation:'local-store-preflight'})){this.fail();return;}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!a?.retired});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});this.detachIfDisposed();}
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading||this.disposed&&!localStoreOwnerReason(this.state))return;const api=this.api;this.reading=true;const first=this.enterGuiSubmission();try{if(first)this.update({});this.receive(await api.localStorePreflightStatus());}catch{this.fail();}finally{this.reading=false;this.returnedGuiSubmission();}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot contact Stores.';if(localStoreOwnerReason(this.state))return localStoreOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for the local Store check.';if(!this.state.request)return this.state.platform==='both'?'Read the current saved shared version. In Credentials choose Use shared-version credentials, then assess and assign both the Google service-account JSON and App Store Connect P8 in that same context.':this.state.platform==='ios'?'Read the saved version, then in Credentials choose This Mac → iOS → Store (or Full), select an App Store Connect P8 with its Key ID and Issuer ID, keep and assign it.':'Read the saved version, then in Credentials choose This Mac → Android → Store (or Full), select a Google service-account JSON, keep and assign it.';return this.source.otherOperationReason();}
 // The new query cannot dispatch from an intent revoked by a synchronous
 // subscriber. Own pending bookkeeping is not a peer/native-currentness grant.
 private invocationCurrent(api:Port,a:Attempt):boolean{
  const owned=()=>!this.disposed&&this.api===api&&api.mode==='native'&&this.state.mode==='native'&&this.attempt===a&&!a.retired&&a.epoch===this.epoch&&!this.state.blocked&&this.state.platform===(a.request.query===PAIRED_VERSIONS_QUERY?'both':a.request.platform??'android');
  if(!owned())return false;
  const base=localStoreRequest(this.source.project(),this.source.assets());
  const live=base&&parseLocalStoreRequest({...base,...(a.request.query===ANDROID_VERSIONS_QUERY?{platform:'android'}:{}),...(a.request.query===undefined?{}:{query:a.request.query})});
  const peer=this.source.otherOperationReason();
  return owned()&&!peer&&sameOfflineData(live,a.request);
 }
 async prepare(query?:typeof APPLE_BUNDLE_QUERY|typeof APPLE_PROFILE_QUERY|typeof IOS_VERSIONS_QUERY|typeof ANDROID_VERSIONS_QUERY|typeof PAIRED_VERSIONS_QUERY){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.status||this.state.platform==='both'&&query!==PAIRED_VERSIONS_QUERY||query!==undefined&&!((this.state.platform==='ios'&&(query===APPLE_BUNDLE_QUERY||query===APPLE_PROFILE_QUERY||query===IOS_VERSIONS_QUERY))||(this.state.platform==='android'&&query===ANDROID_VERSIONS_QUERY)||(this.state.platform==='both'&&query===PAIRED_VERSIONS_QUERY)))return;const api=this.api,request=query===undefined?this.state.request:parseLocalStoreRequest({...this.state.request,...(query===ANDROID_VERSIONS_QUERY?{platform:'android'}:{}),query});if(!request)return;
  this.attempt={request,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false};const a=this.attempt;
  this.enterGuiSubmission();this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{
   if(!this.invocationCurrent(api,a)||a.id!==null||this.state.status?.statusRevision!==a.after){
    a.retired=true;
    if(this.attempt===a&&!a.id){this.attempt=null;this.update({unconfirmed:this.state.blocked||active(this.state.status)});}
    else if(a.id)void this.cancelOriginal(false);
    return; // This original Prepare was never invoked; no native promise lost.
   }
   this.receive(await api.prepareLocalStorePreflight(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{this.update({pending:false});this.returnedGuiSubmission();}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(a?.delegated)return; // Only native CLI consent can consume this linked review.
  if(a?.started||this.hasPendingGuiSubmission())return; // A queued second click cannot cancel the original run.
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  const consentUntil=this.state.consentUntil;
  a.started=true;this.clearTimer();this.enterGuiSubmission();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{
   if(this.now()>=consentUntil||!this.invocationCurrent(api,a)||!sameId(a.id,this.state.status?.operation)||this.state.status?.operation?.phase!=='awaiting-consent'||!this.state.status.operation.intentUsable){
    this.invalidate();return; // Keep/cancel the actual prepared native original.
   }
   this.receive(await api.startLocalStorePreflight({...a.id,consentVersion:storeConsent(a.request.platform,a.request.query)}));}catch{this.fail();}finally{this.update({pending:false});this.returnedGuiSubmission();}}
 cancel=()=>{this.invalidate();return this.cancelOriginal(true);};
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.enterGuiSubmission();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalStorePreflight(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}finally{this.returnedGuiSubmission();}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();this.detachIfDisposed();}
}

// Platform-neutral saved input comparison; no build-tool or archive selection.
function own(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const field = Object.getOwnPropertyDescriptor(value, key);
  return field?.enumerable && Object.hasOwn(field, 'value') ? field.value : undefined;
}

export function localStoreProjectObservation(session: ProjectSession, version: ReleaseVersionState | null): LocalStoreProject {
  const project: LocalStoreProject = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, savedConfig: null, savedVersion: null,
    dirtyDraft: isDirty(session), snapshotPending: session.snapshotRequest !== null, versionPending: version?.pending !== null && version?.pending !== undefined,
    saveRecoveryRequired: session.saveRecoveryRequired, inputIssue: 'Refresh a current, format-valid saved configuration, then read its saved version. Prior snapshots and editor baselines are not build inputs.' };
  try {
    if (project.snapshotPending || session.snapshotError !== null || session.snapshotPredatesSave || session.snapshot === null ||
        !Number.isFinite(session.observedAt) || session.observedAt === null || session.observedAt < 0 || session.observationGeneration < 1) return project;
    const observed = savedConfigFromSnapshot(session.snapshot), compared = parseAndroidBuildSavedConfig(session.savedConfigContent);
    if (!observed || !compared || !sameAndroidBuildData(observed, compared)) return project;
    project.savedConfig = compared;
    const data = own(own(session.snapshot, 'config'), 'data');
    project.inputIssue = 'Read a complete saved-version observation for this current configuration. An older, pending, failed or partial version response cannot authorize a Store access check.';
    if (!version || version.mode !== 'native' || version.reason !== null || version.generationLost || version.selectionPending || version.pending !== null ||
        version.stale || version.error !== null || !version.resultBinding || !version.project) return project;
    // Reparse the COMPLETE observe-v2 response, including its fixed assurance,
    // scope and both byte comparisons. Picking just name/build would lose proof
    // of which saved configuration selected the version source.
    const result = parseReleaseVersionObservation(version.result), binding = version.resultBinding;
    if (!result) return project;
    const expected = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
      observationGeneration: session.observationGeneration, dirtyDraft: project.dirtyDraft, snapshotRequest: null, saveRecoveryRequired: false };
    const fields = ['projectId', 'draftRevision', 'baselineGeneration', 'observationGeneration', 'dirtyDraft', 'snapshotRequest', 'saveRecoveryRequired'] as const;
    const current = version.project;
    if (!fields.every((key) => binding[key] === expected[key] && current[key] === expected[key]) ||
        binding.readEpoch !== version.readEpoch || binding.requestId !== version.readEpoch || binding.connectionGeneration !== version.connectionGeneration ||
        binding.selectionGeneration !== version.selectionGeneration || ![binding.observationGeneration, binding.requestId, binding.readEpoch,
          binding.connectionGeneration, binding.selectionGeneration].every(androidBuildCounter)) return project;
    if (!sameAndroidBuildData(result.savedConfig, compared) || own(own(data, 'version'), 'source') !== result.source) {
      project.inputIssue = 'The saved-version response does not match the current saved configuration/source. Refresh the saved configuration and explicitly read the saved version again.'; return project;
    }
    const savedVersion = parseAndroidBuildSavedVersion({ ...result.savedVersion, source: result.source, name: result.version.name, build: result.version.build });
    if (!savedVersion) return project;
    project.savedVersion = savedVersion;
    // Negative UI guidance only, from the same current saved config (never a draft).
    const android = own(own(data, 'android'), 'enabled'), ios = own(own(data, 'ios'), 'enabled');
    project.versionPlatforms = (android === undefined || typeof android === 'boolean') && (ios === undefined || typeof ios === 'boolean')
      ? [...(android === true ? ['android' as const] : []), ...(ios === true ? ['ios' as const] : [])] : null;
    const demoRequired = own(own(own(data, 'ios'), 'review'), 'demoAccountRequired');
    project.iosDemoRequired = typeof demoRequired === 'boolean' ? demoRequired : null;
    project.inputIssue = null;
  } catch { /* Snapshot hooks and parser exceptions never become UI text. */ }
  return project;
}
