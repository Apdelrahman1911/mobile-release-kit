// UI coordination only. The native saved-command Session owns work and cleanup.
import { localStoreStageExecuteContext } from './localStoreStage.ts';
import { androidBuildOwnerReason, type AndroidBuildState, type AndroidBuildProject } from './androidBuild.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { localStoreRequest, type LocalStoreProject } from './localStorePreflight.ts';
import { localHistoryOwnerReason, type LocalHistoryState } from './localReleaseHistory.ts';
import type { LocalPreparedIntentReview, IOSPreparedIntentReview, StagePreparedIntentReview } from './localReleaseHistoryTypes.ts';
import { parseAndroidToolchainCatalogStatus } from './androidToolchainCatalogProtocol.ts';
import { parseLocalHistoryStatus } from './localReleaseHistoryProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreExecuteRequest, parseLocalStoreExecuteStatus, storeExecuteConsent } from './localStoreExecuteProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalStoreExecuteIdentity, LocalStoreExecuteApi, LocalStoreExecuteStatus, PrepareLocalStoreExecute } from './localStoreExecuteTypes.ts';
type Port=LocalStoreExecuteApi&{mode:BridgeMode};
type ExecuteProject=LocalStoreProject & {selection?:AndroidBuildProject['selection']};
type PreparedReview=LocalPreparedIntentReview|IOSPreparedIntentReview|StagePreparedIntentReview;
const requestContext=(request:PrepareLocalStoreExecute)=>({...request,platform:request.platform??'android',operation:'local-store-execute'});
const appId=(value:PreparedReview)=>'bundleId' in value?value.bundleId:value.applicationId;
export interface LocalStoreExecuteState {mode:BridgeMode;platform:'android'|'ios';applicationId:string|null;prepared:PreparedReview|null;request:PrepareLocalStoreExecute|null;status:LocalStoreExecuteStatus|null;pending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
interface Source {project:()=>ExecuteProject|null;assets:()=>AssetDisplayState|null;history:()=>LocalHistoryState|null;tools:()=>AndroidBuildState|null;otherOperationReason:()=>string|null;now?:()=>number}
const active=(s:LocalStoreExecuteStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalStoreExecuteIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalStoreExecuteIdentity|null|undefined,b:LocalStoreExecuteIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original Store execution is unverified. Keep its status and files, and cancel only that original. Do not upload again or remove history to retry.';
export function localStoreExecuteOwnerReason(s:LocalStoreExecuteState):string|null{return s.blocked||s.unconfirmed||s.pending||active(s.status)?'A local Store execution intent or operation is retained. Cancel or finish it before other work.':null;}
// Current UI context only: the native owner independently rechecks the enrolled
// journal, exact files/source, Google assignment and actual registered tool lease.
function executeContext(project:ExecuteProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null,tools:AndroidBuildState|null) {
 if(assets?.scope.stage!=='candidate')return localStoreStageExecuteContext(project,assets,history);
 const base=localStoreRequest(project,assets);
 if(!base||assets?.status?.context?.stage!=='candidate'||assets.scope.stage!=='candidate'||!history||history.historical||localHistoryOwnerReason(history))return null;
 const ios=base.platform==='ios';
 let toolchainSelection;
 if(!ios){
  if(!tools||tools.mode!=='native'||!tools.catalogListening||tools.catalogReadPending||tools.selectionPending||androidBuildOwnerReason(tools))return null;
  const catalog=parseAndroidToolchainCatalogStatus(tools.catalogStatus);
  if(!catalog||catalog.phase!=='ready'||catalog.availability!=='available'||!catalog.selected)return null;
  toolchainSelection=catalog.selected;
 }
 const status=parseLocalHistoryStatus(history.status),op=status?.operation;
 if(history.mode!=='native'||!op||op.phase!=='terminal'||op.outcome!=='complete'||op.context.projectId!==base.projectId||op.context.platform!==base.platform||op.context.action!=='review-prepared'||!op.result)return null;
 const prepared=op.result.preparedIntent,last=op.result.history.at(-1);
 if(!prepared||'stage' in prepared||!last||last.phase!=='prepared'||last.operationId!==prepared.operationId||op.context.candidateOperationId!==prepared.operationId||
   prepared.version.name!==base.savedVersion.name||prepared.version.build!==base.savedVersion.build)return null;
 if(ios?!('bundleId' in prepared):!('applicationId' in prepared)||project?.selection?.applicationId!==prepared.applicationId)return null;
 const request=parseLocalStoreExecuteRequest({...base,candidateOperationId:prepared.operationId,candidateSha256:prepared.candidateSha256,
   intentSha256:prepared.intentSha256,...(ios?{}:{toolchainSelection}),confirmation:`candidate:${ios?'ios':'android'}:${base.savedVersion.name}:${base.savedVersion.build}`});
 return request?{request,prepared,head:op.result.headSequence}:null;
}
export function localStoreExecuteRequest(project:ExecuteProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null,tools:AndroidBuildState|null):PrepareLocalStoreExecute|null {
 return executeContext(project,assets,history,tools)?.request??null;
}
export class LocalStoreExecuteController {
 private state:LocalStoreExecuteState={mode:'unavailable',platform:'android',applicationId:null,prepared:null,request:null,status:null,pending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;
 private attempt:{delegated:boolean;prepareReturned:boolean;request:PrepareLocalStoreExecute;prepared:PreparedReview;epoch:number;after:number;previous:LocalStoreExecuteIdentity|null;id:LocalStoreExecuteIdentity|null;retired:boolean;started:boolean}|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 private selectionPending=false;private historyHead:number|null=null;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalStoreExecuteState>){this.state=Object.freeze({...this.state,...patch});if(!this.disposed)for(const listener of this.listeners)listener();}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const assets=this.source.assets(),platform=assets?.scope.platform==='ios'?'ios':'android';const next=this.selectionPending?null:executeContext(this.source.project(),assets,this.source.history(),assets?.scope.stage==='candidate'?this.source.tools():null);
  const request=next?.request??null,prepared=next?.prepared??null,head=next?.head??null;
  if(platform!==this.state.platform||head!==this.historyHead||!sameOfflineData(request,this.state.request)||!sameOfflineData(prepared,this.state.prepared)){
   this.invalidate();this.historyHead=head;this.update({request,prepared,platform,applicationId:prepared?appId(prepared):null});
  }};
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{this.selectionPending=pending;if(pending)this.invalidate();this.syncProject();};
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started&&!this.attempt.delegated)this.invalidate();};
 agentPreparedMatches(id:LocalStoreExecuteIdentity,revision:number):boolean{
  const a=this.attempt,op=this.state.status?.operation;
  return !!a&&a.prepareReturned&&this.api?.mode==='native'&&!this.disposed&&!a.retired&&!a.started&&a.epoch===this.epoch&&
   !this.reading&&!this.state.pending&&!this.state.blocked&&!this.state.unconfirmed&&!this.state.historical&&sameId(a.id,id)&&sameId(a.id,op)&&
   this.state.status?.statusRevision===revision&&op?.phase==='awaiting-consent'&&op.intentUsable&&sameOfflineData(op.context,requestContext(a.request))&&
   (a.delegated||this.state.consentUntil!==null&&this.now()<this.state.consentUntil);
 }
 delegatePrepared(id:LocalStoreExecuteIdentity,revision:number):(()=>boolean)|null{
  this.syncProject();const a=this.attempt,api=this.api;
  if(!a||a.delegated||!this.agentPreparedMatches(id,revision))return null;
  a.delegated=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  // Monotone even if Allow is lost/refused. No fake started flag or native grant.
  return ()=>this.attempt===a&&this.api===api&&a.delegated&&this.agentPreparedMatches(id,revision);
 }
 beginConnection=()=>{this.invalidate();if(localStoreExecuteOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalStoreExecute(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalStoreExecuteStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,requestContext(a.request)))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,requestContext(a!.request))){this.fail();return;}
  if(ours&&op?.result){const r=op.result.executionReceipt,p=a!.prepared;if(('bundleId' in p? !('bundleId' in r)||r.bundleId!==p.bundleId||r.appStoreAppId!==p.appStoreAppId : !('applicationId' in r)||r.applicationId!==p.applicationId)||r.sourceCommit!==p.sourceCommit||r.sourceTree!==p.sourceTree){this.fail();return;}}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!op&&(!!a?.retired||!sameOfflineData(op.context,this.state.request?requestContext(this.state.request):null))});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});if(this.disposed){this.unlisten?.();this.unlisten=null;}}
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading)return;this.reading=true;try{this.receive(await this.api.localStoreExecuteStatus());}catch{this.fail();}finally{this.reading=false;}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot upload to a Store.';if(localStoreExecuteOwnerReason(this.state))return localStoreExecuteOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for local Store execution.';if(!this.state.request&&this.source.assets()?.scope.stage!=='candidate')return'Review the current stage-prepared intent in Release history, read the matching saved version and assign the same stage-specific Store credentials and iOS review inputs. This reuses the original uploaded binary; Java, Xcode and another build are not required. A changed, pending or failed stage cannot be resent.';if(!this.state.request)return'Review the matching prepared intent in Release history, read the saved version, and assign the same credential in Credentials → This Mac → the candidate platform → Candidate → Store (or Full). Android also requires the protected Android tool copy; iOS requires local Xcode (check Environment doctor).';return this.source.otherOperationReason();}
 async prepare(){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.prepared||!this.state.status)return;const api=this.api,request=this.state.request;
  this.attempt={delegated:false,prepareReturned:false,request,prepared:this.state.prepared,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false};const a=this.attempt;
  this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{this.receive(await api.prepareLocalStoreExecute(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{a.prepareReturned=true;this.update({pending:false});}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(a?.delegated)return; // Only the linked native CLI approval can consume this review.
  if(a?.started)return; // A queued second click cannot cancel the running original.
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  a.started=true;this.clearTimer();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{this.receive(await api.startLocalStoreExecute({...a.id,consentVersion:storeExecuteConsent(a.request)}));}catch{this.fail();}finally{this.update({pending:false});}}
 cancel=()=>{this.invalidate();return this.cancelOriginal(true);};
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalStoreExecute(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();if(!localStoreExecuteOwnerReason(this.state)){this.unlisten?.();this.unlisten=null;}}
}
