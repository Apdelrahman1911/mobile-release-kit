// UI coordination only. The native saved-command Session owns work and cleanup.
import type { AndroidBuildProject } from './androidBuild.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { localStoreRequest, type LocalStoreProject } from './localStorePreflight.ts';
import { localHistoryOwnerReason, type LocalHistoryState } from './localReleaseHistory.ts';
import { stageInputs, currentReview } from './localStoreStage.ts';
import type { LocalPreparedIntentReview, IOSPreparedIntentReview, StageExecutionReceiptReview } from './localReleaseHistoryTypes.ts';
import { parseLocalHistoryStatus } from './localReleaseHistoryProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreReconcileRequest, parseLocalStoreReconcileStatus, reconcileConsent, reconcileRequestContext } from './localStoreReconcileProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalStoreReconcileIdentity, LocalStoreReconcileApi, LocalStoreReconcileStatus, PrepareLocalStoreReconcile } from './localStoreReconcileTypes.ts';
type ReconcileProject=LocalStoreProject & {selection?:AndroidBuildProject['selection']};
type PreparedReview=LocalPreparedIntentReview|IOSPreparedIntentReview|StageExecutionReceiptReview;
const appId=(p:PreparedReview)=>'bundleId' in p?p.bundleId:p.applicationId;
type Port=LocalStoreReconcileApi&{mode:BridgeMode};
export interface LocalStoreReconcileState {platform:'android'|'ios';settlement:boolean;externalReadiness:boolean;mode:BridgeMode;applicationId:string|null;prepared:PreparedReview|null;request:PrepareLocalStoreReconcile|null;status:LocalStoreReconcileStatus|null;pending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
interface Source {project:()=>ReconcileProject|null;assets:()=>AssetDisplayState|null;history:()=>LocalHistoryState|null;otherOperationReason:()=>string|null;now?:()=>number}
const active=(s:LocalStoreReconcileStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalStoreReconcileIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalStoreReconcileIdentity|null|undefined,b:LocalStoreReconcileIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original Store readback is unverified. Keep its status and files, and cancel only that original. Do not upload again or remove history to retry.';
export function localStoreReconcileOwnerReason(s:LocalStoreReconcileState):string|null{return s.blocked||s.unconfirmed||s.pending||active(s.status)?'A local Store readback intent or operation is retained. Cancel or finish it before other work.':null;}
// Current UI context only: the native owner independently rechecks the enrolled
// journal, exact files/source, Store assignment and authenticated current history.
function externalReadinessContext(project:ReconcileProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null) {
 const base=stageInputs(project,assets);
 if(!base||base.platform!=='ios'||base.stage!=='external-testing')return null;
 const op=currentReview(history,base.projectId),p=op?.result?.executionReceipt,last=op?.result?.history.at(-1);
 if(!op||op.context.action!=='review-stage-execution'||op.context.platform!=='ios'||!p||!('stage' in p)||p.stage!=='external-testing'||!('bundleId' in p)||
    !last||last.phase!=='settled-success'||last.operationId!==p.operationId||op.context.stageOperationId!==p.operationId||
    op.result!.headSequence<11||op.result!.headSequence>508||p.version.name!==base.savedVersion.name||p.version.build!==base.savedVersion.build)return null;
 const {stage:_,...inputs}=base;
 const request=parseLocalStoreReconcileRequest({...inputs,action:'external-readiness',stageOperationId:p.operationId,
   candidateOperationId:p.candidateOperationId,candidateSha256:p.candidateSha256,intentSha256:p.intentSha256,executionReceiptSha256:p.receiptSha256,
   confirmation:`external-testing:ios:${base.savedVersion.name}:${base.savedVersion.build}`});
 return request?{request,prepared:p,head:op.result!.headSequence}:null;
}
function reconcileContext(project:ReconcileProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null,settlement=false,externalReadiness=false) {
 if(externalReadiness)return settlement?null:externalReadinessContext(project,assets,history);
 const base=localStoreRequest(project,assets);
 if(!base||base.platform==='ios'&&settlement||assets?.status?.context?.stage!=='candidate'||assets.scope.stage!=='candidate'||!history||history.historical||localHistoryOwnerReason(history))return null;
 const status=parseLocalHistoryStatus(history.status),op=status?.operation;
 if(history.mode!=='native'||!op||op.phase!=='terminal'||op.outcome!=='complete'||op.context.projectId!==base.projectId||op.context.platform!==base.platform||op.context.action!=='review-reconcile'||!op.result)return null;
 const prepared=op.result.preparedIntent,last=op.result.history.at(-1);
 if(!prepared||'stage' in prepared||!last||!['execute-pending','settled-success','settled-failure','reconciliation-required'].includes(last.phase)||last.operationId!==prepared.operationId||op.context.candidateOperationId!==prepared.operationId||
   prepared.version.name!==base.savedVersion.name||prepared.version.build!==base.savedVersion.build)return null;
 if(base.platform==='ios'?!('bundleId' in prepared):!('applicationId' in prepared)||project?.selection?.applicationId!==prepared.applicationId)return null;
 if(settlement&&(last.phase==='settled-success'||op.result.headSequence>512))return null;
 const request=parseLocalStoreReconcileRequest({...base,...(settlement?{settlement:'record-current-target'}:{}),candidateOperationId:prepared.operationId,candidateSha256:prepared.candidateSha256,
   intentSha256:prepared.intentSha256,confirmation:`candidate:${base.platform==='ios'?'ios':'android'}:${base.savedVersion.name}:${base.savedVersion.build}`});
 return request?{request,prepared,head:op.result.headSequence}:null;
}
export function localStoreReconcileRequest(project:ReconcileProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null,settlement=false,externalReadiness=false):PrepareLocalStoreReconcile|null {
 return reconcileContext(project,assets,history,settlement,externalReadiness)?.request??null;
}
export class LocalStoreReconcileController {
 private state:LocalStoreReconcileState={platform:'android',settlement:false,externalReadiness:false,mode:'unavailable',applicationId:null,prepared:null,request:null,status:null,pending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;
 private attempt:{request:PrepareLocalStoreReconcile;prepared:PreparedReview;head:number;epoch:number;after:number;previous:LocalStoreReconcileIdentity|null;id:LocalStoreReconcileIdentity|null;retired:boolean;started:boolean}|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 private selectionPending=false;private historyHead:number|null=null;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalStoreReconcileState>){this.state=Object.freeze({...this.state,...patch});if(!this.disposed)for(const listener of this.listeners)listener();}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const assets=this.source.assets(),platform=assets?.scope.platform==='ios'?'ios':'android';
  const settlement=platform==='ios'&&!localStoreReconcileOwnerReason(this.state)?false:this.state.settlement;
  const externalReadiness=platform!=='ios'&&!localStoreReconcileOwnerReason(this.state)?false:this.state.externalReadiness;
  const next=this.selectionPending?null:reconcileContext(this.source.project(),assets,this.source.history(),settlement,externalReadiness);
  const request=next?.request??null,prepared=next?.prepared??null,head=next?.head??null;
  if(platform!==this.state.platform||externalReadiness!==this.state.externalReadiness||settlement!==this.state.settlement||head!==this.historyHead||!sameOfflineData(request,this.state.request)||!sameOfflineData(prepared,this.state.prepared)){
   this.invalidate();this.historyHead=head;this.update({request,prepared,platform,settlement,externalReadiness,applicationId:prepared?appId(prepared):null});
  }};
 setSettlement(value:boolean){if(value&&this.state.platform==='ios'||localStoreReconcileOwnerReason(this.state))return false;if(value!==this.state.settlement){this.invalidate();this.update({settlement:value});this.syncProject();}return true;}
 setExternalReadiness(value:boolean){if(value&&this.state.platform!=='ios'||localStoreReconcileOwnerReason(this.state))return false;if(value!==this.state.externalReadiness){this.invalidate();this.update({externalReadiness:value,settlement:false});this.syncProject();}return true;}
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{this.selectionPending=pending;if(pending)this.invalidate();this.syncProject();};
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started)this.invalidate();};
 beginConnection=()=>{this.invalidate();if(localStoreReconcileOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalStoreReconcile(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalStoreReconcileStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,reconcileRequestContext(a.request)))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,reconcileRequestContext(a!.request))){this.fail();return;}
  if(ours&&op?.result){const r=op.result.readinessReceipt??op.result.reconciliationReceipt,p=a!.prepared;if(op.result.headSequence!==a!.head+(a!.request.settlement||a!.request.action==='external-readiness'?1:0)||('bundleId' in r?r.bundleId:r.applicationId)!==appId(p)||('appStoreAppId' in r)&&(!('appStoreAppId' in p)||r.appStoreAppId!==p.appStoreAppId)||r.sourceCommit!==p.sourceCommit||r.sourceTree!==p.sourceTree){this.fail();return;}}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!op&&(!!a?.retired||!sameOfflineData(op.context,this.state.request?reconcileRequestContext(this.state.request):null))});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});if(this.disposed){this.unlisten?.();this.unlisten=null;}}
  // Recompute only idle display eligibility after the actual original closes.
  // A retained Android recovery choice cannot strand a newly selected iOS view.
  if(op?.phase==='terminal'&&!localStoreReconcileOwnerReason(this.state)&&(this.state.platform==='ios'&&this.state.settlement||this.state.platform!=='ios'&&this.state.externalReadiness))this.syncProject();
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading)return;this.reading=true;try{this.receive(await this.api.localStoreReconcileStatus());}catch{this.fail();}finally{this.reading=false;}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot contact Stores.';if(localStoreReconcileOwnerReason(this.state))return localStoreReconcileOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for local Store readback.';if(!this.state.request&&this.state.externalReadiness)return'In Release history, choose iOS and review the latest successful external stage receipt. Keep its saved version and assign the original App Store Connect key, review contact and operation commitment under Credentials → This Mac → iOS → External testing → Store (or Full). The original operation must be complete, not interrupted.';if(!this.state.request&&this.state.settlement)return'Review the latest interrupted or failed execution for a Store check. Already successful executions and a full recovery journal cannot record another checkpoint. Keep the matching saved version and assigned Google account.';if(!this.state.request&&this.state.platform==='ios')return'In Release history, choose iOS and review the latest execution for a Store check. Read the matching saved version and assign the same App Store Connect P8, Key ID and Issuer ID in Credentials → This Mac → iOS → Candidate → Store (or Full).';if(!this.state.request)return'In Release history, review the latest execution for a Store check, read the matching saved version, and assign the same Google service account in Credentials → This Mac → Android → Candidate → Store (or Full).';return this.source.otherOperationReason();}
 async prepare(){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.prepared||!this.state.status||this.historyHead===null)return;const api=this.api,request=this.state.request;
  this.attempt={request,prepared:this.state.prepared,head:this.historyHead,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false};const a=this.attempt;
  this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{this.receive(await api.prepareLocalStoreReconcile(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{this.update({pending:false});}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(a?.started)return; // A queued second click cannot cancel the running original.
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  a.started=true;this.clearTimer();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{this.receive(await api.startLocalStoreReconcile({...a.id,consentVersion:reconcileConsent(a.request)}));}catch{this.fail();}finally{this.update({pending:false});}}
 cancel=()=>{this.invalidate();return this.cancelOriginal(true);};
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalStoreReconcile(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();if(!localStoreReconcileOwnerReason(this.state)){this.unlisten?.();this.unlisten=null;}}
}
