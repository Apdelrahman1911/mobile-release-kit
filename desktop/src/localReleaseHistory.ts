import { parseLocalHistoryReview, sameLocalHistoryReview } from './agentLocalHistoryProtocol.ts';
import type { LocalHistoryReview } from './agentLocalHistoryProtocol.ts';
// UI coordination only. The native saved-command Session owns work and cleanup.
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalHistoryRequest, parseLocalHistoryStatus, localHistoryConsent, candidateHistoryAction, stageHistoryAction } from './localReleaseHistoryProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalHistoryIdentity, LocalHistoryApi, LocalHistoryStatus, PrepareLocalHistory, LocalHistoryAction } from './localReleaseHistoryTypes.ts';
type Port=LocalHistoryApi&{mode:BridgeMode};
export interface LocalHistoryState {mode:BridgeMode;inputPlatform:'android'|'ios';request:PrepareLocalHistory|null;status:LocalHistoryStatus|null;pending:boolean;callersPending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
interface Source {projectId:()=>string|null;otherOperationReason:()=>string|null;delegationReason?:()=>string|null;now?:()=>number}
const active=(s:LocalHistoryStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalHistoryIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalHistoryIdentity|null|undefined,b:LocalHistoryIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original local history operation is unverified. Keep its status and cancel; another run is not safe until native cleanup is confirmed.';
export function localHistoryOwnerReason(s:LocalHistoryState):string|null{return s.blocked||s.unconfirmed||s.pending||s.callersPending||active(s.status)?'A local release-history intent or operation is retained. Cancel or finish it before other work.':null;}
export function localHistoryRequest(projectId:string|null, action:LocalHistoryAction,candidateOperationId?:string,platform?:'android'|'ios'):PrepareLocalHistory|null{
 return parseLocalHistoryRequest({projectId,executionMode:'local',action,...(stageHistoryAction(action)?{stageOperationId:candidateOperationId,platform:platform??'android'}:{...(candidateHistoryAction(action)?{candidateOperationId}:{}),...(platform===undefined?{}:{platform})})});
}
export class LocalReleaseHistoryController {
 private state:LocalHistoryState={mode:'unavailable',inputPlatform:'android',request:null,status:null,pending:false,callersPending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private action:LocalHistoryAction='verify'; private candidateOperationId:string|undefined; private candidateProjectId:string|null=null; private selectionPending=false; private observedProjectId:string|null=null;
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;private pendingGuiSubmissions=0;
 private attempt:{request:PrepareLocalHistory;epoch:number;after:number;previous:LocalHistoryIdentity|null;id:LocalHistoryIdentity|null;retired:boolean;started:boolean;delegated:boolean}|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalHistoryState>){this.state=Object.freeze({...this.state,...patch,callersPending:this.hasPendingGuiSubmission()});if(!this.disposed)for(const listener of this.listeners){try{listener();}catch{/* An observer cannot release an original call. */}}}
 // Actual JavaScript callers, separate from native status/finality. A terminal
 // event cannot retire an outstanding invocation or its original listener.
 hasPendingGuiSubmission():boolean{return this.pendingGuiSubmissions!==0;}
 private enterGuiSubmission():boolean{const first=!this.hasPendingGuiSubmission();this.pendingGuiSubmissions=Number.isSafeInteger(this.pendingGuiSubmissions)&&this.pendingGuiSubmissions>=0&&this.pendingGuiSubmissions<Number.MAX_SAFE_INTEGER?this.pendingGuiSubmissions+1:Infinity;return first;}
 private returnedGuiSubmission():void{const held=this.hasPendingGuiSubmission();if(Number.isSafeInteger(this.pendingGuiSubmissions)&&this.pendingGuiSubmissions>0)this.pendingGuiSubmissions--;if(held!==this.hasPendingGuiSubmission())this.update({});this.detachIfDisposed();}
 private detachIfDisposed():void{if(!this.disposed||this.hasPendingGuiSubmission()||localHistoryOwnerReason(this.state)||!this.unlisten)return;const original=this.unlisten;this.unlisten=null;try{original();}catch{this.update({blocked:true,unconfirmed:true,error});}}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const projectId=this.source.projectId();if(this.observedProjectId!==projectId){this.observedProjectId=projectId;this.update({inputPlatform:'android'});}if(this.candidateProjectId!==null&&this.candidateProjectId!==projectId){this.action='verify';this.candidateOperationId=undefined;this.candidateProjectId=null;this.update({inputPlatform:'android'});}const next=this.selectionPending?null:localHistoryRequest(projectId,this.action,this.candidateOperationId,(this.action==='review-inputs'||this.action==='abandon-inputs'||this.action==='review-prepared'||this.action==='review-execution'||this.action==='review-reconcile'||stageHistoryAction(this.action))&&this.state.inputPlatform==='ios'?'ios':undefined);if(!sameOfflineData(next,this.state.request)){this.invalidate();this.update({request:next});}};
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{this.selectionPending=pending;if(pending)this.invalidate();this.syncProject();};
 setAction=(action:LocalHistoryAction)=>{if(this.disposed||this.hasPendingGuiSubmission())return;if(action!==this.action||this.candidateOperationId!==undefined){this.action=action;this.candidateOperationId=undefined;this.candidateProjectId=null;this.update({inputPlatform:'android'});this.syncProject();}};
 setInputPlatform=(platform:'android'|'ios'):boolean=>{
  // A pre-Start platform edit may still retire the pending Prepare, as before.
  // It never releases that caller or admits a new selection after a terminal.
  const retiringPrepare=this.state.pending&&this.attempt!==null&&!this.attempt.started;
  if(this.disposed||this.hasPendingGuiSubmission()&&!retiringPrepare||!['android','ios'].includes(platform)||this.state.blocked||(this.attempt?.started||this.state.status?.operation?.phase==='running'||this.state.status?.operation?.phase==='starting'||this.state.status?.operation?.phase==='stopping'||this.state.status?.operation?.phase==='unknown')&&active(this.state.status))return false;
  if(platform!==this.state.inputPlatform){if(this.action==='review-inputs'||this.action==='abandon-inputs'||this.action==='review-prepared'||this.action==='review-execution'||this.action==='review-reconcile'||stageHistoryAction(this.action))this.invalidate();this.update({inputPlatform:platform});this.syncProject();}
  return true;
 };
 selectCandidate=(action:'review-inputs'|'abandon-inputs'|'review-prepared'|'review-execution'|'review-reconcile'|'review-recovery',operationId:string):boolean=>{
  const op=this.state.status?.operation;
  if(localHistoryOwnerReason(this.state)||this.state.historical||!op?.result||op.context.projectId!==this.source.projectId())return false;
  const row=op.result.history.find(row=>row.operationId===operationId);
  if(!row||(action==='review-prepared'?row.phase!=='prepared':action==='review-execution'?row.phase!=='settled-success':action==='review-recovery'?row.phase!=='target-reconciled':action==='review-reconcile'?(op.result.history.at(-1)!==row||!['execute-pending','settled-success','settled-failure','reconciliation-required'].includes(row.phase)):!['inputs-pending','inputs-ready','settled-failure'].includes(row.phase))||action==='abandon-inputs'&&(row.phase==='settled-failure'||op.result.history.at(-1)!==row))return false;
  if(this.state.inputPlatform==='ios'&&action==='review-recovery')return false;
  this.action=action;this.candidateOperationId=operationId;this.candidateProjectId=op.context.projectId;this.syncProject();return this.state.request?.candidateOperationId===operationId&&this.state.request.action===action;
 };
 selectStage=(action:'review-stage-prepared'|'review-stage-execution'|'review-external-readiness',operationId:string):boolean=>{
  const op=this.state.status?.operation;
  if(localHistoryOwnerReason(this.state)||this.state.historical||op?.phase!=='terminal'||op.outcome!=='complete'||!op.result||op.context.projectId!==this.source.projectId())return false;
  const row=op.result.history.find(row=>row.operationId===operationId);
  if(!row||action==='review-external-readiness'&&this.state.inputPlatform!=='ios'||row.phase!==(action==='review-stage-prepared'?'prepared':action==='review-external-readiness'?'external-ready':'settled-success'))return false;
  this.action=action;this.candidateOperationId=operationId;this.candidateProjectId=op.context.projectId;this.syncProject();
  const request=this.state.request;
  return !!request&&'stageOperationId' in request&&request.stageOperationId===operationId&&request.action===action;
 };
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started&&!this.attempt.delegated)this.invalidate();};
 beginConnection=()=>{this.invalidate();if(localHistoryOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalReleaseHistory(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalHistoryStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,a.request))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,a!.request)){this.fail();return;}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!op&&(!!a?.retired||!sameOfflineData(op.context,this.state.request))});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});this.detachIfDisposed();}
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading||this.disposed&&!localHistoryOwnerReason(this.state))return;const api=this.api;this.reading=true;const first=this.enterGuiSubmission();try{if(first)this.update({});this.receive(await api.localReleaseHistoryStatus());}catch{this.fail();}finally{this.reading=false;this.returnedGuiSubmission();}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot access project history or Keychain.';if(localHistoryOwnerReason(this.state))return localHistoryOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for local release history.';if(!this.state.request)return'Select a project and finish any pending project selection. No Store credentials or saved version are required.';return this.source.delegationReason?.()??this.source.otherOperationReason();}
 private invocationCurrent(api:Port,a:NonNullable<LocalReleaseHistoryController['attempt']>):boolean{
  const owned=()=>!this.disposed&&this.api===api&&api.mode==='native'&&this.attempt===a&&!a.retired&&a.epoch===this.epoch&&!this.state.blocked&&!this.selectionPending;
  if(!owned())return false;const project=this.source.projectId(),peer=this.source.otherOperationReason();
  return owned()&&!peer&&project===a.request.projectId&&sameOfflineData(this.state.request,a.request);
 }
 // Comparison DATA only from THIS genuinely returned Prepare. The private
 // Attempt/API/epoch, not an awaiting-consent event or a copied DTO, admits Allow.
 delegationReview():LocalHistoryReview|null{
  const a=this.attempt,api=this.api,s=this.state,op=s.status?.operation;
  if(!a||!api||a.retired||a.started||a.delegated||!a.id||a.epoch!==this.epoch||s.pending||this.reading||this.hasPendingGuiSubmission()||s.blocked||s.unconfirmed||s.historical||s.status?.availability!=='available'||op?.phase!=='awaiting-consent'||!op.intentUsable||!sameId(a.id,op)||!sameOfflineData(op.context,a.request)||s.consentUntil===null||!Number.isFinite(this.now())||this.now()>=s.consentUntil||!this.invocationCurrent(api,a))return null;
  const r=a.request;if(r.action==='abandon-inputs')return null;
  return parseLocalHistoryReview({kind:r.action,...a.id,statusRevision:s.status.statusRevision,...(r.platform!==undefined?{platform:r.platform}:{}),...(r.candidateOperationId!==undefined?{candidateOperationId:r.candidateOperationId}:{}),...('stageOperationId' in r&&r.stageOperationId!==undefined?{stageOperationId:r.stageOperationId}:{})});
 }
 // Only a peer/currentness gate for a genuine MAIN comparison. This does not
 // install an Attempt, infer a return, or grant ordinary GUI Start.
 cliPreparationReason(review:LocalHistoryReview):string|null {
  const s=this.state,op=s.status?.operation,a=this.attempt;
  if(this.disposed||s.blocked||s.unconfirmed||s.pending||this.reading||this.hasPendingGuiSubmission())return 'The original Desktop history caller is still pending or unconfirmed.';
  if(active(s.status)&&(!sameId(review,op)||a?.id&&sameId(a.id,op)))return 'A different or GUI-owned history intent is retained.';
  return null;
 }
 delegatePrepared(review:LocalHistoryReview):(()=>boolean)|null{
  const r=this.delegationReview(),a=this.attempt,api=this.api,status=this.state.status;
  if(!r||!a||!api||!status||!sameLocalHistoryReview(r,review))return null;
  // Monotone, even if the later Allow is refused/lost. Only the old GUI timer
  // and hidden-tab cancellation are removed. Native expiry/Stop never changes.
  a.delegated=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  return ()=>this.attempt===a&&a.delegated&&!a.started&&this.state.status===status&&!this.state.pending&&!this.reading&&!this.hasPendingGuiSubmission()&&!this.state.unconfirmed&&!this.state.historical&&this.invocationCurrent(api,a);
 }
 async prepare(){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.status)return;const api=this.api,request=this.state.request;
  this.attempt={request,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false,delegated:false};const a=this.attempt;
  this.enterGuiSubmission();this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{if(!this.invocationCurrent(api,a)||a.id!==null||this.state.status?.statusRevision!==a.after){a.retired=true;if(this.attempt===a&&!a.id){this.attempt=null;this.update({unconfirmed:this.state.blocked||active(this.state.status)});}else if(a.id)void this.cancelOriginal(false);return;}
   this.receive(await api.prepareLocalReleaseHistory(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{this.update({pending:false});this.returnedGuiSubmission();}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(a?.started||a?.delegated||this.hasPendingGuiSubmission())return; // A queued second click cannot cancel the running original.
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  const consentUntil=this.state.consentUntil;a.started=true;this.clearTimer();this.enterGuiSubmission();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{if(this.now()>=consentUntil||!this.invocationCurrent(api,a)||!sameId(a.id,this.state.status?.operation)||this.state.status?.operation?.phase!=='awaiting-consent'||!this.state.status.operation.intentUsable){this.invalidate();return;}
   this.receive(await api.startLocalReleaseHistory({...a.id,consentVersion:localHistoryConsent(a.request)}));}catch{this.fail();}finally{this.update({pending:false});this.returnedGuiSubmission();}}
 cancel=()=>{this.invalidate();return this.cancelOriginal(true);};
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.enterGuiSubmission();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalReleaseHistory(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}finally{this.returnedGuiSubmission();}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();this.detachIfDisposed();}
}
