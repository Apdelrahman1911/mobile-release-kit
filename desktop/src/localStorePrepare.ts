// UI coordination only. The native saved-command Session owns work and cleanup.
import { localStoreStagePrepareRequest } from './localStoreStage.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { localStoreRequest, type LocalStoreProject } from './localStorePreflight.ts';
import { localHistoryOwnerReason, type LocalHistoryState } from './localReleaseHistory.ts';
import { parseLocalHistoryStatus } from './localReleaseHistoryProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStorePrepareRequest, parseLocalStorePrepareStatus, storePrepareConsent } from './localStorePrepareProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalStorePrepareIdentity, LocalStorePrepareApi, LocalStorePrepareStatus, PrepareLocalStoreIntent } from './localStorePrepareTypes.ts';
type Port=LocalStorePrepareApi&{mode:BridgeMode};
export interface LocalStorePrepareState {mode:BridgeMode;applicationId:string|null;request:PrepareLocalStoreIntent|null;status:LocalStorePrepareStatus|null;pending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
interface Source {project:()=>LocalStoreProject|null;assets:()=>AssetDisplayState|null;history:()=>LocalHistoryState|null;otherOperationReason:()=>string|null;now?:()=>number}
const active=(s:LocalStorePrepareStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalStorePrepareIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalStorePrepareIdentity|null|undefined,b:LocalStorePrepareIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original Store preparation is unverified. Keep its status and cancel; another run is not safe until native cleanup is confirmed.';
export function localStorePrepareOwnerReason(s:LocalStorePrepareState):string|null{return s.blocked||s.unconfirmed||s.pending||active(s.status)?'A local Store preparation intent or operation is retained. Cancel or finish it before other work.':null;}
// This is current UI context, not a grant or proof of native file finality.
export function localStorePrepareRequest(project:LocalStoreProject|null,assets:AssetDisplayState|null,history:LocalHistoryState|null):PrepareLocalStoreIntent|null {
 if(assets?.scope.stage!=='candidate')return localStoreStagePrepareRequest(project,assets,history);
 const base=localStoreRequest(project,assets);
 if(!base||assets?.status?.context?.stage!=='candidate'||assets.scope.stage!=='candidate'||!history||history.historical||localHistoryOwnerReason(history))return null;
 const status=parseLocalHistoryStatus(history.status),op=status?.operation;
 if(history.mode!=='native'||!op||op.phase!=='terminal'||op.outcome!=='complete'||op.context.projectId!==base.projectId||op.context.action!=='review-inputs'||op.context.platform!==base.platform||!op.result)return null;
 const candidate=op.result.candidateInputs,last=op.result.history.at(-1);
 if(!candidate||!(base.platform==='ios'?'bundleId' in candidate:'applicationId' in candidate)||!last||last.phase!=='inputs-ready'||last.operationId!==candidate.operationId||op.context.candidateOperationId!==candidate.operationId||candidate.version.name!==base.savedVersion.name||candidate.version.build!==base.savedVersion.build)return null;
 return parseLocalStorePrepareRequest({...base,candidateOperationId:candidate.operationId,candidateSha256:candidate.candidateSha256,confirmation:`candidate:${base.platform??'android'}:${base.savedVersion.name}:${base.savedVersion.build}`});
}
export class LocalStorePrepareController {
 private state:LocalStorePrepareState={mode:'unavailable',applicationId:null,request:null,status:null,pending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;
 private attempt:{request:PrepareLocalStoreIntent;epoch:number;after:number;previous:LocalStorePrepareIdentity|null;id:LocalStorePrepareIdentity|null;retired:boolean;started:boolean}|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 private selectionPending=false;private historyHead:number|null=null;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalStorePrepareState>){this.state=Object.freeze({...this.state,...patch});if(!this.disposed)for(const listener of this.listeners)listener();}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const history=this.source.history(),next=this.selectionPending?null:localStorePrepareRequest(this.source.project(),this.source.assets(),history);const result=history?.status?.operation?.result;const candidate=next&&'stage' in next?result?.executionReceipt:result?.candidateInputs;const applicationId=next&&candidate?('bundleId' in candidate?candidate.bundleId:candidate.applicationId):null;const head=next?history?.status?.operation?.result?.headSequence??null:null;if(applicationId!==this.state.applicationId||head!==this.historyHead||!sameOfflineData(next,this.state.request)){this.invalidate();this.historyHead=head;this.update({request:next,applicationId});}};
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{this.selectionPending=pending;if(pending)this.invalidate();this.syncProject();};
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started)this.invalidate();};
 beginConnection=()=>{this.invalidate();if(localStorePrepareOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalStorePrepare(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalStorePrepareStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,{...a.request,platform:a.request.platform??'android',operation:'local-store-prepare'}))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,{...a!.request,platform:a!.request.platform??'android',operation:'local-store-prepare'})){this.fail();return;}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!op&&(!!a?.retired||!sameOfflineData(op.context,this.state.request?{...this.state.request,platform:this.state.request.platform??'android',operation:'local-store-prepare'}:null))});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});if(this.disposed){this.unlisten?.();this.unlisten=null;}}
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading)return;this.reading=true;try{this.receive(await this.api.localStorePrepareStatus());}catch{this.fail();}finally{this.reading=false;}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot contact Stores.';if(localStorePrepareOwnerReason(this.state))return localStorePrepareOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for local Store preparation.';if(!this.state.request&&this.source.assets()?.scope.stage!=='candidate')return'Review the latest successful execution receipt in Release history. Choose External testing after internal testing, or Production after an external release available to testers. Read the same saved version and assign Store credentials for that exact stage in Credentials → This Mac. iOS also needs review contact, commitment key and demo account when required. Pending or uncertain history cannot be promoted.';if(!this.state.request)return'Review the current ready candidate in Release history, read the matching saved version, then assign matching credentials in Credentials → This Mac → Android or iOS → Candidate → Store (or Full). Use a Google service-account JSON for Android, or an App Store Connect P8 with Key ID and Issuer ID for iOS.';return this.source.otherOperationReason();}
 async prepare(){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.status)return;const api=this.api,request=this.state.request;
  this.attempt={request,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false};const a=this.attempt;
  this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{this.receive(await api.prepareLocalStorePrepare(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{this.update({pending:false});}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(a?.started)return; // A queued second click cannot cancel the running original.
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  a.started=true;this.clearTimer();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{this.receive(await api.startLocalStorePrepare({...a.id,consentVersion:storePrepareConsent(a.request.platform,'stage' in a.request?a.request.stage:undefined)}));}catch{this.fail();}finally{this.update({pending:false});}}
 cancel=()=>{this.invalidate();return this.cancelOriginal(true);};
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalStorePrepare(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();if(!localStorePrepareOwnerReason(this.state)){this.unlisten?.();this.unlisten=null;}}
}
