// UI coordination only. The native saved-command Session owns work and cleanup.
import type { AndroidBuildProject } from './androidBuild.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { assetStorageWritable } from './assetSessionProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, STORE_CONSENT } from './localStorePreflightProtocol.ts';
import type { BridgeMode } from './types.ts';
import type { LocalStoreIdentity, LocalStorePreflightApi, LocalStoreStatus, PrepareLocalStorePreflight } from './localStorePreflightTypes.ts';
type Port=LocalStorePreflightApi&{mode:BridgeMode};
export interface LocalStoreState {mode:BridgeMode;request:PrepareLocalStorePreflight|null;status:LocalStoreStatus|null;pending:boolean;unconfirmed:boolean;blocked:boolean;historical:boolean;acknowledged:boolean;consentUntil:number|null;error:string|null}
interface Source {project:()=>AndroidBuildProject|null;assets:()=>AssetDisplayState|null;otherOperationReason:()=>string|null;now?:()=>number}
const active=(s:LocalStoreStatus|null)=>!!s?.operation&&s.operation.phase!=='terminal';
const identity=(v:LocalStoreIdentity)=>({operationId:v.operationId,ownerGeneration:v.ownerGeneration});
const sameId=(a:LocalStoreIdentity|null|undefined,b:LocalStoreIdentity|null|undefined)=>!!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
const error='The original Store check is unverified. Keep its status and cancel; another run is not safe until native cleanup is confirmed.';
export function localStoreOwnerReason(s:LocalStoreState):string|null{return s.blocked||s.unconfirmed||s.pending||active(s.status)?'A local Store access-check intent or operation is retained. Cancel or finish it before other work.':null;}
export function localStoreRequest(project:AndroidBuildProject|null,assets:AssetDisplayState|null):PrepareLocalStorePreflight|null{
 const status=assets?.status,c=status?.context;
 if(!project||project.inputIssue||project.dirtyDraft||project.snapshotPending||project.versionPending||project.saveRecoveryRequired||!project.savedConfig||!project.savedVersion||!assets||assets.mode!=='native'||assets.blocked||assets.busy||assets.updatingContext||assets.observationFailed||assets.originPending||!assets.contextCurrent||!status||!status.capability.available||!assetStorageWritable(status)||status.operation&&(status.operation.phase!=='idle'||status.operation.settlement!=='known')||!c||c.projectId!==project.projectId||c.platform!=='android'||c.executionMode!=='local'||!['full','store'].includes(c.purpose)||assets.scope.executionMode!=='local')return null;
 const rows=status.assignments.filter(r=>r.kind==='google-service-account'&&r.availability==='available'&&r.contextRevision===c.revision);
 if(rows.length!==1)return null;const row=rows[0]!;
 if(!status.records.some(r=>r.kind==='google-service-account'&&r.recordId===row.recordId&&r.revision===row.recordRevision&&r.availability==='assigned'))return null;
 return parseLocalStoreRequest({projectId:project.projectId,draftRevision:project.draftRevision,baselineGeneration:project.baselineGeneration,savedConfig:project.savedConfig,savedVersion:project.savedVersion,credentialContextRevision:c.revision,recordId:row.recordId,recordRevision:row.recordRevision,executionMode:'local'});
}
export class LocalStorePreflightController {
 private state:LocalStoreState={mode:'unavailable',request:null,status:null,pending:false,unconfirmed:false,blocked:false,historical:false,acknowledged:false,consentUntil:null,error:null};
 private api:Port|null=null;private unlisten:(()=>void)|null=null;private listeners=new Set<()=>void>();private disposed=false;private epoch=0;private reading=false;
 private attempt:{request:PrepareLocalStorePreflight;epoch:number;after:number;previous:LocalStoreIdentity|null;id:LocalStoreIdentity|null;retired:boolean;started:boolean}|null=null;
 private cancelClaim:string|null=null;private failedCancel:string|null=null;private timer:ReturnType<typeof setTimeout>|null=null;
 private readonly source:Source;
 constructor(source:Source){this.source=source;}
 getSnapshot=()=>this.state;
 subscribe=(listener:()=>void)=>{this.listeners.add(listener);return()=>{this.listeners.delete(listener);};};
 private now(){return(this.source.now??(()=>performance.now()))();}
 private update(patch:Partial<LocalStoreState>){this.state=Object.freeze({...this.state,...patch});if(!this.disposed)for(const listener of this.listeners)listener();}
 private clearTimer(){if(this.timer!==null)clearTimeout(this.timer);this.timer=null;}
 syncProject=()=>{const next=localStoreRequest(this.source.project(),this.source.assets());if(!sameOfflineData(next,this.state.request)){this.invalidate();this.update({request:next});}};
 invalidate=()=>{this.epoch++;if(this.attempt)this.attempt.retired=true;this.clearTimer();this.update({acknowledged:false,consentUntil:null,historical:!!this.state.status?.operation});void this.cancelOriginal(false);};
 beforeWorkspaceAction=()=>this.invalidate();selectionIntent=()=>this.invalidate();snapshotIntent=()=>this.invalidate();versionIntent=()=>this.invalidate();
 setSelectionPending=(pending:boolean)=>{if(pending)this.invalidate();else this.syncProject();};
 setVisible=(visible:boolean)=>{if(!visible&&this.attempt&&!this.attempt.started)this.invalidate();};
 beginConnection=()=>{this.invalidate();if(localStoreOwnerReason(this.state)){this.update({blocked:true});return;}this.unlisten?.();this.unlisten=null;this.api=null;this.update({mode:'unavailable',status:null});};
 async connect(api:Port){if(this.disposed||this.api===api)return;if(this.api)this.beginConnection();if(this.api||this.state.blocked)return;this.api=api;this.update({mode:api.mode});if(api.mode!=='native')return;
  try{const unlisten=await api.subscribeLocalStorePreflight(v=>{if(this.api===api)this.receive(v);});if(this.api!==api){unlisten();return;}this.unlisten=unlisten;await this.checkStatus();}catch{this.fail();}}
 private fail(){this.update({blocked:true,unconfirmed:true,error});this.clearTimer();if(this.attempt)this.attempt.retired=true;void this.cancelOriginal(false);}
 private receive(input:unknown){const next=parseLocalStoreStatus(input),old=this.state.status;if(!next){this.fail();return;}
  if(old&&next.statusRevision<old.statusRevision)return;
  if(old&&next.statusRevision===old.statusRevision){if(!sameOfflineData(old,next))this.fail();return;}
  const a=this.attempt,op=next.operation;
  if(a?.id&&active(old)&&!sameId(a.id,op)){this.fail();return;}
  if(a&&!a.id&&next.statusRevision>a.after&&op&&!sameId(a.previous,op)&&sameOfflineData(op.context,{...a.request,platform:'android',operation:'local-store-preflight'}))a.id=identity(op);
  const ours=!!a?.id&&sameId(a.id,op);
  if(ours&&!sameOfflineData(op!.context,{...a!.request,platform:'android',operation:'local-store-preflight'})){this.fail();return;}
  this.update({status:next,unconfirmed:a&&!a.id?this.state.unconfirmed:false,blocked:this.state.blocked||next.availability==='cleanup-unknown'||op?.phase==='unknown',historical:!!a?.retired});
  if(ours&&a!.retired&&active(next))void this.cancelOriginal(false);
  if(ours&&op?.phase==='terminal'){this.clearTimer();this.update({unconfirmed:false,pending:false,acknowledged:false,consentUntil:null});if(this.disposed){this.unlisten?.();this.unlisten=null;}}
 }
 async checkStatus(){if(!this.api||this.api.mode!=='native'||this.reading)return;this.reading=true;try{this.receive(await this.api.localStorePreflightStatus());}catch{this.fail();}finally{this.reading=false;}}
 prepareReason():string|null{if(this.state.mode!=='native')return'Use the installed Mac app; browser preview cannot contact Google Play.';if(localStoreOwnerReason(this.state))return localStoreOwnerReason(this.state);if(!this.state.status||this.state.status.availability!=='available')return'This installed runtime is not ready for the local Store check.';if(!this.state.request)return'Read the saved version, then in Credentials choose This Mac → Android → Store (or Full), select a Google service-account JSON, keep and assign it.';return this.source.otherOperationReason();}
 async prepare(){this.syncProject();if(this.prepareReason()||!this.api||!this.state.request||!this.state.status)return;const api=this.api,request=this.state.request;
  this.attempt={request,epoch:this.epoch,after:this.state.status.statusRevision,previous:this.state.status.operation?identity(this.state.status.operation):null,id:null,retired:false,started:false};const a=this.attempt;
  this.update({pending:true,unconfirmed:true,error:null,historical:false});
  try{this.receive(await api.prepareLocalStorePreflight(request));const op=this.state.status?.operation;
   if(this.attempt!==a||a.retired||a.epoch!==this.epoch||!sameId(a.id,op)||op?.phase!=='awaiting-consent'||!op.intentUsable){if(a.id)void this.cancelOriginal(false);return;}
   const deadline=this.now()+60000;this.update({consentUntil:deadline,acknowledged:false});this.timer=setTimeout(()=>{if(this.attempt===a)this.invalidate();},60000);
  }catch{this.fail();}finally{this.update({pending:false});}}
 acknowledge(value:boolean){if(this.state.consentUntil!==null&&this.now()<this.state.consentUntil)this.update({acknowledged:value});}
 async start(){this.syncProject();const a=this.attempt,api=this.api,op=this.state.status?.operation;
  if(!a||!api||a.retired||a.started||!a.id||a.epoch!==this.epoch||!sameId(a.id,op)||!op?.intentUsable||!this.state.acknowledged||this.state.consentUntil===null||this.now()>=this.state.consentUntil||this.source.otherOperationReason()){this.invalidate();return;}
  a.started=true;this.clearTimer();this.update({pending:true,unconfirmed:true,consentUntil:null,acknowledged:false});
  try{this.receive(await api.startLocalStorePreflight({...a.id,consentVersion:STORE_CONSENT}));}catch{this.fail();}finally{this.update({pending:false});}}
 cancel=()=>this.cancelOriginal(true);
 private async cancelOriginal(explicitRetry:boolean){const api=this.api,id=this.attempt?.id??this.state.status?.operation;if(!api||!id||this.state.status?.operation?.phase==='terminal')return;
  const key=id.operationId+id.ownerGeneration;if(this.cancelClaim===key||!explicitRetry&&this.failedCancel===key)return;this.cancelClaim=key;this.failedCancel=null;this.clearTimer();this.update({acknowledged:false,consentUntil:null});
  try{this.receive(await api.cancelLocalStorePreflight(id.operationId,id.ownerGeneration));}catch{
   // Only a settled failed IPC may be retried explicitly for this original.
   // Retain blocked ownership; status/events must not start an automatic loop.
   if(this.cancelClaim===key){this.failedCancel=key;this.cancelClaim=null;}
   this.update({blocked:true,unconfirmed:true,error});}}
 dispose(){this.invalidate();this.disposed=true;this.listeners.clear();if(!localStoreOwnerReason(this.state)){this.unlisten?.();this.unlisten=null;}}
}
