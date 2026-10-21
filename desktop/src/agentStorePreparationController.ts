import {nextStorePermissionRevision} from './agentStorePermissionRevision.ts';
import {parseStorePreparationAccess,parseStorePreparationInput,storePreparationSelection,storePreparationKinds} from './agentStorePreparation.ts';
import type {StorePreparationAccess,StorePreparationInput,StorePreparationPort,PreparationKind,PreparationReview} from './agentStorePreparation.ts';
import {sameOfflineData} from './offlinePreflightProtocol.ts';
export interface PreparationContext {port:StorePreparationPort|null;nativeSession:object|null;epoch:object;projectId:string|null;preview:boolean;input:StorePreparationInput|null;blockedReason:string|null}
export interface PreparationView {selected:PreparationKind;access:StorePreparationAccess|null;input:StorePreparationInput|null;acknowledged:boolean;unknown:boolean;stale:boolean;issue:string|null;pending:'status'|'prepare'|'start'|null;revoking:boolean}
type Work={kind:'status'|'prepare'|'start'|'revoke';context:PreparationContext;generation:object;original:Promise<unknown>|null;completion:Promise<void>;finish():void;at:number|null;before:StorePreparationAccess|null;expectedPermissionRevision:string|null};
const absentEpoch={};
const absent=():PreparationContext=>({port:null,nativeSession:null,epoch:absentEpoch,projectId:null,preview:false,input:null,blockedReason:null});
const same=(a:PreparationContext,b:PreparationContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.epoch===b.epoch&&a.projectId===b.projectId&&a.preview===b.preview&&sameOfflineData(a.input,b.input);
// The separately issued Start grant must still belong to the SAME Prepare
// permission this controller actually received, including before a row exists.
const originalPrepare=(a:StorePreparationAccess)=>[a.status?.prepareGrantId??a.grantId,a.status?.selectionId??a.reviewId] as const;
const sameRow=(a:StorePreparationAccess,b:StorePreparationAccess)=>a.serviceInstance===b.serviceInstance&&a.projectId===b.projectId&&sameOfflineData(a.selection,b.selection)&&originalPrepare(a)[0]===originalPrepare(b)[0]&&originalPrepare(a)[1]===originalPrepare(b)[1]&&(!a.requestId||a.requestId===b.requestId);
const problem='The original Store permission or request is unconfirmed. Keep its IDs; Check or Revoke/Stop only. Do not repeat Prepare or Start.';
const native=(c:PreparationContext)=>c.preview?'CLI preparation is unavailable in preview.':!c.port||!c.nativeSession?'Connect the installed Desktop first.':null;
/** Permission UI only. The existing relay, not this controller, invokes the
 * real native Prepare. No status result is a replacement for an entered call. */
export class StorePreparationController {
 private context=absent();private original:PreparationContext|null=null;private generation:object={};private normal:Work|null=null;private stop:Work|null=null;
 private consent:{context:PreparationContext;revision:string}|null=null;private permission:{context:PreparationContext;revision:string}|null=null;private attempted:StorePreparationInput|null=null;private granted:StorePreparationAccess|null=null;private startedReview:PreparationReview|null=null;
 private observedAt:number|null=null;private disposed=false;private readonly listeners=new Set<()=>void>();
 private state:PreparationView=Object.freeze({selected:'android-access',access:null,input:null,acknowledged:false,unknown:false,stale:true,issue:null,pending:null,revoking:false});
 private readonly source:{current(kind:PreparationKind):PreparationContext;now?():number};
 constructor(source:{current(kind:PreparationKind):PreparationContext;now?():number}){this.source=source;this.syncContext();}
 getSnapshot=()=>this.state;subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
 whenSettled=():Promise<void>=>Promise.all([this.normal?.completion,this.stop?.completion]).then(()=>undefined);
 private read():PreparationContext{try{const c=this.source.current(this.state.selected),p=c.port;
  if(typeof c.preview!=='boolean'||!c.epoch||typeof c.epoch!=='object'||c.nativeSession!==null&&typeof c.nativeSession!=='object'||c.blockedReason!==null&&typeof c.blockedReason!=='string')return absent();
  return {...c,port:p&&['status','allowPrepare','allowStart','revoke'].every(k=>typeof p[k as keyof StorePreparationPort]==='function')?p:null,input:parseStorePreparationInput(c.input)};
 }catch{return absent();}}
 private now():number|null{try{const n=(this.source.now??(()=>performance.now()))();return Number.isFinite(n)&&n>=0?n:null;}catch{return null;}}
 private patch(p:Partial<PreparationView>={}){this.state=Object.freeze({...this.state,...p,pending:this.normal?.kind==='revoke'?null:this.normal?.kind??null,revoking:!!this.stop});if(!this.disposed)for(const l of [...this.listeners]){try{l();}catch{/* listeners cannot retire original calls */}}}
 syncContext(){if(this.disposed)return;const c=this.read(),changed=!same(c,this.context);this.context=c;if(changed){this.consent=null;this.permission=null;this.patch({input:c.input,acknowledged:false,stale:true});}}
 ownerReason=():string|null=>this.state.unknown?problem:this.normal||this.stop?'The original Store permission call is still returning.':this.state.access?.pending?'The same CLI Store preparation is not yet retired by every original owner.':this.state.access?.enabled?'A CLI has unused one-use Store permission. Revoke it before different work.':null;
 peer():{input:StorePreparationInput;review:PreparationReview}|null{
  const a=this.state.access,c=this.original;
  return !this.disposed&&!this.state.unknown&&!this.stop&&this.granted&&c?.input&&a?.status?.phase==='prepared'&&a.status.prepared&&a.status.prepareReturned&&sameRow(this.granted,a)&&same(c,this.context)?{input:c.input,review:a.status.prepared}:null;
 }
 choose(k:PreparationKind):boolean{if(!storePreparationKinds.includes(k)||this.disposed||this.ownerReason())return false;this.consent=null;this.patch({selected:k,acknowledged:false});this.syncContext();return true;}
 private startReady():boolean{const a=this.state.access;return !!a?.status?.prepared&&a.status.phase==='prepared'&&a.status.prepareReturned&&!a.status.startSubmitted&&!a.status.startGrantId;}
 private permissionReason(c:PreparationContext):string|null{return !this.permission||!same(c,this.permission.context)?'Check permission in this Desktop connection before confirming Allow.':nextStorePermissionRevision(this.permission.revision)===null?'Permission cannot be renewed in this Desktop session. Keep the original Stop controls.':null;}
 consentReason():string|null{
  const c=this.read(),a=this.state.access;
  if(this.disposed)return'This controller is retired.';
  if(this.state.unknown)return problem;if(this.normal||this.stop)return'Wait for the original permission reply.';
  if(this.startReady())return native(c)??c.blockedReason??this.permissionReason(c)??(!this.original||!same(this.original,c)||!this.granted||!a||!sameRow(this.granted,a)?'This is not the current returned preparation granted by this controller. Check or stop the original.':sameOfflineData(this.startedReview,a.status?.prepared)?'Start permission was already attempted for this original.':null);
  return this.ownerReason()??native(c)??c.blockedReason??this.permissionReason(c)??(!c.input?'Read saved inputs and assign current credentials for this exact Store step first.':sameOfflineData(c.input,this.attempted)&&a?.status?.settlement!=='settled'?'This selection was already used for a Prepare permission attempt. Check or revoke it.':null);
 }
 allowReason():string|null{return this.consentReason()??(!this.consent||!same(this.consent.context,this.read())||this.consent.revision!==this.permission?.revision?'Confirm this phase and its displayed effects.':null);}
 acknowledge(v:boolean):boolean{this.syncContext();if(typeof v!=='boolean'||this.disposed||this.normal||this.stop||v&&this.consentReason())return false;this.consent=v&&this.permission?{context:this.read(),revision:this.permission.revision}:null;this.patch({acknowledged:!!this.consent});return true;}
 private controls(){return this.original&&(this.ownerReason()||this.state.access?.requestId)?this.original:this.read();}
 statusReason():string|null{return this.disposed?'This controller is retired.':native(this.controls())??(this.normal||this.stop?'Wait for the original caller.':null);}
 revokeReason():string|null{return this.disposed?'This controller is retired.':native(this.controls())??(this.stop?'Revoke/Stop is already returning.':null);}
 remainingSeconds():number|null{const n=this.now();return this.state.stale||!this.state.access?.enabled||n===null||this.observedAt===null||n<this.observedAt?null:Math.max(0,Math.ceil((this.state.access.remainingMs-(n-this.observedAt))/1000));}
 private begin(kind:Work['kind'],c:PreparationContext,expectedPermissionRevision:string|null=null):Work{
  if(kind==='revoke'){this.generation={};this.permission=null;}let finish!:()=>void;const completion=new Promise<void>(r=>{finish=r;});
  const w:Work={kind,context:c,generation:this.generation,original:null,completion,finish,at:this.now(),before:this.state.access,expectedPermissionRevision};
  if(kind==='prepare')this.original=c;if(kind==='revoke')this.stop=w;else this.normal=w;
  this.consent=null;this.patch({acknowledged:false,stale:true});return w;
 }
 private unknown(){this.patch({unknown:true,stale:true,issue:problem,acknowledged:false});this.consent=null;}
 private accept(w:Work,raw:unknown){if(this.disposed||w.generation!==this.generation)return;let a=parseStorePreparationAccess(raw);if(this.disposed||w.generation!==this.generation)return;
  if(!a||['prepare','start'].includes(w.kind)&&(w.expectedPermissionRevision===null||a.permissionRevision!==nextStorePermissionRevision(w.expectedPermissionRevision))||w.kind==='prepare'&&(!w.context.input||!sameOfflineData(a.selection,storePreparationSelection(w.context.input))||a.permission!=='prepare')
   ||w.kind==='start'&&(!w.before?.status?.prepared||a.permission!=='start'||!sameRow(w.before,a)||!sameOfflineData(a.status?.prepared,w.before.status.prepared))||w.kind==='revoke'&&a.enabled){this.unknown();return;}
  const old=this.state.access;
  if(this.permission&&same(this.permission.context,w.context)&&BigInt(a.permissionRevision)<BigInt(this.permission.revision)){this.unknown();return;}
  if(old?.grantId&&(old.pending||old.enabled||old.unknown)&&!sameRow(old,a)){this.unknown();return;}
  if(old?.status&&a.status&&old.requestId===a.requestId&&(old.status.revision>a.status.revision||old.status.revision===a.status.revision&&!sameOfflineData(old.status,a.status))){this.unknown();return;}
  if(old?.grantId===a.grantId&&old?.grantId){
   if(old.permission!==a.permission||old.reviewId!==a.reviewId||old.consumed&&!a.consumed){this.unknown();return;}
   // Same grant countdown is DATA, never a renewal from a delayed reply.
   if(old.enabled&&a.enabled){const now=w.at;if(this.observedAt===null||now===null||now<this.observedAt){this.unknown();return;}const remaining=Math.min(a.remainingMs,Math.max(0,old.remainingMs-(now-this.observedAt)));a=Object.freeze({...a,remainingMs:remaining,enabled:remaining>0});}
  }
  if(this.state.unknown)return;
  if(w.kind==='prepare')this.granted=a;
  const current=same(w.context,this.read());this.permission=current?{context:w.context,revision:a.permissionRevision}:null;
  this.observedAt=w.at;this.patch({access:a,stale:!current,unknown:a.unknown,issue:a.unknown?problem:null});
 }
 private async run(w:Work,send:()=>Promise<unknown>,admit:()=>boolean=()=>true):Promise<boolean>{let sent=false;
  try{if(!admit())return false;sent=true;const p=send();w.original=p;this.accept(w,await p);}
  catch{if(!this.disposed&&w.generation===this.generation)this.unknown();}
  finally{if(this.normal===w)this.normal=null;if(this.stop===w)this.stop=null;this.patch();w.finish();}return sent;
 }
 async allow():Promise<boolean>{this.syncContext();if(this.allowReason())return false;const consent=this.consent,c=this.read();
  if(!consent||this.consent!==consent||!same(consent.context,c)||consent.revision!==this.permission?.revision)return false;
  const start=this.startReady(),s=this.state.access?.status,expected=consent.revision,w=this.begin(start?'start':'prepare',c,expected);
  return this.run(w,()=>{if(start&&s){this.startedReview=s.prepared;return c.port!.allowStart(s,expected);}this.attempted=c.input;return c.port!.allowPrepare(c.input!,expected);},()=>{
   const live=this.read();return !this.disposed&&this.normal===w&&w.generation===this.generation&&!this.stop&&same(c,live)&&this.permission?.revision===expected&&same(this.permission.context,c)&&!live.blockedReason&&(start?!!s?.prepared:!!c.input);
  });
 }
 async status():Promise<boolean>{this.syncContext();if(this.statusReason())return false;const c=this.controls(),w=this.begin('status',c);return this.run(w,()=>c.port!.status());}
 async revoke():Promise<boolean>{if(this.revokeReason())return false;const c=this.controls(),w=this.begin('revoke',c);return this.run(w,()=>c.port!.revoke());}
 dispose(){if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* Keep both original promises and finally; no automatic replay. */}
}
