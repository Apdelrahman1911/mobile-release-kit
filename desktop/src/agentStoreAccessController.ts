import { nextStorePermissionRevision } from './agentStorePermissionRevision.ts';
import { parseAgentStoreAccess, parseStoreReview, sameStoreReview } from './agentStoreAccess.ts';
import type { AgentStoreAccess, AgentStoreAccessPort, StoreKind, StoreReview } from './agentStoreAccess.ts';
export interface AgentStoreContext { port:AgentStoreAccessPort|null; nativeSession:object|null; projectId:string|null; epoch:object; preview:boolean;
  reviews:readonly StoreReview[]; blockedReason:string|null }
export interface AgentStoreView { readonly access:AgentStoreAccess|null; readonly selected:StoreKind; readonly review:StoreReview|null;
  readonly acknowledged:boolean; readonly stale:boolean; readonly unknown:boolean; readonly issue:string|null; readonly pending:'status'|'allow'|null; readonly revoking:boolean }
interface Work {kind:'status'|'allow'|'revoke';context:AgentStoreContext;review:StoreReview|null;generation:object;original:Promise<unknown>|null;
  completion:Promise<void>;finish():void;startedAt:number|null;expectedPermissionRevision:string|null}
const missing={};
const absent=():AgentStoreContext=>({port:null,nativeSession:null,projectId:null,epoch:missing,preview:false,reviews:[],blockedReason:null});
const uncertain='The original Store permission or request is unconfirmed. Keep its IDs, check status or revoke permission and request Stop. Do not submit again.';
const nativeReason=(c:AgentStoreContext)=>c.preview?'CLI Store delegation is unavailable in preview.':!c.port||!c.nativeSession?'Connect the installed Desktop first.':null;
const same=(a:AgentStoreContext,b:AgentStoreContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.projectId===b.projectId&&a.epoch===b.epoch&&a.preview===b.preview;
const sameGrant=(a:AgentStoreAccess,b:AgentStoreAccess)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.grantId===b.grantId&&a.reviewId===b.reviewId&&sameStoreReview(a.review,b.review);
/** ONE retained permission child shared by all exact Store reviews.
 * No Submit, no automatic status/read/renewal, no native-result -> JS join. */
export class AgentStoreAccessController {
  private context=absent(); private original:AgentStoreContext|null=null; private generation:object={};
  private normal:Work|null=null; private revokeWork:Work|null=null; private disposed=false;
  private consent:{context:AgentStoreContext;review:StoreReview;permissionRevision:string}|null=null;
  private permission:{context:AgentStoreContext;revision:string}|null=null;
  private attempted:StoreReview|null=null; private observedAt:number|null=null;
  private readonly listeners=new Set<()=>void>();
  private readonly source:{current():AgentStoreContext;delegate(review:StoreReview):(()=>boolean)|null;now?():number};
  private state:AgentStoreView=Object.freeze({access:null,selected:'access-check',review:null,acknowledged:false,stale:true,unknown:false,issue:null,pending:null,revoking:false});
  constructor(source:{current():AgentStoreContext;delegate(review:StoreReview):(()=>boolean)|null;now?():number}){this.source=source;this.syncContext();}
  getSnapshot=():AgentStoreView=>this.state;
  subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
  whenSettled=():Promise<void>=>Promise.all([this.normal?.completion,this.revokeWork?.completion]).then(()=>undefined);
  private read():AgentStoreContext {
    try {const c=this.source.current();if(typeof c.preview!=='boolean'||!c.epoch||typeof c.epoch!=='object'||
      c.nativeSession!==null&&typeof c.nativeSession!=='object'||c.blockedReason!==null&&typeof c.blockedReason!=='string'||!Array.isArray(c.reviews)||c.reviews.length>4)return absent();
      const p=c.port,port=p&&['status','allow','revoke'].every(k=>typeof p[k as keyof AgentStoreAccessPort]==='function')?p:null;
      const reviews=c.reviews.map(parseStoreReview).filter((r):r is StoreReview=>r!==null);
      if(new Set(reviews.map(r=>r.kind)).size!==reviews.length)return absent();
      return {...c,port,reviews,projectId:typeof c.projectId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(c.projectId)?c.projectId:null};
    }catch{return absent();}
  }
  private patch(v:Partial<AgentStoreView>={}):void {
    this.state=Object.freeze({...this.state,...v,pending:this.normal?.kind==='allow'?'allow':this.normal?'status':null,revoking:this.revokeWork!==null});
    if(!this.disposed)for(const l of [...this.listeners]){try{l();}catch{/* Rendering cannot free the original. */}}
  }
  syncContext():void {
    if(this.disposed)return;const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected)??null;
    const changed=!same(c,this.context),changedReview=!sameStoreReview(r,this.state.review)&&!(r===null&&this.state.review===null);
    this.context=c;
    if(changed)this.permission=null;
    if(changed||changedReview)this.consent=null;
    if(changed||changedReview)this.patch({review:r,acknowledged:false,...(changed?{stale:true}:{})});
  }
  ownerReason=():string|null=>this.state.unknown?uncertain:this.normal||this.revokeWork?'The original Store permission call is still returning. Check or revoke that original.':
    this.state.access?.pending?'The original delegated Store request is not yet retired by all owners.':this.state.access?.enabled?'A local CLI has one-use permission for this Store review. Revoke it before different work.':null;
  // DATA pin for App's peer check. Only the selected exact original may be
  // excluded; each local controller independently rematches its private Attempt.
  // During delegation the Work keeps this pin after GUI consent disappears.
  peerReview():StoreReview|null {
    if(this.disposed||this.state.unknown||this.revokeWork)return null;
    if(this.normal)return this.normal.kind==='allow'&&this.normal.generation===this.generation?this.normal.review:null;
    return this.ownerReason()?null:this.state.review;
  }
  private controls():AgentStoreContext{return this.ownerReason()&&this.original?this.original:this.read();}
  choose(kind:StoreKind):boolean {
    if(!['access-check','candidate-prepare','execute','reconcile'].includes(kind)||this.disposed||this.ownerReason())return false;
    this.consent=null;this.patch({selected:kind,acknowledged:false});this.syncContext();return true;
  }
  private permissionReason(c:AgentStoreContext):string|null {
    return !this.permission||!same(c,this.permission.context)?'Check permission in this Desktop connection before confirming Allow.':
      nextStorePermissionRevision(this.permission.revision)===null?'Permission cannot be renewed in this Desktop session. Keep the original Stop controls.':null;
  }
  consentReason():string|null {
    const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected);
    return this.disposed?'This permission controller is retired.':this.ownerReason()??nativeReason(c)??c.blockedReason??this.permissionReason(c)??
      (!c.projectId||!r?'Use the original Store panel to review this exact mode in Desktop first.':sameStoreReview(r,this.attempted)?'This review was already used for an Allow attempt. Check or revoke it; never replay.':null);
  }
  allowReason():string|null {const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected)??null;
    return this.consentReason()??(!this.consent||!same(c,this.consent.context)||this.consent.permissionRevision!==this.permission?.revision||!sameStoreReview(r,this.consent.review)?'Confirm permission for this one exact Store review.':null);}
  acknowledge(v:boolean):boolean {this.syncContext();if(typeof v!=='boolean'||this.disposed||this.normal||this.revokeWork||v&&this.consentReason())return false;
    const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected);this.consent=v&&r&&this.permission?{context:c,review:r,permissionRevision:this.permission.revision}:null;this.patch({acknowledged:!!this.consent});return true;}
  statusReason():string|null{return this.disposed?'This permission controller is retired.':nativeReason(this.controls())??(this.normal||this.revokeWork?'Wait for the original permission reply; revoke remains available.':null);}
  revokeReason():string|null{return this.disposed?'This permission controller is retired.':nativeReason(this.controls())??(this.revokeWork?'Revocation and Stop are already requested.':null);}
  private now():number|null{try{const n=this.source.now?this.source.now():performance.now();return Number.isFinite(n)&&n>=0?n:null;}catch{return null;}}
  remainingSeconds():number|null{const now=this.now();return !this.state.access?.enabled||this.state.stale||this.observedAt===null||now===null||now<this.observedAt?null:Math.max(0,Math.ceil((this.state.access.remainingMs-(now-this.observedAt))/1000));}
  private begin(kind:Work['kind'],context:AgentStoreContext,review:StoreReview|null,expectedPermissionRevision:string|null=null):Work {
    if(kind==='revoke'){this.generation={};this.permission=null;} // Fence late Allow BEFORE native call.
    let finish!:()=>void;const completion=new Promise<void>(r=>{finish=r;});
    const w:Work={kind,context,review,generation:this.generation,original:null,completion,finish,startedAt:this.now(),expectedPermissionRevision};
    this.original=context;if(kind==='revoke')this.revokeWork=w;else this.normal=w;
    this.consent=null;this.patch({acknowledged:false,stale:true});return w;
  }
  private unknown():void{this.consent=null;this.patch({unknown:true,stale:true,acknowledged:false,issue:uncertain});}
  private accept(w:Work,raw:unknown):void {
    if(this.disposed||w.generation!==this.generation)return;
    const a=parseAgentStoreAccess(raw);
    if(this.disposed||w.generation!==this.generation)return; // Proxy/copy reentry.
    if(!a||w.kind==='allow'&&(w.expectedPermissionRevision===null||a.permissionRevision!==nextStorePermissionRevision(w.expectedPermissionRevision))||w.kind==='revoke'&&a.enabled||w.kind==='allow'&&(!a.grantId||!sameStoreReview(a.review,w.review))){this.unknown();return;}
    const old=this.state.access;
    if(this.permission&&same(this.permission.context,w.context)&&BigInt(a.permissionRevision)<BigInt(this.permission.revision)){this.unknown();return;}
    if(w.kind!=='allow'&&old?.grantId&&(old.enabled||old.pending||old.unknown)&&!sameGrant(old,a)){this.unknown();return;}
    if(old?.grantId===a.grantId&&old?.grantId&&(!sameGrant(old,a)||old.consumed&&(!a.consumed||old.requestId!==a.requestId)||
      old.status&&a.status&&a.status.revision<old.status.revision)){this.unknown();return;}
    // Unknown never becomes a new lease or completion on a later public read.
    if(this.state.unknown)return;
    const current=same(w.context,this.read());
    this.permission=current?{context:w.context,revision:a.permissionRevision}:null;this.observedAt=w.startedAt;
    this.patch({access:a,stale:!current,unknown:a.unknown,issue:a.unknown?uncertain:null});
  }
  private async run(w:Work,send:()=>Promise<unknown>,admit:()=>boolean=()=>true):Promise<void>{
    try {if(!admit())return;const p=send();w.original=p;const raw=await p;this.accept(w,raw);}
    catch{ // Even an unclassified synchronous throw can follow native handoff.
      if(!this.disposed&&w.generation===this.generation)this.unknown();
    }finally{if(this.normal===w)this.normal=null;if(this.revokeWork===w)this.revokeWork=null;this.patch();w.finish();}
  }
  async status():Promise<boolean>{this.syncContext();if(this.statusReason())return false;const c=this.controls(),w=this.begin('status',c,null);await this.run(w,()=>c.port!.status());return true;}
  async allow():Promise<boolean>{this.syncContext();if(this.allowReason())return false;const consent=this.consent,c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected);
    if(!consent||this.consent!==consent||!r||!same(c,consent.context)||!sameStoreReview(r,consent.review)||consent.permissionRevision!==this.permission?.revision)return false;
    // Pin the ACTUALLY returned revision before begin publishes to listeners.
    const expected=consent.permissionRevision;
    this.attempted=r;const w=this.begin('allow',c,r,expected);let sent=false;
    await this.run(w,()=>{sent=true;return c.port!.allow(r,expected);},()=>{
      const current=()=>{const live=this.read();return !this.disposed&&this.normal===w&&w.generation===this.generation&&!this.revokeWork&&same(c,live)&&this.permission?.revision===expected&&same(this.permission.context,c)&&!live.blockedReason;};
      const live=this.read();if(!current()||!sameStoreReview(live.reviews.find(v=>v.kind===r.kind)??null,r))return false;
      // This removes only the original GUI timer/Start choice. The actual
      // native Prepared/expiry is unchanged; failed or lost Allow cannot undo it.
      const pin=this.source.delegate(r);return !!pin&&pin()&&current();
    });return sent;}
  async revoke():Promise<boolean>{if(this.revokeReason())return false;const c=this.controls(),w=this.begin('revoke',c,null);await this.run(w,()=>c.port!.revoke());return true;}
  dispose():void {if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* Both original promises and finally remain retained, no automatic revoke. */}
}
