import { copyToolSetupInput, parseAgentToolSetupAccess, parseToolSetupReview, parseToolSetupStatus, sameToolSetupReview, toolSetupId, TOOL_SETUP_KINDS } from './agentToolSetup.ts';
import type { AgentToolSetupAccess, AgentToolSetupPort, ToolSetupDelegation, ToolSetupKind, ToolSetupReview } from './agentToolSetup.ts';
export interface AgentToolSetupContext { port:AgentToolSetupPort|null; nativeSession:object|null; projectId:string|null; epoch:object; preview:boolean;
  reviews:readonly ToolSetupReview[]; blockedReason:string|null }
interface Source {
  current(kind:ToolSetupKind):AgentToolSetupContext;
  delegate(review:ToolSetupReview):ToolSetupDelegation|null;
  prepareRequirements():Promise<void>; prepareReason():string|null;
  now?():number; nonce?():string;
}
export interface AgentToolSetupView { readonly selected:ToolSetupKind; readonly review:ToolSetupReview|null; readonly access:AgentToolSetupAccess|null;
  readonly acknowledged:boolean; readonly pending:'prepare'|'allow'|'check'|null; readonly revoking:boolean; readonly stale:boolean;
  readonly unknown:boolean; readonly issue:string|null; readonly nativeReadJoined:boolean }
interface Work { readonly kind:'allow'|'check'|'revoke'|'prepare'; readonly context:AgentToolSetupContext; readonly generation:object;
  readonly startedAt:number|null; original:Promise<unknown>|null; readonly completion:Promise<void>; finish():void }
interface Original { context:AgentToolSetupContext; review:ToolSetupReview; consent:string; pin:Omit<ToolSetupDelegation,'input'>|null; released:boolean; sent:boolean }
const absentEpoch={};
const absent=():AgentToolSetupContext=>({port:null,nativeSession:null,projectId:null,epoch:absentEpoch,preview:false,reviews:[],blockedReason:null});
const same=(a:AgentToolSetupContext,b:AgentToolSetupContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.projectId===b.projectId&&a.epoch===b.epoch&&a.preview===b.preview;
const sameGrant=(a:AgentToolSetupAccess,b:AgentToolSetupAccess)=>a.grantId===b.grantId&&a.reviewId===b.reviewId&&a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&sameToolSetupReview(a.review,b.review);
const uncertain='The original tool permission or operation is unconfirmed. Preserve its IDs; check or request Stop, never submit again.';
const nativeReason=(c:AgentToolSetupContext)=>c.preview?'CLI tool setup is unavailable in preview.':!c.port||!c.nativeSession?'Connect the installed Desktop first.':null;
export class AgentToolSetupController {
  private context=absent(); private original:Original|null=null; private normal:Work|null=null; private revokeWork:Work|null=null;
  private generation:object={}; private consent:{context:AgentToolSetupContext;review:ToolSetupReview}|null=null;
  private readonly spent=new Set<string>(); private disposed=false; private notifying=false; private readonly listeners=new Set<()=>void>();
  private observedAt:number|null=null;
  private state:AgentToolSetupView=Object.freeze({selected:'doctor',review:null,access:null,acknowledged:false,pending:null,revoking:false,stale:true,unknown:false,issue:null,nativeReadJoined:false});
  private readonly source:Source;
  constructor(source:Source){this.source=source;this.syncContext();}
  getSnapshot=():AgentToolSetupView=>this.state;
  subscribe=(f:()=>void)=>{this.listeners.add(f);return()=>{this.listeners.delete(f);};};
  whenSettled=():Promise<void>=>Promise.all([this.normal?.completion,this.revokeWork?.completion]).then(()=>undefined);
  private patch(p:Partial<AgentToolSetupView>={}):void{
    this.state=Object.freeze({...this.state,...p,pending:this.normal?.kind==='revoke'?null:this.normal?.kind??null,revoking:!!this.revokeWork});
    if(this.disposed||this.notifying)return;this.notifying=true;
    try{for(const f of [...this.listeners]){try{f();}catch{/* A renderer cannot release native work. */}}}finally{this.notifying=false;}
  }
  private read():AgentToolSetupContext{try{
    const c=this.source.current(this.state.selected);if(!c||typeof c.epoch!=='object'||!c.epoch||typeof c.preview!=='boolean'||
      c.nativeSession!==null&&(!c.nativeSession||typeof c.nativeSession!=='object')||c.blockedReason!==null&&typeof c.blockedReason!=='string'||!Array.isArray(c.reviews)||c.reviews.length>5)return absent();
    const reviews=c.reviews.map(parseToolSetupReview);if(reviews.some(r=>r===null)||new Set(reviews.map(r=>r!.kind)).size!==reviews.length)return absent();
    const port=c.port&&['access','allow','revoke','requestStatus'].every(k=>typeof c.port![k as keyof AgentToolSetupPort]==='function')?c.port:null;
    return {...c,port,reviews:reviews as ToolSetupReview[],projectId:typeof c.projectId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(c.projectId)?c.projectId:null};
  }catch{return absent();}}
  private now():number|null{try{const n=this.source.now?this.source.now():performance.now();return Number.isFinite(n)&&n>=0?n:null;}catch{return null;}}
  private nonce():string|null{try{const value=this.source.nonce?this.source.nonce():Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
    return toolSetupId(value)&&!this.spent.has(value)?value:null;}catch{return null;}}
  syncContext():void{
    if(this.disposed)return;const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected)??null;
    const changed=!same(c,this.context)||!sameToolSetupReview(r,this.state.review);this.context=c;
    if(changed)this.consent=null;
    if(changed)this.patch({review:r,acknowledged:false,stale:this.original?!same(this.original.context,c):true});
  }
  ownerReason=():string|null=>this.state.unknown?uncertain:this.normal||this.revokeWork?'The original tool permission call is still returning.':
    this.state.access?.pending?'The same tool caller, native owner and history writer have not all retired.':
    this.state.access?.enabled?'A local CLI has one-use tool permission. Withdraw it before unrelated work.':
    this.original&&!this.original.released?'Check the original tool request and its native status before another task.':null;
  // Only the fixed Advanced Prepare invokes the existing Tool controller. All
  // peers still observe ownerReason(); this avoids blocking that very caller.
  toolPreparePeerReason():string|null{return this.normal?.kind==='prepare'?null:this.ownerReason();}
  choose(k:ToolSetupKind):boolean{if(!TOOL_SETUP_KINDS.includes(k)||this.disposed||this.ownerReason())return false;this.consent=null;this.patch({selected:k,acknowledged:false});this.syncContext();return true;}
  prepareReason():string|null{try{return this.disposed?'This permission view is retired.':this.ownerReason()??this.source.prepareReason();}catch{return 'Original tool preparation is unavailable.';}}
  consentReason():string|null{const c=this.read(),r=c.reviews.find(v=>v.kind===this.state.selected);return this.disposed?'This permission view is retired.':this.ownerReason()??nativeReason(c)??c.blockedReason??
    (!c.projectId||!r?'Use the original Desktop controls to prepare this exact tool step first.':this.spent.size>=32?'This session has retained 32 permission attempts. Keep their history; do not discard uncertain work to continue.':null);}
  allowReason():string|null{const c=this.read(),r=c.reviews.find(v=>v.kind===this.state.selected)??null;return this.consentReason()??
    (!this.consent||!same(c,this.consent.context)||!sameToolSetupReview(r,this.consent.review)?'Approve only this one tool step and its stated effects.':null);}
  acknowledge(value:boolean):boolean{this.syncContext();if(this.disposed||typeof value!=='boolean'||this.normal||this.revokeWork||value&&this.consentReason())return false;
    const c=this.read(),r=c.reviews.find(v=>v.kind===this.state.selected);this.consent=value&&r?{context:c,review:r}:null;this.patch({acknowledged:!!this.consent});return true;}
  private controls():AgentToolSetupContext{return this.original&&!this.original.released?this.original.context:this.read();}
  checkReason():string|null{return this.disposed?'This permission view is retired.':nativeReason(this.controls())??(this.normal||this.revokeWork?'Wait for the original reply; Stop remains available.':null);}
  revokeReason():string|null{return this.disposed?'This permission view is retired.':nativeReason(this.controls())??(this.revokeWork?'The original Stop request is still returning.':!this.original?'No permission was attempted in this view.':null);}
  remainingSeconds():number|null{const now=this.now();return !this.state.access?.enabled||this.state.stale||this.observedAt===null||now===null||now<this.observedAt?null:Math.max(0,Math.ceil((this.state.access.remainingMs-(now-this.observedAt))/1000));}
  private begin(kind:Work['kind'],context:AgentToolSetupContext):Work{
    if(kind==='revoke')this.generation={};let finish!:()=>void;const completion=new Promise<void>(r=>{finish=r;});
    const w:Work={kind,context,generation:this.generation,startedAt:this.now(),original:null,completion,finish};
    if(kind==='revoke')this.revokeWork=w;else this.normal=w;this.consent=null;this.patch({acknowledged:false,stale:true});return w;
  }
  private finish(w:Work):void{if(this.normal===w)this.normal=null;if(this.revokeWork===w)this.revokeWork=null;this.patch();w.finish();}
  private unknown():void{this.consent=null;this.patch({unknown:true,issue:uncertain,stale:true,acknowledged:false});}
  private current(w:Work):boolean{return !this.disposed&&w.generation===this.generation;}
  private accept(w:Work,raw:unknown):AgentToolSetupAccess|null{
    if(!this.current(w))return null;const a=parseAgentToolSetupAccess(raw);if(!this.current(w))return null;
    const o=this.original,old=this.state.access;
    if(a&&w.kind==='revoke'&&o&&!o.sent){
      // Revoke-before-Allow tombstoned THIS nonce. An older historical lease
      // returned by the shared access view is not adopted as this permission.
      if(!o.pin)o.released=true;
      this.patch({access:null,stale:!same(w.context,this.read())});return null;
    }
    if(!a||w.kind==='revoke'&&a.enabled||o&&a.grantId!==o.consent&&!(w.kind==='revoke'&&a.grantId===null&&!old?.consumed)||
        o&&a.review!==null&&!sameToolSetupReview(a.review,o.review)||w.kind==='allow'&&(!a.grantId||!a.review)) {this.unknown();return null;}
    if(old?.grantId&&o&&old.grantId===o.consent&&a.grantId!==null&&(!sameGrant(old,a)||old.consumed&&(!a.consumed||old.requestId!==a.requestId)||
        old.status&&a.status&&(a.status.revision<old.status.revision||old.status.settlement==='settled'&&JSON.stringify(a.status)!==JSON.stringify(old.status)))){this.unknown();return null;}
    if(this.state.unknown)return null;
    this.observedAt=w.startedAt;this.patch({access:a,stale:!same(w.context,this.read()),unknown:a.unknown,issue:a.unknown?uncertain:null});return a;
  }
  async prepareRequirements():Promise<boolean>{this.syncContext();if(this.prepareReason())return false;const w=this.begin('prepare',this.read());
    try{
      // Publishing pending can synchronously switch the project/API or retire
      // this view. Do not let the underlying owner's fresh capture retarget it.
      const current=()=>this.current(w)&&this.normal===w&&!this.revokeWork&&same(w.context,this.read());
      if(!current()||this.source.prepareReason()!==null||!current())return false;
      const promise=this.source.prepareRequirements();w.original=promise;await promise;
    }catch{if(this.current(w))this.patch({issue:'Read the original tool preparation status. Preparation was not confirmed.'});}
    finally{this.finish(w);this.syncContext();}return true;}
  async allow():Promise<boolean>{this.syncContext();if(this.allowReason())return false;const c=this.read(),r=c.reviews.find(r=>r.kind===this.state.selected)!;
    const nonce=this.nonce();if(!nonce){this.patch({issue:'A fresh one-use permission ID could not be created.'});return false;}
    // Burn once before listeners or native calls. A rejected/lost Allow is never retried.
    this.spent.add(nonce);
    // The nonce is already retained when the first notification can reenter
    // Revoke; never stop a previous grant or miss a pre-Allow withdrawal.
    const original:Original={context:c,review:r,consent:nonce,pin:null,released:true,sent:false};this.original=original;
    const w=this.begin('allow',c);let sent=false;
    try{
      const current=()=>this.current(w)&&this.normal===w&&!this.revokeWork&&same(c,this.read())&&!this.read().blockedReason;
      if(!current()||!sameToolSetupReview(this.read().reviews.find(v=>v.kind===r.kind)??null,r))return false;
      const d=this.source.delegate(r);if(!d)return false;
      // Retain the original pin before any additional serialization or notify.
      // The private draft belongs only to this invocation, not long-lived UI history.
      original.pin={current:d.current,readAfterReturned:d.readAfterReturned};original.released=false;
      const input=copyToolSetupInput(d.input);if(!input||!sameToolSetupReview(input.review,r)||input.projectId!==c.projectId||!d.current()||!current()){
        this.patch({issue:'This original was delegated but Allow was not sent. Request Stop, then check it; no automatic retry.'});return false;}
      this.patch({nativeReadJoined:false});
      if(!current()||!d.current())return false;
      sent=true;original.sent=true;const promise=c.port!.allow(nonce,input);w.original=promise;const raw=await promise;this.accept(w,raw);
    }catch{if(this.current(w)){
      if(sent)this.unknown();
      else this.patch({issue:'Allow was never invoked. Keep the original prepared step; use its Cancel control if needed, then Check here.'});
    }}
    finally{this.finish(w);}return sent;}
  private async observeUnsent(w:Work):Promise<void>{
    const original=this.original;
    if(!original||original.sent||original.released||this.state.unknown||
      (this.normal!==null&&this.normal!==w)||this.revokeWork&&this.revokeWork!==w)return;
    // This is a local never-invoked flag, not absence of a native reply. A
    // delegate may already hold the original UI intent. Only its fresh native
    // read can release it; an awaiting Prepared still needs ordinary Cancel.
    const okay=!original.pin||await original.pin.readAfterReturned(null);
    if(!this.current(w)||this.original!==original||original.sent)return;
    if(okay){original.released=true;this.patch({access:null,nativeReadJoined:!!original.pin,issue:null});}
    else this.patch({issue:'Allow was never invoked. Cancel the original prepared step with its existing Desktop control, then Check here.'});
  }
  private async observeReturned(w:Work,a:AgentToolSetupAccess):Promise<void>{
    const original=this.original;if(!original||!original.pin||original.released||this.state.unknown||a.pending||a.unknown||a.enabled||a.grantId!==original.consent||
      (this.normal!==null&&this.normal!==w)||this.revokeWork&&this.revokeWork!==w)return;
    // Caller responses already returned; the existing controller now makes a
    // genuinely post-return read. Neither an event nor a final child DTO joins it.
    const okay=await original.pin.readAfterReturned(a.status);
    if(!this.current(w)||this.original!==original)return;
    if(!okay){this.patch({issue:'Service retirement was observed, but the original native status has not matched. Keep this request and check again.'});return;}
    original.released=true;this.patch({nativeReadJoined:true,issue:null});
  }
  async check():Promise<boolean>{this.syncContext();if(this.checkReason())return false;const c=this.controls(),w=this.begin('check',c);
    try{
      if(this.original&&!this.original.sent){await this.observeUnsent(w);return true;}
      const old=this.state.access;let raw:unknown;
      if(this.original&&old?.consumed&&old.grantId===this.original.consent&&old.status){
        const promise=c.port!.requestStatus(old.status.origin);w.original=promise;const s=parseToolSetupStatus(await promise);
        if(!s||s.origin.projectId!==old.projectId||s.origin.serviceInstance!==old.serviceInstance||s.origin.requestId!==old.requestId||s.grantId!==old.grantId||s.reviewId!==old.reviewId||!sameToolSetupReview(s.review,old.review)){if(this.current(w))this.unknown();return true;}
        raw={...old,status:s,pending:s.settlement!=='settled',unknown:s.state==='unknown',enabled:false,remainingMs:0};
      }else{const promise=c.port!.access();w.original=promise;raw=await promise;}
      const a=this.accept(w,raw);if(a&&this.current(w))await this.observeReturned(w,a);
    }catch{if(this.current(w))this.unknown();}finally{this.finish(w);this.syncContext();}return true;}
  async revoke():Promise<boolean>{if(this.revokeReason())return false;const o=this.original!,w=this.begin('revoke',o.context);
    try{const promise=o.context.port!.revoke(o.consent);w.original=promise;const a=this.accept(w,await promise);if(this.current(w)){
      if(a)await this.observeReturned(w,a);else if(!o.sent)await this.observeUnsent(w);
    }}
    catch{if(this.current(w))this.unknown();}finally{this.finish(w);}return true;}
  dispose():void{if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* Existing promises/native owners remain; no automatic new calls. */}
}
