import { localHistoryPreparationHeld, sameLocalHistoryOrigin, sameLocalHistoryOriginal, sameLocalHistorySelection } from './agentLocalHistoryPreparation.ts';
import type { LocalHistoryPreparationComparison, LocalHistoryOrigin } from './agentLocalHistoryPreparation.ts';
import { nextStorePermissionRevision } from './agentStorePermissionRevision.ts';
import { parseAgentLocalHistoryAccess, parseLocalHistoryReview, sameLocalHistoryReview } from './agentLocalHistoryProtocol.ts';
import type { AgentLocalHistoryAccess, AgentLocalHistoryPort, LocalHistoryKind, LocalHistoryReview } from './agentLocalHistoryProtocol.ts';
export interface AgentLocalHistoryContext { port:AgentLocalHistoryPort|null; nativeSession:object|null; projectId:string|null; epoch:object; preview:boolean;
  reviews:readonly LocalHistoryReview[]; blockedReason:string|null }
export interface AgentLocalHistoryView { readonly access:AgentLocalHistoryAccess|null; readonly preparation:LocalHistoryPreparationComparison|null; readonly selected:LocalHistoryKind; readonly review:LocalHistoryReview|null;
  readonly acknowledged:boolean; readonly stale:boolean; readonly unknown:boolean; readonly issue:string|null; readonly pending:'status'|'allow'|null; readonly revoking:boolean }
interface Work {kind:'status'|'allow'|'revoke';context:AgentLocalHistoryContext;review:LocalHistoryReview|null;generation:object;original:Promise<unknown>|null;
  completion:Promise<void>;finish():void;startedAt:number|null;expectedPermissionRevision:string|null;query:LocalHistoryOrigin|undefined}
interface HeldPreparation {context:AgentLocalHistoryContext;comparison:LocalHistoryPreparationComparison;until:number|null;firstCheck:number|null}
const missing={};
const absent=():AgentLocalHistoryContext=>({port:null,nativeSession:null,projectId:null,epoch:missing,preview:false,reviews:[],blockedReason:null});
const uncertain='The original local-history permission or request is unconfirmed. Keep its IDs, check status or revoke permission and request Stop. Do not submit again.';
const nativeReason=(c:AgentLocalHistoryContext)=>c.preview?'CLI local history is unavailable in preview.':!c.port||!c.nativeSession?'Connect the installed Desktop first.':null;
const same=(a:AgentLocalHistoryContext,b:AgentLocalHistoryContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.projectId===b.projectId&&a.epoch===b.epoch&&a.preview===b.preview;
const sameGrant=(a:AgentLocalHistoryAccess,b:AgentLocalHistoryAccess)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.grantId===b.grantId&&a.reviewId===b.reviewId&&sameLocalHistoryReview(a.review,b.review);
/** ONE retained permission child shared by all exact local-history reviews.
 * No Submit, no automatic status/read/renewal, no native-result -> JS join. */
export class AgentLocalHistoryController {
  private context=absent(); private original:AgentLocalHistoryContext|null=null; private generation:object={};
  private normal:Work|null=null; private revokeWork:Work|null=null; private disposed=false;
  private consent:{context:AgentLocalHistoryContext;review:LocalHistoryReview;permissionRevision:string;preparation:HeldPreparation|null}|null=null;
  private permission:{context:AgentLocalHistoryContext;revision:string}|null=null;
  private preparation:HeldPreparation|null=null; private attempted:LocalHistoryReview|null=null; private observedAt:number|null=null; private end:number|null=null;
  private readonly listeners=new Set<()=>void>();
  private readonly source:{current():AgentLocalHistoryContext;delegate(review:LocalHistoryReview):(()=>boolean)|null;preparationReason?(review:LocalHistoryReview):string|null;now?():number};
  private state:AgentLocalHistoryView=Object.freeze({access:null,preparation:null,selected:'verify',review:null,acknowledged:false,stale:true,unknown:false,issue:null,pending:null,revoking:false});
  constructor(source:{current():AgentLocalHistoryContext;delegate(review:LocalHistoryReview):(()=>boolean)|null;preparationReason?(review:LocalHistoryReview):string|null;now?():number}){this.source=source;this.syncContext();}
  getSnapshot=():AgentLocalHistoryView=>this.state;
  subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
  whenSettled=():Promise<void>=>Promise.all([this.normal?.completion,this.revokeWork?.completion]).then(()=>undefined);
  private read():AgentLocalHistoryContext {
    try {const c=this.source.current();if(typeof c.preview!=='boolean'||!c.epoch||typeof c.epoch!=='object'||
      c.nativeSession!==null&&typeof c.nativeSession!=='object'||c.blockedReason!==null&&typeof c.blockedReason!=='string'||!Array.isArray(c.reviews)||c.reviews.length>1)return absent();
      const p=c.port,port=p&&['status','allow','revoke'].every(k=>typeof p[k as keyof AgentLocalHistoryPort]==='function')?p:null;
      const reviews=c.reviews.map(parseLocalHistoryReview).filter((r):r is LocalHistoryReview=>r!==null);
      if(new Set(reviews.map(r=>r.kind)).size!==reviews.length)return absent();
      return {...c,port,reviews,projectId:typeof c.projectId==='string'&&/^[A-Za-z0-9_-]{1,64}$(?![\s\S])/.test(c.projectId)?c.projectId:null};
    }catch{return absent();}
  }
  private patch(v:Partial<AgentLocalHistoryView>={}):void {
    this.state=Object.freeze({...this.state,...v,preparation:this.preparation?.comparison??null,pending:this.normal?.kind==='allow'?'allow':this.normal?'status':null,revoking:this.revokeWork!==null});
    if(!this.disposed)for(const l of [...this.listeners]){try{l();}catch{/* Rendering cannot free the original. */}}
  }
  syncContext():void {
    if(this.disposed)return;const c=this.read(),r=this.selectedReview(c);
    const changed=!same(c,this.context),changedReview=!sameLocalHistoryReview(r,this.state.review)&&!(r===null&&this.state.review===null);
    this.context=c;
    if(changed)this.permission=null;
    if(changed||changedReview)this.consent=null;
    if(changed||changedReview)this.patch({review:r,selected:r?.kind??this.state.selected,acknowledged:false,...(changed?{stale:true}:{})});
  }
  private selectedReview(c:AgentLocalHistoryContext):LocalHistoryReview|null {
    const p=this.preparation;
    return c.reviews[0]??(p&&same(c,p.context)&&p.comparison.runtimeProjectId===c.projectId?p.comparison.live:null);
  }
  private baseOwnerReason():string|null{return this.state.unknown?uncertain:this.normal||this.revokeWork?'The original local-history permission call is still returning. Check or revoke that original.':
    this.state.access?.pending?'The original delegated local-history request is not yet retired by all owners.':this.state.access?.enabled?'A local CLI has one-use permission for this local-history review. Revoke it before different work.':null;}
  ownerReason=():string|null=>this.baseOwnerReason()??(this.preparation&&localHistoryPreparationHeld(this.preparation.comparison)?'A CLI-proposed history intent is retained. Check this original, then separately approve Start or revoke it.':null);
  private preparationReason(c:AgentLocalHistoryContext,r:LocalHistoryReview):string|null {
    const p=this.preparation,now=this.now();
    if(!p||!same(p.context,c)||p.comparison.runtimeProjectId!==c.projectId||p.comparison.request.phase!=='prepared'||!sameLocalHistoryReview(p.comparison.live,r))return 'Check this exact CLI-proposed history intent in its original Desktop/project first.';
    if(p.until===null||p.firstCheck===null||now===null||now<p.firstCheck||now>=p.until)return 'This original comparison window expired. Revoke it; another Check cannot renew approval.';
    return this.source.preparationReason?.(r)??null;
  }
  // DATA pin for App's peer check. Only the selected exact original may be
  // excluded; each local controller independently rematches its private Attempt.
  // During delegation the Work keeps this pin after GUI consent disappears.
  peerReview():LocalHistoryReview|null {
    if(this.disposed||this.state.unknown||this.revokeWork)return null;
    if(this.normal)return this.normal.kind==='allow'&&this.normal.generation===this.generation?this.normal.review:null;
    return this.ownerReason()?null:this.state.review;
  }
  private controls():AgentLocalHistoryContext{return this.ownerReason()&&this.original?this.original:this.read();}
  private permissionReason(c:AgentLocalHistoryContext):string|null {
    return !this.permission||!same(c,this.permission.context)?'Check permission in this Desktop connection before confirming Allow.':
      nextStorePermissionRevision(this.permission.revision)===null?'Permission cannot be renewed in this Desktop session. Keep the original Stop controls.':null;
  }
  consentReason():string|null {
    const c=this.read(),r=this.selectedReview(c),gui=c.reviews[0]??null;
    return this.disposed?'This permission controller is retired.':this.baseOwnerReason()??nativeReason(c)??c.blockedReason??this.permissionReason(c)??
      (!c.projectId||!r?'Prepare this mode in Release History or request local-history-prepare, then explicitly Check it here.':
       sameLocalHistoryOriginal(r,this.attempted)?'This original review was already used for an Allow attempt. Check or revoke it; never replay.':
       gui?(this.preparation&&localHistoryPreparationHeld(this.preparation.comparison)?'A different CLI preparation is retained. Check or revoke that original.':null):this.preparationReason(c,r));
  }
  allowReason():string|null {const c=this.read(),r=this.selectedReview(c);
    return this.consentReason()??(!this.consent||!same(c,this.consent.context)||this.consent.permissionRevision!==this.permission?.revision||!sameLocalHistoryReview(r,this.consent.review)||this.consent.preparation!==(!c.reviews.length?this.preparation:null)?'Confirm permission for this one exact local-history review.':null);}
  acknowledge(v:boolean):boolean {this.syncContext();if(typeof v!=='boolean'||this.disposed||this.normal||this.revokeWork||v&&this.consentReason())return false;
    const c=this.read(),r=this.selectedReview(c);this.consent=v&&r&&this.permission?{context:c,review:r,permissionRevision:this.permission.revision,preparation:c.reviews.length?null:this.preparation}:null;this.patch({acknowledged:!!this.consent});return true;}
  statusReason():string|null{return this.disposed?'This permission controller is retired.':nativeReason(this.controls())??(this.normal||this.revokeWork?'Wait for the original permission reply; revoke remains available.':null);}
  revokeReason():string|null{return this.disposed?'This permission controller is retired.':nativeReason(this.controls())??(this.revokeWork?'Revocation and Stop are already requested.':null);}
  private now():number|null{try{const n=this.source.now?this.source.now():performance.now();return Number.isFinite(n)&&n>=0?n:null;}catch{return null;}}
  remainingSeconds():number|null{const now=this.now();return !this.state.access?.enabled||this.state.stale||this.observedAt===null||now===null||now<this.observedAt?null:Math.max(0,Math.ceil(((this.end??this.observedAt)-now)/1000));}
  private begin(kind:Work['kind'],context:AgentLocalHistoryContext,review:LocalHistoryReview|null,expectedPermissionRevision:string|null=null,query:LocalHistoryOrigin|undefined=undefined):Work {
    if(kind==='revoke'){this.generation={};this.permission=null;} // Fence late Allow BEFORE native call.
    let finish!:()=>void;const completion=new Promise<void>(r=>{finish=r;});
    const w:Work={kind,context,review,generation:this.generation,original:null,completion,finish,startedAt:this.now(),expectedPermissionRevision,query};
    this.original=context;if(kind==='revoke')this.revokeWork=w;else this.normal=w;
    this.consent=null;this.patch({acknowledged:false,stale:true});return w;
  }
  private unknown():void{this.consent=null;this.patch({unknown:true,stale:true,acknowledged:false,issue:uncertain});}
  private acceptPreparation(w:Work,a:AgentLocalHistoryAccess):boolean {
    if(w.kind!=='status')return true;
    const next=a.preparation,old=this.preparation;
    if(w.query&&(!next||!sameLocalHistoryOrigin(w.query,next.request.origin)))return false;
    if(!next){if(old&&localHistoryPreparationHeld(old.comparison))return false;return true;}
    const sameOriginal=!!old&&sameLocalHistoryOrigin(old.comparison.request.origin,next.request.origin);
    if(old&&localHistoryPreparationHeld(old.comparison)&&!sameOriginal)return false;
    if(sameOriginal&&old){
      const before=old.comparison.request,after=next.request;
      if(old.comparison.runtimeProjectId!==next.runtimeProjectId||!sameLocalHistorySelection(before.selection,after.selection)||after.revision<before.revision||before.review&&(!after.review||!sameLocalHistoryOriginal(before.review,after.review)||after.review.statusRevision<before.review.statusRevision)||before.phase==='handed-off'&&after.phase!=='handed-off'||['refused','cancelled','expired'].includes(before.phase)&&after.phase!==before.phase||old.comparison.live&&next.live&&next.live.statusRevision<old.comparison.live.statusRevision)return false;
    }
    const usable=next.request.phase==='prepared'&&next.live!==null;
    const start=sameOriginal&&old!.firstCheck!==null?old!.firstCheck:usable?w.startedAt:null;
    // The first actual Check start, original native remainder, and every prior
    // observed ceiling. A delayed reply or a later Check can never renew it.
    const candidate=!usable||w.startedAt===null?null:w.startedAt+Math.min(60000,next.request.remainingMs);
    const ceiling=start===null||candidate===null?null:Math.min(start+60000,candidate);
    const until=sameOriginal&&old!.until!==null?(ceiling===null?old!.until:Math.min(old!.until,ceiling)):ceiling;
    this.preparation={context:w.context,comparison:next,firstCheck:start,until};
    return next.request.phase!=='unknown';
  }
  private accept(w:Work,raw:unknown):void {
    if(this.disposed||w.generation!==this.generation)return;
    const a=parseAgentLocalHistoryAccess(raw);
    if(this.disposed||w.generation!==this.generation)return; // Proxy/copy reentry.
    if(!a||w.kind==='allow'&&(w.expectedPermissionRevision===null||a.permissionRevision!==nextStorePermissionRevision(w.expectedPermissionRevision))||w.kind==='revoke'&&a.enabled||w.kind==='allow'&&(!a.grantId||!sameLocalHistoryReview(a.review,w.review))){this.unknown();return;}
    const old=this.state.access;
    if(this.permission&&same(this.permission.context,w.context)&&BigInt(a.permissionRevision)<BigInt(this.permission.revision)){this.unknown();return;}
    if(w.kind!=='allow'&&old?.grantId&&(old.enabled||old.pending||old.unknown)&&!sameGrant(old,a)){this.unknown();return;}
    if(old?.grantId===a.grantId&&old?.grantId&&(!sameGrant(old,a)||old.consumed&&(!a.consumed||old.requestId!==a.requestId)||
      old.status&&a.status&&a.status.revision<old.status.revision)){this.unknown();return;}
    // Unknown never becomes a new lease or completion on a later public read.
    if(this.state.unknown)return;
    if(!this.acceptPreparation(w,a)){this.unknown();return;}
    const current=same(w.context,this.read());
    this.permission=current?{context:w.context,revision:a.permissionRevision}:null;
    const candidateEnd=w.startedAt===null?null:w.startedAt+a.remainingMs;
    const existing=!!old?.grantId&&sameGrant(old,a);
    this.end=candidateEnd===null?null:existing&&this.end!==null?Math.min(this.end,candidateEnd):candidateEnd;
    this.observedAt=existing?this.observedAt:w.startedAt;
    this.consent=null;this.patch({access:a,review:this.selectedReview(this.read()),acknowledged:false,stale:!current,unknown:a.unknown,issue:a.unknown?uncertain:null});
  }
  private async run(w:Work,send:()=>Promise<unknown>,admit:()=>boolean=()=>true):Promise<void>{
    try {if(!admit())return;const p=send();w.original=p;const raw=await p;this.accept(w,raw);}
    catch{ // Even an unclassified synchronous throw can follow native handoff.
      if(!this.disposed&&w.generation===this.generation)this.unknown();
    }finally{if(this.normal===w)this.normal=null;if(this.revokeWork===w)this.revokeWork=null;this.patch();w.finish();}
  }
  async status():Promise<boolean>{this.syncContext();if(this.statusReason())return false;const c=this.controls(),query=this.preparation&&localHistoryPreparationHeld(this.preparation.comparison)?this.preparation.comparison.request.origin:undefined,w=this.begin('status',c,null,null,query);
    await this.run(w,()=>c.port!.status(query));return true;}
  async allow():Promise<boolean>{this.syncContext();if(this.allowReason())return false;const consent=this.consent,c=this.read(),r=this.selectedReview(c);
    if(!consent||this.consent!==consent||!r||!same(c,consent.context)||!sameLocalHistoryReview(r,consent.review)||consent.permissionRevision!==this.permission?.revision)return false;
    // Pin the ACTUALLY returned revision and native preparation comparison
    // before Work publication; neither is recomputed from a later response.
    const expected=consent.permissionRevision,preparation=consent.preparation;
    this.attempted=r;const w=this.begin('allow',c,r,expected);let sent=false;
    await this.run(w,()=>{sent=true;return c.port!.allow(r,expected,preparation?.comparison.request.origin);},()=>{
      const current=()=>{const live=this.read();return !this.disposed&&this.normal===w&&w.generation===this.generation&&!this.revokeWork&&same(c,live)&&this.permission?.revision===expected&&same(this.permission.context,c)&&!live.blockedReason;};
      const live=this.read();if(!current()||!sameLocalHistoryReview(this.selectedReview(live),r))return false;
      if(preparation){return this.preparation===preparation&&!live.reviews.length&&!this.preparationReason(live,r)&&current()&&this.preparation===preparation;}
      // Ordinary GUI Prepare alone has this Attempt-owned one-use handoff.
      // A CLI comparison never constructs or pretends to join such an Attempt.
      const pin=this.source.delegate(r);return !!pin&&pin()&&current();
    });return sent;}
  async revoke():Promise<boolean>{if(this.revokeReason())return false;const c=this.controls(),w=this.begin('revoke',c,null);await this.run(w,()=>c.port!.revoke());return true;}
  dispose():void {if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* Both original promises and finally remain retained, no automatic revoke. */}
}
