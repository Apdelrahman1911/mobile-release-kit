import { GITHUB_ACTION_KINDS, parseAgentGithubActionAccess, parseGithubActionSelection, parseGithubActionStatus, sameGithubActionReview, sameGithubActionSelection } from './agentGithubActionAccess.ts';
import type { AgentGithubActionAccess, AgentGithubActionPort, GithubActionDelegate, GithubActionKind, GithubActionQuery, GithubActionReview, GithubActionSelection, GithubActionStatus } from './agentGithubActionAccess.ts';
export interface AgentGithubActionContext {port:AgentGithubActionPort|null;nativeSession:object|null;projectId:string|null;epoch:object;preview:boolean;blockedReason:string|null;reviews:readonly GithubActionSelection[]}
interface Origin {permissionRevision:string;context:AgentGithubActionContext;selection:GithubActionSelection;delegate:GithubActionDelegate|null;sent:boolean;revoked:boolean;withdrawn:boolean;grant:{id:string;project:string;instance:string;review:GithubActionReview}|null;query:GithubActionQuery|null;status:GithubActionStatus|null}
interface Work {expectedPermissionRevision:string|null;kind:'allow'|'check'|'revoke';context:AgentGithubActionContext;origin:Origin|null;original:Promise<unknown>|null;completion:Promise<void>;finish():void}
export interface AgentGithubActionView {selected:GithubActionKind;review:GithubActionSelection|null;acknowledged:boolean;access:AgentGithubActionAccess|null;status:GithubActionStatus|null;pending:'allow'|'check'|null;revoking:boolean;withdrawn:boolean;stale:boolean;unknown:boolean;issue:string|null}
const missing={};
const absent=():AgentGithubActionContext=>({port:null,nativeSession:null,projectId:null,epoch:missing,preview:false,blockedReason:null,reviews:[]});
const same=(a:AgentGithubActionContext,b:AgentGithubActionContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.projectId===b.projectId&&a.epoch===b.epoch&&a.preview===b.preview;
const querySame=(a:GithubActionQuery,b:GithubActionQuery)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.requestId===b.requestId;
const uncertain='The original GitHub permission or request is unconfirmed. Keep its IDs, Check or Revoke/Stop it, and do not Submit again.';
/** ONE retained controller across three existing panels. No Submit, timer,
 * automatic read/retry, native Start or public-status-derived permission. */
export class AgentGithubActionAccessController {
  private context=absent();private origin:Origin|null=null;private normal:Work|null=null;private revokeWork:Work|null=null;private disposed=false;
  private consent:{context:AgentGithubActionContext;selection:GithubActionSelection;revision:string}|null=null;
  private accessWitness:{context:AgentGithubActionContext;revision:string}|null=null;
  private readonly listeners=new Set<()=>void>();
  private state:AgentGithubActionView=Object.freeze({selected:'repository-create',review:null,acknowledged:false,access:null,status:null,pending:null,revoking:false,withdrawn:false,stale:true,unknown:false,issue:null});
  private readonly source:{current():AgentGithubActionContext;syncOriginal():void;delegate(selection:GithubActionSelection):GithubActionDelegate|null};
  constructor(source:{current():AgentGithubActionContext;syncOriginal():void;delegate(selection:GithubActionSelection):GithubActionDelegate|null}){this.source=source;this.syncContext();}
  getSnapshot=()=>this.state;
  subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
  whenSettled=()=>Promise.all([this.normal?.completion,this.revokeWork?.completion]).then(()=>undefined);
  private read():AgentGithubActionContext {
    try{const c=this.source.current(),p=c.port;
      if(!c.epoch||typeof c.epoch!=='object'||c.nativeSession!==null&&typeof c.nativeSession!=='object'||typeof c.preview!=='boolean'||c.blockedReason!==null&&typeof c.blockedReason!=='string'||!Array.isArray(c.reviews)||c.reviews.length>6)return absent();
      const reviews=c.reviews.map(parseGithubActionSelection).filter((r):r is GithubActionSelection=>r!==null);
      if(new Set(reviews.map(r=>r.kind)).size!==reviews.length)return absent();
      return {...c,port:p&&['access','allow','request','revoke'].every(k=>typeof p[k as keyof AgentGithubActionPort]==='function')?p:null,
        projectId:typeof c.projectId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(c.projectId)?c.projectId:null,reviews};
    }catch{return absent();}
  }
  private patch(v:Partial<AgentGithubActionView>={}):void {
    this.state=Object.freeze({...this.state,...v,pending:this.normal?.kind==='allow'?'allow':this.normal?'check':null,revoking:!!this.revokeWork,withdrawn:!!this.origin?.withdrawn});
    if(!this.disposed)for(const l of [...this.listeners]){try{l();}catch{/* No callback can abandon an original call. */}}
  }
  syncContext=():void=>{
    if(this.disposed)return;const c=this.read(),r=c.reviews.find(x=>x.kind===this.state.selected)??null;
    const changed=!same(c,this.context)||!sameGithubActionSelection(r,this.state.review)&&!(r===null&&this.state.review===null);
    if(!same(c,this.context))this.accessWitness=null;this.context=c;if(changed){this.consent=null;this.patch({review:r,acknowledged:false,stale:this.origin?!same(c,this.origin.context):true});}
  };
  private usable(c:AgentGithubActionContext):string|null{return c.preview?'Unavailable in preview.':!c.port||!c.nativeSession?'Use the installed Desktop with the original project READ permission.':null;}
  ownerReason=():string|null=>this.state.unknown?uncertain:this.normal||this.revokeWork?'An original GitHub permission caller is returning.':
    this.origin&&(!this.origin.withdrawn||!this.origin.delegate?.released())?'The original GitHub CLI permission or operation is retained. Check, revoke and finish its original controls.':
    !this.origin&&(this.state.access?.pending||this.state.access?.enabled)?'An existing GitHub permission or request is still retained.':null;
  peerSelection():GithubActionSelection|null {
    if(this.disposed||this.state.unknown||this.revokeWork)return null;
    return this.normal?.kind==='allow'?this.normal.origin?.selection??null:this.ownerReason()?null:this.state.review;
  }
  choose(kind:GithubActionKind):boolean {if(this.disposed||!GITHUB_ACTION_KINDS.includes(kind)||this.ownerReason())return false;this.consent=null;this.patch({selected:kind,acknowledged:false});this.syncContext();return true;}
  consentReason():string|null {
    const c=this.read(),r=c.reviews.find(x=>x.kind===this.state.selected);
    return this.disposed?'This controller is closed.':this.ownerReason()??this.usable(c)??c.blockedReason??(!c.projectId||!r?'Use the original action panel to finish its exact Review, or connect Activity, first.':null)??(!this.accessWitness||!same(c,this.accessWitness.context)?'Check the original CLI permission before confirming Allow.':this.accessWitness.revision==='18446744073709551615'?'The original permission revision is exhausted. Check and Stop remain available.':null);
  }
  allowReason():string|null {const c=this.read(),r=c.reviews.find(x=>x.kind===this.state.selected)??null;return this.consentReason()??
    (!this.consent||!same(c,this.consent.context)||!sameGithubActionSelection(r,this.consent.selection)||this.accessWitness?.revision!==this.consent.revision?'Confirm one local CLI submission of this exact reviewed action or GET-only reconciliation.':null);}
  acknowledge(value:boolean):boolean {this.syncContext();if(typeof value!=='boolean'||this.disposed||this.normal||this.revokeWork||value&&this.consentReason())return false;
    const c=this.read(),r=c.reviews.find(x=>x.kind===this.state.selected);this.consent=value&&r&&this.accessWitness?{context:c,selection:r,revision:this.accessWitness.revision}:null;this.patch({acknowledged:!!this.consent});return true;}
  private controls():AgentGithubActionContext{return this.origin?.context??this.context;}
  checkReason():string|null{return this.disposed?'Closed.':this.usable(this.controls())??(this.normal||this.revokeWork?'Wait for the original permission caller.':null);}
  revokeReason():string|null{return this.disposed?'Closed.':this.usable(this.controls())??(this.revokeWork?'The original Revoke is returning.':!this.origin&&!this.state.access?.grantId?'No original permission is observed.':null);}
  private begin(kind:Work['kind'],c:AgentGithubActionContext,o:Origin|null):Work {let finish!:()=>void;const completion=new Promise<void>(r=>{finish=r;});
    const w:Work={kind,context:c,origin:o,expectedPermissionRevision:kind==='allow'?o?.permissionRevision??null:null,original:null,completion,finish};if(kind==='revoke')this.revokeWork=w;else this.normal=w;this.consent=null;this.patch({acknowledged:false});return w;}
  private finish(w:Work):void {if(this.normal===w)this.normal=null;if(this.revokeWork===w)this.revokeWork=null;this.patch();w.finish();}
  private unknown():void {this.consent=null;this.patch({unknown:true,issue:uncertain,stale:true,acknowledged:false});this.origin?.delegate?.uncertain();}
  private current(w:Work):boolean{return !this.disposed&&same(w.context,this.read())&&(w.kind==='revoke'?this.revokeWork===w:this.normal===w);}
  private async returned(w:Work,send:()=>Promise<unknown>):Promise<unknown> {const p=send();w.original=p;if(!(p instanceof Promise))throw new Error('No original permission promise');return await p;}
  private acceptAccess(a:AgentGithubActionAccess,o:Origin):boolean {
    if(!a.grantId||!a.projectId||!a.serviceInstance||!a.review||!sameGithubActionSelection(a.review,o.selection))return false;
    const g=o.grant;if(g&&(g.id!==a.grantId||g.project!==a.projectId||g.instance!==a.serviceInstance||!sameGithubActionReview(g.review,a.review)))return false;
    if(o.query&&(!a.status||!querySame(a.status.origin,o.query)))return false;
    o.grant??={id:a.grantId,project:a.projectId,instance:a.serviceInstance,review:a.review};
    return !a.status||this.acceptStatus(a.status,o);
  }
  private acceptStatus(s:GithubActionStatus,o:Origin):boolean {
    const g=o.grant;if(!g||s.grantId!==g.id||s.origin.projectId!==g.project||s.origin.serviceInstance!==g.instance||!sameGithubActionReview(s.review,g.review)||o.query&&!querySame(o.query,s.origin))return false;
    const old=o.status;if(old&&(s.revision<old.revision||s.revision===old.revision&&JSON.stringify(s)!==JSON.stringify(old)||old.settlement==='settled'&&JSON.stringify(s)!==JSON.stringify(old)))return false;
    o.query=s.origin;o.status=s;return true;
  }
  async allow():Promise<boolean> {
    this.source.syncOriginal();this.syncContext();if(this.allowReason())return false;const c=this.read(),r=c.reviews.find(x=>x.kind===this.state.selected);if(!r||!this.consent)return false;const revision=this.consent.revision;
    const o:Origin={permissionRevision:revision,context:c,selection:r,delegate:null,sent:false,revoked:false,withdrawn:false,grant:null,query:null,status:null};this.origin=o;
    this.accessWitness=null;const w=this.begin('allow',c,o);this.patch({access:null,status:null,stale:true});let sent=false;
    try{
      this.source.syncOriginal();const live=this.read();if(!this.current(w)||o.revoked||live.blockedReason||!sameGithubActionSelection(r,live.reviews.find(x=>x.kind===r.kind)??null))return false;
      o.delegate=this.source.delegate(r);
      if(!o.delegate||!o.delegate.current()||!this.current(w)||o.revoked||this.read().blockedReason)return false;
      sent=true;o.sent=true;const raw=await this.returned(w,()=>c.port!.allow(r,w.expectedPermissionRevision!));const a=parseAgentGithubActionAccess(raw);
      if(!a||BigInt(a.permissionRevision)!==BigInt(o.permissionRevision)+1n||!this.acceptAccess(a,o)){this.unknown();return true;}
      if(a.unknown){this.unknown();return true;}
      o.delegate.allowReturned(); // genuine Allow caller only, never a native Start.
      if(!this.state.unknown&&!o.revoked)this.patch({access:a,status:o.status,stale:!this.current(w),issue:null});
    }catch{this.unknown();}finally{
      try{if(!sent&&!this.state.unknown){o.withdrawn=true;o.delegate?.notSubmitted();if(!o.delegate)this.origin=null;}}catch{this.unknown();}
      this.finish(w);
    }
    return sent;
  }
  async check():Promise<boolean> {
    this.syncContext();if(this.checkReason())return false;
    // Only the already-returned old delegate can release this controller for a
    // NEW Access observation. A copied latest status cannot replace its caller.
    if(!this.state.unknown&&this.origin?.withdrawn&&this.origin.delegate?.released())this.origin=null;
    const c=this.controls(),o=this.origin,w=this.begin('check',c,o);
    try{
      if(o?.query){
        const s=parseGithubActionStatus(await this.returned(w,()=>c.port!.request(o.query!)));
        if(!s||!this.acceptStatus(s,o)){this.unknown();return true;}
        if(!this.state.unknown)this.patch({status:s,stale:!this.current(w),issue:null});
        if(s.settlement==='unknown')this.unknown();else if(!this.state.unknown)o.delegate?.observe(s);
      }else{
        const a=parseAgentGithubActionAccess(await this.returned(w,()=>c.port!.access()));
        if(!a||o&&!this.acceptAccess(a,o)){this.unknown();return true;}
        if(!o&&this.current(w)&&!this.revokeWork&&!this.state.unknown){
          if(this.accessWitness&&same(this.accessWitness.context,c)&&BigInt(a.permissionRevision)<BigInt(this.accessWitness.revision)){this.unknown();return true;}
          this.accessWitness={context:c,revision:a.permissionRevision};
        }
        if(!this.state.unknown)this.patch({access:a,status:o?.status??a.status,stale:!this.current(w),issue:null});
        if(a.unknown){this.unknown();return true;}
        if(o&&a.status){
          // Exact retained Query, never a later lease. A final A coalesced with
          // queued B cannot strand A or let B impersonate its completion.
          const s=parseGithubActionStatus(await this.returned(w,()=>c.port!.request(o.query!)));
          if(!s||!this.acceptStatus(s,o)){this.unknown();return true;}
          if(!this.state.unknown)this.patch({status:s,issue:null});
          if(s.settlement==='unknown')this.unknown();else if(!this.state.unknown)o.delegate?.observe(s);
        }else if(o&&!a.enabled&&!a.pending&&!this.state.unknown)o.delegate?.unusedReturned();
      }
    }catch{this.unknown();}finally{this.finish(w);}return true;
  }
  async revoke():Promise<boolean> {
    if(this.revokeReason())return false;const c=this.controls(),o=this.origin;
    this.accessWitness=null;if(o)o.revoked=true; // latch before publishing listeners or entering raw {} Revoke.
    const w=this.begin('revoke',c,o);
    try{
      const a=parseAgentGithubActionAccess(await this.returned(w,()=>c.port!.revoke()));
      if(!a||a.enabled||o&&a.grantId!==null&&!this.acceptAccess(a,o)){this.unknown();return true;}
      if(o)o.withdrawn=true;
      if(a.unknown){this.unknown();return true;}
      if(!this.state.unknown)this.patch({access:a,status:o?.status??a.status,stale:!this.current(w),issue:null});
      // A separate Check samples the same native original. Revoke returning
      // alone never clears the controller's retained delegation or Unknown.
    }catch{this.unknown();}finally{this.finish(w);}return true;
  }
  dispose():void {if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* all caller closures stay retained; no fresh revoke/port */}
}
