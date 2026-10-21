import { appleCliId, parseAppleCliAccess, parseAppleCliReview, parseAppleCliStatus, sameAppleCliReview } from './agentAppleProvisioning.ts';
import type { AppleCliAccess, AppleCliPort, AppleCliQuery, AppleCliReview, AppleCliStatus } from './agentAppleProvisioning.ts';
// Comparison callbacks belonging to the SAME Apple controller/Attempt. They
// cannot invoke native Start or reconstruct a returned native Prepared.
export interface AppleCliDelegate {current():boolean;allowReturned():void;observe(status:AppleCliStatus):Promise<void>;unusedReturned():Promise<void>;checkReturned():void;uncertain():void;notSubmitted():Promise<void>}
export interface AppleCliContext {port:AppleCliPort|null;nativeSession:object|null;projectId:string|null;epoch:object;preview:boolean;blockedReason:string|null;review:AppleCliReview|null}
interface Origin {context:AppleCliContext;review:AppleCliReview;nonce:string;delegate:AppleCliDelegate|null;sent:boolean;revoked:boolean;withdrawn:boolean;query:AppleCliQuery|null;status:AppleCliStatus|null}
interface Work {kind:'allow'|'check'|'revoke';context:AppleCliContext;origin:Origin|null;original:Promise<unknown>|null;completion:Promise<void>;finish():void}
export interface AppleCliView {review:AppleCliReview|null;acknowledged:boolean;access:AppleCliAccess|null;status:AppleCliStatus|null;pending:'allow'|'check'|null;revoking:boolean;withdrawn:boolean;revoked:boolean;stale:boolean;unknown:boolean;issue:string|null}
const unavailable={};
const absent=():AppleCliContext=>({port:null,nativeSession:null,projectId:null,epoch:unavailable,preview:false,blockedReason:null,review:null});
const same=(a:AppleCliContext,b:AppleCliContext)=>a.port===b.port&&a.nativeSession===b.nativeSession&&a.projectId===b.projectId&&a.epoch===b.epoch&&a.preview===b.preview;
const querySame=(a:AppleCliQuery,b:AppleCliQuery)=>a.projectId===b.projectId&&a.serviceInstance===b.serviceInstance&&a.requestId===b.requestId;
const uncertain='This original CLI permission or operation is unconfirmed. Keep its IDs; check or revoke it, and do not Submit again.';
function nonce():string{const bytes=new Uint8Array(16);globalThis.crypto.getRandomValues(bytes);const id=[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');if(!appleCliId(id))throw new Error('nonce');return id;}
export class AgentAppleProvisioningController {
  private readonly listeners=new Set<()=>void>();private context=absent();private origin:Origin|null=null;
  private normal:Work|null=null;private revokeWork:Work|null=null;private disposed=false;
  private consent:{context:AppleCliContext;review:AppleCliReview}|null=null;
  private state:AppleCliView=Object.freeze({review:null,acknowledged:false,access:null,status:null,pending:null,revoking:false,withdrawn:false,revoked:false,stale:true,unknown:false,issue:null});
  private readonly source: {current():AppleCliContext;syncOriginal():void;delegate(review:AppleCliReview,nonce:string):AppleCliDelegate|null;nonce?():string};
  constructor(source: AgentAppleProvisioningController['source']){this.source=source;this.syncContext();}
  getSnapshot=()=>this.state;subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
  whenSettled=()=>Promise.all([this.normal?.completion,this.revokeWork?.completion]).then(()=>undefined);
  private read():AppleCliContext{try{const c=this.source.current(),p=c.port;
    if(!c.epoch||typeof c.epoch!=='object'||c.nativeSession!==null&&typeof c.nativeSession!=='object'||typeof c.preview!=='boolean'||c.blockedReason!==null&&typeof c.blockedReason!=='string')return absent();
    return {...c,port:p&&['access','allow','revoke','request'].every(k=>typeof p[k as keyof AppleCliPort]==='function')?p:null,
      projectId:typeof c.projectId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(c.projectId)?c.projectId:null,review:parseAppleCliReview(c.review)};
  }catch{return absent();}}
  private patch(values:Partial<AppleCliView>={}):void{this.state=Object.freeze({...this.state,...values,pending:this.normal?.kind==='allow'?'allow':this.normal?'check':null,revoking:!!this.revokeWork,withdrawn:!!this.origin?.withdrawn,revoked:!!this.origin?.revoked});
    if(!this.disposed)for(const l of [...this.listeners]){try{l();}catch{/* Listener cannot retire a caller. */}}}
  syncContext=():void=>{if(this.disposed)return;const c=this.read();if(!same(c,this.context)||!sameAppleCliReview(c.review,this.context.review))this.consent=null;
    const changed=!same(c,this.context)||!sameAppleCliReview(c.review,this.state.review)&&!(c.review===null&&this.state.review===null);this.context=c;
    if(changed)this.patch({review:c.review,acknowledged:false,stale:this.origin?!same(c,this.origin.context):false});};
  private usable(c:AppleCliContext):string|null{return c.preview?'Unavailable in browser preview.':!c.port||!c.nativeSession?'Use the installed Desktop with ordinary project Read access.':null;}
  ownerReason=():string|null=>this.state.unknown?uncertain:this.normal||this.revokeWork?'An original Apple CLI permission caller is returning.':
    this.origin && (!this.origin.withdrawn || (this.origin.status ? this.origin.status.settlement!=='settled' : this.state.access?.pending))?'The original Apple CLI permission or cleanup remains active.':null;
  consentReason=():string|null=>this.usable(this.context)||this.context.blockedReason||!this.context.review&&'Prepare one Apple step below first, then choose its normal Start or this Advanced delegation.'||
    this.state.unknown&&uncertain||this.normal!==null&&'Wait for the original caller.'||this.revokeWork!==null&&'Wait for Revoke.'||
    this.origin!==null&&!this.origin.withdrawn&&'Withdraw the earlier exact permission before allowing another step.'||null;
  allowReason=():string|null=>this.consentReason()??(!this.consent||!same(this.consent.context,this.context)||!sameAppleCliReview(this.consent.review,this.context.review)?'Confirm this exact prepared Apple step once.':null);
  acknowledge(value:boolean):void{this.syncContext();this.consent=value&&!this.consentReason()&&this.context.review?{context:this.context,review:this.context.review}:null;this.patch({acknowledged:!!this.consent});}
  private controls():AppleCliContext{return this.origin?.context??this.context;}
  checkReason=():string|null=>this.usable(this.controls())??(this.normal?'Wait for the original permission caller.':this.disposed?'Closed.':null);
  revokeReason=():string|null=>this.usable(this.controls())??(!this.origin?'No exact attempted permission is retained.':this.revokeWork?'The original Revoke is returning.':this.disposed?'Closed.':null);
  private begin(kind:Work['kind'],c:AppleCliContext,o:Origin|null):Work{let finish!:()=>void;const completion=new Promise<void>(resolve=>{finish=resolve;});const w:Work={kind,context:c,origin:o,original:null,completion,finish};
    if(kind==='revoke')this.revokeWork=w;else this.normal=w;this.consent=null;this.patch({acknowledged:false});return w;}
  private unknown():void{this.patch({unknown:true,issue:uncertain,stale:true,acknowledged:false});this.consent=null;this.origin?.delegate?.uncertain();}
  private current(w:Work):boolean{return !this.disposed&&same(w.context,this.read())&&(w.kind==='revoke'?this.revokeWork===w:this.normal===w);}
  private async returned(w:Work,send:()=>Promise<unknown>):Promise<unknown>{const p=send();w.original=p;return await p;}
  private finish(w:Work):void{if(this.normal===w)this.normal=null;if(this.revokeWork===w)this.revokeWork=null;
    if(!this.normal&&!this.revokeWork&&this.origin&&!this.origin.sent&&!this.state.unknown)this.origin=null;this.patch();w.finish();}
  private sameAccess(a:AppleCliAccess,o:Origin):boolean{return a.grantId===o.nonce&&sameAppleCliReview(a.review,o.review)&&a.reviewId===o.review.operationId&&
    (!o.query||a.projectId===o.query.projectId&&a.serviceInstance===o.query.serviceInstance&&a.requestId===o.query.requestId);}
  private acceptStatus(s:AppleCliStatus,o:Origin):boolean{
    if(s.grantId!==o.nonce||!sameAppleCliReview(s.review,o.review)||s.reviewId!==o.review.operationId||o.query&&!querySame(o.query,s.origin))return false;
    const old=o.status;if(old&&(s.revision<old.revision||s.revision===old.revision&&JSON.stringify(s)!==JSON.stringify(old)||old.settlement==='settled'&&JSON.stringify(s)!==JSON.stringify(old)))return false;
    o.query=s.origin;o.status=s;return true;
  }
  async allow():Promise<boolean>{this.source.syncOriginal();this.syncContext();if(this.allowReason())return false;const c=this.read(),r=c.review;if(!r)return false;
    let n:string;try{n=(this.source.nonce??nonce)();if(!appleCliId(n))return false;}catch{return false;}
    const o:Origin={context:c,review:r,nonce:n,delegate:null,sent:false,revoked:false,withdrawn:false,query:null,status:null};this.origin=o;
    const w=this.begin('allow',c,o);let sent=false;
    try{
      this.source.syncOriginal();const now=this.read();if(!this.current(w)||o.revoked||now.blockedReason||!sameAppleCliReview(r,now.review))return false;
      o.delegate=this.source.delegate(r,n);if(!o.delegate||!o.delegate.current()||!this.current(w)||o.revoked||this.read().blockedReason)return false;
      sent=true;o.sent=true;const raw=await this.returned(w,()=>c.port!.allow(r,n));
      const a=parseAppleCliAccess(raw);if(!a||!this.sameAccess(a,o)){this.unknown();return true;}
      if(!this.state.unknown && !o.revoked)this.patch({access:a,stale:!this.current(w),unknown:a.unknown,issue:a.unknown?uncertain:null});
      if(a.unknown)this.unknown();
      // This is the actual Allow return, not a native Start return.
      o.delegate.allowReturned();
    }catch{this.unknown();}finally{try{if(!sent&&!this.state.unknown)await o.delegate?.notSubmitted();}catch{this.unknown();}this.finish(w);}return sent;
  }
  async check():Promise<boolean>{this.syncContext();if(this.checkReason())return false;const c=this.controls(),o=this.origin,w=this.begin('check',c,o);
    try{
      if(!c.port)return false;
      // An exact retained request uses its original address, never the latest
      // lease. Coalesced final-A/new-B therefore cannot strand A.
      if(o?.query){
        const raw=await this.returned(w,()=>c.port!.request(o.query!));const s=parseAppleCliStatus(raw);
        if(!s||!this.acceptStatus(s,o)){this.unknown();return true;}
        if(s.state==='unknown'){this.patch({status:s});this.unknown();return true;}
        if(!this.state.unknown){this.patch({status:s,stale:!this.current(w),unknown:false,issue:null});
          await o.delegate?.observe(s);}
      }else{
        const raw=await this.returned(w,()=>c.port!.access());const a=parseAppleCliAccess(raw);
        if(!a||o&&!this.sameAccess(a,o)){this.unknown();return true;}
        if(a.unknown){this.patch({access:a});this.unknown();}
        if(!this.state.unknown)this.patch({access:a,stale:!this.current(w),unknown:a.unknown,issue:a.unknown?uncertain:null});
        if(o&&a.status){if(!this.acceptStatus(a.status,o)){this.unknown();return true;}
          // Separate actual exact-address Query, even when access contained a row.
          const result=await this.returned(w,()=>c.port!.request(o.query!));const s=parseAppleCliStatus(result);
          if(!s||!this.acceptStatus(s,o)){this.unknown();return true;}
        if(s.state==='unknown'){this.patch({status:s});this.unknown();return true;}
          if(!this.state.unknown){this.patch({status:s,unknown:false,issue:null});await o.delegate?.observe(s);}
        }else if(o&&!a.enabled&&!a.pending&&!a.unknown&&!this.state.unknown)await o.delegate?.unusedReturned();
      }
    }catch{this.unknown();}finally{this.finish(w);o?.delegate?.checkReturned();}return true;
  }
  async revoke():Promise<boolean>{if(this.revokeReason())return false;const c=this.controls(),o=this.origin!;o.revoked=true;const w=this.begin('revoke',c,o);
    try{const raw=await this.returned(w,()=>c.port!.revoke(o.nonce));const a=parseAppleCliAccess(raw);
      // No absence/status/countdown is a returned exact-Revoke acknowledgment.
      if(!a||a.enabled||a.grantId!==null&&!this.sameAccess(a,o)){this.unknown();return true;}
      o.withdrawn=true;if(!this.state.unknown)this.patch({access:a,stale:!this.current(w),unknown:a.unknown,issue:a.unknown?uncertain:null});
    }catch{this.unknown();}finally{this.finish(w);}return true;
  }
  dispose():void{if(this.disposed)return;this.disposed=true;this.consent=null;this.listeners.clear();/* Promises/originals remain owned until their real finally. */}
}
