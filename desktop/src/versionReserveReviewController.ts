//! Bounded read metadata child. Native Review stays on VersionReserveController
//! and its actual MAIN promise; metadata never constructs a private review.
import { parseReserveReviewStatus, sameReviewOrigin } from './versionReserveReview.ts';
import type { ReserveReviewOrigin, ReserveReviewPort, ReserveReviewStatus } from './versionReserveReview.ts';
export interface ReviewContext {port:ReserveReviewPort|null;nativeSession:object|null;projectId:string|null;epoch:object;enabled:boolean;preview:boolean}
interface Held {context:ReviewContext;status:ReserveReviewStatus;attempted:boolean;returned:boolean;run:Promise<void>|null}
export class VersionReserveReviewController {
  private held:Held|null=null;
  private read:Promise<boolean>|null=null;
  private stop:Promise<boolean>|null=null;
  private subscription:{port:ReserveReviewPort;pending:Promise<void>;off:(()=>void)|null}|null=null;
  private disposed=false;private failed=false;private hinted=false;
  private readonly listeners=new Set<()=>void>();
  private view:{status:ReserveReviewStatus|null;checking:boolean;stopping:boolean;unknown:boolean}=Object.freeze({status:null,checking:false,stopping:false,unknown:false});
  private readonly source:{current():ReviewContext;start(status:ReserveReviewStatus,port:ReserveReviewPort):Promise<boolean>};
  constructor(source:{current():ReviewContext;start(status:ReserveReviewStatus,port:ReserveReviewPort):Promise<boolean>}){this.source=source}
  getSnapshot=()=>this.view;
  subscribe=(f:()=>void)=>{this.listeners.add(f);return()=>{this.listeners.delete(f)}};
  private publish(){this.view=Object.freeze({status:this.held?.status??null,checking:!!this.read,stopping:!!this.stop,unknown:this.failed||this.held?.status.settlement==='unknown'});if(!this.disposed)for(const f of [...this.listeners]){try{f()}catch{/* Notification cannot settle callers. */}}}
  private current(h:Held){const c=this.source.current();return !this.disposed&&c.port===h.context.port&&c.nativeSession===h.context.nativeSession&&c.projectId===h.context.projectId&&c.epoch===h.context.epoch&&c.enabled===h.context.enabled&&!c.preview}
  private retains(){const h=this.held;return this.failed||!!h&&(h.status.settlement!=='settled'||h.run!==null||h.attempted&&!h.returned)}
  ownerReason=():string|null=>this.failed||this.held?.status.settlement==='unknown'?'The original CLI source review is unconfirmed; keep its request.':this.read||this.stop||this.retains()?'The original CLI source review is still finishing.':null;
  supports=(id:string,revision:number):boolean=>{const h=this.held;return !!h&&h.attempted&&h.returned&&!h.run&&!this.read&&!this.stop&&!this.failed&&this.current(h)&&h.status.phase==='review-ready'&&h.status.review?.id===id&&h.status.review.revision===revision&&h.status.remainingMs>0};
  whenSettled=()=>Promise.all([this.read,this.stop,this.held?.run]).then(()=>undefined);
  syncContext(){
    if(this.disposed)return;const c=this.source.current();
    if(this.subscription?.port===c.port)return;
    if(this.retains()||this.read||this.stop)return; // original subscription and callers remain rooted
    this.subscription?.off?.();this.subscription=null;
    if(this.held&&this.held.context.port!==c.port){this.held=null;this.publish()}
    if(!c.port||!c.nativeSession||c.preview)return;
    const sub={port:c.port,pending:Promise.resolve(),off:null as (()=>void)|null};this.subscription=sub;
    sub.pending=Promise.resolve().then(()=>sub.port.subscribe(hint=>{
      if(this.disposed||this.subscription!==sub||!parseReserveReviewStatus(hint))return;
      this.hinted=true;void this.check(); // hint only; genuine exact read follows
    })).then(off=>{if(this.disposed||this.subscription!==sub)off();else{sub.off=off;void this.check();}},()=>{if(this.subscription===sub&&this.retains()){this.failed=true;this.publish()}});
  }
  private accept(raw:unknown,port:ReserveReviewPort,origin:ReserveReviewOrigin|null):boolean{
    if(raw===null)return origin===null;
    const s=parseReserveReviewStatus(raw);if(!s||origin&&!sameReviewOrigin(origin,s.origin)){this.failed=true;this.publish();return false}
    let h=this.held;
    if(h&&sameReviewOrigin(h.status.origin,s.origin)){
      if(s.revision<h.status.revision)return false;
      const old={...h.status,remainingMs:0},next={...s,remainingMs:0};
      if(s.revision===h.status.revision&&JSON.stringify(old)!==JSON.stringify(next)){this.failed=true;this.publish();return false}
      h.status=s;
    }else{
      if(this.retains())return false;
      const c=this.source.current();if(this.disposed||c.port!==port||!c.nativeSession||c.preview)return false;
      h={context:c,status:s,attempted:false,returned:false,run:null};this.held=h;
    }
    this.publish();
    if(s.phase==='queued'&&!h.attempted&&!this.failed){
      // Attempt flag and retained promise precede any synchronous publication.
      h.attempted=true;const original=h;
      h.run=Promise.resolve().then(async()=>{
        let sent=false;
        try{if(this.current(original))sent=await this.source.start(original.status,port);
          if(!sent)await this.cancelOriginal(original);
        }catch{this.failed=true}
        finally{original.returned=true;original.run=null;this.publish();this.hinted=true;void this.check()}
      });this.publish();
    }
    return true;
  }
  check=():Promise<boolean>=>{
    if(this.disposed)return Promise.resolve(false);if(this.read){this.hinted=true;return this.read}
    const old=this.held,port=old&&this.retains()?old.context.port:this.source.current().port;
    if(!port)return Promise.resolve(false);
    this.hinted=false;
    const work=Promise.resolve().then(async()=>{
      try{
        const q=this.held?.context.port===port?this.held.status.origin:null;
        if(!this.accept(await port.status(q),port,q))return false;
        // Exact old first, then ONE fresh latest only after its true metadata
        // AND actual MAIN caller resolve. Unknown/null/errors never release.
        if(q&&!this.retains()&&!this.disposed&&this.source.current().port===port){
          const latest=await port.status(null);this.accept(latest,port,null);
        }return true;
      }catch{
        // A dormant optional service has no admitted original to lose. Only
        // pending/unknown custody becomes absorbing; ordinary GUI stays usable.
        if(this.retains())this.failed=true;
        this.publish();return false;
      }
    }).finally(()=>{if(this.read===work)this.read=null;this.publish();if(this.hinted&&!this.disposed){this.hinted=false;void this.check()}});
    this.read=work;this.publish();return work;
  };
  private async cancelOriginal(h:Held):Promise<boolean>{
    try{const raw=await h.context.port!.cancel(h.status.origin);return this.accept(raw,h.context.port!,h.status.origin)}catch{this.failed=true;this.publish();return false}
  }
  cancel=():Promise<boolean>=>{
    if(this.stop)return this.stop;const h=this.held;if(!h)return Promise.resolve(false);
    const p=Promise.resolve().then(()=>this.cancelOriginal(h)).finally(()=>{if(this.stop===p)this.stop=null;this.publish()});this.stop=p;this.publish();return p;
  };
  dispose(){this.disposed=true;this.subscription?.off?.();this.listeners.clear()}
}
