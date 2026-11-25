import { appleCliId, appleCliModes } from './agentAppleProvisioning.ts';
import type { AppleCliQuery } from './agentAppleProvisioning.ts';
import { applePreparationSelection, parseApplePreparationAccess, parseApplePreparationStatus, sameApplePreparationQuery } from './agentApplePreparation.ts';
import type { ApplePreparationAccess, ApplePreparationDelegate, ApplePreparationMode, ApplePreparationPort, ApplePreparationStatus } from './agentApplePreparation.ts';
import type { PrepareAppleProvisioning } from './appleProvisioningTypes.ts';
export interface ApplePreparationContext {port:ApplePreparationPort|null;session:object|null;epoch:object;projectId:string|null;preview:boolean;blockedReason:string|null}
interface Origin {context:ApplePreparationContext;selection:PrepareAppleProvisioning;nonce:string;delegate:ApplePreparationDelegate|null;sent:boolean;allowJoined:boolean;revoked:boolean;withdrawn:boolean;query:AppleCliQuery|null;status:ApplePreparationStatus|null;scopeId:string|null;serviceInstance:string|null;serviceProject:string|null}
interface Work {original:Promise<unknown>|null;completion:Promise<void>;finish():void}
const same=(a:ApplePreparationContext,b:ApplePreparationContext)=>a.port===b.port&&a.session===b.session&&a.epoch===b.epoch&&a.projectId===b.projectId&&a.preview===b.preview;
const sameData=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
const unavailable={};const empty=():ApplePreparationContext=>({port:null,session:null,epoch:unavailable,projectId:null,preview:false,blockedReason:null});
const uncertain='The original CLI preparation is unconfirmed. Keep its request ID, check or withdraw its exact permission; do not repeat Prepare.';
function nonce(){const bytes=new Uint8Array(16);globalThis.crypto.getRandomValues(bytes);const id=[...bytes].map(n=>n.toString(16).padStart(2,'0')).join('');if(!appleCliId(id))throw Error('nonce');return id;}
export interface ApplePreparationView {mode:ApplePreparationMode;selection:PrepareAppleProvisioning|null;acknowledged:boolean;access:ApplePreparationAccess|null;status:ApplePreparationStatus|null;pending:boolean;revoking:boolean;listening:boolean;stale:boolean;unknown:boolean;issue:string|null;withdrawn:boolean}
interface Source {current():ApplePreparationContext;syncOriginal():void;selection(mode:ApplePreparationMode):PrepareAppleProvisioning|null;reserve(selection:PrepareAppleProvisioning,nonce:string):ApplePreparationDelegate|null;nonce?():string}
export class AgentApplePreparationController {
  private readonly source:Source;
  private context=empty();private origin:Origin|null=null;private work:Work|null=null;private revokeWork:Work|null=null;
  private off:(()=>void)|null=null;private subscribing:Promise<void>|null=null;private listeningPort:ApplePreparationPort|null=null;private again=false;private disposed=false;
  private consent:{context:ApplePreparationContext;selection:PrepareAppleProvisioning}|null=null;
  private state:ApplePreparationView=Object.freeze({mode:'review',selection:null,acknowledged:false,access:null,status:null,pending:false,revoking:false,listening:false,stale:false,unknown:false,issue:null,withdrawn:false});
  private readonly listeners=new Set<()=>void>();
  constructor(source:Source){this.source=source;this.syncContext();}
  getSnapshot=()=>this.state;subscribe=(fn:()=>void)=>{this.listeners.add(fn);return()=>{this.listeners.delete(fn);};};
  whenSettled=()=>Promise.all([this.work?.completion,this.revokeWork?.completion,this.subscribing]).then(()=>undefined);
  private read():ApplePreparationContext{try{const c=this.source.current();return c&&c.epoch&&typeof c.epoch==='object'&&c.session!==null&&typeof c.session==='object'&&typeof c.preview==='boolean'?c:empty();}catch{return empty();}}
  private publish(values:Partial<ApplePreparationView>={}){this.state=Object.freeze({...this.state,...values,pending:!!this.work,revoking:!!this.revokeWork,listening:!!this.off,withdrawn:!!this.origin?.withdrawn});if(!this.disposed)for(const fn of [...this.listeners]){try{fn();}catch{/* Not a caller return. */}}}
  syncContext=():void=>{if(this.disposed)return;const c=this.read(),selection=applePreparationSelection(this.source.selection(this.state.mode));
    if(!same(c,this.context)||!sameData(selection,this.state.selection))this.consent=null;
    const changed=!same(c,this.context)||!sameData(selection,this.state.selection);this.context=c;
    if(changed)this.publish({selection,acknowledged:!!this.consent,stale:!!this.origin&&!same(c,this.origin.context)});
    if(!this.origin&&!this.subscribing&&c.port!==this.listeningPort){try{this.off?.();}catch{this.unknown();return;}this.off=null;this.listeningPort=c.port;
      if(c.port){const p=c.port;this.subscribing=(async()=>{try{const off=await p.subscribe(raw=>this.event(raw));if(this.disposed||this.listeningPort!==p){off();return;}this.off=off;}catch{this.unknown();}finally{this.subscribing=null;this.publish();}})();}
    }
  };
  setMode(mode:ApplePreparationMode){if(this.ownerReason()||!(appleCliModes as readonly string[]).includes(mode))return;this.consent=null;this.publish({mode,acknowledged:false});this.syncContext();}
  ownerReason=():string|null=>this.state.unknown?uncertain:this.work||this.revokeWork||this.subscribing?'An original Apple preparation caller is returning.':this.origin&&!this.origin.withdrawn?'The earlier Apple preparation permission remains retained.':null;
  allowReason=():string|null=>this.context.preview||!this.context.port||!this.context.session?'Use the installed Desktop with ordinary Read access.':!this.off?'Wait for the original preparation listener.':this.context.blockedReason??this.ownerReason()??(!this.state.selection?'Select the actual Apple credentials and a currently available step in the app.':!this.consent?'Confirm preparation of this exact selected step once.':null);
  acknowledge(v:boolean){this.source.syncOriginal();this.syncContext();const c=this.context,s=this.state.selection;this.consent=v&&s&&!this.context.blockedReason&&!this.ownerReason()&&!!this.off?{context:c,selection:s}:null;this.publish({acknowledged:!!this.consent});}
  private begin(revoke=false):Work{let finish!:()=>void;const completion=new Promise<void>(yes=>{finish=yes;});const w={original:null,completion,finish};if(revoke)this.revokeWork=w;else this.work=w;this.consent=null;this.publish({acknowledged:false});return w;}
  private end(w:Work){if(this.work===w)this.work=null;if(this.revokeWork===w)this.revokeWork=null;this.publish();w.finish();if(this.again&&!this.work&&!this.revokeWork&&!this.state.unknown){this.again=false;void this.check();}}
  private unknown(){this.consent=null;this.publish({unknown:true,issue:uncertain,acknowledged:false});this.origin?.delegate?.uncertain();}
  private async call(w:Work,send:()=>Promise<unknown>){const p=send();w.original=p;return await p;}
  private access(a:ApplePreparationAccess,o:Origin):boolean{if(a.grantId!==o.nonce||a.mode!==o.selection.mode||!a.scopeId||!a.projectId||!a.serviceInstance||o.scopeId!==null&&o.scopeId!==a.scopeId||o.serviceInstance!==null&&o.serviceInstance!==a.serviceInstance||o.serviceProject!==null&&o.serviceProject!==a.projectId)return false;
    o.scopeId=a.scopeId;o.serviceInstance=a.serviceInstance;o.serviceProject=a.projectId;return !a.status||this.accept(a.status,o);}
  private accept(s:ApplePreparationStatus,o:Origin):boolean{if(s.grantId!==o.nonce||s.mode!==o.selection.mode||s.scopeId!==o.scopeId||s.origin.projectId!==o.serviceProject||s.origin.serviceInstance!==o.serviceInstance||o.query&&!sameApplePreparationQuery(s.origin,o.query))return false;
    const old=o.status;if(old&&(s.revision<old.revision||s.revision===old.revision&&!sameData(old,s)||old.phase==='unknown'&&s.phase!=='unknown'||old.settlement==='settled'&&s.settlement==='pending'||old.prepared&&s.prepared&&!sameData(old.prepared,s.prepared)))return false;
    o.query=s.origin;o.status=s;return true;}
  private event(raw:unknown){const o=this.origin;if(!o||!o.sent)return;const s=parseApplePreparationStatus(raw);if(!s){this.unknown();return;}
    if(s.grantId!==o.nonce)return; // another original is never adopted from the relay
    if(o.scopeId===null||!o.allowJoined){this.again=true;return;}
    if(!this.accept(s,o)){this.unknown();return;}this.again=true;if(!this.work&&!this.revokeWork&&!this.state.unknown){this.again=false;void this.check();}}
  async allow():Promise<boolean>{this.source.syncOriginal();this.syncContext();if(this.allowReason())return false;const c=this.read(),s=this.state.selection,consent=this.consent;
    if(!s||!consent||!same(consent.context,c)||!sameData(consent.selection,s))return false;let n:string;try{n=(this.source.nonce??nonce)();if(!appleCliId(n))return false;}catch{return false;}
    const o:Origin={context:c,selection:s,nonce:n,delegate:null,sent:false,allowJoined:false,revoked:false,withdrawn:false,query:null,status:null,scopeId:null,serviceInstance:null,serviceProject:null};this.origin=o;const w=this.begin();
    try{this.source.syncOriginal();if(this.disposed||!same(c,this.read())||o.revoked||this.read().blockedReason||!sameData(s,this.source.selection(s.mode as ApplePreparationMode)))return false;
      o.delegate=this.source.reserve(s,n);this.source.syncOriginal();
      if(!o.delegate?.current()||o.revoked||!same(c,this.read())||this.read().blockedReason)return false;
      o.sent=true;const a=parseApplePreparationAccess(await this.call(w,()=>c.port!.allow(s,n)));o.allowJoined=true;o.delegate.allowReturned();
      if(!a||!this.access(a,o)){this.unknown();return true;}if(!this.state.unknown&&!o.revoked)this.publish({access:a,stale:!same(c,this.read())});if(a.status)this.again=true;
    }catch{this.unknown();}finally{if(!o.sent){o.delegate?.notSent();if(!this.state.unknown&&this.origin===o)this.origin=null;}this.end(w);}return o.sent;}
  checkReason=():string|null=>this.work?'Wait for the original caller.':!this.origin?.context.port?'No original preparation scope is retained.':this.disposed?'Closed.':null;
  async check():Promise<boolean>{if(this.checkReason())return false;const o=this.origin!,p=o.context.port!,w=this.begin();
    try{let s:ApplePreparationStatus|null=null;
      if(o.query){s=parseApplePreparationStatus(await this.call(w,()=>p.request(o.query!)));if(!s||!this.accept(s,o)){this.unknown();return true;}}
      else{const a=parseApplePreparationAccess(await this.call(w,()=>p.access()));if(!a||!this.access(a,o)){this.unknown();return true;}if(!this.state.unknown)this.publish({access:a});s=a.status;if(s){s=parseApplePreparationStatus(await this.call(w,()=>p.request(s!.origin)));if(!s||!this.accept(s,o)){this.unknown();return true;}}}
      if(s&&!this.state.unknown){this.publish({status:s,stale:!same(o.context,this.read())});if(s.phase==='unknown'){this.unknown();return true;}
        if(s.phase==='queued'){
          // Recheck after the status listeners too. Only a returned exact
          // withdrawal may close the old native no-Host caller after context
          // departure; a new service/preview can never dispatch preparation.
          if(o.withdrawn||!this.disposed&&same(o.context,this.read())&&!this.read().preview&&!this.read().blockedReason)await o.delegate?.run(s.origin,o.withdrawn);
        }
        else if(s.settlement==='settled'){await o.delegate?.observe(s);}
      }
    }catch{this.unknown();}finally{this.end(w);}return true;}
  revokeReason=():string|null=>this.revokeWork?'Wait for the original withdrawal.':!this.origin?.context.port?'No exact attempted permission is retained.':this.disposed?'Closed.':null;
  async revoke():Promise<boolean>{if(this.revokeReason())return false;const o=this.origin!,w=this.begin(true);o.revoked=true;
    try{const a=parseApplePreparationAccess(await this.call(w,()=>o.context.port!.revoke(o.nonce)));
      if(!a||a.enabled||a.grantId!==null&&!this.access(a,o)){this.unknown();return true;}o.withdrawn=true;o.delegate?.withdrawn(o.query);
      if(!this.state.unknown)this.publish({access:a});if(o.query)this.again=true;
    }catch{this.unknown();}finally{this.end(w);}return true;}
  dispose(){if(this.disposed)return;this.disposed=true;this.listeners.clear();this.consent=null;try{this.off?.();}catch{this.unknown();}this.off=null;/* Original promises remain retained. */}
}
