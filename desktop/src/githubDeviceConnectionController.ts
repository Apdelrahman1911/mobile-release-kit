// No automatic OAuth poll/browser action. Actual original invocation Promises
// stay retained independently of status DATA; only Connection owns HTTP facts.
import type { GitHubConnectionController } from './githubConnectionController.ts';
import type { GitHubConnectionContext, GitHubConnectionObservationPort } from './githubConnectionTypes.ts';
import { connectionKeys, connectionOpaqueId, connectionRepository, connectionRevision, sameConnectionData, parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { DEVICE_CONSENT, deviceTerminal, parseDeviceStart, parseDeviceStatus, deviceStartFailure } from './githubDeviceConnectionProtocol.ts';
import type { DeviceStart, DeviceStatus, DeviceReason, GitHubDeviceApi, DeviceCompletion } from './githubDeviceConnectionProtocol.ts';
export interface DeviceSource { current(): { api: GitHubDeviceApi | null; port: GitHubConnectionObservationPort | null; context: GitHubConnectionContext | null; blocked: string | null } }
export interface DeviceView { mode:'native'|'unavailable'; context:GitHubConnectionContext|null; status:DeviceStatus|null; original:DeviceStatus|null;
  fresh:boolean; consent:boolean; pendingCount:number; reading:boolean; cancelRequested:boolean; issue:'unconfirmed'|'cleanup-unknown'|null;
  reason:DeviceReason|null; browserRequested:boolean }
interface Binding { identity:GitHubDeviceApi; api:GitHubDeviceApi; port:GitHubConnectionObservationPort }
interface Attempt { binding:Binding; context:GitHubConnectionContext; epoch:object; request:DeviceStart; previousId:string|null; id:string|null;
  sent:boolean; retired:boolean; cancelRequested:boolean; cancelSent:boolean; ended:boolean; refused:boolean; latest:DeviceStatus|null;
  completion:Promise<unknown>; resolve:(v:DeviceCompletion)=>void; reject:(v:unknown)=>void; deliveryClaimed:boolean }
interface Work { kind:'start'|'check'|'status'|'open'|'cancel'|'http-status'; promise:Promise<unknown>|null }
const unconfirmed=()=>({code:'DeviceConnectionUnconfirmed'});
function frozen<T>(v:T):T { if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.values(v).forEach(frozen);Object.freeze(v)}return v }
function context(value:unknown):GitHubConnectionContext|null { try {const v=copyBoundedComparisonData(value,1024,16);return connectionKeys(v,['documentId','projectId','projectGeneration','repository'])&&
  connectionOpaqueId(v.documentId)&&connectionOpaqueId(v.projectId)&&connectionRevision(v.projectGeneration)&&connectionRepository(v.repository)?v as unknown as GitHubConnectionContext:null;}catch{return null} }
export class GitHubDeviceConnectionController {
  #connection:GitHubConnectionController;#source:DeviceSource;#now:()=>number;
  #binding:Binding|null=null;#context:GitHubConnectionContext|null=null;#epoch:object={};#serial=0;#disposed=false;#retiring=false;#notifying=false;
  #status:DeviceStatus|null=null;#fresh=false;#at=0;#consent=false;#browser=false;#reason:DeviceReason|null=null;#issue:DeviceView['issue']=null;
  #attempt:Attempt|null=null;#works=new Set<Work>();#read:Work|null=null;#cancelObserved:string|null=null;
  #listeners=new Set<()=>void>();#off:(()=>void)|null=null;
  #state:DeviceView=frozen({mode:'unavailable',context:null,status:null,original:null,fresh:false,consent:false,pendingCount:0,reading:false,cancelRequested:false,issue:null,reason:null,browserRequested:false});
  constructor(connection:GitHubConnectionController,source:DeviceSource,now:()=>number=()=>globalThis.performance.now()) {
    this.#connection=connection;this.#source=source;this.#now=now;this.#off=connection.subscribe(()=>this.syncContext());
  }
  getSnapshot=():DeviceView=>this.#state;
  subscribe=(fn:()=>void):(()=>void)=>{this.#listeners.add(fn);return()=>{this.#listeners.delete(fn)}};
  #current(){try{const c=this.#source.current();return{api:c.api,port:c.port,context:context(c.context),blocked:typeof c.blocked==='string'?c.blocked:null}}catch{return{api:null,port:null,context:null,blocked:'The current connection is unavailable.'}}}
  #publish(){this.#state=frozen({mode:this.#binding?'native':'unavailable',context:this.#context,status:this.#fresh?this.#status:null,
    original:this.#attempt?.sent?this.#attempt.latest:this.#status,fresh:this.#fresh,consent:this.#consent,pendingCount:this.#works.size,reading:this.#read!==null,
    cancelRequested:!!this.#attempt?.cancelRequested||this.#cancelObserved!==null,issue:this.#issue,reason:this.#reason,browserRequested:this.#browser});
    if(this.#notifying)return;this.#notifying=true;try{for(const fn of [...this.#listeners]){try{fn()}catch{/* View exceptions cannot retire work. */}}}finally{this.#notifying=false}}
  #fail(unknown=false){if(this.#issue!=='cleanup-unknown')this.#issue=unknown?'cleanup-unknown':'unconfirmed';this.#fresh=false;this.#consent=false;
    const a=this.#attempt;if(a?.sent&&!a.deliveryClaimed){a.deliveryClaimed=true;a.reject(unconfirmed())}this.#publish()}
  ownerReason():string|null {if(this.#issue)return 'The original browser connection is unconfirmed. Keep the app open; check or stop that original instead of requesting another code.';
    if(this.#works.size||this.#attempt?.sent&&!this.#attempt.ended||this.#status&&this.#status.phase!=='idle'&&!deviceTerminal(this.#status))return 'The original browser connection is still active. Its Check and Stop controls remain available.';
    return null}
  attach(api:GitHubDeviceApi|null,port:GitHubConnectionObservationPort|null):boolean {
    if(this.#disposed||this.#retiring)return false;if(this.#binding?.identity===api&&this.#binding?.port===port)return true;if(this.ownerReason())return false;
    this.beforeContextIntent();if(this.ownerReason())return false;
    if(api?.mode==='native'&&port?.mode==='native'){
      const{status,start,check,open,cancel}=api;if(![status,start,check,open,cancel].every(f=>typeof f==='function'))return false;
      this.#binding={identity:api,port,api:Object.freeze({mode:'native' as const,status:()=>status.call(api),start:(v:DeviceStart)=>start.call(api,v),
        check:(v:{operationId:string;revision:number})=>check.call(api,v),open:(v:{operationId:string;revision:number})=>open.call(api,v),cancel:(v:{operationId:string})=>cancel.call(api,v)})};
    }else this.#binding=null;
    this.#attempt=null;this.#status=null;this.#fresh=false;this.#reason=null;this.#cancelObserved=null;this.syncContext();return true;
  }
  syncContext():void {if(this.#disposed)return;const c=this.#current();const changed=!sameConnectionData(c.context,this.#context)||!!this.#binding&&(this.#binding.identity!==c.api||this.#binding.port!==c.port);
    this.#context=c.context;if(changed)this.beforeContextIntent();this.#publish()}
  beforeContextIntent():void {this.#epoch={};this.#serial++;this.#fresh=false;this.#consent=false;this.#browser=false;
    const a=this.#attempt;if(a&&!a.ended){a.retired=true;if(a.sent)a.cancelRequested=true;else a.ended=true}this.#publish();this.#sendCancel()}
  setConsent(value:boolean):boolean {if(typeof value!=='boolean'||this.#disposed||this.#retiring||this.ownerReason()||!this.#fresh)return false;this.#consent=value;this.#publish();return true}
  startReason():string|null {const c=this.#current(),b=this.#binding;if(this.#disposed||this.#retiring||!b||b.identity!==c.api||b.port!==c.port)return 'Browser sign-in needs the connected native Desktop app.';
    if(!c.context)return 'Choose your app project and repository first.';if(this.ownerReason())return this.ownerReason();if(c.blocked)return c.blocked;
    if(!this.#fresh||!this.#status)return 'Check browser sign-in availability first.';
    if(!this.#status.available)return this.#status.reason==='publisher-unconfigured'?'The publisher has not configured its device-enabled GitHub OAuth App. Use a selected GitHub CLI account or the token option.':'The installed browser sign-in runtime is unavailable.';
    if(!this.#connection.canConnect()||this.#status.connectionRevision!==this.#connection.getSnapshot().status?.revision)return 'Check the connection status below or finish its original task first.';
    return this.#consent?null:'Approve the session-only GitHub repo permission below.'}
  #same(a:Attempt):boolean{const c=this.#current();return !this.#disposed&&!this.#retiring&&this.#attempt===a&&!a.retired&&this.#epoch===a.epoch&&this.#binding===a.binding&&
    c.api===a.binding.identity&&c.port===a.binding.port&&sameConnectionData(c.context,a.context)&&!c.blocked}
  start():boolean {
    if(this.startReason())return false;const c=this.#current(),b=this.#binding,s=this.#status;if(!b||!c.context||!s||!this.#consent)return false;
    const request=parseDeviceStart({projectId:c.context.projectId,repository:c.context.repository,expectedDocumentRevision:s.documentRevision,expectedConnectionRevision:s.connectionRevision,consentVersion:DEVICE_CONSENT});if(!request)return false;
    let resolve!:(v:DeviceCompletion)=>void,reject!:(v:unknown)=>void;const completion=new Promise<unknown>((yes,no)=>{resolve=yes;reject=no});
    const a:Attempt={binding:b,context:c.context,epoch:this.#epoch,request,previousId:s.operationId,id:null,sent:false,retired:false,cancelRequested:false,cancelSent:false,ended:false,refused:false,latest:null,completion,resolve,reject,deliveryClaimed:false};
    this.#attempt=a;this.#reason=null;this.#browser=false;
    // The existing Connection latch first rechecks all synchronous subscribers.
    // Only its actual handoff can mark this original sent and consume consent.
    const accepted=this.#connection.connectDevice(request,{port:b.port,submit:()=>{
      if(!this.#same(a)||!this.#consent)throw{code:'device_stale'};
      a.sent=true;this.#consent=false;this.#fresh=false;this.#serial++;
      this.#call('start',a,()=>b.api.start(request));return completion;
    }});
    if(!accepted&&!a.sent){a.ended=true;this.#publish()}return accepted;
  }
  #call(kind:Work['kind'],a:Attempt|null,invoke:()=>Promise<unknown>,original?:DeviceStatus):void {
    const work:Work={kind,promise:null};this.#works.add(work);this.#publish();
    // A reentrant Stop/context edit can cancel before native Start. In this
    // path handoff already happened, so return the explicit pre-entry refusal.
    if(kind==='start'&&a&&!this.#same(a)){a.refused=true;a.ended=true;a.deliveryClaimed=true;a.reject({code:'device_stale'});this.#finish(work);return}
    if(['check','open'].includes(kind)&&a&&!this.#same(a)){this.#finish(work);return}
    try {const promise=invoke();work.promise=promise;if(!promise||typeof promise.then!=='function')throw unconfirmed();
      void promise.then(value=>{
        if(kind==='open'){if(value!==null){this.#fail();return}if(a&&this.#same(a))this.#browser=true;this.#publish();return}
        const s=parseDeviceStatus(value);if(!s){this.#fail();return}
        if(original&&(s.operationId!==original.operationId||s.projectId!==original.projectId||s.repository!==original.repository)){this.#fail();return}
        this.#accept(s,true,a);
      },error=>{
        if(kind==='start'&&a){const f=deviceStartFailure(error);if(f.notAdmitted&&!a.id&&!a.latest?.http){a.refused=true;a.ended=true;this.#fresh=false;this.#reason=f.reason==='invalid-input'?'response-invalid':f.reason==='unqualified'?'runtime-unavailable':f.reason as DeviceReason;
          if(!a.deliveryClaimed){a.deliveryClaimed=true;a.reject({code:f.code})}this.#publish();return}}
        if(kind==='check') {let code:unknown;try{code=error&&typeof error==='object'?Object.getOwnPropertyDescriptor(error,'code')?.value:null}catch{/* no accessor */}
          if(['device_wait','query_timeout','busy','device_stale'].includes(code as string)){this.#fresh=false;this.#reason=code==='device_wait'?'waiting':code==='query_timeout'?'expired':'target-changed';this.#publish();return}}
        if(kind==='open'){this.#reason='runtime-unavailable';this.#publish();return}this.#fail();
      }).finally(()=>this.#finish(work));
    }catch(error){if(kind==='start'&&a){const f=deviceStartFailure(error);if(f.notAdmitted&&!a.id){a.refused=true;a.ended=true;a.deliveryClaimed=true;a.reject({code:f.code});this.#fresh=false;this.#reason=f.reason==='publisher-unconfigured'?'publisher-unconfigured':'response-invalid'}else this.#fail()}else this.#fail();this.#finish(work)}
  }
  #match(s:DeviceStatus,a:Attempt):boolean{return s.operationId!==null&&s.operationId!==a.previousId&&(!a.id||s.operationId===a.id)&&s.projectId===a.request.projectId&&s.repository===a.request.repository}
  #accept(s:DeviceStatus,returned:boolean,a=this.#attempt):void {
    if(this.#issue==='cleanup-unknown')return;
    if(a?.sent&&!a.refused){
      if(!this.#match(s,a)){if(!returned&&!a.id&&(s.phase==='idle'||s.operationId===a.previousId))return;this.#fail();return}
      if(s.phase==='cleanup-unknown'){a.id=s.operationId;a.latest=s;this.#status=s;this.#fail(true);return}
      const old=a.latest;
      if(old){
        if(old.http&&!sameConnectionData(old.http,s.http)||old.code&&s.code&&old.code.userCode!==s.code.userCode){this.#fail();return}
        if(s.revision<old.revision)return;
        if(deviceTerminal(old)&&(s.phase!==old.phase||s.reason!==old.reason||!sameConnectionData(old.http,s.http))){this.#fail();return}
        if(s.revision===old.revision&&(s.phase!==old.phase||s.reason!==old.reason||!sameConnectionData(old.http,s.http)||!!s.code!==!!old.code)){this.#fail();return}
      }
      a.id=s.operationId;a.latest=s;
    }
    this.#status=s;this.#at=this.#now();const c=this.#current();
    this.#fresh=this.#issue===null&&!!this.#binding&&this.#binding.identity===c.api&&this.#binding.port===c.port&&sameConnectionData(this.#context,c.context)&&(!a?.sent||this.#same(a));
    this.#reason=s.reason==='none'?null:s.reason;if(s.phase==='cleanup-unknown'){this.#fail(true);return}this.#publish();this.#sendCancel();
  }
  #finish(work:Work):void {this.#works.delete(work);if(this.#read===work)this.#read=null;this.#publish();this.#sendCancel();this.#settle();this.#disposeIfReturned()}
  #settle():void {const a=this.#attempt;if(!a?.sent||a.ended||a.deliveryClaimed||this.#works.size||this.#issue||!a.latest||!deviceTerminal(a.latest))return;
    const s=a.latest;if(s.phase==='cleanup-unknown'){this.#fail(true);return}
    if(!s.http){a.ended=true;a.deliveryClaimed=true;a.resolve({device:s,connection:null});this.#publish();return}
    // Status is read from the SAME original HTTP port only AFTER all device
    // invoke callers returned. It is not a fabricated gh result/Connect call.
    const work:Work={kind:'http-status',promise:null};this.#works.add(work);a.deliveryClaimed=true;this.#publish();
    try {const p=a.binding.port.status();work.promise=p;if(!p||typeof p.then!=='function')throw unconfirmed();void p.then(value=>{
      const c=parseGitHubConnectionStatus(value);if(!c||c.session?.id!==s.http!.sessionId||c.operation?.id!==s.http!.operationId||c.operation.phase!=='settled'){a.reject(unconfirmed());this.#fail();return}
      a.ended=true;a.resolve({device:s,connection:c});this.#publish();
    },()=>{a.reject(unconfirmed());this.#fail()}).finally(()=>this.#finish(work));}catch{a.reject(unconfirmed());this.#fail();this.#finish(work)}
  }
  canRead():boolean{return !this.#disposed&&!!(this.#attempt?.sent?this.#attempt.binding:this.#binding)&&!this.#read}
  read():boolean {const b=this.#attempt?.sent&&!this.#attempt.refused?this.#attempt.binding:this.#binding;if(!b||!this.canRead())return false;
    const work:Work={kind:'status',promise:null},epoch=this.#epoch,serial=this.#serial,c=this.#current().context;this.#read=work;this.#works.add(work);this.#publish();
    try {const p=b.api.status();work.promise=p;if(!p||typeof p.then!=='function')throw unconfirmed();void p.then(value=>{
      const s=parseDeviceStatus(value);if(!s){if(serial===this.#serial)this.#fail();return}
      const a=this.#attempt;
      if(s.phase==='cleanup-unknown'&&a?.sent&&this.#match(s,a)){this.#accept(s,false);return}
      if(serial!==this.#serial||epoch!==this.#epoch||b!==this.#binding||!sameConnectionData(c,this.#current().context))return;
      this.#accept(s,false);
    },()=>{if(serial===this.#serial)this.#fail()}).finally(()=>this.#finish(work));return true;}catch{this.#fail();this.#finish(work);return false}
  }
  checkReason():string|null {const a=this.#attempt,s=a?.latest;if(!a?.sent||!this.#same(a)||!this.#fresh||!s||s.phase!=='pending'||!s.code)return 'Only the same current device code can be checked. Read its status if needed.';
    if(this.#issue||this.#works.size||a.cancelRequested)return 'Wait for the original request or Stop to finish.';
    const elapsed=Math.max(0,(this.#now()-this.#at)/1000);
    if(elapsed<s.code.checkAfterSeconds)return `GitHub requires at least ${s.code.checkAfterSeconds} seconds after this status before another check.`;
    if(s.code.remainingSeconds-elapsed<24)return 'This code has too little time for a complete connection. Stop it; do not replace an unconfirmed request.';return null}
  check():boolean{if(this.checkReason())return false;const a=this.#attempt!,s=a.latest!;this.#serial++;this.#fresh=false;this.#call('check',a,()=>a.binding.api.check({operationId:s.operationId!,revision:s.revision}));return true}
  canOpen():boolean{const a=this.#attempt;return !!a?.latest?.code&&this.#same(a)&&this.#fresh&&!this.#issue&&!this.#works.size&&!a.cancelRequested&&a.latest.phase==='pending'}
  open():boolean{if(!this.canOpen())return false;const a=this.#attempt!,s=a.latest!;this.#call('open',a,()=>a.binding.api.open({operationId:s.operationId!,revision:s.revision}));return true}
  canCancel():boolean{if(this.#disposed)return false;const a=this.#attempt;if(a?.sent&&!a.ended)return !a.cancelRequested;
    return !!this.#status?.operationId&&(!deviceTerminal(this.#status)||this.#status.phase==='cleanup-unknown')&&this.#cancelObserved===null}
  cancel():boolean{if(!this.canCancel())return false;const a=this.#attempt;this.#serial++;this.#fresh=false;this.#consent=false;
    if(a?.sent&&!a.ended){a.retired=true;a.cancelRequested=true;this.#publish();this.#sendCancel();return true}
    const s=this.#status!,b=this.#binding!;this.#cancelObserved=s.operationId;this.#call('cancel',null,()=>b.api.cancel({operationId:s.operationId!}),s);return true}
  #sendCancel():void{const a=this.#attempt;if(!a?.sent||a.ended||!a.cancelRequested||a.cancelSent||!a.id)return;
    a.cancelSent=true;this.#call('cancel',a,()=>a.binding.api.cancel({operationId:a.id!}))}
  dispose():void{if(this.#disposed||this.#retiring)return;this.#retiring=true;this.beforeContextIntent();this.#listeners.clear();this.#disposeIfReturned()}
  #disposeIfReturned(){if(!this.#retiring||this.ownerReason())return;this.#off?.();this.#off=null;this.#disposed=true}
}
