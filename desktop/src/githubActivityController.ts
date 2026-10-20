// Presentation only. The retained native Connection/Setup owner supplies every
// result, cancellation and join; navigation never starts a remote read.
import { browserRequestReturned, browserFailure, BROWSER_HELP } from './githubPullRequestManagement.ts';
import type { GitHubBrowserState, GitHubBrowserPage } from './githubPullRequestManagement.ts';
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { parseActivitySelection, activityError, ACTIVITY_HELP, parseActivityStatus } from './githubActivityProtocol.ts';
import type { ActivityObservation, ActivityReason, ActivitySelection, ActivityStatus, ActivityTarget, GitHubActivityPort } from './githubActivityProtocol.ts';
interface Context {documentId:string;projectId:string;projectGeneration:number;repository:string;sessionId:string;accountId:string;repositoryId:string}
interface Original {port:GitHubActivityPort;live:boolean;unlisten:(()=>void)|null;status:ActivityStatus|null;fresh:boolean}
interface Work {owner:Original;kind:'subscribe'|'status'|'read'|'cancel'|'browser';ended:boolean;promise:Promise<unknown>|null}
interface Attempt {owner:Original;work:Work;context:Context;epoch:object;selection:ActivitySelection;revision:number;previousId:string|null;operationId:string|null;sent:boolean;stopWanted:boolean;stopSent:boolean}
interface BoundResult {owner:Original;context:Context;epoch:object;observation:ActivityObservation}
export interface GitHubActivityView {browserState:GitHubBrowserState;browserPending:boolean;native:boolean;status:ActivityStatus|null;branchDraft:string;pending:boolean;observing:boolean;cancelling:boolean;uncertain:boolean;error:ActivityReason|null;originalRepository:string|null}
function immutable<T>(v:T):T{if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.values(v).forEach(immutable);Object.freeze(v);}return v;}
function context(view:GitHubConnectionViewState):Context|null{
  const c=view.context,s=view.status,a=s?.account.value,r=s?.repository.value,session=s?.session;
  if(!c||!s||!a||!r||!session||view.mode!=='native'||view.blocked||view.uncertain||view.retirementPending||view.busy||session.state!=='connected'||
    session.projectId!==c.projectId||session.targetRepository!==c.repository||s.account.state!=='observed'||s.repository.state!=='observed'||r.fullName.toLowerCase()!==c.repository.toLowerCase())return null;
  return {...c,sessionId:session.id,accountId:a.id,repositoryId:r.id};
}
function inContext(t:ActivityTarget,c:Context):boolean{return t.repository.toLowerCase()===c.repository.toLowerCase()&&t.accountId===c.accountId&&t.repositoryId===c.repositoryId;}
function advances(a:ActivityStatus,b:ActivityStatus):boolean{
  if(a.revision===b.revision)return same(a,b);
  if(a.revision>b.revision||a.reason==='cleanup-unknown'||a.operation?.phase==='cleanup-unknown')return false;
  const x=a.operation,y=b.operation;
  if(x&&y?.id===x.id){
    if(x.projectId!==y.projectId||!same(x.target,y.target)||!same(x.selection,y.selection)||x.phase==='settled'&&!same(x,y)||x.phase==='stopping'&&y.phase==='running')return false;
    // Context retirement may remove a result, never replace terminal evidence.
    if(x.phase==='settled'&&b.result!==null&&!same(a.result,b.result))return false;
  }else if(x&&x.phase!=='settled')return false;
  return true;
}
export class GitHubActivityController {
  private state:GitHubActivityView=immutable({browserState:'idle',browserPending:false,native:false,status:null,branchDraft:'',pending:false,observing:false,cancelling:false,uncertain:false,error:null,originalRepository:null});
  private listeners=new Set<()=>void>();private desired:GitHubActivityPort|null=null;private original:Original|null=null;private work=new Set<Work>();
  private attempt:Attempt|null=null;private result:BoundResult|null=null;private current:Context|null=null;private epoch:object={};private unknown=false;private disposed=false;private cancelledId:string|null=null;
  private browserToken:object|null=null;
  private connection:()=>GitHubConnectionViewState;private peer:(selection?:ActivitySelection)=>string|null;
  constructor(connection:()=>GitHubConnectionViewState,peer:(selection?:ActivitySelection)=>string|null=()=>null){this.connection=connection;this.peer=peer;}
  getSnapshot=():GitHubActivityView=>this.state;
  subscribe=(f:()=>void):(()=>void)=>{this.listeners.add(f);return()=>{this.listeners.delete(f);};};
  private update(p:Partial<GitHubActivityView>={}):void{this.state=immutable({...this.state,...p,pending:this.attempt!==null,browserPending:[...this.work].some(w=>w.kind==='browser'),
    observing:[...this.work].some(w=>w.kind==='status'||w.kind==='subscribe'),cancelling:[...this.work].some(w=>w.kind==='cancel')});
    for(const f of [...this.listeners]){try{f();}catch{/* Rendering never disowns an original invocation. */}}}
  private fail(reason:ActivityReason):void{if(this.unknown){this.update();return;}this.unknown=true;this.result=null;this.update({uncertain:true,error:reason});}
  private invalidate():void{this.epoch={};this.browserToken=null;this.state=immutable({...this.state,browserState:'idle'});this.result=null;if(this.attempt)this.attempt.stopWanted=true;this.update();this.stopInvalidated();}
  beforeWorkspaceAction():void{if(!this.disposed)this.invalidate();}
  syncContext=():void=>{if(this.disposed)return;const c=context(this.connection());if(!same(c,this.current)){this.current=c;this.invalidate();}};
  setBranch(value:string):void{if(!this.disposed&&typeof value==='string'&&value.length<=200&&value!==this.state.branchDraft){this.invalidate();this.update({branchDraft:value});}}
  private owns(o:Original):boolean{return this.unknown||this.attempt?.owner===o||[...this.work].some(w=>w.owner===o)||!!o.status?.operation&&o.status.operation.phase!=='settled';}
  private maintain():void{
    const old=this.original;
    if(old&&(this.desired!==old.port||this.disposed)){
      if(this.owns(old))return;const stop=old.unlisten;old.unlisten=null;old.live=false;
      try{stop?.();}catch{this.fail('cleanup-unknown');return;}this.original=null;
    }
    if(this.original||this.disposed||!this.desired)return;
    const o:Original={port:this.desired,live:true,unlisten:null,status:null,fresh:false};this.original=o;
    const w=this.latch(o,'subscribe');
    try{const promise=o.port.subscribe(v=>{this.receive(o,v);});if(!(promise instanceof Promise))throw new Error('Original subscription not retained');w.promise=promise;
      void promise.then(stop=>{if(typeof stop!=='function'){this.fail('response-invalid');return;}o.unlisten=stop;},()=>this.fail('runtime-unavailable')).finally(()=>{
        this.finish(w);if(this.original===o&&o.live&&o.port===this.desired&&!this.disposed&&!this.unknown)this.checkStatus();
      });
    }catch{this.fail('response-invalid');this.finish(w);}
  }
  connect(port:GitHubActivityPort|null):void{if(this.disposed||this.desired===port)return;this.desired=port;this.syncContext();this.invalidate();this.update({native:port!==null});this.maintain();}
  private latch(owner:Original,kind:Work['kind']):Work{const w:Work={owner,kind,ended:false,promise:null};this.work.add(w);this.update();return w;}
  private finish(w:Work):void{w.ended=true;w.promise=null;this.work.delete(w);this.settle();this.update();this.maintain();}
  private origin(a:Attempt,s:ActivityStatus):boolean{const o=s.operation;return a.sent&&s.revision>a.revision&&s.sessionId===a.context.sessionId&&!!o&&o.id!==a.previousId&&
    (!a.operationId||o.id===a.operationId)&&o.projectId===a.context.projectId&&inContext(o.target,a.context)&&same(o.selection,a.selection);}
  private receive(o:Original,raw:unknown):ActivityStatus|null{
    if(o!==this.original||!o.live)return null;const next=parseActivityStatus(raw);
    if(o!==this.original||!o.live)return null;
    if(!next){this.fail('response-invalid');return null;}
    if(this.unknown){const a=this.attempt;if(a?.owner===o&&this.origin(a,next)&&a.operationId===null)a.operationId=next.operation!.id;this.update();this.stopInvalidated();return null;}
    const s=immutable(next),old=o.status;
    if(old&&s.revision<old.revision){if(!advances(s,old)){this.fail('response-invalid');return null;}}
    else{
      if(old&&!advances(old,s)){this.fail('response-invalid');return null;}
      o.status=s;o.fresh=true;
      if(s.reason==='cleanup-unknown'||s.operation?.phase==='cleanup-unknown'){
        const a=this.attempt;if(a?.owner===o&&this.origin(a,s))a.operationId=s.operation!.id;this.update({status:s});this.fail('cleanup-unknown');this.stopInvalidated();return s;
      }
      if(this.result&&!same(this.result.observation,s.result))this.result=null;
      this.update({status:s,error:this.attempt?this.state.error:s.operation?.reason&&s.operation.reason!=='none'?s.operation.reason:null});
    }
    const a=this.attempt;if(a?.owner===o&&this.origin(a,s))a.operationId=s.operation!.id;
    this.settle();this.stopInvalidated();return s;
  }
  private settle():void{
    const a=this.attempt,s=a?.owner.status;
    if(!a||!s||!a.work.ended||!this.origin(a,s)||s.operation?.phase!=='settled'||this.unknown)return;
    this.attempt=null;
    if(s.result&&a.epoch===this.epoch&&a.owner===this.original&&a.owner.port===this.desired&&!this.disposed&&same(a.context,context(this.connection())))
      this.result={owner:a.owner,context:a.context,epoch:a.epoch,observation:s.result};
    this.update({uncertain:false,error:s.operation.reason==='none'?null:s.operation.reason});
  }
  canCheck():boolean{const o=this.original;return !!o?.live&&(!this.disposed||this.owns(o))&&![...this.work].some(w=>w.owner===o&&(w.kind==='status'||w.kind==='subscribe'));}
  checkStatus():void{
    if(!this.canCheck())return;const o=this.original!,w=this.latch(o,'status');
    const failed=()=>{o.fresh=false;this.update({error:'response-invalid',uncertain:this.attempt!==null||this.unknown});};
    try{const promise=o.port.status();if(!(promise instanceof Promise))throw new Error('Original status not retained');w.promise=promise;
      void promise.then(v=>{this.receive(o,v);},failed).finally(()=>this.finish(w));}catch{failed();this.finish(w);}
  }
  currentResult():ActivityObservation|null{
    const r=this.result,o=this.original;return r&&!this.disposed&&!this.unknown&&r.owner===o&&o.live&&o.port===this.desired&&o.fresh&&r.epoch===this.epoch&&
      same(r.context,context(this.connection()))&&same(r.observation,o.status?.result)?r.observation:null;
  }
  ownerReason():string|null{
    if(this.unknown)return ACTIVITY_HELP['cleanup-unknown'];
    if([...this.work].some(w=>w.kind==='browser'))return 'The original browser request is still returning. Other tasks wait for that same call.';
    return this.attempt||this.work.size||this.original?.status?.operation&&this.original.status.operation.phase!=='settled'?
      'The original GitHub activity read is still running or closing. Status and Stop remain available.':null;
  }
  readReason(selected:ActivitySelection={kind:'overview',branch:this.state.branchDraft||null}):string|null{
    const o=this.original,c=context(this.connection()),s=o?.status;
    if(!parseActivitySelection(selected))return ACTIVITY_HELP['invalid-input'];
    if(this.disposed||!o?.live||o.port!==this.desired||!o.unlisten)return ACTIVITY_HELP['runtime-unavailable'];
    if(this.unknown)return ACTIVITY_HELP['cleanup-unknown'];
    if(this.ownerReason())return ACTIVITY_HELP.busy;
    if(!c||this.connection().observing)return ACTIVITY_HELP['not-connected'];
    if(!s||!o.fresh||s.sessionId!==c.sessionId)return 'Check current activity status first.';
    if(!s.available)return ACTIVITY_HELP[s.reason];return this.peer(selected);
  }
  matchesContext(expected:unknown):boolean {return same(expected,context(this.connection()));}
  refreshResult(expected:ActivityObservation):void {if(this.currentResult()===expected)this.read(expected.selection);}
  browserReason(expected:ActivityObservation):string|null {
    if(this.currentResult()!==expected||expected.data.kind!=='pull-request')return BROWSER_HELP.stale;
    if(!this.original?.port.openBrowser)return BROWSER_HELP.unavailable;
    if(['unconfirmed','unavailable','stale'].includes(this.state.browserState))return BROWSER_HELP[this.state.browserState];
    return this.readReason(expected.selection);
  }
  openPullRequest(expected:ActivityObservation,page:GitHubBrowserPage):void {
    if(!['conversation','files'].includes(page)||this.browserReason(expected))return;
    const o=this.original!,s=o.status!,c=context(this.connection()),epoch=this.epoch,revision=this.connection().status?.revision;
    if(!c||revision===undefined||!s.operation||!o.port.openBrowser)return;
    const token={};this.browserToken=token;
    const w:Work={owner:o,kind:'browser',ended:false,promise:null};this.work.add(w);this.update({browserState:'requesting'});
    const peer=this.peer();
    const current=()=>this.browserToken===token&&this.epoch===epoch&&this.currentResult()===expected&&o===this.original&&o.port===this.desired&&
      o.status===s&&same(c,context(this.connection()))&&this.connection().status?.revision===revision;
    if(!current()||peer||this.work.size!==1){if(this.browserToken===token)this.update({browserState:'stale'});this.finish(w);return;}
    const returned=(raw:unknown)=>{const ok=browserRequestReturned(raw);if(this.browserToken===token)this.update({browserState:current()?(ok?'request-sent':'unconfirmed'):'stale'});};
    const failed=(raw:unknown)=>{const state=browserFailure(raw);if(this.browserToken===token)this.update({browserState:current()?state:'stale'});};
    try {
      const promise=o.port.openBrowser({kind:'activity-pull-request',sessionId:c.sessionId,expectedRevision:s.revision,
        expectedConnectionRevision:revision,operationId:s.operation.id,page});
      if(!(promise instanceof Promise))throw new Error('Original browser request not retained');w.promise=promise;
      void promise.then(returned,failed).finally(()=>this.finish(w));
    }catch(e){failed(e);this.finish(w);}
  }
  readSelection(from:ActivityObservation,selected:ActivitySelection):void{
    // Row callbacks must belong to this exact still-current result, not a
    // previously rendered repository, port or away-and-back selection.
    const current=this.currentResult();if(current!==from||current.data.kind!=='overview')return;
    if(selected.kind==='pull-request'&&current.data.pullRequests.rows.some(r=>r.number===selected.number)||
      selected.kind==='workflow-run'&&current.data.workflowRuns.rows.some(r=>r.id===selected.runId&&r.attempt===selected.attempt))this.read(selected);
  }
  readPushRecovery(branch:string,stillCurrent:()=>boolean):{result:()=>ActivityObservation|null}|null {
    const selected=parseActivitySelection({kind:'overview',branch});
    if(!selected||selected.kind!=='overview'||selected.branch===null||this.readReason(selected))return null;
    const previous=this.attempt;
    this.read(selected,stillCurrent);
    const a=this.attempt;
    if(!a||a===previous||!a.sent||!same(a.selection,selected))return null;
    return Object.freeze({result:()=>{
      let current=false;try{current=stillCurrent();}catch{/* A failed comparison is only a veto. */}
      const s=a.owner.status,r=this.currentResult();
      return current&&a.work.ended&&a.operationId!==null&&s?.operation?.id===a.operationId&&this.origin(a,s)&&r===s.result?r:null;
    }});
  }
  read(selected:ActivitySelection={kind:'overview',branch:this.state.branchDraft||null},stillCurrent:()=>boolean=()=>true):void{
    const parsed=parseActivitySelection(selected);if(!parsed)return;selected=parsed;
    if(this.readReason(selected))return;
    const source=this.connection(),o=this.original!,c=context(source),s=o.status,epoch=this.epoch;
    if(!c||!s||!source.status)return;const revision=source.status.revision;
    const w:Work={owner:o,kind:'read',ended:false,promise:null};this.work.add(w);
    const a:Attempt={owner:o,work:w,context:c,epoch,selection:immutable(structuredClone(selected)),revision:s.revision,previousId:s.operation?.id??null,operationId:null,sent:false,stopWanted:false,stopSent:false};
    this.attempt=a;this.result=null;this.browserToken=null;this.update({error:null,browserState:'idle',originalRepository:c.repository});
    let sourceCurrent=false;try{sourceCurrent=stillCurrent();}catch{/* Veto only; never invoke on a thrown binding check. */}
    const peer=this.peer(selected);
    if(!sourceCurrent||this.attempt!==a||a.stopWanted||epoch!==this.epoch||o!==this.original||o.port!==this.desired||this.disposed||this.unknown||o.status!==s||!o.fresh||peer||
      !same(c,context(this.connection()))||revision!==this.connection().status?.revision){this.attempt=null;this.update({error:a.stopWanted?'cancelled':'target-changed'});this.finish(w);return;}
    a.sent=true;
    const failed=(raw:unknown,sync:boolean)=>{const e=activityError(raw);
      if(!sync&&e.notAdmitted&&this.attempt===a&&a.operationId===null&&!this.unknown){this.attempt=null;o.fresh=false;this.update({error:e.reason});}
      else this.fail(e.reason);
    };
    try{const promise=o.port.read({sessionId:c.sessionId,projectId:c.projectId,expectedRevision:s.revision,expectedConnectionRevision:revision,selection:a.selection});
      if(!(promise instanceof Promise))throw new Error('Original read not retained');w.promise=promise;
      void promise.then(v=>{const accepted=this.receive(o,v);if(!accepted||!this.origin(a,accepted))this.fail('response-invalid');},e=>failed(e,false)).finally(()=>this.finish(w));
    }catch(e){failed(e,true);this.finish(w);}
  }
  canCancel():boolean{
    const o=this.original,op=o?.status?.operation,a=this.attempt,id=a?.operationId??op?.id;
    if(a&&!a.operationId)return !a.stopWanted&&!a.stopSent;
    return !!o?.live&&!!id&&(this.unknown&&!!a?.operationId||!!op&&op.phase!=='settled')&&id!==this.cancelledId&&!a?.stopSent&&![...this.work].some(w=>w.kind==='cancel');
  }
  private stopInvalidated():void{if(this.attempt?.stopWanted&&this.attempt.operationId&&this.canCancel())this.cancel();}
  cancel():void{
    const a=this.attempt;if(a&&!a.operationId){if(this.canCancel()){a.stopWanted=true;this.update();}return;}if(!this.canCancel())return;
    const o=this.original!,id=a?.operationId??o.status!.operation!.id;this.cancelledId=id;if(a)a.stopSent=true;
    const w=this.latch(o,'cancel');
    try{const promise=o.port.cancel({operationId:id});if(!(promise instanceof Promise))throw new Error('Original Stop not retained');w.promise=promise;
      void promise.then(v=>{this.receive(o,v);},()=>this.fail('response-invalid')).finally(()=>this.finish(w));}catch{this.fail('response-invalid');this.finish(w);}
  }
  dispose():void{this.disposed=true;this.desired=null;this.invalidate();this.maintain();}
}
