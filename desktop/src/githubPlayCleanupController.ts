// Presentation of the SAME native Connection/Setup calls. No HTTP, scheduler,
// cleanup executor, credential, candidate selector or new native operation owner.
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { parsePlayCleanupStatus, playCleanupError, PLAY_CLEANUP_HELP } from './githubPlayCleanupProtocol.ts';
import type { PlayCleanupAgentAccess, PlayCleanupConsent, PlayCleanupKind, PlayCleanupPending, PlayCleanupPort, PlayCleanupReason,
  PlayCleanupStatus, PlayCleanupTarget } from './githubPlayCleanupProtocol.ts';

interface Context {documentId:string;projectId:string;projectGeneration:number;repository:string;sessionId:string;accountId:string;accountLogin:string;repositoryId:string}
interface Capture {context:Context;project:ProjectSession}
interface Revocation {sessionId:string;revision:number;consent:PlayCleanupConsent}
interface Original {port:PlayCleanupPort;live:boolean;unlisten:(()=>void)|null;status:PlayCleanupStatus|null;fresh:boolean;closeCheck:object|null;revocation:Revocation|null;stopId:string|null}
interface Work {owner:Original;kind:'subscribe'|'status'|'start'|'allow'|'cancel'|'discard';ended:boolean;promise:Promise<unknown>|null}
interface Attempt {owner:Original;work:Work;capture:Capture;epoch:object;kind:PlayCleanupKind;target:PlayCleanupTarget|null;
  revision:number;previousId:string|null;operationId:string|null;marker:string|null;sent:boolean;replyOk:boolean;stopWanted:boolean;stopSent:boolean;consent:PlayCleanupConsent|null}
interface Review {owner:Original;capture:Capture;epoch:object;consent:PlayCleanupConsent}
interface Delegation {owner:Original;work:Work;review:Review;revision:number;sent:boolean;replyOk:boolean}
export interface PlayCleanupView {native:boolean;status:PlayCleanupStatus|null;confirmed:boolean;pending:boolean;allowing:boolean;
  observing:boolean;cancelling:boolean;discarding:boolean;uncertain:boolean;error:PlayCleanupReason|null;originalRepository:string|null}
function immutable<T>(v:T):T {if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.values(v).forEach(immutable);Object.freeze(v);}return v;}
function context(view:GitHubConnectionViewState):Context|null {
  const c=view.context,s=view.status,a=s?.account.value,r=s?.repository.value,session=s?.session;
  if(!c||!s||!a||!r||!session||view.mode!=='native'||view.blocked||view.uncertain||view.retirementPending||view.busy||
    session.state!=='connected'||session.projectId!==c.projectId||session.targetRepository!==c.repository||
    s.account.state!=='observed'||s.repository.state!=='observed'||r.fullName.toLowerCase()!==c.repository.toLowerCase())return null;
  return {...c,sessionId:session.id,accountId:a.id,accountLogin:a.login,repositoryId:r.id};
}
function sameCapture(a:Capture|null,b:Capture|null):boolean {return a===b||!!a&&!!b&&a.project===b.project&&same(a.context,b.context);}
function inContext(t:PlayCleanupTarget,c:Context):boolean {return t.scope.repository.toLowerCase()===c.repository.toLowerCase()&&t.scope.accountId===c.accountId&&t.scope.repositoryId===c.repositoryId;}
function sameConsent(a:PlayCleanupConsent,b:PlayCleanupConsent):boolean {return a.id===b.id&&a.expiresAt===b.expiresAt&&same(a.prepared,b.prepared);}
function advances(a:PlayCleanupStatus,b:PlayCleanupStatus):boolean {
  // Native excludes only remainingMs DATA from revision changes. Identity,
  // enabled state, original expiry and every other field must still match.
  if(a.revision===b.revision)return a.agentAccess&&b.agentAccess
    ?same(a,{...b,agentAccess:{...b.agentAccess,remainingMs:a.agentAccess.remainingMs}}):same(a,b);
  if(a.revision>b.revision||a.reason==='cleanup-unknown'||a.operation?.phase==='cleanup-unknown')return false;
  const x=a.operation,y=b.operation;
  if(x&&y?.id===x.id){
    if(x.kind!==y.kind||x.projectId!==y.projectId||!same(x.target,y.target)||
      x.phase==='settled'&&(!same(x,y)||!same(a.observed,b.observed)||a.acknowledged!==b.acknowledged||!same(a.pending,b.pending))||
      x.phase==='stopping'&&y.phase==='running'||x.effect==='potentially-applied'&&y.phase!=='settled'&&y.effect!=='potentially-applied')return false;
    // A retired consent cannot be restored by a later status of the same
    // terminal Prepare. Delegation changes only its explicit one-way flag.
    if(x.phase==='settled'&&!a.consent&&b.consent)return false;
  }else if(x&&x.phase!=='settled')return false;
  if(a.consent&&b.consent?.id===a.consent.id&&(!sameConsent(a.consent,b.consent)||a.consent.agentAllowed&&!b.consent.agentAllowed))return false;
  const p=a.agentAccess,q=b.agentAccess;
  if(p&&q?.consentId===p.consentId&&(p.projectId!==q.projectId||p.serviceInstance!==q.serviceInstance||q.remainingMs>p.remainingMs||!p.enabled&&q.enabled))return false;
  return true;
}

export class GitHubPlayCleanupController {
  private state:PlayCleanupView=immutable({native:false,status:null,confirmed:false,pending:false,allowing:false,observing:false,
    cancelling:false,discarding:false,uncertain:false,error:null,originalRepository:null});
  private listeners=new Set<()=>void>();
  private desired:PlayCleanupPort|null=null;
  private original:Original|null=null;
  private work=new Set<Work>();
  private attempt:Attempt|null=null;
  private review:Review|null=null;
  private delegation:Delegation|null=null;
  private delegatedReview:Review|null=null;
  private current:Capture|null=null;
  private epoch:object={};
  private approval:object={};
  private unknown=false;
  private cancelledId:string|null=null;
  private disposed=false;
  private readonly connection:()=>GitHubConnectionViewState;
  private readonly selectedProject:()=>ProjectSession|null;
  private readonly peer:()=>string|null;
  private readonly now:()=>number;
  constructor(connection:()=>GitHubConnectionViewState,selectedProject:()=>ProjectSession|null,
    peer:()=>string|null=()=>null,now:()=>number=Date.now) {
    this.connection=connection;this.selectedProject=selectedProject;this.peer=peer;this.now=now;
  }
  getSnapshot=():PlayCleanupView=>this.state;
  subscribe=(f:()=>void):(()=>void)=>{this.listeners.add(f);return()=>{this.listeners.delete(f);};};
  private capture():Capture|null {const c=context(this.connection()),p=this.selectedProject();return c&&p&&p.project.id===c.projectId?{context:c,project:p}:null;}
  private update(patch:Partial<PlayCleanupView>={}):void {
    this.state=immutable({...this.state,...patch,pending:this.attempt!==null,allowing:this.delegation!==null,
      observing:[...this.work].some(w=>w.kind==='status'||w.kind==='subscribe'),cancelling:[...this.work].some(w=>w.kind==='cancel'),
      discarding:[...this.work].some(w=>w.kind==='discard')});
    for(const f of [...this.listeners]){try{f();}catch{/* A view cannot disown a native caller. */}}
  }
  private fail(reason:PlayCleanupReason):void {if(this.unknown){this.update();return;}this.unknown=true;this.review=null;this.update({uncertain:true,confirmed:false,error:reason});}
  private invalidate():void {this.epoch={};this.review=null;this.delegatedReview=null;if(this.attempt)this.attempt.stopWanted=true;this.update({confirmed:false});this.stopInvalidated();}
  beforeWorkspaceAction():void {if(!this.disposed)this.invalidate();}
  syncContext=():void=>{if(this.disposed)return;const c=this.capture();if(!sameCapture(c,this.current)){this.current=c;this.invalidate();}};
  setConfirmed(value:boolean):void {if(!this.disposed){this.approval={};this.update({confirmed:value===true&&this.currentConsent()!==null});}}
  private owns(o:Original):boolean {return this.unknown||o.closeCheck!==null||this.attempt?.owner===o||this.delegation?.owner===o||
    [...this.work].some(w=>w.owner===o)||!!o.status?.consent||!!o.status?.operation&&o.status.operation.phase!=='settled';}
  private maintain():void {
    const old=this.original;
    if(old&&(this.desired!==old.port||this.disposed)){
      if(this.owns(old))return;
      const unlisten=old.unlisten;old.unlisten=null;old.live=false;
      try{unlisten?.();}catch{this.fail('cleanup-unknown');return;}this.original=null;
    }
    if(this.original||this.disposed||!this.desired)return;
    const o:Original={port:this.desired,live:true,unlisten:null,status:null,fresh:false,closeCheck:null,revocation:null,stopId:null};this.original=o;
    const w=this.latch(o,'subscribe');
    try{
      const promise=o.port.subscribe(v=>{this.receive(o,v);});if(!(promise instanceof Promise))throw Error('Missing subscription');w.promise=promise;
      void promise.then(stop=>{if(typeof stop!=='function'){this.fail('response-invalid');return;}o.unlisten=stop;},()=>this.fail('runtime-unavailable'))
        .finally(()=>{this.finish(w);if(this.original===o&&o.live&&o.port===this.desired&&!this.disposed&&!this.unknown)this.checkStatus();});
    }catch{this.fail('response-invalid');this.finish(w);}
  }
  connect(port:PlayCleanupPort|null):void {if(this.disposed||this.desired===port)return;this.desired=port;this.syncContext();this.invalidate();this.update({native:port!==null});this.maintain();}
  private latch(owner:Original,kind:Work['kind']):Work {const w:Work={owner,kind,ended:false,promise:null};this.work.add(w);this.update();return w;}
  private finish(w:Work):void {w.ended=true;w.promise=null;this.work.delete(w);this.settle();this.update();this.maintain();}
  private origin(a:Attempt,s:PlayCleanupStatus):boolean {
    const o=s.operation,c=a.capture.context;
    return a.sent&&s.revision>a.revision&&s.sessionId===c.sessionId&&!!o&&o.id!==a.previousId&&(!a.operationId||o.id===a.operationId)&&
      o.projectId===c.projectId&&o.kind===a.kind&&inContext(o.target,c)&&(a.target===null||same(o.target,a.target))&&
      (a.marker===null||a.marker===o.target.marker)&&(a.consent===null||same(o.target,a.consent.prepared.target));
  }
  private receive(o:Original,raw:unknown):PlayCleanupStatus|null {
    if(o!==this.original||!o.live)return null;
    const next=parsePlayCleanupStatus(raw);
    if(o!==this.original||!o.live)return null; // Even descriptor traps can reenter navigation.
    if(!next){this.fail('response-invalid');return null;}
    let s=immutable(next);
    if(this.unknown){
      // Status can recover only the original Stop/withdrawal address. Never
      // replace an uncertain result, restore consent, free admission or retry.
      const a=this.attempt;
      if(a?.owner===o&&this.origin(a,s)&&a.operationId===null){a.operationId=s.operation!.id;a.target=s.operation!.target;}
      const r=o.revocation;
      if(r&&s.sessionId===r.sessionId&&s.revision>=r.revision&&s.consent&&sameConsent(r.consent,s.consent))
        o.revocation={...r,revision:s.revision};
      const d=this.delegation;
      if(d?.sent&&d.owner===o&&s.revision>d.revision&&s.sessionId===d.review.capture.context.sessionId&&s.operation?.kind==='dispatch'&&
        s.operation.projectId===d.review.capture.context.projectId&&same(s.operation.target,d.review.consent.prepared.target)&&
        (o.stopId===null||o.stopId===s.operation.id))o.stopId=s.operation.id;
      this.update();this.stopInvalidated();return null;
    }
    const old=o.status;
    if(old&&s.revision<old.revision){if(!advances(s,old)){this.fail('response-invalid');return null;}}
    else {
      if(old&&!advances(old,s)){this.fail('response-invalid');return null;}
      // An earlier Doc-locked Allow/read reply may arrive after a countdown
      // update at the same revision. Retain the minimum actually observed;
      // it cannot renew a grant or replace its original native expiry.
      if(old&&old.revision===s.revision&&old.agentAccess&&s.agentAccess&&s.agentAccess.remainingMs>old.agentAccess.remainingMs)s=old;
      o.status=s;o.fresh=o.closeCheck===null;
      o.revocation=s.consent&&s.sessionId?{sessionId:s.sessionId,revision:s.revision,consent:s.consent}:null;
      if(s.reason==='cleanup-unknown'||s.operation?.phase==='cleanup-unknown'){
        const a=this.attempt;if(a?.owner===o&&this.origin(a,s)){a.operationId=s.operation!.id;a.target=s.operation!.target;}
        this.update({status:s});this.fail('cleanup-unknown');this.stopInvalidated();return s;
      }
      if(this.review&&!same(s.consent,this.review.consent)){this.review=null;this.update({confirmed:false});}
      this.update({status:s,error:this.attempt||this.delegation||o.closeCheck?this.state.error:s.operation?.reason&&s.operation.reason!=='none'?s.operation.reason:null});
    }
    const a=this.attempt;if(a?.owner===o&&this.origin(a,s)){a.operationId=s.operation!.id;a.target=s.operation!.target;}
    this.settle();this.stopInvalidated();return s;
  }
  private settle():void {
    const a=this.attempt,s=a?.owner.status;
    if(a&&s&&a.work.ended&&this.origin(a,s)&&s.operation?.phase==='settled'&&!this.unknown){
      this.attempt=null;
      if(a.kind==='prepare'&&a.replyOk&&s.consent&&!s.consent.agentAllowed&&a.epoch===this.epoch&&a.owner.port===this.desired&&!this.disposed&&
        sameCapture(a.capture,this.capture())&&s.consent.prepared.accountLogin===a.capture.context.accountLogin)
        this.review={owner:a.owner,epoch:a.epoch,capture:a.capture,consent:s.consent};
      this.update({uncertain:false,error:s.operation.reason==='none'?null:s.operation.reason});
    }
    const d=this.delegation;
    if(d&&d.work.ended&&d.replyOk&&!this.unknown){
      const s=d.owner.status;
      if(d.review.epoch===this.epoch&&!this.disposed&&d.owner.port===this.desired&&sameCapture(d.review.capture,this.capture())&&
        s?.consent?.agentAllowed&&sameConsent(s.consent,d.review.consent))this.delegatedReview=d.review;
      this.delegation=null;this.update();
    }
  }
  canCheck():boolean {const o=this.original;return !!o?.live&&(!this.disposed||this.owns(o))&&![...this.work].some(w=>w.owner===o&&(w.kind==='status'||w.kind==='subscribe'));}
  checkStatus():void {
    if(!this.canCheck())return;const o=this.original!,closeCheck=o.closeCheck,w=this.latch(o,'status');
    const failed=()=>{o.fresh=false;this.update({error:'response-invalid',uncertain:this.state.uncertain||!!this.attempt||!!this.delegation||!!o.status?.operation&&o.status.operation.phase!=='settled'});};
    try{
      const promise=o.port.status();if(!(promise instanceof Promise))throw Error('Missing Status');w.promise=promise;
      void promise.then(v=>{
        const parsed=parsePlayCleanupStatus(v),accepted=this.receive(o,parsed);
        if(accepted&&!this.unknown&&o===this.original&&o.live&&closeCheck!==null&&o.closeCheck===closeCheck&&o.status&&accepted.revision===o.status.revision){
          o.closeCheck=null;o.fresh=true;this.update({error:o.status.operation?.reason&&o.status.operation.reason!=='none'?o.status.operation.reason:null});
        }
        // Under unknown, a genuinely later Check may refresh only the exact
        // retained withdrawal address after a known Close refusal.
        if(this.unknown&&parsed&&closeCheck!==null&&o.closeCheck===closeCheck&&o===this.original&&o.live&&
          o.revocation&&parsed.sessionId===o.revocation.sessionId&&parsed.revision===o.revocation.revision&&
          parsed.consent&&sameConsent(parsed.consent,o.revocation.consent)){o.closeCheck=null;this.update();}
      },failed).finally(()=>this.finish(w));
    }catch{failed();this.finish(w);}
  }
  currentConsent():PlayCleanupConsent|null {
    const r=this.review,o=this.original;
    return r&&o&&!this.unknown&&!this.disposed&&r.owner===o&&o.port===this.desired&&o.fresh&&r.epoch===this.epoch&&
      sameCapture(this.capture(),r.capture)&&same(o.status?.consent,r.consent)&&!r.consent.agentAllowed&&this.now()<Date.parse(r.consent.expiresAt)?r.consent:null;
  }
  currentAgentAccess():PlayCleanupAgentAccess|null {
    const o=this.original,s=o?.status,c=this.capture(),r=this.delegatedReview;
    return o&&!this.unknown&&!this.disposed&&!this.delegation&&!this.work.size&&o.port===this.desired&&o.fresh&&c&&
      r&&r.owner===o&&r.epoch===this.epoch&&sameCapture(r.capture,c)&&
      s?.consent?.agentAllowed&&s.agentAccess?.enabled&&s.sessionId===c.context.sessionId&&inContext(s.consent.prepared.target,c.context)&&
      sameConsent(r.consent,s.consent)&&this.now()<Date.parse(s.consent.expiresAt)?s.agentAccess:null;
  }
  ownerReason():string|null {
    if(this.unknown)return PLAY_CLEANUP_HELP['cleanup-unknown'];
    if(this.attempt||this.delegation||this.work.size||this.original?.status?.operation&&this.original.status.operation.phase!=='settled')
      return 'The original Google Play cleanup task is still active. Check status or Stop it before another task.';
    if(this.original?.closeCheck)return 'Check task status to refresh the original review. Close has not been repeated.';
    if(this.original?.status?.consent)return 'Run, delegate or close the original cleanup review before another task.';
    return null;
  }
  private startReason():string|null {
    const o=this.original,c=this.capture(),s=o?.status;
    if(this.disposed||!o?.live||o.port!==this.desired||!o.unlisten)return PLAY_CLEANUP_HELP['runtime-unavailable'];
    if(this.unknown)return PLAY_CLEANUP_HELP['cleanup-unknown'];
    if(this.attempt||this.delegation||this.work.size||s?.operation&&s.operation.phase!=='settled')return 'Wait for the original request to finish; status and Stop stay available.';
    if(!c||this.connection().observing)return PLAY_CLEANUP_HELP['not-connected'];
    const p=c.project;
    if(p.saveRecoveryRequired||p.saveRecoveryNeedsReload||p.sourceChanged||p.snapshotPredatesSave||p.snapshotRequest!==null||!p.savedConfigContent)
      return 'Read the current saved project and resolve any recovery first. The original cleanup controls remain available.';
    if(isDirty(p))return 'Review and save the current Settings draft first; cleanup uses saved configuration, not unsaved edits.';
    if(!s||!o.fresh||s.sessionId!==c.context.sessionId)return 'Check the current cleanup task status first.';
    if(s.consent&&!this.currentConsent())return s.consent.agentAllowed?'This cleanup is delegated to the CLI. Revoke permission before a new review.':'Close the previous or expired review before preparing another.';
    if(!s.available)return PLAY_CLEANUP_HELP[s.reason];return this.peer();
  }
  prepareReason():string|null {return this.startReason()??(this.currentConsent()?'Run, delegate or close the current review first.':null);}
  dispatchReason():string|null {return this.startReason()??(!this.currentConsent()?'Review this saved project’s previous draft first.':!this.state.confirmed?'Confirm the cleanup and its workflow effects below.':null);}
  allowAgentReason():string|null {return this.dispatchReason();}
  pendingReason():string|null {return this.startReason()??(this.currentConsent()?'Close this review before checking previous requests.':null);}
  observeReason(row:PlayCleanupPending):string|null {
    const blocked=this.pendingReason();if(blocked)return blocked;const c=this.capture();
    return c&&this.original?.status?.pending.includes(row)&&inContext(row.prepared.target,c.context)?null:'Read this repository’s saved cleanup request first; an older row cannot select a replacement.';
  }
  private begin(kind:PlayCleanupKind,marker:string|null,invoke:(p:PlayCleanupPort,a:Attempt,connectionRevision:number)=>Promise<unknown>,row:PlayCleanupPending|null=null):void {
    if(kind==='prepare'?this.prepareReason():kind==='dispatch'?this.dispatchReason():kind==='pending'?this.pendingReason():!row||this.observeReason(row))return;
    const o=this.original,c=this.capture(),s=o?.status,source=this.connection(),epoch=this.epoch,consent=this.currentConsent(),approval=this.approval;
    if(!o||!c||!s||!source.status||kind==='dispatch'&&(!consent||!this.state.confirmed))return;
    const connectionRevision=source.status.revision;
    const selected=kind==='observe'?row:null;
    const w:Work={owner:o,kind:'start',ended:false,promise:null};this.work.add(w);
    const a:Attempt={owner:o,work:w,capture:c,epoch,kind,target:kind==='dispatch'?consent!.prepared.target:selected?.prepared.target??null,
      revision:s.revision,previousId:s.operation?.id??null,operationId:null,marker,sent:false,replyOk:false,stopWanted:false,stopSent:false,
      consent:kind==='dispatch'?consent:null};
    this.attempt=a;this.review=null;this.update({confirmed:false,error:null,originalRepository:c.context.repository});
    const peer=this.peer();
    if(this.attempt!==a||a.stopWanted||kind==='dispatch'&&approval!==this.approval||this.epoch!==epoch||o!==this.original||o.port!==this.desired||
      this.disposed||this.unknown||o.status!==s||!o.fresh||peer||!sameCapture(c,this.capture())||connectionRevision!==this.connection().status?.revision||
      kind==='dispatch'&&this.now()>=Date.parse(consent!.expiresAt)){
      this.attempt=null;this.update({error:a.stopWanted?'cancelled':'target-changed'});this.finish(w);return;
    }
    a.sent=true;
    const failed=(error:unknown,sync:boolean)=>{
      const parsed=playCleanupError(error);
      if(!sync&&parsed.notAdmitted&&this.attempt===a&&a.operationId===null&&!this.unknown){this.attempt=null;o.fresh=false;this.update({error:parsed.reason});}
      else this.fail(parsed.reason);
    };
    try{
      const promise=invoke(o.port,a,connectionRevision);if(!(promise instanceof Promise))throw Error('Missing original request');w.promise=promise;
      void promise.then(v=>{const accepted=this.receive(o,v);a.replyOk=accepted!==null&&this.origin(a,accepted);if(!a.replyOk)this.fail('response-invalid');},e=>failed(e,false)).finally(()=>this.finish(w));
    }catch(e){failed(e,true);this.finish(w);}
  }
  prepare():void {this.begin('prepare',null,(p,a,expectedConnectionRevision)=>p.prepare({sessionId:a.capture.context.sessionId,expectedRevision:a.revision,expectedConnectionRevision}));}
  dispatch():void {const c=this.currentConsent();if(!c||this.dispatchReason())return;this.begin('dispatch',c.prepared.target.marker,(p,a)=>p.start({sessionId:a.capture.context.sessionId,expectedRevision:a.revision,consentId:a.consent!.id,confirm:true}));}
  loadPending():void {this.begin('pending',null,(p,a,expectedConnectionRevision)=>p.pending({sessionId:a.capture.context.sessionId,expectedRevision:a.revision,expectedConnectionRevision}));}
  observe(row:PlayCleanupPending):void {this.begin('observe',row.prepared.target.marker,(p,a)=>p.observe({sessionId:a.capture.context.sessionId,expectedRevision:a.revision,marker:a.marker!}),row);}
  allowAgent():void {
    if(this.allowAgentReason())return;
    const r=this.review,o=this.original,s=o?.status,source=this.connection(),epoch=this.epoch,approval=this.approval;
    if(!r||!o||!s||!source.status||!this.currentConsent())return;
    const connectionRevision=source.status.revision,w:Work={owner:o,kind:'allow',ended:false,promise:null};this.work.add(w);
    const d:Delegation={owner:o,work:w,review:r,revision:s.revision,sent:false,replyOk:false};this.delegation=d;this.review=null;
    this.update({confirmed:false,error:null});const peer=this.peer();
    if(this.delegation!==d||o!==this.original||o.port!==this.desired||this.disposed||this.unknown||this.epoch!==epoch||approval!==this.approval||
      o.status!==s||!o.fresh||peer||!sameCapture(r.capture,this.capture())||connectionRevision!==this.connection().status?.revision||this.now()>=Date.parse(r.consent.expiresAt)){
      this.delegation=null;this.update({error:'target-changed'});this.finish(w);return;
    }
    d.sent=true;
    try{
      const promise=o.port.allowAgent({sessionId:r.capture.context.sessionId,expectedRevision:s.revision,consentId:r.consent.id,confirm:true});
      if(!(promise instanceof Promise))throw Error('Missing original Allow');w.promise=promise;
      void promise.then(v=>{
        const accepted=this.receive(o,v);
        // Native copies this SAME consent/access under its original Doc lock.
        // A newer event may already show CLI consumption; never restore it.
        d.replyOk=!!accepted&&accepted.revision>d.revision&&accepted.sessionId===r.capture.context.sessionId&&
          !!accepted.consent&&sameConsent(accepted.consent,r.consent)&&accepted.consent.agentAllowed&&!!accepted.agentAccess;
        if(!d.replyOk)this.fail('response-invalid');
      },e=>this.fail(playCleanupError(e).reason)).finally(()=>this.finish(w));
    }catch(e){this.fail(playCleanupError(e).reason);this.finish(w);}
  }
  canCancel():boolean {
    const o=this.original,op=o?.status?.operation,a=this.attempt;
    if(a&&!a.operationId)return !a.stopWanted&&!a.stopSent;
    const id=a?.operationId??o?.stopId??op?.id;
    return !!o?.live&&!!id&&(this.unknown&&(!!a?.operationId||!!o.stopId)||!!op&&op.phase!=='settled')&&id!==this.cancelledId&&
      ![...this.work].some(w=>w.kind==='cancel')&&!a?.stopSent;
  }
  private stopInvalidated():void {if(this.attempt?.stopWanted&&this.attempt.operationId&&this.canCancel())this.cancel();}
  cancel():void {
    const a=this.attempt;if(a&&!a.operationId){a.stopWanted=true;this.update();return;}if(!this.canCancel())return;
    const o=this.original!,id=a?.operationId??o.stopId??o.status!.operation!.id;this.cancelledId=id;if(a)a.stopSent=true;
    const w=this.latch(o,'cancel');
    try{const promise=o.port.cancel({operationId:id});if(!(promise instanceof Promise))throw Error('Missing original Stop');w.promise=promise;
      void promise.then(v=>{this.receive(o,v);},()=>this.fail('response-invalid')).finally(()=>this.finish(w));
    }catch{this.fail('response-invalid');this.finish(w);}
  }
  canDiscard():boolean {
    const o=this.original;return !!o?.live&&!!o.revocation&&o.closeCheck===null&&!this.attempt&&
      ![...this.work].some(w=>w.kind==='start'||w.kind==='discard')&&(this.unknown||o.fresh)&&o.status?.operation?.phase==='settled';
  }
  discardReview():void {
    if(!this.canDiscard())return;const o=this.original!,r=o.revocation!;
    this.review=null;this.epoch={};this.state=immutable({...this.state,confirmed:false});const w=this.latch(o,'discard');
    const failed=(e:unknown,sync:boolean)=>{
      const parsed=playCleanupError(e);
      if(!sync&&parsed.notAdmitted){o.closeCheck={};o.fresh=false;this.update({error:parsed.reason});}else this.fail(parsed.reason);
    };
    try{
      const promise=o.port.discard({sessionId:r.sessionId,expectedRevision:r.revision,consentId:r.consent.id});
      if(!(promise instanceof Promise))throw Error('Missing original Close');w.promise=promise;
      void promise.then(v=>{
        const parsed=parsePlayCleanupStatus(v);
        if(!parsed||parsed.sessionId!==r.sessionId||parsed.revision<=r.revision||parsed.consent!==null||parsed.agentAccess!==null||
          parsed.operation?.id!==o.status?.operation?.id||parsed.operation?.kind!=='prepare'||parsed.operation.phase!=='settled'||
          !same(parsed.operation.target,r.consent.prepared.target)){this.fail('response-invalid');return;}
        this.receive(o,parsed);
        // A known withdrawal ends only this consent's revocation route. Lost
        // Allow/Start and their unknown ownership are deliberately not cleared.
        if(o.revocation?.consent.id===r.consent.id)o.revocation=null;
      },e=>failed(e,false)).finally(()=>this.finish(w));
    }catch(e){failed(e,true);this.finish(w);}
  }
  dispose():void {this.disposed=true;this.desired=null;this.invalidate();this.maintain();}
}
