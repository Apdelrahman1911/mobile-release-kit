// App-retained continuation, not a native owner. Only an actual current image
// controller candidate can dispatch; events/IDs never manufacture one.
import { parseImagesPreparationStatus, sameImagesReadOriginal } from './serviceMetadataImagesPrepareProtocol.ts';
import type { ImagesPreparationStatus, ImagesReadOriginal, ImagesReadObservation, ImagesPrepareChoice, MetadataImagesPrepareApi } from './serviceMetadataImagesPrepareProtocol.ts';
import { sameImagesAgentOrigin } from './serviceMetadataImagesProtocol.ts';
import type { ImagesAgentOrigin } from './serviceMetadataImagesProtocol.ts';
export interface ImagePreparationCandidate {
  api:MetadataImagesPrepareApi; projectId:string; original:ImagesReadOriginal; remainingMs:number;
  same():boolean; pristine():boolean; matches(o:ImagesReadObservation):boolean;
  prepare(q:ImagesAgentOrigin,choices:readonly ImagesPrepareChoice[]):Promise<boolean>;
  nativeReady(s:ImagesPreparationStatus):boolean; nativeFinal():boolean;
}
interface Held { candidate:ImagePreparationCandidate|null; status:ImagesPreparationStatus; readStarted:boolean; readReturned:boolean;
  prepareStarted:boolean; prepareReturned:boolean; cancelStarted:boolean; unknown:boolean; end:number; }
interface Work { start:number; api:MetadataImagesPrepareApi; promise:Promise<void> }
export interface ImagesPreparationView { status:ImagesPreparationStatus|null; pending:boolean; error:string|null }
export class ServiceMetadataImagesPrepareController {
 private api:MetadataImagesPrepareApi|null=null;private held:Held|null=null;private read:Work|null=null;private calls=new Set<Work>();
 private listeners=new Set<()=>void>();private unlisten:(()=>void)|null=null;private disposed=false;private timer:ReturnType<typeof setTimeout>|null=null;
 private view:ImagesPreparationView=Object.freeze({status:null,pending:false,error:null});
 private readonly candidate:()=>ImagePreparationCandidate|null;private readonly now:()=>number;
 constructor(candidate:()=>ImagePreparationCandidate|null,now:()=>number){this.candidate=candidate;this.now=now;}
 getSnapshot=():ImagesPreparationView=>this.view;
 subscribe=(f:()=>void):(()=>void)=>{this.listeners.add(f);return()=>{this.listeners.delete(f);};};
 private publish(error=this.view.error):void{this.view=Object.freeze({status:this.held?.status??null,pending:this.calls.size>0||this.read!==null,error});for(const f of this.listeners)f();}
 async connect(api?:MetadataImagesPrepareApi):Promise<void>{
  if(this.disposed||this.api===api)return;
  if(this.hasPendingCalls()||this.retains()){this.sourceChanged();return;}
  this.unlisten?.();this.unlisten=null;this.api=api??null;if(!api)return;
  try{const stop=await api.subscribe(v=>{if(this.api===api&&!this.disposed)this.receive(v);});if(this.api!==api||this.disposed){stop();return;}this.unlisten=stop;}
  catch{this.publish('Image request notifications are unavailable. Use Check on the original request.');}
  await this.check();
 }
 hasPendingCalls():boolean{return this.calls.size>0||this.read!==null;}
 retains():boolean {const h=this.held;return this.hasPendingCalls()||!!h&&(h.unknown||h.status.settlement==='unknown'||h.status.phase!=='final'&&h.status.phase!=='transferred');}
 newOriginal():boolean{if(this.retains())return false;this.held=null;this.publish(null);return true;}
 approvalReady():boolean {const h=this.held;return !this.hasPendingCalls()&&(!h||!h.prepareStarted||h.prepareReturned&&!h.unknown&&h.status.phase==='reviewing'&&!!h.candidate?.nativeReady(h.status)||h.status.phase==='transferred'||h.status.phase==='final');}
 private resolved(h:Held):boolean{return !h.unknown&&h.status.phase==='final'&&h.status.settlement==='settled'&&this.calls.size===0&&(!h.readStarted||h.readReturned)&&(!h.prepareStarted||h.prepareReturned&&!!h.candidate?.nativeFinal());}
 private accept(raw:unknown,h?:Held):boolean {
  const s=parseImagesPreparationStatus(raw);if(!s){if(h)h.unknown=true;this.publish('Image preparation reply is unconfirmed. Keep the original request.');return false;}
  if(h){if(this.held!==h||!sameImagesAgentOrigin(h.status.origin,s.origin)||s.revision<h.status.revision)return false;
   if(s.revision===h.status.revision&&JSON.stringify({...s,remainingMs:0})!==JSON.stringify({...h.status,remainingMs:0})){h.unknown=true;this.publish('Conflicting original image request.');return false;}
   if(h.status.settlement==='unknown'&&s.settlement!=='unknown'){h.unknown=true;return false;}h.status=s;
  }else{this.held={candidate:null,status:s,readStarted:false,readReturned:false,prepareStarted:false,prepareReturned:false,cancelStarted:false,unknown:s.settlement==='unknown',end:Infinity};}
  this.publish();return true;
 }
 private receive(raw:unknown):void {
  const s=parseImagesPreparationStatus(raw);if(!s)return;
  const h=this.held;
  if(h&&!sameImagesAgentOrigin(h.status.origin,s.origin)){
   // Resolve the ORIGINAL native and actual callers first. A coalesced latest
   // notification is only a hint; Check obtains one fresh latest afterward.
   void this.check();return;
  }
  if(!this.accept(s,h??undefined))return;
  this.arm();this.drive();
 }
 check():Promise<void>{
  if(this.read)return this.read.promise;const api=this.api;if(!api||this.disposed)return Promise.resolve();
  const h=this.held;const work:Work={start:this.now(),api,promise:Promise.resolve()};this.read=work;
  work.promise=Promise.resolve().then(async()=>{
   if(this.api!==api||this.disposed)return;
   const s=await api.status(h?.status.origin);
   if(this.api!==api||this.read!==work)return;
   if(h){if(s!==null){if(this.accept(s,h))this.shrink(h,work,s);}else{h.unknown=true;this.publish('The original image request was not returned.');}
    if(s!==null&&this.held===h&&this.resolved(h)){
     // One truly later read, never a cold event or missing old result.
     const latest=await api.status();if(this.api!==api||this.read!==work||this.held!==h||!this.resolved(h))return;
     if(latest&&!sameImagesAgentOrigin(latest.origin,h.status.origin))this.accept(latest);
    }
   }else if(s!==null&&this.held===null)this.accept(s);
  }).catch(()=>{if(h&&this.held===h)h.unknown=true;this.publish('Image preparation status unavailable. Check the same request; do not resend.');})
   .finally(()=>{if(this.read===work)this.read=null;this.publish();this.drive();this.release();});
  this.publish();return work.promise;
 }
 private work(h:Held,fn:(w:Work)=>Promise<void>):void{
  const api=this.api;if(!api)return;const w:Work={start:this.now(),api,promise:Promise.resolve()};this.calls.add(w);this.publish();
  w.promise=Promise.resolve().then(()=>fn(w)).catch(()=>{h.unknown=true;this.publish('The original caller did not return a confirmed image preparation.');})
   .finally(()=>{this.calls.delete(w);this.publish();this.drive();this.release();});
 }
 private shrink(h:Held,w:Work,s:ImagesPreparationStatus):void {
  h.end=Math.min(h.end,w.start+s.remainingMs);this.arm();
 }
 private arm():void {if(this.timer!==null)clearTimeout(this.timer);this.timer=null;const h=this.held;
  if(!h||!Number.isFinite(h.end)||h.status.phase==='transferred'||h.status.phase==='final'||h.unknown)return;
  const left=h.end-this.now();if(left<=0){this.cancel();return;}
  this.timer=setTimeout(()=>{this.timer=null;if(this.held===h)this.cancel();},Math.min(left,2147483647));
 }
 private drive():void {
  const h=this.held,api=this.api;if(this.disposed||!h||!api||this.calls.size||this.read||h.unknown)return;
  if(h.status.phase==='queued-read'&&!h.readStarted){
   const c=this.candidate();
   if(!c||c.api!==api||c.projectId!==h.status.runtimeProjectId||!c.pristine()){
    this.publish('Choose images with “Enable CLI preparation” before Open; keep the untouched current selection. Otherwise use the ordinary editor.');this.cancel();return;
   }
   h.candidate=c;h.readStarted=true;h.end=this.now()+c.remainingMs;
   this.work(h,async w=>{
    if(this.disposed||this.held!==h||this.api!==api||!c.same()||!c.pristine()){this.cancel();return;}
    const s=await api.inspect(h.status.origin,c.original);h.readReturned=true;
    if(this.held!==h||this.api!==api)return;
    if(s.observation&&(!sameImagesReadOriginal(s.observation.original,c.original)||!c.matches(s.observation))){h.unknown=true;this.publish('The native observation differs from the captured selection.');return;}
    if(this.accept(s,h))this.shrink(h,w,s);
   });return;
  }
  if(h.status.phase==='queued-prepare'&&h.readReturned&&!h.prepareStarted){
   const c=h.candidate,choices=h.status.choices;
   if(!c||!choices||!c.same()||!c.pristine()||this.now()>=h.end){this.cancel();return;}
   h.prepareStarted=true;
   this.work(h,async w=>{
    if(this.disposed||this.held!==h||this.api!==api||!c.same()||!c.pristine()||this.now()>=h.end){this.cancel();return;}
    const ok=await c.prepare(h.status.origin,choices);h.prepareReturned=true;
    if(!ok){this.cancel();return;}
    // This is after THAT actual Prepare Promise, not prepare()'s bool/event.
    const s=await api.status(h.status.origin);if(this.held!==h||this.api!==api)return;
    if(s&&this.accept(s,h))this.shrink(h,w,s);else{h.unknown=true;this.publish('Original Prepare status was not returned.');}
   });return;
  }
 }
 sourceChanged():void {const h=this.held;if(!h||h.status.phase==='transferred'||h.status.phase==='final')return;
  if(h.candidate&&(!h.candidate.same()||!h.prepareStarted&&!h.candidate.pristine()))this.cancel();
 }
 cancel=():void=>{const h=this.held,api=this.api;if(!h||!api||h.cancelStarted||h.status.phase==='transferred'||h.status.phase==='final')return;
  h.cancelStarted=true;
  this.work(h,async()=>{const s=await api.cancel(h.status.origin);if(this.held===h&&this.api===api)this.accept(s,h);});
 };
 private release():void{if(!this.disposed||this.hasPendingCalls())return;this.unlisten?.();this.unlisten=null;}
 dispose():void{if(this.disposed)return;this.cancel();this.disposed=true;if(this.timer!==null)clearTimeout(this.timer);this.timer=null;this.release();this.listeners.clear();}
}
