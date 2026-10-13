//! One fixed, native-notice-triggered removal peer, subordinate to Document.
//! The notice/id/request are DATA. Only the SAME authenticated native channel,
//! retired main confirmation and private Saved Completion can reach QuitReady.
//! There is no renderer command, independent scheduler, service action or writer.
use super::*;
use std::{cell::{Cell,RefCell}, mem::{size_of,size_of_val}, os::fd::BorrowedFd,
    panic::{catch_unwind,AssertUnwindSafe}, sync::{OnceLock,TryLockError}, task::Wake};
use mrk_macos_installed_native::{self as native, android_registration::RemovalClock,
    android_service_management::Decision, install_producer::{RemovalProducerVerifier,ProducerCheckpoint,SignatureResult},
    removal_coordinator as peer_native};
use crate::{installed_runtime::{AppRemovalWorkGate,AppRemovalCleanup,AdmissionFailure,
    RemovalRequestOriginal,RemovalProducerAdmission,RemovalCurrent},
    macos_remove_protocol as wire, macos_remove_producer::RemovalData,
    saved_command_owner::{MacosRemovalPrompt,MacosRemovalConfirmed,MacosMaintenanceHandle,
        MacosMaintenanceCompletion,MacosMaintenancePhase,AndroidServiceDispatcher}};

const LOCAL_WORK:Duration=Duration::from_secs(300);
const LOCAL_HARD:Duration=Duration::from_secs(310);
const TAIL:Duration=Duration::from_secs(10);
const HEARTBEAT:Duration=Duration::from_millis(5);
const TASK_STORAGE:usize=64*1024;
const SIGNAL_STORAGE:usize=4096;
const INSPECTOR_RESERVE:usize=16*1024*1024;
const ENTRY:&str="app/Contents/MacOS/mrk-macos-entry";
const PAYLOAD:&str="app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop";
const REMOVER:&str="app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-macos-remove";
type Flow<T>=std::result::Result<T,()>;

fn unavailable()->BridgeError{super::macos_maintenance::unavailable()}
fn arc_bytes<T>()->Option<usize>{
    let(layout,_)=std::alloc::Layout::new::<[usize;2]>().extend(std::alloc::Layout::new::<T>()).ok()?;
    Some(layout.pad_to_align().size())
}
fn fits(prior:usize,reserved:usize)->bool{prior.checked_add(reserved).is_some_and(|n|n<=SESSION_BYTES)}
fn first(a:Option<(AdmissionFailure,Instant)>,b:Option<(AdmissionFailure,Instant)>)->Option<(AdmissionFailure,Instant)>{
    match(a,b){(Some(a),Some(b))=>Some(if a.1<=b.1{a}else{b}),(a,None)|(None,a)=>a}
}

/// Fixed DATA decisions used by admission, not a transferable owner proof.
#[derive(Default)]
pub(super) struct HintState{current:Option<[u8;16]>,last:Option<[u8;16]>,generation:u32}
impl HintState{
    pub(super) fn admit(&mut self,id:[u8;16])->Option<u32>{
        if id==[0;16]||self.current.is_some()||self.last==Some(id){return None;}
        let generation=self.generation.checked_add(1).filter(|g|*g<u32::MAX)?;
        self.generation=generation;self.current=Some(id);self.last=Some(id);Some(generation)
    }
    pub(super) fn retire(&mut self,id:[u8;16],generation:u32,known:bool)->bool{
        if !known||self.current!=Some(id)||self.generation!=generation{return false;}
        self.current=None;true
    }
}

/// Only Send/private DATA cross the existing main/relay/worker boundaries.
/// Native peer, current-source cells and every FD remain on the original worker.
#[derive(Default,Clone,Copy,Debug,PartialEq,Eq)]
struct HandoffData{confirmed:bool,taken:bool,saved:bool,completion:bool}
impl HandoffData{
    fn confirmed(&mut self)->bool{if *self!=Self::default(){return false;}self.confirmed=true;true}
    fn take(&mut self)->bool{if !self.confirmed||self.taken{return false;}self.taken=true;true}
    fn bind(&mut self)->bool{if !self.taken||self.saved{return false;}self.saved=true;true}
    fn complete(&mut self)->bool{if !self.saved||self.completion{return false;}self.completion=true;true}
}
struct Offers{
    confirmed:Option<MacosRemovalConfirmed>,state:HandoffData,
    saved:Option<MacosMaintenanceHandle>,completion:Option<MacosMaintenanceCompletion>,
}
impl Offers{fn new()->Self{Self{confirmed:None,state:HandoffData::default(),saved:None,completion:None}}}
fn resources_data(signature:bool,inspector:bool,request:bool,cut:bool,unknown:bool)->bool{
    signature&&inspector&&request&&cut&&!unknown
}
fn joined_data_only(unknown:bool,worker:bool,coordinator:bool,main:bool,returned:bool)->bool{
    !unknown&&worker&&coordinator&&main&&returned
}
struct Original{
    document:Weak<Inner>,identity:Weak<()>,id:[u8;16],generation:u32,
    pickers:[Option<Arc<OriginalWork>>;3],source_generation:u32,
    admitted:Instant,work:Instant,hard:Instant,stop:watch::Sender<bool>,first:Mutex<Option<(AdmissionFailure,Instant)>>,
    unknown:AtomicBool,clock:OnceLock<Arc<RemovalClock>>,source:OnceLock<AppRemovalWorkGate>,
    dispatcher:Arc<AndroidServiceDispatcher>,prompt:OnceLock<Arc<MacosRemovalPrompt>>,offers:Mutex<Offers>,
    reservation:usize,whole:usize,
    worker:AsyncMutex<Option<JoinHandle<WorkerReturn>>>,returned:Mutex<Option<std::result::Result<WorkerReturn,tokio::task::JoinError>>>,
    worker_joined:AtomicBool,coordinator:Mutex<Option<JoinHandle<bool>>>,
    coordinator_return:Mutex<Option<std::result::Result<bool,tokio::task::JoinError>>>,coordinator_joined:AtomicBool,
    final_at:OnceLock<Instant>,ready_taken:AtomicBool,
    // A wrapper-observed Instant is retained as such, never converted to a
    // historical Parent stamp. Raw native first-F stays in this exact custody.
    peer_observation:Mutex<Option<peer_native::RemovalPeerCustody>>,
}
struct WorkerReturn{
    known:bool,resources_retired:bool,main_retired:bool,
    completion:Option<MacosMaintenanceCompletion>,retired:Option<peer_native::RemovalPeerRetired>,
    first:Option<(AdmissionFailure,Instant)>,at:Instant,
}
impl WorkerReturn{fn unknown(first:Option<(AdmissionFailure,Instant)>)->Self{Self{
    known:false,resources_retired:false,main_retired:false,completion:None,retired:None,first,at:Instant::now()}}}

#[derive(Clone)]
pub(super) struct Handle{original:Arc<Original>}
pub(super) struct Admitted{handle:Handle,release:Option<oneshot::Sender<()>>}
pub(super) struct QuitReady{handle:Handle,completion:MacosMaintenanceCompletion,peer:peer_native::RemovalPeerRetired}
impl QuitReady{
    pub(super) fn handle(&self)->&Handle{&self.handle}
    pub(super) fn request_quit(self)->bool{
        self.handle.original.work_ok()&&self.completion.request_quit()
            &&self.peer.role()==peer_native::RemovalPeerRole::App
            &&self.peer.cutoff().is_some_and(|cutoff|self.handle.original.clock.get().and_then(|c|c.cutoff())
                .is_some_and(|current|current.same_original(cutoff)))
            &&self.handle.can_exit()
    }
}
impl Admitted{
    pub(super) fn handle(&self)->Handle{self.handle.clone()}
    pub(super) fn release(mut self)->Flow<()>{
        if self.release.take().is_none_or(|sender|sender.send(()).is_err()){
            self.handle.original.note(AdmissionFailure::Native,Instant::now());return Err(());
        }Ok(())
    }
}
impl Drop for Admitted{fn drop(&mut self){if self.release.is_some(){self.handle.original.note(AdmissionFailure::Stopped,Instant::now());}}}
impl Wake for Original{
    fn wake(self:Arc<Self>){self.wake_by_ref();}
    fn wake_by_ref(self:&Arc<Self>){if let Some(document)=self.document.upgrade(){document.changes.send_modify(|_|{});}}
}
impl Original{
    fn signal(&self){if let Some(document)=self.document.upgrade(){document.changes.send_modify(|_|{});}}
    fn poison(&self){self.unknown.store(true,Ordering::SeqCst);self.stop.send_replace(true);if let Some(prompt)=self.prompt.get(){prompt.stop();}self.signal();}
    fn note(&self,why:AdmissionFailure,at:Instant){
        if at>Instant::now(){self.poison();return;}
        match self.first.try_lock(){Ok(mut value)=>*value=first(*value,Some((why,at))),Err(_)=>{self.poison();return;}}
        if let Some(source)=self.source.get(){source.source_note(why,at);}
        if matches!(why,AdmissionFailure::Unknown|AdmissionFailure::AlreadyUsed){self.unknown.store(true,Ordering::SeqCst);}
        self.stop.send_replace(true);if let Some(prompt)=self.prompt.get(){prompt.stop();}self.signal();
    }
    fn note_source(&self,at:Instant){
        // Inspector publication is presentation-only; its original source gate
        // already retains the actual failure kind when one was observed.
        // Preserve that same first-F rather than rename a native/ACL failure.
        match self.source.get().and_then(AppRemovalWorkGate::source_first){
            Some((why,first))if first<=at=>self.note(why,first),_=>self.note(AdmissionFailure::Inventory,at)
        }
    }
    fn local_first(&self)->Option<(AdmissionFailure,Instant)>{
        let local=match self.first.try_lock(){Ok(value)=>*value,Err(_)=>{self.poison();None}};
        first(local,self.source.get().and_then(AppRemovalWorkGate::source_first))
    }
    fn local_end(&self,external:Option<(AdmissionFailure,Instant)>)->Option<Instant>{
        let first=first(self.local_first(),external);
        let mut end=match first{Some((_,at))=>at.checked_add(TAIL)?.min(self.hard),None=>self.hard};
        // A returned native/wrapper observation only narrows this original
        // local tail. It is NOT a conversion of native_first_failure.
        if let Ok(value)=self.peer_observation.try_lock(){if let Some(at)=value.as_ref().and_then(|v|v.first_failure){end=end.min(at.checked_add(TAIL)?);}}
        else{self.poison();return None;}
        Some(end)
    }
    fn local_expired(&self,external:Option<(AdmissionFailure,Instant)>)->bool{
        self.unknown.load(Ordering::SeqCst)||self.local_end(external).is_none_or(|end|Instant::now()>=end)
    }
    fn cleanup_ok(&self)->bool{
        if self.local_expired(None){return false;}
        self.source.get().is_none_or(|source|source.source_cleanup_verdict(self.local_first())==AppRemovalCleanup::Allowed)
    }
    fn work_ok(&self)->bool{
        let now=Instant::now();
        if now<self.admitted{self.poison();return false;}
        if now>=self.work{self.note(AdmissionFailure::Deadline,self.work);return false;}
        if self.local_first().is_some()||self.unknown.load(Ordering::SeqCst)||*self.stop.borrow(){return false;}
        if self.document.upgrade().is_none()||self.identity.upgrade().is_none(){self.note(AdmissionFailure::Stopped,now);return false;}
        if let Some(source)=self.source.get(){
            if source.source_work().is_err(){self.stop.send_replace(true);if let Some(prompt)=self.prompt.get(){prompt.stop();}return false;}
        }
        true
    }
    fn raw_work(&self)->Flow<u64>{
        if !self.work_ok(){return Err(());}
        self.clock.get().and_then(|clock|clock.work_sample()).ok_or(())
    }
    fn pause(&self){std::thread::park_timeout(HEARTBEAT.min(self.local_end(None).unwrap_or(self.hard).saturating_duration_since(Instant::now())));}
    fn main_retired(&self)->bool{self.prompt.get().is_none_or(|prompt|prompt.never_requested()||prompt.known_main_retired())}
    fn observe_peer(&self,custody:peer_native::RemovalPeerCustody){
        match self.peer_observation.try_lock(){Ok(mut slot)=>{
            if slot.as_ref().is_some_and(|old|old.native_calls>custody.native_calls||old.native_returns>custody.native_returns
                ||old.native_first_failure!=0&&(old.native_first_failure!=custody.native_first_failure||old.native_first_code!=custody.native_first_code)){
                drop(slot);self.poison();return;
            }
            *slot=Some(custody);
        },Err(_)=>{self.poison();return;}}
        if custody.unknown{self.poison();}
    }
}
impl Handle{
    pub(super) fn same(&self,other:&Self)->bool{Arc::ptr_eq(&self.original,&other.original)}
    pub(super) fn id(&self)->[u8;16]{self.original.id}
    pub(super) fn generation(&self)->u32{self.original.generation}
    pub(super) fn source_generation(&self)->u32{self.original.source_generation}
    pub(super) fn reservation(&self)->Option<usize>{
        (!self.original.unknown.load(Ordering::SeqCst)&&self.original.whole<=SESSION_BYTES).then_some(self.original.reservation)
    }
    pub(super) fn picker_originals(&self)->&[Option<Arc<OriginalWork>>;3]{&self.original.pickers}
    pub(super) fn sources_match(&self,pickers:&[Option<Arc<OriginalWork>>;3],generation:u32)->bool{
        generation==self.original.source_generation&&self.original.pickers.iter().zip(pickers).all(|(a,b)|match(a,b){
            (None,None)=>true,(Some(a),Some(b))=>Arc::ptr_eq(a,b),_=>false})
    }
    pub(super) fn stop(&self,why:AdmissionFailure,at:Instant){self.original.note(why,at);}
    pub(super) fn poison(&self){self.original.poison();}
    pub(super) fn work_ok(&self)->bool{self.original.work_ok()}
    pub(super) fn take_confirmation(&self)->Option<MacosRemovalConfirmed>{
        if !self.original.work_ok(){return None;}
        let mut offers=self.original.offers.try_lock().ok()?;
        if offers.confirmed.is_none()||!offers.state.take(){return None;}
        offers.confirmed.take()
    }
    pub(super) fn bind_saved(&self,saved:MacosMaintenanceHandle)->bool{
        let Some(cutoff)=self.original.clock.get().and_then(|clock|clock.cutoff())else{return false;};
        let Ok(mut offers)=self.original.offers.try_lock()else{self.original.poison();return false;};
        if offers.saved.is_some()||!saved.removal_matches(cutoff)||!offers.state.bind(){self.original.poison();return false;}
        offers.saved=Some(saved);true
    }
    pub(super) fn offer_completion(&self,completion:MacosMaintenanceCompletion)->bool{
        let mut offers=match self.original.offers.try_lock(){Ok(offers)=>offers,Err(_)=>{
            // Retain this SAME one-shot result on failed publication. The
            // original unknown slot remains charged and cannot be replaced.
            std::mem::forget(completion);self.original.poison();return false;}};
        let matching=self.original.clock.get().and_then(|clock|clock.cutoff()).is_some_and(|cutoff|
            offers.saved.as_ref().is_some_and(|saved|completion.matches_removal(saved,cutoff)));
        if !matching||!offers.state.complete(){
            std::mem::forget(completion);drop(offers);self.original.poison();return false;
        }
        offers.completion=Some(completion);drop(offers);self.original.signal();true
    }
    pub(super) fn reconcile(&self){
        let original=&self.original;
        if original.coordinator_joined.load(Ordering::SeqCst){
            if let Some(prompt)=original.prompt.get(){prompt.tick(false);}
            // A finite coordinator may have returned at hard while the actual
            // blocking call remains. Poll/join only its retained original.
            if !original.worker_joined.load(Ordering::SeqCst){if let Ok(mut slot)=original.worker.try_lock(){
                let waker=Waker::from(original.clone());let mut cx=TaskContext::from_waker(&waker);
                let _=poll_worker(original,&mut slot,&mut cx);
            }}return;
        }
        let Ok(mut slot)=original.coordinator.try_lock()else{return;};
        let Ok(mut returned)=original.coordinator_return.try_lock()else{return;};
        if returned.is_some(){original.poison();return;}
        let Some(task)=slot.as_mut()else{original.poison();return;};
        let waker=Waker::from(original.clone());let mut cx=TaskContext::from_waker(&waker);
        if let Poll::Ready(result)=Pin::new(task).poll(&mut cx){
            let known=matches!(result,Ok(true));*returned=Some(result);slot.take();
            original.coordinator_joined.store(true,Ordering::SeqCst);let _=original.final_at.set(Instant::now());
            if !known{original.poison();}
        }
    }
    pub(super) fn can_exit(&self)->bool{
        let o=&self.original;
        let returned=o.returned.try_lock().is_ok_and(|value|matches!(value.as_ref(),Some(Ok(value))
            if value.known&&value.resources_retired&&value.main_retired));
        joined_data_only(o.unknown.load(Ordering::SeqCst),o.worker_joined.load(Ordering::SeqCst),
            o.coordinator_joined.load(Ordering::SeqCst),o.main_retired(),returned)
    }
    pub(super) fn may_reopen(&self)->bool{
        if !self.can_exit(){return false;}
        let Ok(offers)=self.original.offers.try_lock()else{return false;};
        let Ok(returned)=self.original.returned.try_lock()else{return false;};
        matches!(returned.as_ref(),Some(Ok(value)) if value.retired.is_none()
            &&match &value.completion{Some(completion)=>completion.may_reopen(),None=>offers.saved.is_none()})
    }
    pub(super) fn take_ready(&self)->Option<QuitReady>{
        if !self.can_exit()||!self.original.work_ok()||self.original.ready_taken.load(Ordering::SeqCst){return None;}
        let mut returned=self.original.returned.try_lock().ok()?;
        let Some(Ok(value))=returned.as_mut()else{return None;};
        let complete=value.completion.as_ref()?;let retired=value.retired.as_ref()?;
        let saved=self.original.offers.try_lock().ok()?;
        let cutoff=self.original.clock.get()?.cutoff()?;
        if !complete.request_quit()||!complete.matches_removal(saved.saved.as_ref()?,cutoff)
            ||retired.role()!=peer_native::RemovalPeerRole::App||retired.cutoff().is_none_or(|peer|!peer.same_original(cutoff))
            ||self.original.final_at.get().is_none_or(|joined|*joined<value.at)
            ||self.original.ready_taken.swap(true,Ordering::SeqCst){return None;}
        Some(QuitReady{handle:self.clone(),completion:value.completion.take()?,peer:value.retired.take()?})
    }
}

pub(super) fn working_reservation()->Option<usize>{
    // Request6+inspector43=49 explicit FDs during the single walk; retained26
    // +request6+native3=35 steady. PER-Book48 remains unchanged, not a global
    // process quota. Saved's full independent quote is added before this GO.
    arc_bytes::<Original>()?.checked_add(INSPECTOR_RESERVE)?
        .checked_add(RemovalRequestOriginal::working_reservation_bytes()?)?
        .checked_add(RemovalProducerVerifier::project_owned_upper_bound()?)?
        .checked_add(peer_native::RemovalPeer::project_owned_upper_bound()?)?
        .checked_add(MacosRemovalPrompt::reservation_bytes()?)?
        .checked_add(size_of::<Backing>())?.checked_add(size_of::<BackingGuard>())?
        .checked_add(4*wire::FRAME_LIMIT+8*wire::FRAME_BODY_LIMIT+4*crate::macos_remove_producer::DESCRIPTOR_LIMIT)?
        .checked_add(12*SIGNAL_STORAGE+TASK_STORAGE)
}
pub(super) fn reserve(document:&DocumentBinding,id:[u8;16],generation:u32,at:Instant,
    pickers:[Option<Arc<OriginalWork>>;3],source_generation:u32,prior_and_saved:usize,
    dispatcher:Arc<AndroidServiceDispatcher>)->Result<Admitted,BridgeError>{
    let reservation=working_reservation().ok_or_else(unavailable)?;
    if !fits(prior_and_saved,reservation){return Err(unavailable());}
    let work=at.checked_add(LOCAL_WORK).ok_or_else(unavailable)?;let hard=at.checked_add(LOCAL_HARD).ok_or_else(unavailable)?;
    if id==[0;16]||generation==0||Instant::now()>=work{return Err(unavailable());}
    let executor=tokio::runtime::Handle::try_current().map_err(|_|unavailable())?;let(stop,_)=watch::channel(false);
    let original=Arc::new(Original{document:Arc::downgrade(&document.inner),identity:Arc::downgrade(&document.inner.session_identity),id,generation,
        pickers,source_generation,admitted:at,work,hard,stop,first:Mutex::new(None),unknown:AtomicBool::new(false),
        clock:OnceLock::new(),source:OnceLock::new(),dispatcher,prompt:OnceLock::new(),offers:Mutex::new(Offers::new()),
        reservation,whole:prior_and_saved.checked_add(reservation).ok_or_else(unavailable)?,worker:AsyncMutex::new(None),returned:Mutex::new(None),
        worker_joined:AtomicBool::new(false),coordinator:Mutex::new(None),coordinator_return:Mutex::new(None),
        coordinator_joined:AtomicBool::new(false),final_at:OnceLock::new(),ready_taken:AtomicBool::new(false),peer_observation:Mutex::new(None)});
    let(release,enter)=oneshot::channel();let(worker_enter,worker_wait)=oneshot::channel();
    let worker_task={let original=original.clone();move||worker(original,worker_wait)};
    let coordinator=coordinate(original.clone(),enter,worker_enter);
    let tasks=size_of_val(&worker_task).checked_add(size_of_val(&coordinator))
        .and_then(|bytes|bytes.checked_add(4*size_of::<WorkerReturn>()))
        .and_then(|bytes|bytes.checked_add(size_of::<QuitReady>())).ok_or_else(unavailable)?;
    if tasks>TASK_STORAGE{return Err(unavailable());}
    // GO is closed. Returning this admitted original also on publication
    // failure lets Document retain/close its one slot, never lose a spawned task.
    let published=catch_unwind(AssertUnwindSafe(||->Flow<()>{
        let mut worker=original.worker.try_lock().map_err(|_|())?;
        let mut owner=original.coordinator.try_lock().map_err(|_|())?;
        *worker=Some(executor.spawn_blocking(worker_task));*owner=Some(executor.spawn(coordinator));Ok(())
    }));
    if !matches!(published,Ok(Ok(()))){original.poison();}
    Ok(Admitted{handle:Handle{original},release:Some(release)})
}

fn poll_worker(original:&Original,slot:&mut Option<JoinHandle<WorkerReturn>>,cx:&mut TaskContext<'_>)->Poll<bool>{
    if original.worker_joined.load(Ordering::SeqCst){return Poll::Ready(!original.unknown.load(Ordering::SeqCst));}
    let mut returned=match original.returned.try_lock(){Ok(value)=>value,Err(TryLockError::WouldBlock)=>return Poll::Pending,
        Err(_)=>{original.poison();return Poll::Ready(false);}};
    if returned.is_some(){original.poison();return Poll::Ready(false);}
    let Some(task)=slot.as_mut()else{original.poison();return Poll::Ready(false);};
    let Poll::Ready(result)=Pin::new(task).poll(cx)else{return Poll::Pending;};
    let known=matches!(&result,Ok(value) if value.known&&value.resources_retired&&value.main_retired);
    if let Ok(value)=&result{if let Some((why,at))=value.first{original.note(why,at);}}
    *returned=Some(result);slot.take();original.worker_joined.store(true,Ordering::SeqCst);
    if !known{original.poison();}Poll::Ready(known)
}
async fn coordinate(original:Arc<Original>,mut release:oneshot::Receiver<()>,worker_enter:oneshot::Sender<()>)->bool{
    let mut release_worker=Some(worker_enter);let mut worker=original.worker.lock().await;
    let waker=Waker::from(original.clone());
    loop{
        if let Some(prompt)=original.prompt.get(){prompt.tick(true);}
        if !original.cleanup_ok(){original.poison();return false;}
        if release_worker.is_some(){match release.try_recv(){
            Ok(())=>{if original.work_ok(){if release_worker.take().is_none_or(|sender|sender.send(()).is_err()){original.poison();}}
                else{release_worker.take();}},
            Err(oneshot::error::TryRecvError::Closed)=>{original.note(AdmissionFailure::Stopped,Instant::now());release_worker.take();},
            Err(oneshot::error::TryRecvError::Empty)=>{},
        }}
        let joined={let mut cx=TaskContext::from_waker(&waker);poll_worker(&original,&mut worker,&mut cx)};
        if let Poll::Ready(known)=joined{return known&&original.cleanup_ok()&&original.main_retired();}
        tokio::time::sleep(HEARTBEAT.min(original.local_end(None).unwrap_or(original.hard).saturating_duration_since(Instant::now()))).await;
    }
}

struct Backing{request:RemovalRequestOriginal,inspector:Option<RemovalProducerAdmission>,remove:RemovalProducerVerifier,remove_entered:bool}
/// Before any native constructor/call can retain pointers, this same Box owns
/// all raw4 buffers/FD/ACL/verifier allocations. Unwind/Unknown forgets THIS
/// backing, on THIS blocking worker; a joined task is not retirement credit.
struct BackingGuard{value:Option<Box<Backing>>,retain:Cell<bool>}
impl Drop for BackingGuard{fn drop(&mut self){if self.retain.get(){if let Some(value)=self.value.take(){std::mem::forget(value);}}}}
fn worker(original:Arc<Original>,mut enter:oneshot::Receiver<()>)->WorkerReturn{
    loop{
        if !original.work_ok(){return WorkerReturn{known:true,resources_retired:true,main_retired:true,
            completion:None,retired:None,first:original.local_first(),at:Instant::now()};}
        match enter.try_recv(){Ok(())=>break,Err(oneshot::error::TryRecvError::Empty)=>original.pause(),
            Err(oneshot::error::TryRecvError::Closed)=>{original.note(AdmissionFailure::Stopped,Instant::now());}}
    }
    let Some(request)=RemovalRequestOriginal::reserved(original.id)else{original.poison();return WorkerReturn::unknown(original.local_first());};
    let mut backing=BackingGuard{value:Some(Box::new(Backing{request,inspector:None,remove:RemovalProducerVerifier::new(),remove_entered:false})),retain:Cell::new(true)};
    let result=catch_unwind(AssertUnwindSafe(||run_worker(&original,&mut backing)));
    match result{Ok(value)=>value,Err(_)=>{original.note(AdmissionFailure::Unknown,Instant::now());WorkerReturn::unknown(original.local_first())}}
}

fn hash(bytes:&[u8])->[u8;32]{use sha2::Digest;sha2::Sha256::digest(bytes).into()}
fn hex<const N:usize>(text:&str)->Option<[u8;N]>{
    if text.len()!=N.checked_mul(2)?{return None;}let mut bytes=[0;N];
    for(i,pair)in text.as_bytes().chunks_exact(2).enumerate(){
        let one=|b:u8|match b{b'0'..=b'9'=>Some(b-b'0'),b'a'..=b'f'=>Some(b-b'a'+10),_=>None};
        bytes[i]=one(pair[0])?.checked_mul(16)?.checked_add(one(pair[1])?)?;
    }(bytes!=[0;N]).then_some(bytes)
}
fn hex_id(id:[u8;16])->String{id.iter().map(|b|format!("{b:02x}")).collect()}
fn challenge_data(binding:&wire::BindingData)->Option<peer_native::RemovalChallengeData>{
    let input=binding.fields_data();let mut release=[0;128];
    if input.release.len()>release.len(){return None;}release[..input.release.len()].copy_from_slice(input.release.as_bytes());
    let data=peer_native::RemovalChallengeData{request_id:hex(input.request_id)?,root_nonce:hex(input.root_nonce)?,source:hex(input.source_commit)?,
        target:match input.target{wire::TargetData::Arm64=>peer_native::RemovalTargetData::Arm64,wire::TargetData::Intel=>peer_native::RemovalTargetData::Intel},
        release,release_len:u8::try_from(input.release.len()).ok()?,remove_producer:hex(input.remove_producer_sha256)?,
        installed_producer:hex(input.installed_producer_sha256)?,inventory:hex(input.installed_inventory_sha256)?,protocol:hex(input.protocol_sha256)?,
        start:input.start,work:input.work,hard:input.hard};data.valid_data().then_some(data)
}
/// This fixed function is never selected from input. Native invokes it exactly
/// on the original received Challenge buffer, then performs same-peer POST.
fn decode_challenge(bytes:&[u8])->Option<peer_native::RemovalChallengeData>{
    let frame=wire::FrameData::parse_framed_data(bytes).ok()?;
    (frame.kind_data()==wire::FrameKindData::Challenge).then(||challenge_data(frame.binding_data())).flatten()
}
fn code_hash(current:&RemovalCurrent<'_>,path:&str)->Flow<[u8;32]>{
    let inventory=current.inventory().map_err(|_|())?;
    let mut rows=inventory.files.iter().filter(|entry|entry.path==path);
    let row=rows.next().ok_or(())?;
    if !row.executable||row.size==0||rows.next().is_some(){return Err(());}hex(&row.sha256).ok_or(())
}
fn joined_data(request:&wire::RequestData,current:&RemovalCurrent<'_>)->Flow<[[u8;32];3]>{
    let binding=request.binding_data().fields_data();
    let target=wire::TargetData::compiled().ok_or(())?;
    if binding.target!=target||binding.source_commit!=option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").unwrap_or("")
        ||binding.release!=crate::macos_install_paths::RELEASE||binding.protocol_sha256!=crate::macos_install_paths::PROTOCOL_SHA{return Err(());}
    let remove=RemovalData::parse_data(request.remove_descriptor_data(),target).map_err(|_|())?;
    let actual=remove.binding_data();let selected=current.selected().map_err(|_|())?.current_data().binding_data();
    if hash(request.remove_descriptor_data())!=hex(binding.remove_producer_sha256).ok_or(())?
        ||hash(current.installed_descriptor().map_err(|_|())?)!=hex(binding.installed_producer_sha256).ok_or(())?
        ||hash(current.inventory_bytes().map_err(|_|())?)!=hex(binding.installed_inventory_sha256).ok_or(())?
        ||actual.source_commit!=binding.source_commit||actual.release!=binding.release||actual.protocol_sha256!=binding.protocol_sha256
        ||actual.installed_producer_sha256!=binding.installed_producer_sha256||actual.installed_inventory_sha256!=binding.installed_inventory_sha256
        ||selected.source_commit!=binding.source_commit||selected.release!=binding.release||selected.protocol_sha256!=binding.protocol_sha256
        ||selected.inventory_sha256!=binding.installed_inventory_sha256{return Err(());}
    // parsed installed DATA is only a tuple check. Its actual signature and full
    // filesystem roster are still the retained inspector/verifier instances.
    remove.installed_data(current.installed_descriptor().map_err(|_|())?).map_err(|_|())?;
    let result=[code_hash(current,ENTRY)?,code_hash(current,PAYLOAD)?,code_hash(current,REMOVER)?];
    if result[2]!=hex(actual.remover_executable_sha256).ok_or(())?{return Err(());}Ok(result)
}
fn source_post(original:&Original,request:&RemovalRequestOriginal,current:&RemovalCurrent<'_>)->Flow<()>{
    if !original.work_ok(){return Err(());}let stop=original.stop.subscribe();
    request.recheck(original.work,&stop).map_err(|_|())?;
    current.recheck(original.work,&stop,&mut|_,at|original.note_source(at)).map_err(|_|())?;
    if !original.work_ok(){return Err(());}Ok(())
}
fn signature_gate(original:&Original,parent_veto:&Cell<bool>,point:ProducerCheckpoint)->Decision{
    let(phase,custody)=match point{ProducerCheckpoint::Before{phase,custody}|ProducerCheckpoint::Returned{phase,custody,..}=>(phase,custody)};
    if let Some(at)=custody.first_failure{original.note(AdmissionFailure::Native,at);}
    if custody.unknown{original.poison();return Decision::Unknown;}
    if phase.is_cleanup(){return if original.cleanup_ok(){Decision::Proceed}else{Decision::Unknown};}
    if original.work_ok(){Decision::Proceed}else if original.local_first().is_some(){Decision::Stop}else{
        // ProducerVerifier's Unknown immediately returns and close short-circuits;
        // no subsequent callback can import its generated Instant as local F.
        parent_veto.set(true);Decision::Unknown
    }
}
fn peer_cleanup(phase:peer_native::RemovalPeerPhase)->bool{
    use peer_native::{RemovalPeerPhase as P,RemovalPeerOperation as O};
    matches!(phase,P::Call(O::WaitExit|O::Close)|P::Native{cleanup:true,..}|P::Retire)
}
fn peer_gate(original:&Original,request:&RemovalRequestOriginal,current:&RemovalCurrent<'_>,point:peer_native::RemovalPeerCheckpoint)->Decision{
    let(phase,custody)=match point{peer_native::RemovalPeerCheckpoint::Before{phase,custody}
        |peer_native::RemovalPeerCheckpoint::Returned{phase,custody,..}=>(phase,custody)};
    original.observe_peer(custody); // genuine returned facts precede any POST veto
    if custody.unknown{return Decision::Unknown;}
    if peer_cleanup(phase){return if original.cleanup_ok(){Decision::Proceed}else{Decision::Unknown};}
    if source_post(original,request,current).is_ok(){Decision::Proceed}
    else if original.local_first().is_some(){Decision::Stop}
    else if original.clock.get().is_some_and(|clock|clock.work_stopped()&&!clock.invalid())
        &&!original.unknown.load(Ordering::SeqCst){
        // A known Parent work-stop may still close this peer before original
        // hard. Its wrapper-observed first is kept separately in peer custody;
        // it is NEVER imported into AppRemovalWorkGate as a local/native F.
        Decision::Stop
    }else{Decision::Unknown}
}
fn await_frame(original:&Original,peer:&mut peer_native::RemovalPeer<'_>,gate:&mut dyn FnMut(peer_native::RemovalPeerCheckpoint)->Decision,
    begun:peer_native::RemovalPeerProgress)->Flow<()>{
    if begun!=peer_native::RemovalPeerProgress::Ready{return Err(());}
    loop{original.raw_work()?;match peer.poll_frame(gate){peer_native::RemovalPeerProgress::Ready=>return Ok(()),
        peer_native::RemovalPeerProgress::Pending=>original.pause(),_=>return Err(())}}
}
fn send_frame_data(original:&Original,transcript:&mut wire::TranscriptData,frame:wire::FrameData,buffer:&mut[u8;wire::FRAME_LIMIT])->Flow<usize>{
    let count=frame.encode_framed_data(buffer).map_err(|_|())?;
    // This DATA transition is not a returned native send; positive worker
    // result additionally requires poll_frame on the exact native original.
    transcript.advance_data(wire::ActionData::Send,&buffer[..count],original.raw_work()?).map_err(|_|())?;Ok(count)
}
fn exchange(original:&Original,request:&RemovalRequestOriginal,current:&RemovalCurrent<'_>,peer:&mut peer_native::RemovalPeer<'_>,
    completion:&mut Option<MacosMaintenanceCompletion>)->Flow<()>{
    let mut gate=|point|peer_gate(original,request,current,point);
    if peer.admit_source(&mut gate)!=peer_native::RemovalPeerProgress::Ready
        ||peer.open(&mut gate)!=peer_native::RemovalPeerProgress::Ready{return Err(());}
    loop{original.raw_work()?;match peer.connect(&mut gate){peer_native::RemovalPeerProgress::Ready=>break,
        peer_native::RemovalPeerProgress::Pending=>original.pause(),_=>return Err(())}}
    if peer.authenticate(&mut gate)!=peer_native::RemovalPeerProgress::Ready{return Err(());}
    let begun=peer.receive(&mut gate);await_frame(original,peer,&mut gate,begun)?;
    let cutoff=peer.admit_challenge(decode_challenge,&mut gate).map_err(|_|())?;
    let clock=original.clock.get().ok_or(())?;
    if !clock.authenticate_once(&cutoff){return Err(());}
    source_post(original,request,current)?;
    let binding=request.request().map_err(|_|())?.binding_data();
    // Native admitted the actual complete Challenge and matched the expected
    // binding. Encoding that independently expected DATA advances only this
    // parser; it does NOT stand in for a second socket read/native proof.
    let mut transcript=wire::TranscriptData::new_data(wire::RoleData::App,binding.clone());
    let mut buffer=[0;wire::FRAME_LIMIT];
    let count=wire::FrameData::challenge_data(binding).map_err(|_|())?.encode_framed_data(&mut buffer).map_err(|_|())?;
    transcript.advance_data(wire::ActionData::Receive,&buffer[..count],original.raw_work()?).map_err(|_|())?;
    let prompt=Arc::new(MacosRemovalPrompt::reserved(clock.clone(),original.dispatcher.clone()));
    original.prompt.set(prompt.clone()).map_err(|_|())?;
    if !prompt.request(){return Err(());}original.signal();
    let confirmation=loop{
        if !original.work_ok(){prompt.stop();}
        match prompt.take(){Ok(Some(value))=>break value,Ok(None)=>{original.note(AdmissionFailure::Stopped,Instant::now());return Err(());},Err(())=>{}}
        if !original.cleanup_ok(){return Err(());}original.pause();
    };
    if !original.work_ok()||!confirmation.cutoff().same_original(&cutoff){return Err(());}
    let nonce=hex_id(confirmation.app_nonce());
    let count=send_frame_data(original,&mut transcript,wire::FrameData::confirmed_data(binding,&nonce).map_err(|_|())?,&mut buffer)?;
    let begun=peer.send_confirmed(confirmation.native(),&buffer[..count],&mut gate);await_frame(original,peer,&mut gate,begun)?;
    source_post(original,request,current)?;
    {let mut offers=original.offers.try_lock().map_err(|_|())?;
        if offers.confirmed.is_some()||!offers.state.confirmed(){return Err(());}offers.confirmed=Some(confirmation);}
    original.signal();
    loop{
        original.raw_work()?;
        let mut offers=original.offers.try_lock().map_err(|_|())?;
        if let Some(value)=offers.completion.take(){*completion=Some(value);break;}
        if offers.state.completion{return Err(());}drop(offers);original.pause();
    }
    let result=completion.as_ref().ok_or(())?;
    {let offers=original.offers.try_lock().map_err(|_|())?;
        if !result.matches_removal(offers.saved.as_ref().ok_or(())?,&cutoff)||!result.request_quit(){return Err(());}}
    let status=result.status();
    let branch=match(status.phase,status.unregister_accepted,status.not_registered){
        (MacosMaintenancePhase::Prepared,true,true)=>wire::PreparationData::UnregisteredNow,
        (MacosMaintenancePhase::Prepared,false,true)=>wire::PreparationData::NeverRegistered,_=>return Err(()),};
    source_post(original,request,current)?;
    let count=send_frame_data(original,&mut transcript,wire::FrameData::prepared_data(binding,&nonce,branch).map_err(|_|())?,&mut buffer)?;
    let begun=peer.send_prepared(&buffer[..count],&mut gate);await_frame(original,peer,&mut gate,begun)?;
    let begun=peer.receive(&mut gate);await_frame(original,peer,&mut gate,begun)?;
    let received=peer.received_frame(&mut gate).map_err(|_|())?;
    transcript.advance_data(wire::ActionData::Receive,received,original.raw_work()?).map_err(|_|())?;
    if transcript.progress_data()!=wire::ProgressData::FramesExchanged||!result.request_quit(){return Err(());}
    source_post(original,request,current)
}

fn run_worker(original:&Original,guard:&mut BackingGuard)->WorkerReturn{
    let backing=guard.value.as_mut().expect("one reserved removal backing");
    let stop=original.stop.subscribe();let mut completion=None;let mut retired=None;let mut peer_known=true;
    let mut forward=false;
    let preparation=(||->Flow<()>{
        backing.request.read_once(original.work,&stop).map_err(|_|())?;
        let bound=backing.request.request().map_err(|_|())?.binding_data().clock_data();
        // First raw DATA appears only after this bounded read. Enforce its
        // original endpoints NOW; never restart local or Parent time.
        let clock=RemovalClock::capture_removal_data(bound.start_data(),bound.work_data(),bound.hard_data()).ok_or(())?;
        let gate=AppRemovalWorkGate::new(clock.clone()).ok_or(())?;
        original.clock.set(clock).map_err(|_|())?;original.source.set(gate.clone()).map_err(|_|())?;
        if let Some((why,at))=original.local_first(){gate.source_note(why,at);}
        backing.request.bind_clock_once(gate.clone(),original.work,&stop).map_err(|_|())?;
        backing.inspector=Some(RemovalProducerAdmission::new(gate));
        let inspector=backing.inspector.as_mut().ok_or(())?;
        inspector.admit(original.work,&stop,&mut|_,at|original.note_source(at),
            &mut|first|original.local_expired(first),&mut|_,_|{}).map_err(|_|())?;
        if inspector.retained_bytes().is_none_or(|n|n>INSPECTOR_RESERVE){return Err(());}
        let current=inspector.current(original.work,&stop,&mut|_,at|original.note_source(at)).map_err(|_|())?;
        let request=backing.request.request().map_err(|_|())?;
        let code=joined_data(request,&current)?;let binding=challenge_data(request.binding_data()).ok_or(())?;
        source_post(original,&backing.request,&current)?;
        let parent_veto=Cell::new(false);backing.remove_entered=true;
        let signature=backing.remove.verify_and_close(request.remove_descriptor_data(),request.remove_signature_data(),
            &mut|point|signature_gate(original,&parent_veto,point));
        if signature!=SignatureResult::SignatureVerified||!backing.remove.settled(){
            if signature==SignatureResult::Unknown{original.poison();}
            else if !parent_veto.get(){original.note(AdmissionFailure::Native,Instant::now());}return Err(());
        }
        source_post(original,&backing.request,&current)?;
        let all=current.originals().map_err(|_|())?;let req=backing.request.originals().map_err(|_|())?;
        let fds:[BorrowedFd<'_>;20]=[all[0],all[1],all[2],all[3],all[8],all[16],all[19],all[20],all[21],all[22],
            all[24],all[17],all[18],all[23],all[25],all[10],all[11],req[0],req[1],req[2]];
        let source=peer_native::RemovalSourceOriginals::new(current.installed_signature_verifier().map_err(|_|())?,
            current.entry_verifier().map_err(|_|())?,current.payload_verifier().map_err(|_|())?,&backing.remove,None,fds,
            [current.installed_descriptor().map_err(|_|())?,current.installed_signature().map_err(|_|())?,
                request.remove_descriptor_data(),request.remove_signature_data()],code,backing.request.hash()).ok_or(())?;
        // guard.retain was armed BEFORE this constructor. A constructor panic
        // cannot free any borrowed raw4/source cell or permit another attempt.
        let mut callback=|point|peer_gate(original,&backing.request,&current,point);
        let mut peer=peer_native::RemovalPeer::app(source,binding,&mut callback);
        let flow=catch_unwind(AssertUnwindSafe(||exchange(original,&backing.request,&current,&mut peer,&mut completion)));
        forward=matches!(flow,Ok(Ok(())));
        if flow.is_err(){original.note(AdmissionFailure::Unknown,Instant::now());}
        if !forward{original.stop.send_replace(true);if let Some(prompt)=original.prompt.get(){prompt.stop();}}
        // Close and retire once, separately caught. Unknown pointer/backing are
        // never touched again or moved to the async coordinator for cleanup.
        if original.cleanup_ok()&&!peer.custody().unknown{
            let closed=catch_unwind(AssertUnwindSafe(||peer.close(&mut callback)));
            if closed.is_err(){original.note(AdmissionFailure::Unknown,Instant::now());}
            if matches!(closed,Ok(peer_native::RemovalPeerProgress::Ready|peer_native::RemovalPeerProgress::Refused))&&original.cleanup_ok(){
                match catch_unwind(AssertUnwindSafe(||peer.retire(&mut callback))){Ok(Ok(value))=>retired=value,
                    Ok(Err(_))=>{},Err(_)=>original.note(AdmissionFailure::Unknown,Instant::now())}
            }
        }
        original.observe_peer(peer.custody());peer_known=peer.settled();
        if !peer_known{std::mem::forget(peer);original.poison();return Err(());}
        drop(peer);
        if forward&&retired.is_none(){return Err(());}Ok(())
    })();
    if preparation.is_err(){
        if let Some((why,at))=backing.request.first_failure(){original.note(why,at);}
        original.stop.send_replace(true);if let Some(prompt)=original.prompt.get(){prompt.stop();}
    }
    // A failed forward sequence still observes actual main close/capture return.
    // It cannot declare the prompt retired solely because its worker is done.
    while !original.main_retired()&&original.cleanup_ok(){
        if let Some(prompt)=original.prompt.get(){if let Ok(value)=prompt.take(){drop(value);}}
        original.pause();
    }
    let main=original.main_retired();
    if !peer_known||!main||!original.cleanup_ok(){original.poison();return WorkerReturn::unknown(original.local_first());}
    let parent_veto=Cell::new(false);
    let signature=!backing.remove_entered||backing.remove.settled()||backing.remove.close(&mut|point|signature_gate(original,&parent_veto,point));
    let inspector=backing.inspector.as_mut().is_none_or(|inspector|inspector.settle(original.work,&stop,
        &mut|_,at|original.note_source(at),&mut|first|original.local_expired(first)));
    let request=backing.request.settle(&mut|first|original.local_expired(first));
    let known=resources_data(signature,inspector,request,original.cleanup_ok(),original.unknown.load(Ordering::SeqCst));
    if known{guard.retain.set(false);}else{original.poison();}
    if !forward{retired=None;}
    WorkerReturn{known,resources_retired:known,main_retired:main,completion,retired,first:original.local_first(),at:Instant::now()}
}

// No native pointer crosses main. One explicitly retained selector observer,
// one fixed inbox and at most one close capture in the existing exit observer.
enum NoticeCleanup{Open,Queued(Arc<NoticeClose>),Known,Unknown}
struct NoticeClose{runtime:Arc<NoticeRuntime>,end:Instant,returned:Mutex<Option<bool>>}
pub(crate) struct NoticeRuntime{
    inbox:Arc<peer_native::RemovalNoticeInbox>,started:AtomicBool,enabled:AtomicBool,unknown:AtomicBool,cleanup:Mutex<NoticeCleanup>,
}
thread_local!{static NOTICE:RefCell<Option<(Arc<NoticeRuntime>,peer_native::RemovalNotice)>>=const{RefCell::new(None)};}
impl NoticeRuntime{
    pub(super) fn reserved()->Arc<Self>{Arc::new(Self{inbox:peer_native::RemovalNoticeInbox::reserved(),
        started:AtomicBool::new(false),enabled:AtomicBool::new(false),unknown:AtomicBool::new(false),cleanup:Mutex::new(NoticeCleanup::Open)})}
    pub(super) fn reservation_bytes()->Option<usize>{
        arc_bytes::<Self>()?.checked_add(peer_native::RemovalNotice::project_owned_upper_bound()?)?
            .checked_add(peer_native::RemovalNoticeInbox::project_owned_upper_bound()?)?
            .checked_add(arc_bytes::<NoticeClose>()?)?.checked_add(SIGNAL_STORAGE)
    }
    pub(super) fn retained_bytes(&self)->Option<usize>{
        (!self.unknown.load(Ordering::SeqCst)&&self.inbox.known()).then(Self::reservation_bytes).flatten()
    }
    pub(super) fn install(self:&Arc<Self>)->bool{
        if !native::main_thread()||self.started.swap(true,Ordering::SeqCst){self.unknown.store(true,Ordering::SeqCst);return false;}
        let status=NOTICE.with(|cell|{
            let Ok(mut slot)=cell.try_borrow_mut()else{return peer_native::RemovalNoticeStart::Unknown;};
            if slot.is_some(){return peer_native::RemovalNoticeStart::Unknown;}
            // reserveNone still has no typed distinction between invalid
            // precheck and allocation absence; do not infer a new fact here.
            let Some(original)=peer_native::RemovalNotice::reserve(&self.inbox)else{return peer_native::RemovalNoticeStart::Unknown;};
            *slot=Some((self.clone(),original));
            match slot.as_mut(){Some((_,original))=>original.start(),None=>peer_native::RemovalNoticeStart::Unknown}
        });
        self.observe_start(status)
    }
    fn observe_start(&self,status:peer_native::RemovalNoticeStart)->bool{
        match status{
            peer_native::RemovalNoticeStart::Registered=>{self.enabled.store(true,Ordering::SeqCst);true},
            // Disable only ingress. The SAME native original remains in TLS;
            // ordinary Quit must actually retire its known center/absence.
            peer_native::RemovalNoticeStart::DisabledKnown=>false,
            peer_native::RemovalNoticeStart::Unknown=>{self.unknown.store(true,Ordering::SeqCst);false}
        }
    }
    pub(crate) fn poll_hint(&self,cx:&mut TaskContext<'_>)->Poll<Option<[u8;16]>>{
        if !self.started.load(Ordering::SeqCst)||!self.enabled.load(Ordering::SeqCst)||self.unknown.load(Ordering::SeqCst){return Poll::Ready(None);}
        self.inbox.poll_hint(cx)
    }
    #[cfg(feature="desktop-shell")]
    async fn close_for_exit(self:&Arc<Self>,app:&tauri::AppHandle,end:Instant)->bool{
        if Instant::now()>=end||self.unknown.load(Ordering::SeqCst){return false;}
        let capture={
            let mut state=match self.cleanup.try_lock(){Ok(state)=>state,Err(_)=>return false,};
            match &*state{NoticeCleanup::Known=>return true,NoticeCleanup::Unknown=>return false,
                NoticeCleanup::Queued(_)=>None,NoticeCleanup::Open=>{
                    let held=Arc::new(NoticeClose{runtime:self.clone(),end,returned:Mutex::new(None)});
                    let capture=held.clone();*state=NoticeCleanup::Queued(held);Some(capture)
                }}
        };
        if let Some(capture)=capture{
            if app.run_on_main_thread(move||NoticeClose::perform(&capture)).is_err(){
                self.unknown.store(true,Ordering::SeqCst);return false;
            }
        }
        loop{
            if Instant::now()>=end{self.unknown.store(true,Ordering::SeqCst);return false;}
            let done={
                let mut state=match self.cleanup.try_lock(){Ok(state)=>state,Err(_)=>return false,};
                let old=std::mem::replace(&mut *state,NoticeCleanup::Unknown);
                match old{
                    NoticeCleanup::Queued(held)=>match Arc::try_unwrap(held){
                        Err(held)=>{*state=NoticeCleanup::Queued(held);None},
                        Ok(returned)=>{
                            let known=Arc::ptr_eq(&returned.runtime,self)&&returned.end==end
                                &&returned.returned.into_inner().is_ok_and(|value|value==Some(true))
                                &&self.inbox.closed()&&self.inbox.known()&&Instant::now()<end;
                            *state=if known{NoticeCleanup::Known}else{NoticeCleanup::Unknown};Some(known)
                        }
                    },NoticeCleanup::Known=>{*state=NoticeCleanup::Known;Some(true)},
                    _=>Some(false),
                }
            };
            if let Some(known)=done{if !known{self.unknown.store(true,Ordering::SeqCst);}return known;}
            tokio::time::sleep(HEARTBEAT.min(end.saturating_duration_since(Instant::now()))).await;
        }
    }
}
impl NoticeClose{
    fn perform(this:&Self){
        let good=if !native::main_thread()||Instant::now()>=this.end{false}else{NOTICE.with(|cell|{
            let Ok(mut slot)=cell.try_borrow_mut()else{return false;};
            let Some((runtime,original))=slot.as_mut()else{return false;};
            if !Arc::ptr_eq(runtime,&this.runtime){return false;}
            // One consuming attempt. is_retired alone is not the known-result
            // predicate; an Err AFTER actual consumption remains failed.
            let result=original.retire(this.end);
            let good=result.is_ok()&&original.is_retired()&&Instant::now()<this.end;
            if good{slot.take();}good
        })};
        match this.returned.try_lock(){Ok(mut result)if result.is_none()=>*result=Some(good),
            _=>this.runtime.unknown.store(true,Ordering::SeqCst)};
        if !good{this.runtime.unknown.store(true,Ordering::SeqCst);}
    }
}
#[cfg(feature="desktop-shell")]
pub(crate) async fn settle_notice_for_exit(app:&tauri::AppHandle,document:&DocumentBinding)->bool{
    let Some(runtime)=document.removal_notice_runtime()else{return true;};
    let Some(end)=document.exit_cleanup_end()else{return false;};
    // Deliberately NOT part of Document.can_exit: core Quit readiness first,
    // then actual main observer/capture retirement, then SAME relay join.
    runtime.close_for_exit(app,end).await
}


#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn fixed_ingress_and_private_completion_never_replace_originals(){
        // Only the production DATA reducers/codec execute here. No native
        // pointer, authenticated cutoff, confirmation, task or Completion is
        // fabricated from these flags or sampled from the environment.
        // Typed known startup refusal does not grant retirement; it merely
        // disables ingress while retaining the SAME ordinary-Quit obligation.
        let disabled=NoticeRuntime::reserved();assert!(!disabled.observe_start(peer_native::RemovalNoticeStart::DisabledKnown));
        assert!(!disabled.enabled.load(Ordering::SeqCst));assert!(!disabled.unknown.load(Ordering::SeqCst));
        assert!(disabled.retained_bytes().is_some());assert!(matches!(&*disabled.cleanup.lock().unwrap(),NoticeCleanup::Open));
        let unknown=NoticeRuntime::reserved();assert!(!unknown.observe_start(peer_native::RemovalNoticeStart::Unknown));
        assert!(unknown.retained_bytes().is_none());assert!(!unknown.enabled.load(Ordering::SeqCst));
        let mut hints=HintState::default();let a=[1;16];let b=[2;16];
        assert!(hints.admit([0;16]).is_none());let generation=hints.admit(a).unwrap();
        assert!(hints.admit(a).is_none());assert!(hints.admit(b).is_none());
        assert!(!hints.retire(a,generation,false));assert!(!hints.retire(b,generation,true));
        assert!(!hints.retire(a,generation+1,true));assert!(hints.admit(b).is_none());
        assert!(hints.retire(a,generation,true));assert!(hints.admit(a).is_none());
        assert_eq!(hints.admit(b),Some(generation+1));
        let mut exhausted=HintState{generation:u32::MAX-1,..HintState::default()};assert!(exhausted.admit(a).is_none());
        let mut handoff=HandoffData::default();
        assert!(!handoff.take());assert!(!handoff.bind());assert!(!handoff.complete());
        assert!(handoff.confirmed());assert!(!handoff.confirmed());assert!(!handoff.bind());
        assert!(handoff.take());assert!(!handoff.take());assert!(!handoff.complete());
        assert!(handoff.bind());assert!(!handoff.bind());assert!(handoff.complete());assert!(!handoff.complete());
        for mask in 0..32{
            let v=|bit|mask&(1<<bit)!=0;
            assert_eq!(resources_data(v(0),v(1),v(2),v(3),v(4)),mask==15);
            assert_eq!(joined_data_only(v(4),v(0),v(1),v(2),v(3)),mask==15);
        }
        let reserved=working_reservation().unwrap();assert!(reserved>INSPECTOR_RESERVE&&reserved<SESSION_BYTES);
        assert!(fits(SESSION_BYTES-reserved,reserved));assert!(!fits(SESSION_BYTES-reserved+1,reserved));assert!(!fits(usize::MAX,1));
        for target in [wire::TargetData::Arm64,wire::TargetData::Intel]{
            let release=format!("{}fixture",target.release_prefix());
            let binding=wire::BindingData::new_data(wire::BindingInputData{
                request_id:"11111111111111111111111111111111",root_nonce:"22222222222222222222222222222222",
                source_commit:"3333333333333333333333333333333333333333",release:&release,target,
                remove_producer_sha256:&"4".repeat(64),installed_producer_sha256:&"5".repeat(64),
                installed_inventory_sha256:&"6".repeat(64),protocol_sha256:&"7".repeat(64),start:1,work:110_000_000_001,hard:120_000_000_001}).unwrap();
            let expected=challenge_data(&binding).unwrap();let mut bytes=[0;wire::FRAME_LIMIT];
            let used=wire::FrameData::challenge_data(&binding).unwrap().encode_framed_data(&mut bytes).unwrap();
            let decoded=decode_challenge(&bytes[..used]).unwrap();
            assert_eq!(decoded.request_id,expected.request_id);assert_eq!(decoded.root_nonce,expected.root_nonce);
            assert_eq!((decoded.start,decoded.work,decoded.hard),(expected.start,expected.work,expected.hard));
            assert!(decode_challenge(&bytes[..used-1]).is_none());assert!(decode_challenge(&bytes[..used+1]).is_none());
            let used=wire::FrameData::confirmed_data(&binding,"88888888888888888888888888888888").unwrap().encode_framed_data(&mut bytes).unwrap();
            assert!(decode_challenge(&bytes[..used]).is_none());
            let clock=binding.clock_data();assert!(clock.work_sample_data(1,clock.work_data()-1).is_ok());
            assert!(clock.work_sample_data(1,clock.work_data()).is_err());
            assert!(clock.settlement_sample_data(clock.work_data(),clock.hard_data()-1).is_ok());
            assert!(clock.settlement_sample_data(clock.work_data(),clock.hard_data()).is_err());
            assert!(clock.work_sample_data(2,1).is_err());
        }
        assert!(hex::<16>("00000000000000000000000000000000").is_none());
        assert!(hex::<16>("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none());
    }
}
