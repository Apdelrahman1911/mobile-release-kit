//! Fixed installed Android service setup and Register's fresh read-only Check.
//! All native identity/manager custody belongs to the original saved lifecycle.
//! Completed setup DATA never supplies authenticated peer Ready or copy consent.
use super::*;

const TASK_STORAGE:usize=64*1024;
const HEARTBEAT:Duration=Duration::from_millis(5);

#[derive(Default)]
pub(super) struct State {
    generation:u32,active:Option<Arc<SetupOriginal>>,last:Option<Completed>,
    capability:Option<Availability>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    retirement:Option<Arc<Retirement>>,
}
struct Completed {
    data:wire::ServiceOperation,phase:wire::ServicePhase,reason:wire::Reason,
    prerequisite:wire::Prerequisite,observation:Option<wire::ServiceObservation>,
}
pub(crate) struct Snapshot {
    owner:Weak<Inner>,document:Weak<()>,at:Instant,request:wire::ServiceRequest,
    registration:u32,project:RegisteredRoot,pickers:[Option<Arc<crate::asset_session::OriginalWork>>;3],
    source_generation:u32,saved:crate::asset_session::ValidatedSavedInput,cohort:Mutex<Option<AdmissionCohort>>,
}
pub(crate) struct Checked { snapshot:Snapshot,id:String }
impl Snapshot {
    pub(crate) fn check_originals(self)->Result<Checked,BridgeError>{
        // Original picker proof is outside BOTH Document and Saved locks.
        for original in self.pickers.iter().flatten(){
            if !original.android_source_selected_settled(){return Err(wire::service_unavailable());}
        }
        let id=nonce(SavedCommandDomain::AndroidBuild).map_err(|_|wire::service_unavailable())?;
        Ok(Checked{snapshot:self,id})
    }
}
impl Checked {
    pub(crate) fn context(&self)->&android_wire::Prepare{&self.snapshot.request.context}
    pub(crate) fn picker_originals(&self)->&[Option<Arc<crate::asset_session::OriginalWork>>;3]{&self.snapshot.pickers}
}
struct WorkerReturn {known:bool,first:Option<(wire::Reason,Instant)>,observation:Option<wire::ServiceObservation>,retained:Option<usize>}
struct SetupOriginal {
    owner:Weak<Inner>,document:Weak<()>,data:wire::ServiceOperation,
    registration:u32,project:RegisteredRoot,pickers:[Option<Arc<crate::asset_session::OriginalWork>>;3],
    saved:crate::asset_session::ValidatedSavedInput,cohort:AdmissionCohort,control:Arc<Control>,
    reservation:std::sync::OnceLock<usize>,settling:AtomicBool,
    worker:AsyncMutex<Option<JoinHandle<WorkerReturn>>>,returned:Mutex<Option<Result<WorkerReturn,tokio::task::JoinError>>>,
    worker_joined:AtomicBool,coordinator:Mutex<Option<JoinHandle<bool>>>,
    coordinator_return:Mutex<Option<Result<bool,tokio::task::JoinError>>>,coordinator_joined:AtomicBool,
    joined_at:std::sync::OnceLock<Instant>,accepted:AtomicBool,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    preparation:Preparation,
}
pub(crate) struct Finalization {original:Arc<SetupOriginal>}
impl Finalization {pub(crate) fn context(&self)->&android_wire::Prepare{&self.original.data.context}}
/// This sender releases only the installed identity/service Check. It never
/// authorizes installation implicitly, source reading, Hello or payload.
pub(crate) struct Admitted {status:wire::ServiceStatus,release:Option<oneshot::Sender<()>>,original:Arc<SetupOriginal>}
impl Admitted {
    pub(crate) fn release(mut self)->Result<wire::ServiceStatus,BridgeError>{
        if self.release.take().is_none_or(|sender|sender.send(()).is_err()){
            self.original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());return Err(wire::service_unconfirmed());
        }
        Ok(self.status.clone())
    }
}
impl Drop for Admitted {
    fn drop(&mut self){if self.release.is_some(){self.original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());}}
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
use mrk_macos_installed_native::{self as installed_native,android_service_management as management,
    android_maintenance_client as maintenance_native,android_registration as registration_native};
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
use crate::installed_runtime::AndroidServiceIdentitySlots;

/// Constructed once by the actual shell for the original local main window.
/// Headless/unsupported adapters have no constructor and cannot install one.
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
pub(crate) struct Dispatcher {
    #[cfg(feature="desktop-shell")]
    window:tauri::WebviewWindow,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl Dispatcher {
    #[cfg(feature="desktop-shell")]
    pub(crate) fn original_main(window:tauri::WebviewWindow)->Option<Self>{
        (installed_native::main_thread() && window.label()=="main").then_some(Self{window})
    }
    fn dispatch(&self,capture:Arc<CallbackOriginal>)->Result<(),()>{
        if installed_native::main_thread(){return Err(());}
        #[cfg(feature="desktop-shell")]
        {self.window.run_on_main_thread(move||CallbackOriginal::perform(&capture)).map_err(|_|())}
        #[cfg(not(feature="desktop-shell"))]
        {let _=capture;Err(())}
    }
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
const PENDING:u8=0;
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
const CALLBACK_RETIRED:u8=1;
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
const OWNER_FINALIZED:u8=2;
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
struct Retirement {
    original:Arc<Control>,action:management::Action,require_enabled:bool,phase:std::sync::atomic::AtomicU8,
    retired_serial:std::sync::atomic::AtomicU32,maintenance:Option<MaintenanceTail>,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
struct MaintenanceTail {
    operation:[u8;16],cutoff:std::sync::OnceLock<Instant>,original:Mutex<Option<maintenance_native::TailAdmission>>,
    retired:AtomicBool,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl MaintenanceTail {
    fn new(operation:[u8;16])->Self{Self{operation,cutoff:std::sync::OnceLock::new(),original:Mutex::new(None),retired:AtomicBool::new(false)}}
    /// Only the actual extracted final callback or proved never-requested path
    /// calls this. A status/callback-return bit cannot release the SAME DATA.
    fn retire(&self)->bool{
        let Ok(mut held)=self.original.try_lock()else{return false;};
        if self.retired.load(Ordering::SeqCst){return held.is_none();}
        if let Some(original)=held.take(){original.retire();}
        self.retired.store(true,Ordering::SeqCst);true
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl Retirement {
    fn retained_bytes(&self)->Option<usize>{arc_bytes::<Self>()?.checked_add(self.original.retained_bytes()?)?
        .checked_add(arc_bytes::<()>()?)} // The completed original still retains its own cohort allocation.
    fn callback_retired(&self,serial:u32,deferred:bool)->bool{
        if self.phase.load(Ordering::SeqCst)!=PENDING || serial==0 || serial==u32::MAX
            || self.retired_serial.compare_exchange(serial-1,serial,Ordering::SeqCst,Ordering::SeqCst).is_err(){return false;}
        if deferred{return true;}
        if self.maintenance.as_ref().is_some_and(|tail|!tail.retire()){return false;}
        self.phase.compare_exchange(PENDING,CALLBACK_RETIRED,Ordering::SeqCst,Ordering::SeqCst).is_ok()
    }
    fn finalize(&self)->bool{
        if self.maintenance.as_ref().is_some_and(|tail|!tail.retired.load(Ordering::SeqCst)){return false;}
        self.phase.compare_exchange(CALLBACK_RETIRED,OWNER_FINALIZED,Ordering::SeqCst,Ordering::SeqCst).is_ok()
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
#[derive(Clone,Copy,Default)]
struct CapturedFailure {first:Option<(wire::Reason,Instant)>,unknown:bool}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl CapturedFailure {
    fn note(&mut self,reason:wire::Reason,at:Instant){
        if self.first.is_none_or(|(_,old)|at<old){self.first=Some((reason,at));}
        self.unknown|=reason==wire::Reason::CleanupUnknown;
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
#[derive(Clone,Copy)]
struct CallbackReturned {native:Option<(management::Progress,management::Custody)>,failure:CapturedFailure,at:Instant}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
struct CallbackOriginal {
    gate:WorkGate,action:management::Action,serial:u32,retirement:Arc<Retirement>,
    returned:Mutex<Option<CallbackReturned>>,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
enum ExtractedCallback {
    Pending(Arc<CallbackOriginal>),Returned(u32,CallbackReturned),Unknown(Option<CallbackReturned>),
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
struct MainBinding {retirement:Arc<Retirement>,serial:u32}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl MainBinding {
    fn reusable(&self)->bool{self.retirement.phase.load(Ordering::SeqCst)==OWNER_FINALIZED
        && !self.retirement.original.unknown.load(Ordering::SeqCst)}
    fn resumes(&self,original:&CallbackOriginal,custody:management::Custody)->bool{
        Arc::ptr_eq(&self.retirement,&original.retirement)
            && Arc::ptr_eq(&self.retirement.original,&original.gate.control)
            && self.retirement.action==original.action && self.retirement.phase.load(Ordering::SeqCst)==PENDING
            && !self.retirement.original.unknown.load(Ordering::SeqCst)
            && original.serial>1 && original.serial<u32::MAX
            && self.serial.checked_add(1)==Some(original.serial)
            && self.retirement.retired_serial.load(Ordering::SeqCst)==self.serial
            && management_deferred(custody,original.action)
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
struct MainSlot {manager:management::ServiceManager,binding:Option<MainBinding>}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
thread_local! {static MAIN:std::cell::RefCell<MainSlot>=std::cell::RefCell::new(MainSlot{
    manager:management::ServiceManager::new(),binding:None});}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn management_settled(custody:management::Custody)->bool{
    !custody.unknown && !custody.in_call && !custody.gate_entered && custody.action.is_none()
        && matches!(custody.cell,management::CellCustody::Absent|management::CellCustody::Consumed)
        && matches!(custody.service,management::ServiceCustody::NotAcquired|management::ServiceCustody::Settled)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn management_deferred(custody:management::Custody,action:management::Action)->bool{
    custody.action==Some(action) && custody.phase==Some(management::Phase::AdmitAction)
        && custody.cell==management::CellCustody::Owned && custody.service==management::ServiceCustody::NotAcquired
        && !custody.action_admitted && !custody.in_call && !custody.gate_entered && !custody.unknown
        && !custody.stopped && custody.first_failure.is_none()
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn management_reason(custody:management::Custody)->wire::Reason{
    if custody.unknown{return wire::Reason::CleanupUnknown;}
    match custody.observation.map(|observation|observation.outcome){
        Some(management::Outcome::DeniedByUser)=>wire::Reason::ApprovalDenied,
        _=>wire::Reason::ServiceUnavailable,
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl CallbackOriginal {
    /// Actual exclusive extraction, not a strong-count observation or a return
    /// slot peek. This consumes no native custody and grants no finality stamp.
    fn extract(held:Arc<Self>,retirement:&Arc<Retirement>)->ExtractedCallback{
        let original=match Arc::try_unwrap(held){Ok(original)=>original,Err(held)=>return ExtractedCallback::Pending(held)};
        let exact=Arc::ptr_eq(&original.retirement,retirement)
            && Arc::ptr_eq(&original.gate.control,&retirement.original) && original.action==retirement.action;
        match original.returned.into_inner().ok().flatten(){
            Some(returned) if exact=>ExtractedCallback::Returned(original.serial,returned),
            returned=>ExtractedCallback::Unknown(returned),
        }
    }
    fn unknown(&self,failure:&mut CapturedFailure){
        failure.unknown=true;
        // AppKit must never take a blocking Control/Slot/watch path. The same
        // independently runnable coordinator projects STOP and notifications.
        self.gate.control.unknown.store(true,Ordering::SeqCst);
        self.gate.control.dirty.store(true,Ordering::SeqCst);
    }
    fn gate(&self,point:management::Checkpoint,failure:&mut CapturedFailure)->management::Decision{
        use management::{Checkpoint,Phase};
        let (phase,custody,returned)=match point{Checkpoint::Before{phase,custody}=>(phase,custody,None),
            Checkpoint::Returned{phase,at,custody}=>(phase,custody,Some(at))};
        if let Some(at)=custody.first_failure{failure.note(management_reason(custody),at);}
        if custody.unknown{failure.unknown=true;}
        if phase==Phase::AllocateCell && returned.is_some() && custody.cell==management::CellCustody::Absent{
            failure.note(wire::Reason::ServiceUnavailable,returned.unwrap());
        }
        // Register requires an actual fresh Enabled observation, whereas the
        // separate setup Check successfully reports other known states. Latch
        // at this real native return, never after cleanup/IPC receipt.
        if self.retirement.require_enabled && phase==Phase::ObserveStatus {
            if let (Some(at),Some(observation))=(returned,custody.observation){
                if observation.status!=management::Status::Enabled{
                    failure.note(if observation.status==management::Status::RequiresApproval{
                        wire::Reason::ApprovalRequired
                    }else{wire::Reason::ServiceUnavailable},at);
                }
            }
        }
        let defer=phase==Phase::AdmitAction && returned.is_none() && !custody.action_admitted && failure.first.is_none() && !failure.unknown;
        self.cut(phase,defer,failure)
    }
    /// Current-original cut only. The prebinding check must not import a
    /// previously finalized TLS action's retained observation or failure.
    fn cut(&self,phase:management::Phase,defer:bool,failure:&mut CapturedFailure)->management::Decision{
        use management::Decision;
        let book=match self.gate.slot.book.try_lock(){
            Ok(book)=>book,Err(TryLockError::WouldBlock) if defer=>return Decision::Defer,
            _=>{self.unknown(failure);return Decision::Unknown;}
        };
        let cohort=book.cohort.as_ref().filter(|cohort|cohort.identity.as_ptr()==Arc::as_ptr(&self.gate.control.cohort));
        let exact=book.original.as_ref().is_some_and(|original|Arc::ptr_eq(original,&self.gate.control))
            && cohort.is_some_and(|cohort|cohort.epoch==self.gate.control.epoch)
            && (book.epoch==self.gate.control.epoch || cohort.is_some_and(|cohort|cohort.first.is_some()));
        if !exact || self.gate.slot.is_unknown() || self.gate.control.unknown.load(Ordering::SeqCst){
            drop(book);self.unknown(failure);return Decision::Unknown;
        }
        if let Some((reason,at))=cohort.and_then(|cohort|cohort.first){failure.note(reason,at);}
        let mut first=match self.gate.control.first.try_lock(){
            Ok(first)=>first,Err(TryLockError::WouldBlock) if defer && failure.first.is_none()=>return Decision::Defer,
            _=>{drop(book);self.unknown(failure);return Decision::Unknown;}
        };
        if let Some((reason,at))=*first{failure.note(reason,at);}
        let now=Instant::now();
        if now>=self.gate.control.work{failure.note(wire::Reason::TimedOut,self.gate.control.work);}
        if let Some((reason,at))=failure.first{
            let (reason,at)=if at>self.gate.control.work{(wire::Reason::TimedOut,self.gate.control.work)}else{(reason,at)};
            if first.is_none_or(|(_,old)|at<old){*first=Some((reason,at));self.gate.control.dirty.store(true,Ordering::SeqCst);}
            failure.first=*first;
        }
        let pending=ControlSlot::pending(&book);
        let mut endpoint=failure.first.and_then(|(_,first)|first.checked_add(SETTLEMENT))
            .map_or(self.gate.control.hard,|end|end.min(self.gate.control.hard));
        // Immutable SAME-tail lower bound, never Control::endpoint/watch or a
        // worker-owned native/identity mutex on AppKit. Missing is not admission.
        if let Some(tail)=&self.retirement.maintenance{
            let Some(cutoff)=tail.cutoff.get().copied()else{
                drop(first);drop(book);self.unknown(failure);return Decision::Unknown;
            };
            if self.action!=management::Action::UnregisterAfterQuiescence || tail.operation==[0;16]{
                drop(first);drop(book);self.unknown(failure);return Decision::Unknown;
            }
            endpoint=endpoint.min(cutoff);
        }else if self.action==management::Action::UnregisterAfterQuiescence{
            drop(first);drop(book);self.unknown(failure);return Decision::Unknown;
        }
        drop(first);drop(book);
        if failure.unknown || now>=endpoint{self.unknown(failure);return Decision::Unknown;}
        if phase.is_cleanup(){return Decision::Proceed;}
        if failure.first.is_some(){return Decision::Stop;}
        if defer && pending{return Decision::Defer;}
        Decision::Proceed
    }
    fn perform(original:&Self){
        let mut failure=CapturedFailure::default();
        let native=if !installed_native::main_thread(){None}else{
            MAIN.try_with(|slot|{
                let Ok(mut slot)=slot.try_borrow_mut()else{return None;};
                let custody=slot.manager.custody();
                let resume=slot.binding.as_ref().is_some_and(|binding|binding.resumes(original,custody));
                if !resume{
                    let retired=slot.binding.as_ref().is_none_or(MainBinding::reusable);
                    if !retired || !management_settled(custody) || original.serial!=1
                        || original.retirement.phase.load(Ordering::SeqCst)!=PENDING
                        || original.retirement.retired_serial.load(Ordering::SeqCst)!=0{return None;}
                    // Validate the new original before retiring the previous
                    // finalized TLS binding. This is not native action admission.
                    if !matches!(original.cut(management::Phase::AllocateCell,false,&mut failure),
                        management::Decision::Proceed|management::Decision::Stop){return None;}
                    // A known Stop between queueing and callback entry still
                    // runs the same engine's no-allocation settlement path.
                    // Unknown never binds or authorizes a native entry.
                    slot.binding=Some(MainBinding{retirement:original.retirement.clone(),serial:original.serial});
                }else{slot.binding.as_mut().unwrap().serial=original.serial;}
                let progress=slot.manager.perform_phased(original.action,&mut|point|original.gate(point,&mut failure));
                Some((progress,slot.manager.custody()))
                // The persistent binding is NEVER cleared here. Only exclusive
                // callback extraction + original owner finality can permit reuse.
            }).ok().flatten()
        };
        // The native/TLS mutable borrow has actually ended before this sole
        // returned record is published. No clone/Weak to CallbackOriginal exists.
        if native.is_none(){original.unknown(&mut failure);}
        let returned=CallbackReturned{native,failure,at:Instant::now()};
        match original.returned.try_lock(){
            Ok(mut slot) if slot.is_none()=>{*slot=Some(returned);}
            _=>original.unknown(&mut failure),
        }
        // Tail return only. The framework closure now retires its sole Arc.
    }
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
enum MainState {Dormant,Queued(Arc<CallbackOriginal>),Deferred(u32),Finished(CallbackReturned),Skipped,Unknown(Option<CallbackReturned>),Transition}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) struct Preparation {
    gate:WorkGate,identity:Mutex<AndroidServiceIdentitySlots>,dispatcher:Arc<Dispatcher>,
    retirement:Arc<Retirement>,requested:AtomicBool,main:Mutex<MainState>,
    returned:Mutex<Option<PreparationReturn>>,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
#[derive(Clone,Copy)]
struct PreparationReturn {known:bool,checked:bool,observation:Option<wire::ServiceObservation>,retained:Option<usize>,maintenance:Option<MaintenanceRun>}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
#[derive(Clone,Copy,Default)]
pub(super) struct MaintenanceRun {
    pub(super) known:bool,pub(super) checked:bool,pub(super) started_or_uncertain:bool,
    pub(super) tail_received:bool,pub(super) unregister_accepted:bool,pub(super) not_registered:bool,
    pub(super) callback_retired:bool,pub(super) peer_ended:bool,pub(super) retained:Option<usize>,
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl MaintenanceRun {
    pub(super) fn prepared(self)->bool{self.known && self.checked && self.started_or_uncertain && self.tail_received
        && self.unregister_accepted && self.not_registered && self.callback_retired && self.peer_ended && self.retained.is_some()}
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl Preparation {
    // Enforced on the ACTUAL settled identity ledger before Register can begin
    // its client/source phase. Peak inspector storage never overlaps sources.
    pub(super) const SETTLED_BYTES:usize=2*1024*1024;
    pub(super) fn new(gate:WorkGate,dispatcher:Arc<Dispatcher>,action:management::Action)->Self{
        Self::create(gate,dispatcher,action,false,None)
    }
    pub(super) fn for_registration(gate:WorkGate,dispatcher:Arc<Dispatcher>)->Self{
        Self::create(gate,dispatcher,management::Action::Observe,true,None)
    }
    pub(super) fn for_maintenance(gate:WorkGate,dispatcher:Arc<Dispatcher>,operation:[u8;16])->Self{
        Self::create(gate,dispatcher,management::Action::UnregisterAfterQuiescence,true,Some(operation))
    }
    fn create(gate:WorkGate,dispatcher:Arc<Dispatcher>,action:management::Action,require_enabled:bool,operation:Option<[u8;16]>)->Self{
        let retirement=Arc::new(Retirement{original:gate.control.clone(),action,require_enabled,phase:std::sync::atomic::AtomicU8::new(PENDING),
            retired_serial:std::sync::atomic::AtomicU32::new(0),maintenance:operation.map(MaintenanceTail::new)});
        Self{identity:Mutex::new(AndroidServiceIdentitySlots::new(gate.clone())),gate,dispatcher,retirement,
            requested:AtomicBool::new(false),main:Mutex::new(MainState::Dormant),returned:Mutex::new(None)}
    }
    pub(super) fn reservation_bytes()->Option<usize>{
        AndroidServiceIdentitySlots::working_reservation_bytes()?.checked_add(std::mem::size_of::<Self>())?
            .checked_add(arc_bytes::<Retirement>()?)?.checked_add(arc_bytes::<Dispatcher>()?)?
            .checked_add(arc_bytes::<CallbackOriginal>()?.checked_mul(2)?)?
            .checked_add(management::ServiceManager::project_owned_upper_bound()?)?
            .checked_add(std::mem::size_of::<MainSlot>())?.checked_add(4*SIGNAL_STORAGE)
    }
    fn project_return(&self,returned:CallbackReturned)->bool{
        if let Some((reason,at))=returned.failure.first{self.gate.control.stop_at(reason,at);}
        if let Some((_,custody))=returned.native{
            if let Some(at)=custody.first_failure{self.gate.control.stop_at(management_reason(custody),at);}
            if custody.unknown{self.gate.control.mark_unknown(custody.first_failure.unwrap_or(returned.at));}
        }
        if returned.failure.unknown{
            if let Some((_,at))=returned.failure.first{self.gate.control.mark_unknown(at);}else{self.gate.control.poisoned();}
        }
        self.gate.control.advance(Instant::now());
        if returned.at>=self.gate.control.endpoint() || self.gate.control.unknown.load(Ordering::SeqCst){
            self.gate.control.mark_unknown(returned.at);return false;
        }
        true
    }
    /// Coordinator-only, no identity/native mutex. The same call also observes
    /// late capture retirement without dispatching new work after final return.
    pub(super) fn tick(&self,allow_dispatch:bool){
        if let Some((reason,at))=self.gate.control.failure(){self.gate.control.stop_at(reason,at);}
        if self.gate.control.unknown.load(Ordering::SeqCst){
            if let Some((_,at))=self.gate.control.failure(){self.gate.control.mark_unknown(at);}else{self.gate.control.poisoned();}
        }
        self.gate.control.advance(Instant::now());
        let mut state=match self.main.try_lock(){Ok(state)=>state,Err(TryLockError::WouldBlock)=>return,
            Err(TryLockError::Poisoned(_))=>{self.gate.control.poisoned();return;}};
        let before=std::mem::replace(&mut *state,MainState::Transition);
        *state=match before{
            MainState::Queued(held)=>match CallbackOriginal::extract(held,&self.retirement){
                ExtractedCallback::Pending(held)=>MainState::Queued(held),
                ExtractedCallback::Returned(serial,returned) if self.project_return(returned)=>match returned.native{
                            Some((management::Progress::Deferred,custody)) if management_deferred(custody,self.retirement.action)
                                && self.retirement.callback_retired(serial,true)=>MainState::Deferred(serial),
                            Some((management::Progress::Finished(observation),custody)) if observation.native_settled
                                && management_settled(custody) && self.retirement.callback_retired(serial,false)=>MainState::Finished(returned),
                            _=>{self.gate.control.mark_unknown(returned.at);MainState::Unknown(Some(returned))}
                },
                ExtractedCallback::Returned(_,returned)=>{self.gate.control.poisoned();MainState::Unknown(Some(returned))},
                ExtractedCallback::Unknown(returned)=>{self.gate.control.poisoned();MainState::Unknown(returned)},
            },other=>other,
        };
        if !allow_dispatch || !self.requested.load(Ordering::SeqCst){return;}
        let serial=match &*state{
            MainState::Dormant=>{
                if self.gate.control.failure().is_some(){*state=MainState::Skipped;return;}
                1
            },
            MainState::Deferred(prior)=>match prior.checked_add(1).filter(|value|*value<u32::MAX){Some(next)=>next,None=>{
                self.gate.control.poisoned();return;}},
            _=>return,
        };
        if Instant::now()>=self.gate.control.endpoint() || self.gate.control.unknown.load(Ordering::SeqCst){return;}
        // Deferred + accepted failure must resume the SAME manager for its
        // native cleanup; a not-yet-created action instead remains Skipped.
        if self.gate.control.failure().is_none() && self.gate.try_work()!=Some(true){return;}
        let held=Arc::new(CallbackOriginal{gate:self.gate.clone(),action:self.retirement.action,serial,
            retirement:self.retirement.clone(),returned:Mutex::new(None)});
        let capture=held.clone(); // ONLY second strong owner; no Weak exists.
        *state=MainState::Queued(held);
        if self.dispatcher.dispatch(capture).is_err(){self.gate.control.poisoned();}
    }
    fn main_result(&self)->Option<(bool,Option<CallbackReturned>)>{
        let state=self.main.try_lock().ok()?;
        match &*state{
            MainState::Dormant if !self.requested.load(Ordering::SeqCst)=>Some((true,None)),
            MainState::Skipped=>Some((true,None)),MainState::Finished(returned)=>Some((true,Some(*returned))),
            MainState::Unknown(returned)=>Some((false,*returned)),_=>None,
        }
    }
    fn observation(returned:CallbackReturned)->Option<wire::ServiceObservation>{
        let (progress,custody)=returned.native?;
        let management::Progress::Finished(observed)=progress else{return None;};
        if observed.action==management::Action::UnregisterAfterQuiescence{return None;}
        if !observed.native_settled || !management_settled(custody){return None;}
        // Native denial/failure predates Stop. Preserve it even when a later
        // lifecycle gate makes Progress's public outcome Stopped.
        let outcome=custody.observation.filter(|value|matches!(value.outcome,management::Outcome::DeniedByUser
            |management::Outcome::Refused|management::Outcome::Error)).map_or(observed.outcome,|value|value.outcome);
        Some(wire::ServiceObservation{
            state:match observed.status{management::Status::NotRegistered=>wire::ServiceState::NotRegistered,
                management::Status::Enabled=>wire::ServiceState::Enabled,management::Status::RequiresApproval=>wire::ServiceState::RequiresApproval,
                management::Status::NotFound=>wire::ServiceState::NotFound,management::Status::Unavailable=>wire::ServiceState::Unavailable,
                management::Status::Error=>wire::ServiceState::Error},
            outcome:match outcome{management::Outcome::NotEntered=>wire::ServiceOutcome::NotEntered,management::Outcome::Observed=>wire::ServiceOutcome::Observed,
                management::Outcome::RegistrationRequested=>wire::ServiceOutcome::RegistrationRequested,management::Outcome::AlreadyRegistered=>wire::ServiceOutcome::AlreadyRegistered,
                management::Outcome::NeedsApproval=>wire::ServiceOutcome::NeedsApproval,management::Outcome::SettingsRequested=>wire::ServiceOutcome::SettingsRequested,
                management::Outcome::DeniedByUser=>wire::ServiceOutcome::DeniedByUser,management::Outcome::Stopped=>wire::ServiceOutcome::Stopped,
                management::Outcome::Refused=>wire::ServiceOutcome::Refused,management::Outcome::Error=>wire::ServiceOutcome::Error,management::Outcome::Unknown=>wire::ServiceOutcome::Unknown,
                management::Outcome::UnregisterAccepted=>return None},
            mutation_entered:observed.mutation_entered,mutation_returned:observed.mutation_returned,
            mutation_uncertain:observed.mutation_uncertain,native_settled:true})
    }
    /// SAME registered blocking worker owns all identity native calls/cleanup.
    /// Main dispatch/actual capture extraction belongs to its independent async
    /// coordinator via tick; no worker-held book is needed to publish STOP.
    pub(super) fn run_once(&self)->bool{
        if self.retirement.action==management::Action::UnregisterAfterQuiescence{self.gate.control.poisoned();return false;}
        let mut identity=match self.identity.try_lock(){Ok(identity)=>identity,
            Err(_)=>{self.gate.control.poisoned();return false;}};
        if self.returned.try_lock().map_or(true,|returned|returned.is_some()){
            self.gate.control.poisoned();return false;
        }
        let stop=self.gate.control.stop.subscribe();
        let checked=self.gate.source_work().is_ok() && identity.check_once(self.gate.control.work,&stop).is_ok();
        if checked{self.requested.store(true,Ordering::SeqCst);self.gate.control.changed();}
        let mut files_known=None;
        let main=loop{
            self.gate.control.advance(Instant::now());
            if self.gate.control.failure().is_some() && files_known.is_none(){files_known=Some(identity.settle());}
            if let Some(result)=self.main_result(){break result;}
            if Instant::now()>=self.gate.control.endpoint(){self.gate.control.mark_unknown(Instant::now());break(false,None);}
            std::thread::park_timeout(HEARTBEAT);
        };
        if checked && self.gate.control.failure().is_none() && main.0
            && identity.recheck(self.gate.control.work,&stop).is_err(){self.gate.control.stop_at(wire::Reason::SigningUnavailable,Instant::now());}
        let files_known=files_known.unwrap_or_else(||identity.settle());
        let observation=main.1.and_then(Self::observation);
        // Complete project-owned retained preparation, not just identity FDs:
        // the settled TLS manager/stamp/dispatcher and callback/return cells
        // remain charged while client/source work proceeds. Control/cohort and
        // selected picker originals are independently charged by parent census.
        let retained=identity.retained_bytes().and_then(|bytes|self.settled_storage(bytes));
        if retained.is_some_and(|bytes|bytes>Self::SETTLED_BYTES){self.gate.control.stop_at(wire::Reason::ResultLimit,Instant::now());}
        let known=files_known && main.0 && retained.is_some() && !self.gate.control.unknown.load(Ordering::SeqCst)
            && Instant::now()<self.gate.control.endpoint();
        let returned=PreparationReturn{known,checked,observation,retained,maintenance:None};
        drop(identity);
        let mut output=match self.returned.try_lock(){Ok(output)=>output,
            Err(_)=>{self.gate.control.poisoned();return false;}};
        if output.is_some(){self.gate.control.poisoned();return false;}
        *output=Some(returned);
        known && checked && self.gate.control.failure().is_none()
    }

    fn request_maintenance(&self,tail:maintenance_native::TailAdmission,
        clock:&maintenance::OriginalClock,signal:&registration_native::Signal)->bool{
        let Some(retained)=self.retirement.maintenance.as_ref()else{
            // TailAdmission's ManuallyDrop keeps uncertain DATA, not a guessed close.
            self.gate.control.poisoned();return false;
        };
        let operation=tail.operation();let cutoff=tail.cutoff();
        let mut held=match retained.original.try_lock(){Ok(held)=>held,Err(_)=>{self.gate.control.poisoned();return false;}};
        if held.is_some() || retained.retired.load(Ordering::SeqCst) || retained.cutoff.get().is_some(){
            self.gate.control.poisoned();return false;
        }
        *held=Some(tail); // Same owning capture remains in the original on every refusal.
        if operation!=retained.operation || self.retirement.action!=management::Action::UnregisterAfterQuiescence
            || retained.cutoff.set(cutoff).is_err() || !self.gate.control.narrow_maintenance(cutoff){
            self.gate.control.poisoned();return false;
        }
        drop(held);
        // All resident F has already been synchronized before this call. A new
        // concurrent publisher is still enforced at each AppKit action cut.
        loop {
            clock.synchronize(&self.gate.control,signal);
            if self.gate.control.failure().is_some() || self.gate.control.unknown.load(Ordering::SeqCst)
                || !signal.admitted(false) || Instant::now()>=self.gate.control.endpoint(){return false;}
            match self.gate.try_work(){
                Some(true)=>break,
                Some(false)=>std::thread::park_timeout(HEARTBEAT.min(
                    self.gate.control.endpoint().saturating_duration_since(Instant::now()))),
                None=>return false,
            }
        }
        // A pending publisher is reversible waiting, not a fabricated refusal.
        // Reimport the SAME F after that wait; no new R/timeout interval.
        clock.synchronize(&self.gate.control,signal);
        if self.gate.control.failure().is_some() || self.gate.control.unknown.load(Ordering::SeqCst)
            || !signal.admitted(false) || Instant::now()>=self.gate.control.endpoint(){return false;}
        if self.requested.swap(true,Ordering::SeqCst){self.gate.control.poisoned();return false;}
        self.gate.control.changed();true
    }
    fn maintenance_observation(returned:Option<CallbackReturned>)->(bool,bool){
        let Some((_progress,custody))=returned.and_then(|returned|returned.native)else{return(false,false);};
        let actual=custody.observation.filter(|value|value.action==management::Action::UnregisterAfterQuiescence);
        let accepted=actual.is_some_and(|value|value.outcome==management::Outcome::UnregisterAccepted
            && value.mutation_entered && value.mutation_returned && !value.mutation_uncertain);
        // These are retained same-service positive facts, not finality. A later
        // release/retire/callback failure must not erase observed NotRegistered.
        // run_maintenance's known and MaintenanceRun::prepared still separately
        // require all native/owner settlement, closes and the original deadline.
        let not_registered=accepted && actual.is_some_and(|value|value.status==management::Status::NotRegistered);
        (accepted,not_registered)
    }
    pub(super) fn maintenance_partial(&self)->(bool,bool){
        let Ok(main)=self.main.try_lock()else{return(false,false);};
        match &*main{MainState::Finished(returned)|MainState::Unknown(Some(returned))=>Self::maintenance_observation(Some(*returned)),
            _=>(false,false)}
    }
    pub(super) fn maintenance_return(&self)->Option<MaintenanceRun>{
        self.returned.try_lock().ok()?.as_ref()?.maintenance
    }
    /// The ORIGINAL IPC worker owns identity -> A/watcher/B/drain -> tail ->
    /// main-result observation -> identity cleanup -> EOF/exit -> client closes.
    /// Its existing independent coordinator alone dispatches/extracts AppKit.
    pub(super) fn run_maintenance(&self,client:&mut maintenance_native::Client,
        clock:&maintenance::OriginalClock,signal:&registration_native::Signal)->MaintenanceRun{
        let empty=MaintenanceRun::default();
        if self.retirement.action!=management::Action::UnregisterAfterQuiescence
            || self.retirement.maintenance.is_none() || self.requested.load(Ordering::SeqCst)
            || self.returned.try_lock().map_or(true,|returned|returned.is_some()){
            self.gate.control.poisoned();return empty;
        }
        let mut identity=match self.identity.try_lock(){Ok(identity)=>identity,
            Err(_)=>{self.gate.control.poisoned();return empty;}};
        let synchronize=||{
            let _=self.gate.try_work(); // SAME durable cohort F, not just its later watch projection.
            clock.synchronize(&self.gate.control,signal);
        };
        let cleanup=||{synchronize();Instant::now()<self.gate.control.endpoint() && signal.admitted(true)};
        let fail=|reason|{let at=Instant::now();self.gate.control.stop_at(reason,at);synchronize();};
        let stop=self.gate.control.stop.subscribe();
        synchronize();
        let checked=self.gate.source_work().is_ok() && identity.check_once(self.gate.control.work,&stop).is_ok();
        if checked && self.gate.source_work().is_ok() && signal.admitted(false){
            let entered=client.begin();let returned_at=Instant::now();
            synchronize();
            match entered{
                Ok(maintenance_native::Drain::Busy)|Ok(maintenance_native::Drain::Refused)=>{
                    self.gate.control.stop_at(wire::Reason::ServiceUnavailable,returned_at);synchronize();
                },
                Err(_)=>{
                    if self.gate.control.failure().is_none(){self.gate.control.stop_at(wire::Reason::ServiceUnavailable,returned_at);}
                    synchronize();
                },
                Ok(maintenance_native::Drain::Started)=>{
                    while cleanup(){
                        let progress=client.step();let returned_at=Instant::now();synchronize();
                        match progress{
                            Ok(maintenance_native::Progress::TailReceived)=>{
                                // Import F BEFORE taking the opaque no-F admission,
                                // and again before publishing main requested.
                                if self.gate.control.failure().is_none() && !self.gate.control.unknown.load(Ordering::SeqCst){
                                    if let Some(tail)=client.take_tail_admission(clock.bridge()){
                                        synchronize();self.request_maintenance(tail,clock,signal);
                                    }else{fail(wire::Reason::ServiceUnavailable);}
                                }
                                break;
                            },
                            Ok(maintenance_native::Progress::Pending)=>{
                                if self.gate.control.failure().is_some() || self.gate.control.unknown.load(Ordering::SeqCst){break;}
                                std::thread::park_timeout(HEARTBEAT);
                            },
                            _=>{
                                if self.gate.control.failure().is_none(){self.gate.control.stop_at(wire::Reason::ServiceUnavailable,returned_at);}
                                synchronize();break;
                            },
                        }
                    }
                },
            }
        }else if self.gate.control.failure().is_none(){fail(wire::Reason::ServiceUnavailable);}
        let mut files_known=None;
        let main=loop{
            synchronize();
            if self.gate.control.failure().is_some() && files_known.is_none(){files_known=Some(identity.settle());}
            if let Some(result)=self.main_result(){break result;}
            if !cleanup(){self.gate.control.mark_unknown(Instant::now());break(false,None);}
            std::thread::park_timeout(HEARTBEAT);
        };
        // No main callback was ever requested, or it was skipped before capture.
        // This is the only non-callback retirement route for the same tail.
        if main.0{
            if let Ok(main_state)=self.main.try_lock(){
                if matches!(&*main_state,MainState::Dormant|MainState::Skipped)
                    && self.retirement.maintenance.as_ref().is_some_and(|tail|!tail.retire()){
                    self.gate.control.poisoned();
                }
            }else{self.gate.control.poisoned();}
        }
        let (unregister_accepted,not_registered)=Self::maintenance_observation(main.1);
        if checked && main.0 && self.gate.control.failure().is_none()
            && identity.recheck(self.gate.control.work,&stop).is_err(){fail(wire::Reason::SigningUnavailable);}
        let files_known=files_known.unwrap_or_else(||identity.settle());
        let identity_retained=identity.retained_bytes().and_then(|bytes|self.settled_storage(bytes));
        drop(identity);
        synchronize();
        let mut peer_ended=false;
        if unregister_accepted{
            while cleanup(){
                let progress=client.step();let at=Instant::now();synchronize();
                match progress{
                    Ok(maintenance_native::Progress::Exited)=>{peer_ended=client.final_observed();break;},
                    Ok(maintenance_native::Progress::Pending)=>std::thread::park_timeout(HEARTBEAT),
                    _=>{if self.gate.control.failure().is_none(){self.gate.control.stop_at(wire::Reason::ServiceUnavailable,at);}break;},
                }
            }
        }
        let started_or_uncertain=client.started_or_uncertain();
        let tail_received=client.genuine_tail_received();
        // Every owned close is attempted only through the SAME book's original
        // cleanup bounds. Unknown never causes a second connection or retry.
        let client_known=client.release() && client.settled();synchronize();
        let retained=identity_retained.and_then(|bytes|bytes.checked_add(client.retained_bytes()?));
        if retained.is_some_and(|bytes|bytes>Self::SETTLED_BYTES){fail(wire::Reason::ResultLimit);}
        let callback_retired=self.retirement.maintenance.as_ref().is_some_and(|tail|tail.retired.load(Ordering::SeqCst));
        let known=files_known && main.0 && callback_retired && client_known && retained.is_some()
            && !self.gate.control.unknown.load(Ordering::SeqCst) && Instant::now()<self.gate.control.endpoint();
        let result=MaintenanceRun{known,checked,started_or_uncertain,tail_received,unregister_accepted,not_registered,
            callback_retired,peer_ended,retained};
        // A valid private native result is still not overall Prepared. Both
        // original worker/coordinator handles and the document cut remain owed.
        let returned=PreparationReturn{known,checked,observation:None,retained,maintenance:Some(result)};
        match self.returned.try_lock(){Ok(mut output) if output.is_none()=>*output=Some(returned),
            _=>{self.gate.control.poisoned();return MaintenanceRun{known:false,..result};}}
        result
    }

    pub(super) fn registration_ready(&self)->bool{
        self.retirement.require_enabled && self.run_once() && self.returned.try_lock().is_ok_and(|returned|returned.is_some_and(|returned|
            returned.known && returned.checked && returned.observation.is_some_and(|observation|
                observation.state==wire::ServiceState::Enabled && observation.outcome==wire::ServiceOutcome::Observed)))
    }
    pub(super) fn run_if_not_returned(&self){
        if self.returned.try_lock().is_ok_and(|returned|returned.is_none()){self.run_once();}
    }
    pub(super) fn known_return(&self)->bool{
        !self.gate.control.unknown.load(Ordering::SeqCst) && self.returned.try_lock().is_ok_and(|returned|
            returned.is_some_and(|returned|returned.known && returned.retained.is_some()))
    }
    fn worker_return(&self)->Option<WorkerReturn>{
        let returned=(*self.returned.try_lock().ok()?)?;
        Some(WorkerReturn{known:returned.known,first:self.gate.control.failure(),observation:returned.observation,retained:returned.retained})
    }
    pub(super) fn finalize(&self)->bool{
        if !self.known_return(){return false;}
        let main=match self.main.try_lock(){Ok(main)=>main,Err(_)=>return false,};
        match &*main{
            MainState::Dormant if !self.requested.load(Ordering::SeqCst)=>self.retirement.maintenance.as_ref().is_none_or(|tail|tail.retired.load(Ordering::SeqCst)),
            MainState::Skipped=>self.retirement.maintenance.as_ref().is_none_or(|tail|tail.retired.load(Ordering::SeqCst)),
            MainState::Finished(_)=>self.retirement.finalize(),_=>false,
        }
    }
    pub(super) fn retained_bytes(&self)->Option<usize>{
        if !self.known_return(){return None;}
        let returned=(*self.returned.try_lock().ok()?)?;
        returned.retained
    }
    fn settled_storage(&self,identity_bytes:usize)->Option<usize>{
        std::mem::size_of::<Self>().checked_add(identity_bytes)?
            .checked_add(arc_bytes::<Retirement>()?)?.checked_add(arc_bytes::<Dispatcher>()?)?
            .checked_add(arc_bytes::<CallbackOriginal>()?.checked_mul(2)?)?
            .checked_add(management::ServiceManager::project_owned_upper_bound()?)?
            .checked_add(std::mem::size_of::<MainSlot>())?.checked_add(4*SIGNAL_STORAGE)
    }
}

fn service_operation_bytes(value:&wire::ServiceOperation)->Option<usize>{
    value.operation_id.capacity().checked_add(value.context.retained_heap_bytes()?)
}
fn completed_state_allocation_bytes(last:Option<&wire::ServiceOperation>)->Option<usize>{
    let mut bytes=std::mem::size_of::<State>();
    if let Some(last)=last{bytes=bytes.checked_add(service_operation_bytes(last)?)?;}
    Some(bytes)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn persistent_manager_allocation_bytes(retirement:&Retirement)->Option<usize>{
    retirement.retained_bytes()?.checked_add(std::mem::size_of::<MainSlot>())?
        .checked_add(management::ServiceManager::project_owned_upper_bound()?)
}
#[cfg(all(test,target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) struct CatalogueServiceData {data:wire::ServiceOperation,retirement:Arc<Retirement>}
#[cfg(all(test,target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl CatalogueServiceData {
    pub(super) fn new(data:wire::ServiceOperation,control:Arc<Control>)->Self{
        assert!(control.lane==ControlLane::Service);
        // A normal Inspect retains the previous setup's nonempty operation and
        // persistent manager charge. This is only inert allocation DATA: no
        // State/Completed, Preparation, ServiceManager or finality is made.
        Self{data,retirement:Arc::new(Retirement{original:control,action:management::Action::Observe,
            require_enabled:false,phase:std::sync::atomic::AtomicU8::new(PENDING),
            retired_serial:std::sync::atomic::AtomicU32::new(0),maintenance:None})}
    }
    pub(super) fn retained_bytes(&self)->Option<usize>{
        assert_eq!(self.retirement.phase.load(Ordering::SeqCst),PENDING);
        completed_state_allocation_bytes(Some(&self.data))?
            .checked_add(persistent_manager_allocation_bytes(&self.retirement)?)
    }
}
fn setup_prerequisite(observation:Option<wire::ServiceObservation>,failure:Option<wire::Reason>)->wire::Prerequisite{
    if failure==Some(wire::Reason::ApprovalDenied)
        || observation.is_some_and(|observation|observation.outcome==wire::ServiceOutcome::DeniedByUser){
        return wire::Prerequisite::ApprovalDenied;
    }
    if failure==Some(wire::Reason::SigningUnavailable){return wire::Prerequisite::SigningUnavailable;}
    if failure.is_some(){return wire::Prerequisite::ServiceUnavailable;}
    match observation.map(|observation|observation.state){
        Some(wire::ServiceState::Enabled)=>wire::Prerequisite::Ready,
        Some(wire::ServiceState::RequiresApproval)=>wire::Prerequisite::ApprovalRequired,
        _=>wire::Prerequisite::ServiceUnavailable,
    }
}
impl State {
    pub(super) fn prerequisite(&self)->wire::Prerequisite{
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if !android_wire::Profile::current().is_some_and(crate::android_toolchain_macos_policy::native_catalog_supports) {
            return wire::Prerequisite::ServiceUnavailable;
        }
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if !management::signing_profile_configured(){return wire::Prerequisite::SigningUnavailable;}
        self.last.as_ref().map_or(wire::Prerequisite::ServiceUnavailable,|last|last.prerequisite)
    }
    pub(super) fn busy(&self)->bool{self.active.is_some()}
    pub(super) fn unknown(&self)->bool{self.active.as_ref().is_some_and(|original|original.control.unknown.load(Ordering::SeqCst))}
    pub(super) fn empty(&self)->bool{
        if self.active.is_some() || self.last.is_some(){return false;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if self.retirement.is_some(){return false;}
        true
    }
    pub(super) fn sources_match(&self,sources:&android_sources::Sources)->bool{
        self.active.as_ref().is_none_or(|original|sources.same_census_originals(&original.pickers)
            && sources.census_generation()==original.data.source_generation)
    }
    pub(super) fn invalidation_failure(&self)->Option<(wire::Reason,Instant)>{
        self.active.as_ref().and_then(|original|WorkGate{slot:original.cohort.slot.clone(),control:original.control.clone()}.first())
    }
    pub(super) fn registration_matches(&self,registration:u32)->bool{self.active.as_ref().is_none_or(|original|original.registration==registration)}
    pub(super) fn stop(&mut self,reason:wire::Reason,at:Instant)->bool{
        let mut changed=false;
        if let Some(original)=&self.active{
            let before=original.control.failure();let unknown=original.control.unknown.load(Ordering::SeqCst);
            original.control.stop_at(reason,at);
            changed|=before!=original.control.failure() || unknown!=original.control.unknown.load(Ordering::SeqCst);
        }
        if let Some(last)=self.last.as_mut(){
            // Retain the actual original denial even when its context is now
            // historical. Never convert it into pending approval or readiness.
            let prerequisite=if last.observation.is_some_and(|value|value.outcome==wire::ServiceOutcome::DeniedByUser){
                wire::Prerequisite::ApprovalDenied
            }else{wire::Prerequisite::ServiceUnavailable};
            changed|=last.prerequisite!=prerequisite;last.prerequisite=prerequisite;
        }
        changed
    }
    pub(super) fn retained_bytes(&self)->Option<usize>{
        if self.active.is_some(){return None;}
        let mut bytes=completed_state_allocation_bytes(self.last.as_ref().map(|last|&last.data))?;
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if let Some(retirement)=&self.retirement{
            if retirement.phase.load(Ordering::SeqCst)!=OWNER_FINALIZED{return None;}
            // The persistent settled TLS manager survives Preparation itself.
            // Count it for inspection/other admissions, not only a next setup.
            bytes=bytes.checked_add(persistent_manager_allocation_bytes(retirement)?)?;
        }
        Some(bytes)
    }
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn adopt_finalized_preparation(&mut self,preparation:&Preparation)->bool{
        if !preparation.finalize(){return false;}
        if preparation.retirement.phase.load(Ordering::SeqCst)==OWNER_FINALIZED{
            self.retirement=Some(preparation.retirement.clone());
        }
        true
    }
    fn status(&self,revision:u32,availability:Availability)->Result<wire::ServiceStatus,BridgeError>{
        let prerequisite=self.prerequisite();
        let (phase,reason,operation,observation)=if let Some(original)=&self.active{
            let unknown=original.control.unknown.load(Ordering::SeqCst);let first=original.control.failure();
            let phase=if unknown{wire::ServicePhase::Unknown}else if first.is_some(){wire::ServicePhase::Stopping}
                else if original.settling.load(Ordering::SeqCst){wire::ServicePhase::Settling}else{match original.data.action{
                    wire::ServiceAction::Check=>wire::ServicePhase::Checking,wire::ServiceAction::RequestRegistration=>wire::ServicePhase::Requesting,
                    wire::ServiceAction::OpenApprovalSettings=>wire::ServicePhase::OpeningSettings}};
            (phase,if unknown{wire::Reason::CleanupUnknown}else{first.map_or(wire::Reason::None,|(reason,_)|reason)},Some(original.data.clone()),None)
        }else if let Some(last)=&self.last{(last.phase,last.reason,Some(last.data.clone()),last.observation)}
        else{(wire::ServicePhase::Idle,if prerequisite==wire::Prerequisite::SigningUnavailable{wire::Reason::SigningUnavailable}else{wire::Reason::ServiceUnavailable},None,None)};
        wire::ServiceStatus{schema_version:1,status_revision:revision,setup_generation:self.generation,
            availability:if phase==wire::ServicePhase::Unknown{android_wire::Availability::CleanupUnknown}else{availability.android()},
            prerequisite,phase,reason,operation,observation}.bounded()
    }
    pub(super) fn reconcile(&mut self,inner:&Inner)->bool{
        let Some(original)=self.active.as_ref().cloned()else{return false;};
        let at=Instant::now();original.control.advance(at);
        let mut changed=original.control.dirty.swap(false,Ordering::SeqCst);
        if original.coordinator_joined.load(Ordering::SeqCst){
            #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
            original.preparation.tick(false);
            if !original.worker_joined.load(Ordering::SeqCst){
                if let Ok(mut slot)=original.worker.try_lock(){
                    let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));
                    let mut cx=TaskContext::from_waker(&waker);
                    let _=poll_worker(&original,&mut slot,&mut cx);
                }
            }
            return changed;
        }
        let mut slot=match original.coordinator.try_lock(){Ok(slot)=>slot,Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>{original.control.poisoned();return true;}};
        let mut returned=match original.coordinator_return.try_lock(){Ok(returned)=>returned,Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>{original.control.poisoned();return true;}};
        if returned.is_some(){original.control.poisoned();return true;}
        let Some(handle)=slot.as_mut()else{original.control.poisoned();return true;};
        let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));let mut cx=TaskContext::from_waker(&waker);
        let Poll::Ready(result)=Pin::new(handle).poll(&mut cx)else{return changed;};
        let positive=matches!(result,Ok(true));*returned=Some(result);slot.take();
        original.coordinator_joined.store(true,Ordering::SeqCst);drop(returned);drop(slot);
        let joined_at=Instant::now();changed=true;
        if !positive || !original.known_return() || joined_at>=original.control.endpoint(){original.control.mark_unknown(joined_at);return changed;}
        if !original.same_owner(inner){original.control.stop_at(wire::Reason::DocumentLost,joined_at);}
        if original.joined_at.set(joined_at).is_err(){original.control.poisoned();}
        changed
    }
    fn finalize(&mut self,inner:&Inner,request:&Finalization,current:Option<&crate::asset_session::ValidatedSavedInput>,
        gate:android_wire::Availability)->bool{
        let original=&request.original;
        if !self.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,original))
            || original.accepted.load(Ordering::SeqCst) || original.control.unknown.load(Ordering::SeqCst){return false;}
        let Some(joined_at)=original.joined_at.get().copied()else{return false;};
        let at=Instant::now();original.control.advance(at);
        if !original.known_return() || at>=original.control.endpoint() || joined_at>=original.control.endpoint(){
            original.control.mark_unknown(at);return true;}
        let returned=match original.returned.try_lock(){Ok(returned)=>returned,Err(TryLockError::WouldBlock)=>return false,
            Err(TryLockError::Poisoned(_))=>{original.control.poisoned();return true;}};
        let Some(Ok(worker))=returned.as_ref()else{original.control.poisoned();return true;};
        let mut book=match inner.android_registration_control.book.try_lock(){Ok(book)=>book,Err(TryLockError::WouldBlock)=>return false,
            Err(TryLockError::Poisoned(_))=>{original.control.poisoned();return true;}};
        if inner.android_registration_control.is_unknown() || book.review.is_some()
            || !book.original.as_ref().is_some_and(|held|Arc::ptr_eq(held,&original.control))
            || !book.cohort.as_ref().is_some_and(|cohort|cohort.identity.as_ptr()==Arc::as_ptr(&original.control.cohort)){
            drop(book);original.control.poisoned();return true;}
        if ControlSlot::pending(&book) || original.control.latches.load(Ordering::SeqCst)!=0{return false;}
        let at=Instant::now();original.control.advance(at);
        let first=original.control.failure();
        if original.control.unknown.load(Ordering::SeqCst) || at>=original.control.endpoint()
            || worker.first.is_some_and(|(_,first)|original.control.failure().is_none_or(|(_,before)|first<before)){
            original.control.mark_unknown(at);return true;}
        if first.is_none(){
            if gate==android_wire::Availability::Busy{return false;}
            if book.epoch!=original.control.epoch || book.cohort.as_ref().is_some_and(|cohort|cohort.first.is_some()){
                drop(book);original.control.poisoned();return true;}
            if gate!=android_wire::Availability::Available || !current.is_some_and(|current|original.saved.same_binding(current)){return false;}
        }
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if !self.adopt_finalized_preparation(&original.preparation){drop(book);original.control.poisoned();return true;}
        let reason=first.map_or(wire::Reason::None,|(reason,_)|reason);
        let phase=match reason{wire::Reason::None=>wire::ServicePhase::Complete,wire::Reason::Cancelled=>wire::ServicePhase::Cancelled,_=>wire::ServicePhase::Refused};
        self.last=Some(Completed{data:original.data.clone(),phase,reason,
            prerequisite:setup_prerequisite(worker.observation,first.map(|(reason,_)|reason)),observation:worker.observation});
        original.accepted.store(true,Ordering::SeqCst);book.original=None;book.cohort=None;self.active=None;
        drop(book);inner.android_registration_control.wake.notify_all();true
    }
}
impl SetupOriginal {
    fn same_owner(&self,inner:&Inner)->bool{self.owner.as_ptr()==inner as *const Inner
        && self.document.upgrade().is_some_and(|document|inner.android_original_document_matches(Some(&document)))}
    fn known_return(&self)->bool{
        if !self.worker_joined.load(Ordering::SeqCst) || self.control.unknown.load(Ordering::SeqCst){return false;}
        let Ok(worker)=self.worker.try_lock()else{return false;};let Ok(returned)=self.returned.try_lock()else{return false;};
        worker.is_none() && matches!(returned.as_ref(),Some(Ok(returned)) if returned.known && returned.retained.is_some())
    }
}
fn poll_worker(original:&SetupOriginal,slot:&mut Option<JoinHandle<WorkerReturn>>,cx:&mut TaskContext<'_>)->Poll<bool>{
    if original.worker_joined.load(Ordering::SeqCst){return Poll::Ready(original.returned.try_lock()
        .is_ok_and(|returned|matches!(returned.as_ref(),Some(Ok(returned)) if returned.known)));}
    let mut returned=match original.returned.try_lock(){Ok(returned)=>returned,Err(TryLockError::WouldBlock)=>return Poll::Pending,
        Err(TryLockError::Poisoned(_))=>{original.control.poisoned();return Poll::Ready(false);}};
    if returned.is_some(){original.control.poisoned();return Poll::Ready(false);}
    let Some(handle)=slot.as_mut()else{original.control.poisoned();return Poll::Ready(false);};
    let Poll::Ready(result)=Pin::new(handle).poll(cx)else{return Poll::Pending;};
    let known=matches!(&result,Ok(returned) if returned.known && returned.retained.is_some());
    if let Ok(returned)=&result{if let Some((reason,at))=returned.first{original.control.stop_at(reason,at);}}
    *returned=Some(result);slot.take();original.worker_joined.store(true,Ordering::SeqCst);drop(returned);
    let at=Instant::now();if !known || at>=original.control.endpoint(){original.control.mark_unknown(at);}
    Poll::Ready(known && !original.control.unknown.load(Ordering::SeqCst))
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn setup_worker(original:Arc<SetupOriginal>,mut enter:oneshot::Receiver<()>)->WorkerReturn{
    loop{
        original.control.advance(Instant::now());
        if original.control.failure().is_some() || original.control.unknown.load(Ordering::SeqCst){break;}
        match enter.try_recv(){Ok(())=>break,Err(oneshot::error::TryRecvError::Empty)=>std::thread::park_timeout(HEARTBEAT),
            Err(oneshot::error::TryRecvError::Closed)=>{original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());break;}}
    }
    original.preparation.run_once();original.settling.store(true,Ordering::SeqCst);original.control.changed();
    original.preparation.worker_return().unwrap_or(WorkerReturn{known:false,first:original.control.failure(),observation:None,retained:None})
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
async fn coordinate(original:Arc<SetupOriginal>,mut release:oneshot::Receiver<()>,worker_enter:oneshot::Sender<()>)->bool{
    let mut worker_enter=Some(worker_enter);let mut released=false;
    let mut worker=original.worker.lock().await;
    let gate=WorkGate{slot:original.cohort.slot.clone(),control:original.control.clone()};
    let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));
    loop{
        original.control.advance(Instant::now());original.preparation.tick(true);
        if Instant::now()>=original.control.endpoint(){original.control.mark_unknown(Instant::now());return false;}
        if original.control.failure().is_some() || original.control.unknown.load(Ordering::SeqCst){worker_enter.take();}
        if !released && worker_enter.is_some(){match release.try_recv(){
            Ok(())=>released=true,Err(oneshot::error::TryRecvError::Empty)=>{},
            Err(oneshot::error::TryRecvError::Closed)=>{original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());worker_enter.take();}
        }}
        if released && worker_enter.is_some() && gate.try_work()==Some(true){
            if worker_enter.take().is_none_or(|sender|sender.send(()).is_err()){original.control.mark_unknown(Instant::now());}
        }
        let joined = {
            let mut cx = TaskContext::from_waker(&waker);
            poll_worker(&original, &mut worker, &mut cx)
        };
        if let Poll::Ready(known)=joined{
            drop(worker);return known && original.known_return() && Instant::now()<original.control.endpoint();
        }
        tokio::time::sleep(HEARTBEAT).await;
    }
}

impl SavedCommandOwner {
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn bind_android_service_dispatcher(&self,document:&Arc<()>,dispatcher:Dispatcher)->bool{
        self.inner.domain==SavedCommandDomain::AndroidBuild && self.inner.android_original_document_matches(Some(document))
            && self.inner.android_service_dispatcher.set(Arc::new(dispatcher)).is_ok()
    }
    fn service_gate(&self,registry:&Registry,gate:android_wire::Availability)->Availability{
        let availability=self.registration_gate(registry,Availability::from_android(gate));
        if availability!=Availability::Available{return availability;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if self.inner.android_service_dispatcher.get().is_some(){return availability;}
        Availability::RuntimeUnqualified
    }
    fn service_status_locked(&self,registry:&mut Registry,gate:android_wire::Availability)->Result<wire::ServiceStatus,BridgeError>{
        let availability=self.service_gate(registry,gate);
        if registry.android_registration.service.capability!=Some(availability){
            registry.android_registration.service.capability=Some(availability);self.inner.bump(registry);
        }
        if registry.exhausted || self.inner.poisoned.load(Ordering::SeqCst){return Err(wire::service_unconfirmed());}
        registry.android_registration.service.status(registry.revision,availability)
    }
    pub(crate) fn android_tool_service_status(&self,gate:android_wire::Availability)->Result<wire::ServiceStatus,BridgeError>{
        self.reconcile();let mut registry=self.inner.lock();self.service_status_locked(&mut registry,gate)
    }
    pub(crate) fn snapshot_android_tool_service(&self,document:&Arc<()>,at:Instant,request:wire::ServiceRequest,
        registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:android_wire::Availability)->Result<Snapshot,BridgeError>{
        let registry=self.inner.lock();
        if self.service_gate(&registry,gate)!=Availability::Available || !self.inner.android_original_document_matches(Some(document)){
            return Err(wire::service_unavailable());}
        if request.setup_generation!=registry.android_registration.service.generation
            || !saved.matches(document,registration,&project,&request.context){return Err(wire::service_invalid());}
        let pickers=registry.android_sources.census_originals().ok_or_else(wire::service_unavailable)?;
        let source_generation=registry.android_sources.census_generation();
        let cohort=self.inner.android_registration_control.claim(saved.epoch(),None).map_err(|_|wire::service_unavailable())?;
        Ok(Snapshot{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),at,request,registration,project,
            pickers,source_generation,saved,cohort:Mutex::new(Some(cohort))})
    }
    pub(crate) fn admit_android_tool_service(&self,document:&Arc<()>,checked:&Checked,current:crate::asset_session::ValidatedSavedInput,
        registration:u32,project:&RegisteredRoot,census:&crate::asset_session::AndroidServiceSetupCensus<'_>,gate:android_wire::Availability)->Result<Admitted,BridgeError>{
        let snapshot=&checked.snapshot;let mut registry=self.inner.lock();
        if self.service_gate(&registry,gate)!=Availability::Available || snapshot.owner.as_ptr()!=Arc::as_ptr(&self.inner)
            || snapshot.document.as_ptr()!=Arc::as_ptr(document) || !self.inner.android_original_document_matches(Some(document))
            || !registry.android_sources.same_census_originals(&snapshot.pickers)
            || registry.android_sources.census_generation()!=snapshot.source_generation
            || snapshot.registration!=registration || &snapshot.project!=project
            || snapshot.request.setup_generation!=registry.android_registration.service.generation
            || !current.matches(document,registration,project,&snapshot.request.context) || !snapshot.saved.same_binding(&current){return Err(wire::service_invalid());}
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {let _=(checked,census);Err(wire::service_unavailable())}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            // Missing shipping identity is an external prerequisite, not a
            // reason to allocate native originals or use ad-hoc signing.
            if !android_wire::Profile::current().is_some_and(crate::android_toolchain_macos_policy::native_catalog_supports)
                || !management::signing_profile_configured(){return Err(wire::service_unavailable());}
            let dispatcher=self.inner.android_service_dispatcher.get().cloned().ok_or_else(wire::service_unavailable)?;
            let work=snapshot.at.checked_add(WORK).ok_or_else(wire::service_unavailable)?;
            let hard=snapshot.at.checked_add(HARD).ok_or_else(wire::service_unavailable)?;
            if Instant::now()>=work{return Err(wire::service_unavailable());}
            let generation=registry.android_registration.service.generation.checked_add(1).filter(|value|*value<u32::MAX)
                .ok_or_else(wire::service_unavailable)?;
            if registry.android_registration.service.last.as_ref().is_some_and(|last|last.data.operation_id==checked.id){return Err(wire::service_unavailable());}
            let previous=setup_retained_bytes(&self.inner,&registry,document,checked,census).ok_or_else(wire::service_unavailable)?;
            let executor=tokio::runtime::Handle::try_current().map_err(|_|wire::service_unavailable())?;
            let cohort=snapshot.cohort.lock().map_err(|_|wire::service_unconfirmed())?.take().ok_or_else(wire::service_invalid)?;
            if !self.inner.android_registration_control.current_claim(&cohort){return Err(wire::service_invalid());}
            let (stop,_)=watch::channel(false);let(audit,_)=watch::channel(hard);
            let control=Arc::new(Control{lane:ControlLane::Service,owner:Arc::downgrade(&self.inner),id:checked.id.clone(),generation,
                admitted:snapshot.at,work,hard,slot:Arc::downgrade(&self.inner.android_registration_control),cohort:cohort.identity.clone(),epoch:cohort.epoch,
                first:Mutex::new(None),unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),latches:AtomicUsize::new(0),stop,audit});
            let data=wire::ServiceOperation{operation_id:checked.id.clone(),setup_generation:generation,source_generation:snapshot.source_generation,
                action:snapshot.request.action,context:snapshot.request.context.clone()};
            let whole=previous.checked_add(arc_bytes::<SetupOriginal>().ok_or_else(wire::service_unavailable)?)
                .and_then(|bytes|bytes.checked_add(service_operation_bytes(&data)?))
                .and_then(|bytes|bytes.checked_add(snapshot.project.path.capacity()))
                .and_then(|bytes|bytes.checked_add(control.retained_bytes()?))
                .and_then(|bytes|bytes.checked_add(Preparation::reservation_bytes()?))
                .and_then(|bytes|bytes.checked_add(TASK_STORAGE))
                .and_then(|bytes|bytes.checked_add(3*wire::REQUEST_LIMIT+3*wire::STATUS_LIMIT))
                .filter(|bytes|*bytes<=OWNED_LIMIT).ok_or_else(wire::service_unavailable)?;
            let action=match data.action{wire::ServiceAction::Check=>management::Action::Observe,
                wire::ServiceAction::RequestRegistration=>management::Action::RequestRegistration,
                wire::ServiceAction::OpenApprovalSettings=>management::Action::OpenApprovalSettings};
            let original=Arc::new(SetupOriginal{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),data,
                registration,project:snapshot.project.clone(),pickers:snapshot.pickers.clone(),saved:current,cohort,control:control.clone(),
                reservation:std::sync::OnceLock::new(),settling:AtomicBool::new(false),worker:AsyncMutex::new(None),returned:Mutex::new(None),
                worker_joined:AtomicBool::new(false),coordinator:Mutex::new(None),coordinator_return:Mutex::new(None),coordinator_joined:AtomicBool::new(false),
                joined_at:std::sync::OnceLock::new(),accepted:AtomicBool::new(false),preparation:Preparation::new(
                    WorkGate{slot:self.inner.android_registration_control.clone(),control:control.clone()},dispatcher,action)});
            let(release,enter)=oneshot::channel();let(worker_enter,worker_wait)=oneshot::channel();
            let worker_task={let original=original.clone();move||setup_worker(original,worker_wait)};
            let coordinator=coordinate(original.clone(),enter,worker_enter);
            let task_bytes=std::mem::size_of_val(&worker_task).checked_add(std::mem::size_of_val(&coordinator))
                .and_then(|bytes|bytes.checked_add(4*std::mem::size_of::<WorkerReturn>()))
                .and_then(|bytes|bytes.checked_add(std::mem::size_of::<Finalization>())).ok_or_else(wire::service_unavailable)?;
            if task_bytes>TASK_STORAGE{return Err(wire::service_unavailable());}
            original.reservation.set(whole).map_err(|_|wire::service_unavailable())?;
            if !self.inner.android_registration_control.install(control,&original.cohort,None){return Err(wire::service_unavailable());}
            registry.android_registration.service.generation=generation;registry.android_registration.service.active=Some(original.clone());
            let publish=||->Result<(),()>{
                let mut worker=original.worker.try_lock().map_err(|_|())?;let mut joined=original.coordinator.try_lock().map_err(|_|())?;
                *worker=Some(executor.spawn_blocking(worker_task));*joined=Some(executor.spawn(coordinator));Ok(())
            };
            if publish().is_err(){original.control.poisoned();self.inner.bump(&mut registry);return Err(wire::service_unconfirmed());}
            self.inner.bump(&mut registry);
            let status=self.service_status_locked(&mut registry,gate).map_err(|_|{
                original.control.stop_at(wire::Reason::ResultLimit,Instant::now());wire::service_unconfirmed()})?;
            Ok(Admitted{status,release:Some(release),original})
        }
    }
    pub(crate) fn android_service_finalization(&self)->Option<Finalization>{
        self.reconcile();let registry=self.inner.lock();
        registry.android_registration.service.active.as_ref().filter(|original|
            original.coordinator_joined.load(Ordering::SeqCst) && original.joined_at.get().is_some()
                && !original.accepted.load(Ordering::SeqCst) && !original.control.unknown.load(Ordering::SeqCst))
            .map(|original|Finalization{original:original.clone()})
    }
    pub(crate) fn finalize_android_service(&self,request:&Finalization,current:Option<&crate::asset_session::ValidatedSavedInput>,gate:android_wire::Availability){
        let mut registry=self.inner.lock();if registry.android_registration.service.finalize(&self.inner,request,current,gate){self.inner.bump(&mut registry);}
    }
    pub(crate) fn cancel_android_tool_service(&self,input:&wire::ServiceCancel,publication:Option<&CancelPublisher>,gate:android_wire::Availability)
        ->Result<wire::ServiceStatus,BridgeError>{
        let mut registry=self.inner.lock();
        if let Some(publication)=publication{
            if publication.original.lane!=ControlLane::Service || publication.original.id!=input.operation_id
                || publication.original.generation!=input.setup_generation || !Arc::ptr_eq(&publication.slot,&self.inner.android_registration_control){
                publication.slot.poisoned();return Err(wire::service_unconfirmed());}
        }
        self.service_status_locked(&mut registry,gate).map_err(|_|wire::service_unconfirmed())
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn setup_retained_bytes(inner:&Inner,registry:&Registry,document:&Arc<()>,checked:&Checked,census:&crate::asset_session::AndroidServiceSetupCensus<'_>)->Option<usize>{
    if registry.active.is_some() || registry.prepared.is_some() || registry.recovery_review.is_some() || registry.recovery.is_some()
        || inner.toolchain.is_some() || registry.android_registration.active.is_some() || registry.android_registration.review.is_some(){return None;}
    #[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer")))]
    if inner.ios_observation.try_lock().ok()?.is_some(){return None;}
    #[cfg(all(test,debug_assertions,feature="development-runtime",not(feature="desktop-shell")))]
    if inner.fixture.try_lock().ok()?.is_some(){return None;}
    let binding=inner.android_document.try_lock().ok()?;
    if !binding.as_ref().is_some_and(|bound|bound.as_ptr()==Arc::as_ptr(document)){return None;}
    let control=inner.android_registration_control.book.try_lock().ok()?;
    if control.original.is_some() || ControlSlot::pending(&control) || inner.android_registration_control.is_unknown(){return None;}
    drop(control);
    let snapshot=&checked.snapshot;
    let mut bytes=census.for_originals(document,checked.picker_originals())?.checked_add(arc_bytes::<Inner>()?)?
        .checked_add(SIGNAL_STORAGE)?.checked_add(inner.android_registration_control.retained_bytes()?)?
        .checked_add(inner.runtime.android_registration_retained_heap_bytes(document)?)?
        .checked_add(registry.android_sources.retained_data_bytes()?.checked_sub(std::mem::size_of::<android_sources::Sources>())?)?
        .checked_add(registry.android_catalog.registration_retained_bytes()?.checked_sub(std::mem::size_of::<android_catalog::Catalog>())?)?
        .checked_add(registry.android_registration.service.retained_bytes()?.checked_sub(std::mem::size_of::<State>())?)?
        .checked_add(std::mem::size_of::<Checked>())?.checked_add(snapshot.request.context.retained_heap_bytes()?)?
        .checked_add(checked.id.capacity())?.checked_add(snapshot.project.path.capacity())?.checked_add(arc_bytes::<()>()?)?;
    if let Some(last)=&registry.android_registration.last{bytes=bytes.checked_add(operation_projection_bytes(&last.data)?)?
        .checked_add(last.report.as_ref().map_or(Some(0),report_bytes)?)?;}
    if let Some(dispatcher)=inner.android_service_dispatcher.get(){let _=dispatcher;bytes=bytes.checked_add(arc_bytes::<Dispatcher>()?)?;}
    #[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer")))]
    {bytes=bytes.checked_add(arc_bytes::<()>()?)?;}
    if let Some(last)=&registry.last{
        let Context::AndroidBuild(context)=&last.context else{return None;};
        if last.stage.is_some_and(|stage|!matches!(stage,Stage::AndroidBuild(_))){return None;}
        bytes=bytes.checked_add(last.operation_id.capacity())?.checked_add(last.owner_generation.capacity())?.checked_add(context.retained_heap_bytes()?)?;
        if let Some(terminal)=&last.result{let Terminal::AndroidBuild(terminal)=terminal else{return None;};bytes=bytes.checked_add(terminal.retained_heap_bytes()?)?;}
    }
    (bytes<=OWNED_LIMIT).then_some(bytes)
}

#[cfg(all(test,target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
mod callback_lifecycle_tests {
    // Inert copied custody/control DATA only. No Dispatcher, ServiceManager,
    // native identity, callback route, service operation or worker is entered.
    use super::*;
    use super::super::lifecycle_book_tests::control_in_lane;
    use management::{Action,CellCustody,Checkpoint,Decision,Phase,ServiceCustody};

    fn callback(gate:WorkGate,require_enabled:bool)->(Arc<Retirement>,Arc<CallbackOriginal>){
        let retirement=Arc::new(Retirement{original:gate.control.clone(),action:Action::Observe,require_enabled,
            phase:std::sync::atomic::AtomicU8::new(PENDING),retired_serial:std::sync::atomic::AtomicU32::new(0),maintenance:None});
        let original=Arc::new(CallbackOriginal{gate,action:Action::Observe,serial:1,
            retirement:retirement.clone(),returned:Mutex::new(None)});
        (retirement,original)
    }
    fn deferred()->management::Custody{management::Custody{action:Some(Action::Observe),phase:Some(Phase::AdmitAction),
        action_admitted:false,cell:CellCustody::Owned,service:ServiceCustody::NotAcquired,in_call:false,gate_entered:false,
        unknown:false,stopped:false,first_failure:None,observation:None}}
    fn observed(status:management::Status)->management::Observation{management::Observation{
        action:Action::Observe,status,outcome:management::Outcome::Observed,mutation_entered:false,mutation_returned:false,
        mutation_uncertain:false,native_settled:true}}
    fn returned(at:Instant)->CallbackReturned{
        let observation=observed(management::Status::Enabled);
        let custody=management::Custody{action:None,phase:None,cell:CellCustody::Consumed,service:ServiceCustody::Settled,
            observation:Some(observation),..deferred()};
        CallbackReturned{native:Some((management::Progress::Finished(observation),custody)),failure:CapturedFailure::default(),at}
    }

    #[test]
    fn callback_stamp_needs_exclusive_capture_return_then_original_owner_finality(){
        let (_,control,_cohort,gate)=control_in_lane(Instant::now(),ControlLane::Service);
        let (retirement,held)=callback(gate,false);
        let binding=MainBinding{retirement:retirement.clone(),serial:1};
        *held.returned.lock().unwrap()=Some(returned(Instant::now()));
        let capture=held.clone();
        let held=match CallbackOriginal::extract(held,&retirement){ExtractedCallback::Pending(held)=>held,
            _=>panic!("published return is not exclusive capture retirement")};
        assert!(!binding.reusable());assert!(!retirement.finalize());
        drop(capture);
        let ExtractedCallback::Returned(serial,returned)=CallbackOriginal::extract(held,&retirement)
            else{panic!("the actual last capture was retired")};
        assert!(management_settled(returned.native.unwrap().1));
        assert_eq!(retirement.phase.load(Ordering::SeqCst),PENDING);
        // Extracted DATA still owes native/deadline validation; even the later
        // CallbackRetired stamp is not permission to replace the TLS original.
        assert!(retirement.callback_retired(serial,false));assert!(!binding.reusable());
        assert!(!retirement.callback_retired(serial,false));
        assert!(retirement.finalize());assert!(binding.reusable());assert!(!retirement.finalize());
        control.unknown.store(true,Ordering::SeqCst);assert!(!binding.reusable());

        for poisoned in [false,true]{
            let (_,_,_cohort,gate)=control_in_lane(Instant::now(),ControlLane::Service);
            let (retirement,held)=callback(gate,false);
            if poisoned{
                let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                    let _guard=held.returned.lock().unwrap();panic!("inert callback-return poison");
                }));assert!(result.is_err());
            }
            assert!(matches!(CallbackOriginal::extract(held,&retirement),ExtractedCallback::Unknown(None)));
            assert!(!retirement.finalize());
            let binding=MainBinding{retirement,serial:1};assert!(!binding.reusable());
        }
    }

    #[test]
    fn deferred_reuses_only_same_private_owner_action_serial_and_unadmitted_cell(){
        let (_,control,_cohort,gate)=control_in_lane(Instant::now(),ControlLane::Service);
        let (retirement,held)=callback(gate.clone(),false);
        assert!(!retirement.callback_retired(0,true));assert!(!retirement.callback_retired(2,true));
        assert!(!retirement.callback_retired(u32::MAX,true));assert!(retirement.callback_retired(1,true));
        let binding=MainBinding{retirement:retirement.clone(),serial:1};
        let mut next=CallbackOriginal{gate:gate.clone(),action:Action::Observe,serial:2,retirement:retirement.clone(),returned:Mutex::new(None)};
        assert!(binding.resumes(&next,deferred()));assert!(!binding.reusable());
        for serial in [0,1,3,u32::MAX]{next.serial=serial;assert!(!binding.resumes(&next,deferred()));}
        next.serial=2;next.action=Action::RequestRegistration;assert!(!binding.resumes(&next,deferred()));next.action=Action::Observe;
        let (_,_,_other_cohort,other)=control_in_lane(Instant::now(),ControlLane::Service);
        next.gate=other.clone();assert!(!binding.resumes(&next,deferred()));next.gate=gate;
        let (other_retirement,_)=callback(other,false);
        next.retirement=other_retirement.clone();assert!(!binding.resumes(&next,deferred()));next.retirement=retirement.clone();
        *held.returned.lock().unwrap()=Some(returned(Instant::now()));
        assert!(matches!(CallbackOriginal::extract(held,&other_retirement),ExtractedCallback::Unknown(Some(_))));
        for wrong in [management::Custody{cell:CellCustody::Absent,..deferred()},
            management::Custody{service:ServiceCustody::Owned,..deferred()},management::Custody{action_admitted:true,..deferred()},
            management::Custody{in_call:true,..deferred()},management::Custody{gate_entered:true,..deferred()},
            management::Custody{unknown:true,..deferred()},management::Custody{stopped:true,..deferred()},
            management::Custody{first_failure:Some(Instant::now()),..deferred()},
            management::Custody{phase:Some(Phase::Mutate),..deferred()}]{assert!(!binding.resumes(&next,wrong));}
        control.stop_at(wire::Reason::Cancelled,Instant::now());
        assert!(binding.resumes(&next,deferred())); // Same original cleanup, not a new action.
        assert!(retirement.callback_retired(2,false));assert!(!binding.resumes(&next,deferred()));
    }


    #[test]
    fn maintenance_preserves_observed_not_registered_after_later_cleanup_unknown() {
        // Copied callback/custody DATA only; no manager, service or native pass.
        let at=Instant::now();
        let observed=management::Observation{action:Action::UnregisterAfterQuiescence,
            status:management::Status::NotRegistered,outcome:management::Outcome::UnregisterAccepted,
            mutation_entered:true,mutation_returned:true,mutation_uncertain:false,native_settled:false};
        for (phase,cell,service) in [(Phase::ReleaseService,CellCustody::Owned,ServiceCustody::Unknown),
            (Phase::RetireCell,CellCustody::Owned,ServiceCustody::Settled),
            (Phase::RetireCell,CellCustody::Consumed,ServiceCustody::Settled)] {
            let custody=management::Custody{action:Some(Action::UnregisterAfterQuiescence),phase:Some(phase),
                action_admitted:true,cell,service,in_call:false,gate_entered:false,unknown:true,stopped:false,
                first_failure:Some(at),observation:Some(observed)};
            let returned=CallbackReturned{native:Some((management::Progress::Unknown(management::Observation{
                outcome:management::Outcome::Unknown,..observed}),custody)),
                failure:CapturedFailure{first:Some((wire::Reason::CleanupUnknown,at)),unknown:true},at};
            let (unregister_accepted,not_registered)=Preparation::maintenance_observation(Some(returned));
            assert!(unregister_accepted && not_registered);
            assert!(!management_settled(custody));
            // Even all other positive DATA cannot turn unsettled native custody
            // into Prepared; these flags do not authorize an actual operation.
            let facts=MaintenanceRun{known:management_settled(custody),checked:true,started_or_uncertain:true,
                tail_received:true,unregister_accepted,not_registered,callback_retired:true,peer_ended:true,retained:Some(1)};
            assert!(!facts.prepared());
            for (observation,expected) in [
                (management::Observation{status:management::Status::Enabled,..observed},(true,false)),
                (management::Observation{mutation_returned:false,..observed},(false,false)),
                (management::Observation{mutation_uncertain:true,..observed},(false,false)),
                (management::Observation{action:Action::Observe,..observed},(false,false))] {
                let mut changed=returned;
                changed.native.as_mut().unwrap().1.observation=Some(observation);
                assert_eq!(Preparation::maintenance_observation(Some(changed)),expected);
            }
        }
        assert_eq!(Preparation::maintenance_observation(None),(false,false));
    }

    #[test]
    fn maintenance_main_cut_needs_tail_action_no_f_and_original_endpoint_without_tail_lock() {
        // Inert gate DATA only: no TailAdmission, manager, callback execution or receipt.
        for case in 0..4 {
            let admitted=Instant::now()-Duration::from_secs(2);
            let (_,control,_cohort,gate)=control_in_lane(admitted,ControlLane::Maintenance);
            let tail=MaintenanceTail::new([1;16]);
            if case!=0 { tail.cutoff.set(if case==3{admitted+Duration::from_secs(1)}else{control.hard}).unwrap(); }
            let action=if case==1{Action::Observe}else{Action::UnregisterAfterQuiescence};
            let retirement=Arc::new(Retirement{original:control.clone(),action,require_enabled:true,
                phase:std::sync::atomic::AtomicU8::new(PENDING),retired_serial:std::sync::atomic::AtomicU32::new(0),
                maintenance:Some(tail)});
            let original=CallbackOriginal{gate,action,serial:1,retirement:retirement.clone(),returned:Mutex::new(None)};
            if case==2 { control.stop_at(wire::Reason::Cancelled,admitted+Duration::from_secs(1)); }
            // Deliberately held: the AppKit cut may inspect immutable cutoff,
            // never wait for the IPC-owned capture/native/identity mutex.
            let _held=retirement.maintenance.as_ref().unwrap().original.lock().unwrap();
            let mut failure=CapturedFailure::default();
            assert_eq!(original.cut(Phase::AdmitAction,true,&mut failure),
                if case==2{Decision::Stop}else{Decision::Unknown});
            assert_eq!(control.unknown.load(Ordering::SeqCst),case!=2);
        }
    }

    #[test]
    fn main_gate_only_defers_at_admission_and_preserves_actual_f_on_short_lock_contention(){
        let admitted=Instant::now()-Duration::from_millis(100);let first_at=admitted+Duration::from_millis(1);
        let (slot,control,_cohort,gate)=control_in_lane(admitted,ControlLane::Service);
        let (_,original)=callback(gate,true);let mut failure=CapturedFailure::default();
        let guard=slot.book.lock().unwrap();
        assert_eq!(original.gate(Checkpoint::Before{phase:Phase::AdmitAction,custody:deferred()},&mut failure),Decision::Defer);
        assert!(failure.first.is_none() && !control.unknown.load(Ordering::SeqCst));
        let custody=management::Custody{phase:Some(Phase::ObserveStatus),action_admitted:true,service:ServiceCustody::Owned,
            observation:Some(observed(management::Status::RequiresApproval)),..deferred()};
        assert_eq!(original.gate(Checkpoint::Returned{phase:Phase::ObserveStatus,at:first_at,custody},&mut failure),Decision::Unknown);
        assert_eq!(failure.first,Some((wire::Reason::ApprovalRequired,first_at)));drop(guard);
        assert!(control.unknown.load(Ordering::SeqCst));assert!(control.failure().is_none());

        let (_,control,_cohort,gate)=control_in_lane(admitted,ControlLane::Service);
        let (_,original)=callback(gate,false);let mut failure=CapturedFailure::default();
        let guard=control.first.lock().unwrap();
        assert_eq!(original.gate(Checkpoint::Before{phase:Phase::AdmitAction,custody:deferred()},&mut failure),Decision::Defer);
        assert!(failure.first.is_none() && !control.unknown.load(Ordering::SeqCst));
        failure.note(wire::Reason::Cancelled,first_at);
        assert_eq!(original.gate(Checkpoint::Before{phase:Phase::ReleaseService,custody:deferred()},&mut failure),Decision::Unknown);
        assert_eq!(failure.first,Some((wire::Reason::Cancelled,first_at)));drop(guard);
        assert!(control.unknown.load(Ordering::SeqCst));assert!(control.failure().is_none());
    }

    #[test]
    fn register_observation_failure_is_at_real_return_and_stop_keeps_original_deadlines(){
        let admitted=Instant::now()-Duration::from_millis(100);let returned_at=admitted+Duration::from_millis(1);
        for require_enabled in [false,true]{
            let (_,control,_cohort,gate)=control_in_lane(admitted,ControlLane::Service);
            let (_,original)=callback(gate,require_enabled);let mut failure=CapturedFailure::default();
            let custody=management::Custody{phase:Some(Phase::ObserveStatus),action_admitted:true,service:ServiceCustody::Owned,
                observation:Some(observed(management::Status::RequiresApproval)),..deferred()};
            assert_eq!(original.gate(Checkpoint::Before{phase:Phase::ObserveStatus,custody},&mut failure),Decision::Proceed);
            assert!(control.failure().is_none());
            assert_eq!(original.gate(Checkpoint::Returned{phase:Phase::ObserveStatus,at:returned_at,custody},&mut failure),
                if require_enabled{Decision::Stop}else{Decision::Proceed});
            assert_eq!(control.failure(),require_enabled.then_some((wire::Reason::ApprovalRequired,returned_at)));
        }
        let (slot,control,_cohort,gate)=control_in_lane(admitted,ControlLane::Service);
        let (_,original)=callback(gate,false);let mut failure=CapturedFailure::default();
        control.stop_at(wire::Reason::Cancelled,returned_at);
        // The prebinding cut imports only this new original, not a previous
        // completed TLS action's retained failure/observation.
        assert_eq!(original.cut(Phase::AllocateCell,false,&mut failure),Decision::Stop);
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        assert_eq!(original.cut(Phase::RetireCell,false,&mut failure),Decision::Proceed);publisher.reject();
        assert_eq!(control.failure(),Some((wire::Reason::Cancelled,returned_at)));
        assert_eq!((control.admitted,control.work,control.hard),(admitted,admitted+WORK,admitted+HARD));
        assert_eq!(control.endpoint(),returned_at+SETTLEMENT);
        for age in [WORK+Duration::from_secs(1),HARD+Duration::from_secs(1)]{
            let (_,_,_cohort,gate)=control_in_lane(Instant::now()-age,ControlLane::Service);
            let control=gate.control.clone();let (_,original)=callback(gate,false);let mut failure=CapturedFailure::default();
            assert_eq!(original.cut(Phase::AllocateCell,false,&mut failure),if age>HARD{Decision::Unknown}else{Decision::Stop});
            assert_eq!(failure.first,Some((wire::Reason::TimedOut,control.work)));
            if age<HARD{assert_eq!(original.cut(Phase::RetireCell,false,&mut failure),Decision::Proceed);}
        }
    }
}
