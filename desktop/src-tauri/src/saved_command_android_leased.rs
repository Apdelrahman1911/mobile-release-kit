//! Mac M2 originals inside SavedCommandOwner. App-only; no new supervisor.
//! Control and frozen returns remain outside native/Registry locks. The fixed
//! close slot is reserved before GO and never substitutes for a borrower join.
#![forbid(unsafe_code)]
use super::*;
use mrk_macos_installed_native::android_catalog_query::{Role,Signal};
use crate::{
    android_catalog_query_client::OriginalClockSlot,
    android_shared_lease_macos::{AppCloseTail,FrozenCloseData,OriginalUseIdentity,
        RawFailureData,CLOSE_TAIL_LEDGER_BYTES},
    installed_runtime::{LeasedAndroidToolchainSlots,android_lease_admission_issue},
};
pub(super) const CONTROL_POLL:Duration=Duration::from_millis(5);

#[derive(Clone,Copy)]
struct LocalFailure {at:Instant,observed:Instant}
/// Distinct same-original control, not a reference to a retired native book.
/// Only genuinely captured LOCAL events enter first. Already inverse-mapped
/// helper time never feeds this latch or gets mapped a second time.
pub(super) struct AndroidUseControl {
    identity:OriginalUseIdentity,signal:Arc<Signal>,clock:OriginalClockSlot,
    role:Role,pub(super) admitted:Instant,pub(super) work:Instant,pub(super) hard:Instant,
    first:Mutex<Option<LocalFailure>>,unknown:AtomicBool,
}
#[derive(Clone,Copy)]
pub(super) struct ControlData {
    pub(super) failure:Option<RawFailureData>,pub(super) local_first:Option<Instant>,
    pub(super) unknown:bool,
}
impl AndroidUseControl {
    pub(super) fn reserved(identity:OriginalUseIdentity,signal:Arc<Signal>,clock:OriginalClockSlot,
        role:Role,admitted:Instant,work:Instant,hard:Instant)->Arc<Self>{
        Arc::new(Self{identity,signal,clock,role,admitted,work,hard,
            first:Mutex::new(None),unknown:AtomicBool::new(false)})
    }
    pub(super) fn identity(&self)->&OriginalUseIdentity{&self.identity}
    pub(super) fn local(&self,at:Instant,observed:Instant,unknown:bool){
        if unknown{self.unknown.store(true,Ordering::SeqCst);}
        if at>observed {
            self.unknown.store(true,Ordering::SeqCst);self.signal.clock_unknown();return;
        }
        match self.first.lock(){
            Ok(mut first)=>if first.as_ref().is_none_or(|before|at<before.at){
                *first=Some(LocalFailure{at,observed});
            },
            Err(_)=>{self.unknown.store(true,Ordering::SeqCst);self.signal.clock_unknown();},
        }
        // Pure same-bracket mapping only, including during/after SH consume.
        // This never calls the older uptime-sampling publish_local.
        let _=self.data();
    }
    pub(super) fn mark_unknown(&self){
        self.unknown.store(true,Ordering::SeqCst);self.signal.clock_unknown();
    }
    pub(super) fn data(&self)->ControlData{
        let local=match self.first.lock(){
            Ok(first)=>*first,
            Err(_)=>{self.unknown.store(true,Ordering::SeqCst);None},
        };
        let mut unknown=self.unknown.load(Ordering::SeqCst) || self.signal.snapshot().unknown;
        if self.work.checked_duration_since(self.admitted)!=Some(Duration::from_nanos(self.role.work_ns()))
            || self.hard.checked_duration_since(self.admitted)!=Some(Duration::from_nanos(self.role.hard_ns())){
            unknown=true;
        }
        let failure=self.clock.get().map(|clock|{
            if !Arc::ptr_eq(clock.signal(),&self.signal) || clock.bounds().role!=self.role
                || !clock.bounds().valid() || self.signal.bounds()!=Some(clock.bounds()){
                unknown=true;self.signal.clock_unknown();
            }
            if let Some(local)=local{
                if clock.publish_local_data(local.at,local.observed,unknown).is_err(){unknown=true;}
            }else if unknown{self.signal.clock_unknown();}
            let data=clock.data();
            if data.original!=clock.bounds() || data.unknown
                || data.first.is_some()!=data.first_instant.is_some()
                || data.cleanup.is_none() || data.cleanup_instant.is_none(){unknown=true;}
            data
        });
        if unknown{self.unknown.store(true,Ordering::SeqCst);self.signal.clock_unknown();}
        ControlData{failure,local_first:local.map(|first|first.at),unknown}
    }
    pub(super) fn unarmed(&self)->bool{
        self.clock.get().is_none() && self.signal.bounds().is_none()
            && self.signal.snapshot().first.is_none() && !self.signal.snapshot().unknown
            && !self.unknown.load(Ordering::SeqCst) && !self.first.is_poisoned()
    }
    pub(super) fn first(&self,local:Option<Instant>)->Option<Instant>{
        let data=self.data();
        min_first(min_first(local,data.local_first),data.failure.and_then(|data|data.first_instant))
    }
    pub(super) fn cutoff(&self,local:Option<Instant>,base:Instant)->Instant{
        let data=self.data();
        if data.unknown{return base.min(self.admitted);}
        let first=min_first(min_first(local,data.local_first),data.failure.and_then(|data|data.first_instant));
        let local_end=first.and_then(|first|first.checked_add(SETTLEMENT)).map_or(base,|end|base.min(end));
        data.failure.and_then(|data|data.cleanup_instant).map_or(local_end,|end|local_end.min(end))
    }
    pub(super) fn stopped(&self)->bool{
        let data=self.data();
        data.unknown || data.local_first.is_some() || data.failure.is_some_and(|data|data.first.is_some())
    }
    pub(super) fn retained_control_charge()->Option<usize>{
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Signal>())?
            .checked_add(std::mem::size_of::<std::sync::OnceLock<Arc<crate::android_shared_lease_macos::OriginalClock>>>())?
            .checked_add(std::mem::size_of::<crate::android_shared_lease_macos::OriginalClock>())?
            .checked_add(8*std::mem::size_of::<usize>())
    }
}
fn min_first(a:Option<Instant>,b:Option<Instant>)->Option<Instant>{
    match(a,b){(Some(a),Some(b))=>Some(a.min(b)),(a,b)=>a.or(b)}
}

/// One fixed close claim/result slot, constructed in the containing original
/// before GO. Its short locks hold only moved/frozen DATA or the actual handle;
/// no native wrapper/book, Registry or Document is borrowed while waiting.
pub(super) struct AndroidCloseSlot {
    executor:tokio::runtime::Handle,control:Arc<AndroidUseControl>,
    claim:Mutex<Option<CloseClaim>>,claimed:AtomicBool,entered:AtomicBool,
    pub(super) handle:AsyncMutex<Option<JoinHandle<Option<FrozenCloseData>>>>,
    pub(super) returned:Mutex<Option<Result<Option<FrozenCloseData>,tokio::task::JoinError>>>,
    pub(super) join_seen:AtomicBool,no_entry:AtomicBool,
}
struct CloseClaim {tail:AppCloseTail,joins:AndroidOriginalJoins}
impl AndroidCloseSlot {
    pub(super) fn reserved(executor:tokio::runtime::Handle,control:Arc<AndroidUseControl>)->Arc<Self>{
        Arc::new(Self{executor,control,claim:Mutex::new(None),claimed:AtomicBool::new(false),
            entered:AtomicBool::new(false),handle:AsyncMutex::new(None),returned:Mutex::new(None),
            join_seen:AtomicBool::new(false),no_entry:AtomicBool::new(false)})
    }
    /// Additive fixed storage is charged BEFORE any tail can move or enter.
    /// This includes Product's transient scalar close ledger and retained
    /// guarded/nonentered FrozenCloseData, not a guessed zero after retirement.
    pub(super) fn fixed_charge()->Option<usize>{
        std::mem::size_of::<Self>().checked_add(std::mem::size_of::<CloseClaim>())?
            .checked_add(std::mem::size_of::<FrozenCloseData>())?
            .checked_add(CLOSE_TAIL_LEDGER_BYTES)?
            .checked_add(2*std::mem::size_of::<usize>())
    }
    pub(super) fn start(self:&Arc<Self>,tail:&mut Option<AppCloseTail>,joins:AndroidOriginalJoins)->bool{
        let Ok(mut handle)=self.handle.try_lock()else{self.control.mark_unknown();return false;};
        let Ok(mut claim)=self.claim.lock()else{self.control.mark_unknown();return false;};
        if self.claimed.load(Ordering::SeqCst) || self.no_entry.load(Ordering::SeqCst)
            || handle.is_some() || claim.is_some() || self.join_seen.load(Ordering::SeqCst)
            || self.returned.is_poisoned() {
            self.control.mark_unknown();return false;
        }
        let Some(tail)=tail.take()else{self.control.mark_unknown();return false;};
        *claim=Some(CloseClaim{tail,joins});self.claimed.store(true,Ordering::SeqCst);
        // The SAME original retains the complete claim before task creation.
        // Loss before native entry leaves it here, not in a detached callback.
        let original=self.clone();
        *handle=Some(self.executor.spawn_blocking(move||{
            let claim=match original.claim.lock(){
                Ok(mut slot)=>slot.take(),
                Err(_)=>{original.control.mark_unknown();return None;},
            };
            let Some(claim)=claim else{original.control.mark_unknown();return None;};
            original.entered.store(true,Ordering::SeqCst);
            // All eligible original joins preceded this claim. The sole tail
            // owns mandatory per-call native pre-admission and final-F ledger.
            Some(claim.tail.consume_after_original_joins(claim.joins))
        }));
        true
    }
    pub(super) fn finish_unentered(&self,joins:AndroidOriginalJoins)->bool{
        if self.claimed.load(Ordering::SeqCst) || self.entered.load(Ordering::SeqCst)
            || self.join_seen.load(Ordering::SeqCst) || !self.control.unarmed()
            || !joins.accepts_original(self.control.identity()){
            self.control.mark_unknown();return false;
        }
        // Distinct no-native-entry disposition; no synthetic FrozenCloseData.
        self.no_entry.store(true,Ordering::SeqCst);true
    }
    /// Read-only M2 memory precondition. Same frozen close DATA as known(), but
    /// every borrowed book is try-locked and no control reducer/native getter is
    /// called. This does not consume a handle, poll, reconcile or establish a join.
    pub(super) fn retained_known(&self)->bool{
        let Ok(_first)=self.control.first.try_lock()else{return false;};
        if self.control.unknown.load(Ordering::SeqCst) || self.control.signal.snapshot().unknown{return false;}
        let Ok(handle)=self.handle.try_lock()else{return false;};
        let Ok(claim)=self.claim.try_lock()else{return false;};
        let Ok(returned)=self.returned.try_lock()else{return false;};
        if handle.is_some() || claim.is_some(){return false;}
        if self.no_entry.load(Ordering::SeqCst){
            return !self.claimed.load(Ordering::SeqCst) && !self.entered.load(Ordering::SeqCst)
                && !self.join_seen.load(Ordering::SeqCst) && self.control.unarmed() && returned.is_none();
        }
        self.claimed.load(Ordering::SeqCst) && self.entered.load(Ordering::SeqCst)
            && self.join_seen.load(Ordering::SeqCst)
            && matches!(returned.as_ref(),Some(Ok(Some(data))) if data.settled && !data.failure.unknown
                && data.remaining==0 && data.not_entered==0 && data.entered_unfinalized==0
                && data.attempted==data.closed && data.first_close_errno.is_none())
    }
    pub(super) fn known(&self)->bool{
        if self.control.data().unknown{return false;}
        if self.no_entry.load(Ordering::SeqCst){
            return !self.claimed.load(Ordering::SeqCst) && !self.entered.load(Ordering::SeqCst)
                && !self.join_seen.load(Ordering::SeqCst) && self.control.unarmed()
                && self.handle.try_lock().is_ok_and(|slot|slot.is_none())
                && self.returned.lock().is_ok_and(|slot|slot.is_none());
        }
        self.claimed.load(Ordering::SeqCst) && self.entered.load(Ordering::SeqCst)
            && self.join_seen.load(Ordering::SeqCst)
            && self.handle.try_lock().is_ok_and(|slot|slot.is_none())
            && self.claim.lock().is_ok_and(|slot|slot.is_none())
            && self.returned.lock().is_ok_and(|slot|matches!(slot.as_ref(),
                Some(Ok(Some(data))) if data.settled && !data.failure.unknown
                    && data.remaining==0 && data.not_entered==0 && data.entered_unfinalized==0
                    && data.attempted==data.closed && data.first_close_errno.is_none()))
    }
    pub(super) fn poll_original(&self,handle:&mut Option<JoinHandle<Option<FrozenCloseData>>>,
        context:&mut TaskContext<'_>)->Poll<bool>{
        let Poll::Ready(joined)=poll_android_original(handle,&self.returned,&self.join_seen,context,
            ||self.control.mark_unknown())else{return Poll::Pending;};
        let timely_data=self.returned.lock().is_ok_and(|returned|matches!(returned.as_ref(),
            Some(Ok(Some(data))) if data.settled && !data.failure.unknown));
        if !joined || !timely_data{self.control.mark_unknown();}
        Poll::Ready(joined)
    }
}

/// An intermediate ORIGINAL worker return. observations=true is not finality:
/// its entire SH tail still belongs to this return until the genuine join gate.
pub(super) struct AndroidObservations {
    pub(super) entered:bool,pub(super) observations:bool,pub(super) integrity:bool,
    pub(super) tail:Option<AppCloseTail>,pub(super) retained_bytes:Option<usize>,
}
impl AndroidObservations {
    fn unknown()->Self{Self{entered:true,observations:false,integrity:false,tail:None,retained_bytes:None}}
}
#[derive(Default)]
pub(super) struct AndroidObservationSlot {
    pub(super) handle:Option<JoinHandle<AndroidObservations>>,
    pub(super) returned:Option<Result<AndroidObservations,tokio::task::JoinError>>,
    pub(super) started:bool,pub(super) joined:bool,pub(super) failed:bool,
}
impl AndroidObservationSlot {
    pub(super) fn frozen_ready(&self)->bool{
        self.started && self.joined && !self.failed && self.handle.is_none()
            && matches!(self.returned.as_ref(),Some(Ok(data)) if data.observations && data.retained_bytes.is_some())
    }
}
pub(super) struct AndroidNativeBooks {
    runtime:crate::installed_runtime::AndroidBuildRuntimeSlots,tools:LeasedAndroidToolchainSlots,
    selection:Option<VerifiedRuntime>,pub(super) phase:NativePhase,
    failure:Option<(AdmissionFailure,Instant)>,pub(super) settlement_started:bool,
    audit:watch::Receiver<Instant>,cleanup:watch::Receiver<Instant>,
    pub(super) control:Arc<AndroidUseControl>,pre_go_reservation:Option<usize>,
}
impl AndroidNativeBooks {
    pub(super) fn new(selected:android_wire::MacToolchainSelection,audit:watch::Receiver<Instant>,
        cleanup:watch::Receiver<Instant>,clocks:Clocks)->Self{
        let tools=LeasedAndroidToolchainSlots::new(selected,audit.clone());
        let control=AndroidUseControl::reserved(tools.original_identity(),tools.query_signal(),
            tools.original_clock_slot(),Role::Start,clocks.admitted,clocks.work,clocks.finality);
        let mut original=Self{runtime:crate::installed_runtime::AndroidBuildRuntimeSlots::new(audit.clone()),tools,
            selection:None,phase:NativePhase::New,failure:None,settlement_started:false,audit,cleanup,control,
            pre_go_reservation:None};
        original.pre_go_reservation=original.retained_now()
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<Session>()))
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<Resources>()))
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<AndroidObservationSlot>()))
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<AndroidObservations>()));
        original
    }
    pub(super) fn reserved_before_go(&self)->bool{self.pre_go_reservation.is_some()}
    pub(super) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        [self.failure,self.runtime.first_failure(),self.tools.first_failure()]
            .into_iter().flatten().min_by_key(|(_,at)|*at)
    }
    fn fail(&mut self,failure:AdmissionFailure){
        let at=Instant::now();
        let observed=self.first_failure().unwrap_or((failure,at));
        if self.failure.is_none_or(|(_,before)|observed.1<before){self.failure=Some(observed);}
        self.control.local(observed.1,at,failure==AdmissionFailure::Unknown);
        self.phase=NativePhase::Refused;
    }
    pub(super) fn publish(&self,publish:&mut dyn FnMut(AdmissionFailure,Instant)){
        if let Some((failure,at))=self.first_failure(){publish(failure,at);}
    }
    fn retained_before_tail(&self)->Option<usize>{
        self.pre_go_reservation?.checked_add(self.retained_now()?)
    }
    fn retained_now(&self)->Option<usize>{
        let selection=self.selection.as_ref().map_or(Some(0),|selected|
            selected.python.capacity().checked_add(selected.bootstrap.capacity())?
                .checked_add(selected.core.capacity())?.checked_add(selected.cwd.capacity()));
        std::mem::size_of::<Self>().checked_add(selection?)?
            .checked_add(self.runtime.retained_bytes()?)?
            .checked_add(self.tools.retained_bytes()?)?
            .checked_add(AndroidUseControl::retained_control_charge()?)?
            .checked_add(AndroidCloseSlot::fixed_charge()?)
    }
    pub(super) fn inspect_once(&mut self,runtime:&RuntimeConfig,_end:Instant,stop:&watch::Receiver<bool>,
        publish:&mut dyn FnMut(AdmissionFailure,Instant))->Result<VerifiedRuntime,BridgeError>{
        if self.phase!=NativePhase::New{return Err(BridgeError::cleanup_unknown());}
        self.phase=NativePhase::Inspecting;
        // Arm original query clock before any runtime/tool failure can strand
        // an unarmed lease. SAME entered inspector retires ClientBook inside
        // this compulsory wrapper, including all ordinary failure paths.
        let first=self.control.data().local_first;
        if let Err(issue)=self.tools.inspect_once(self.control.admitted,self.control.work,self.control.hard,first,stop){
            self.fail(android_lease_admission_issue(issue));self.publish(publish);
            return Err(SavedCommandDomain::AndroidBuild.unavailable());
        }
        let selected=match runtime.resolve_android_build_installed(&mut self.runtime,self.control.work,stop){
            Ok(selected)=>selected,
            Err(error)=>{self.fail(AdmissionFailure::Inventory);self.publish(publish);return Err(error);},
        };
        self.selection=Some(VerifiedRuntime{python:selected.python.clone(),bootstrap:selected.bootstrap.clone(),
            core:selected.core.clone(),cwd:selected.cwd.clone()});
        self.phase=NativePhase::Ready;Ok(selected)
    }
    fn selected_binding(&self,expected:&VerifiedRuntime)->Result<(),AdmissionFailure>{
        if self.phase!=NativePhase::Ready || self.first_failure().is_some() || self.settlement_started
            || self.control.stopped(){return Err(AdmissionFailure::AlreadyUsed);}
        let selected=self.selection.as_ref().ok_or(AdmissionFailure::Unknown)?;
        if (&selected.python,&selected.bootstrap,&selected.core,&selected.cwd)
            !=(&expected.python,&expected.bootstrap,&expected.core,&expected.cwd){return Err(AdmissionFailure::Identity);}
        Ok(())
    }
    pub(super) fn request_binding(&self,expected:&VerifiedRuntime)->Result<android_wire::ToolchainBinding,AdmissionFailure>{
        self.selected_binding(expected)?;self.tools.binding_data().map_err(android_lease_admission_issue)
    }
    pub(super) fn check_before_spawn(&mut self,selected:&VerifiedRuntime,end:Instant,stop:&watch::Receiver<bool>,
        publish:&mut dyn FnMut(AdmissionFailure,Instant))->Result<(),AdmissionFailure>{
        let result=(||{
            self.selected_binding(selected)?;
            self.runtime.transfer_once()?;
            let original=self.runtime.capability()?.prepare_once(end,stop)?;
            if (&original.python,&original.bootstrap,&original.core,&original.cwd)
                !=(&selected.python,&selected.bootstrap,&selected.core,&selected.cwd){return Err(AdmissionFailure::Identity);}
            self.tools.check_before_spawn(end,stop).map_err(android_lease_admission_issue)
        })();
        if let Err(failure)=result{self.fail(failure);self.publish(publish);}
        result
    }
    pub(super) fn claim_once(&mut self)->Result<(),AdmissionFailure>{
        if self.phase!=NativePhase::Ready || self.first_failure().is_some() || self.settlement_started
            || self.control.stopped(){return Err(AdmissionFailure::AlreadyUsed);}
        self.runtime.capability()?.claim_once()?;self.phase=NativePhase::Claimed;Ok(())
    }
    pub(super) fn interrupted(&mut self){
        self.fail(AdmissionFailure::Unknown);self.phase=NativePhase::Unknown;
        self.runtime.mark_interrupted();self.tools.mark_interrupted();
    }
    fn settle_observations(&mut self,used:bool,end:Instant,
        publish:&mut dyn FnMut(AdmissionFailure,Instant))->AndroidObservations{
        if self.settlement_started || self.phase==NativePhase::Claimed && !used{
            publish(AdmissionFailure::Unknown,Instant::now());return AndroidObservations::unknown();
        }
        self.settlement_started=true;
        if self.phase==NativePhase::New && !used && self.runtime.never_started() && self.control.unarmed(){
            // Constructor/no-entry facts are captured BEFORE any tail. No
            // synthetic lease return, native freeze or unentered ClientBook use.
            let bytes=self.retained_before_tail();self.phase=NativePhase::Settled;
            return AndroidObservations{entered:false,observations:bytes.is_some(),integrity:true,tail:None,retained_bytes:bytes};
        }
        self.phase=NativePhase::Settling;self.publish(publish);
        let mut integrity=!used || self.first_failure().is_none();
        if used{
            if let Err(failure)=self.runtime.android_check_after_use(end,&self.audit){
                self.fail(failure);self.publish(publish);integrity=false;
            }
            if let Err(issue)=self.tools.check_after_use(end){
                self.fail(android_lease_admission_issue(issue));self.publish(publish);integrity=false;
            }
        }
        let cleanup=*self.cleanup.borrow();
        let tools=self.tools.settle_observations(cleanup,&self.cleanup,publish);
        let runtime=self.runtime.settle_originals(cleanup,&self.cleanup,publish);
        self.publish(publish);
        let observations=tools==CloseOutcome::Settled && runtime==CloseOutcome::Settled
            && self.tools.observations_settled() && self.runtime.settled();
        let retained_bytes=self.retained_before_tail();
        if !observations || retained_bytes.is_none(){
            self.phase=NativePhase::Unknown;
            return AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes};
        }
        // Last original book/native probe. Never ask it for bytes/settled again.
        let tail=self.tools.take_close_tail();
        self.phase=if tail.is_ok(){NativePhase::Settling}else{NativePhase::Unknown};
        match tail{
            Ok(tail)=>AndroidObservations{entered:true,observations:true,integrity,tail:Some(tail),retained_bytes},
            Err(_)=>AndroidObservations{entered:true,observations:false,integrity:false,tail:None,retained_bytes},
        }
    }
}

pub(super) async fn settle_start_observations(book:&mut Resources,inner:&Arc<Inner>,owner:&Arc<Session>){
    if book.android_observations.is_none(){inner.unknown(owner);return;}
    if !book.android_observations.as_ref().is_some_and(|slot|slot.started){
        let used={
            let startup=match owner.startup.lock(){Ok(startup)=>startup,Err(_)=>{inner.unknown(owner);return;}};
            if !native_consumers_returned(book,&startup,inner,owner){inner.unknown(owner);return;}
            startup.attempted
        };
        let Some(native)=book.native.clone()else{inner.unknown(owner);return;};
        let original=owner.clone();let end=*owner.native_audit_cutoff.borrow();
        let (release,enter)=oneshot::channel();
        let Some(slot)=book.android_observations.as_mut()else{inner.unknown(owner);return;};
        slot.started=true;
        slot.handle=Some(tokio::task::spawn_blocking(move||{
            if enter.blocking_recv().is_err(){return AndroidObservations::unknown();}
            let mut native=match native.lock(){
                Ok(native)=>native,Err(error)=>{let mut native=error.into_inner();native.interrupted();native},
            };
            native.settle_observations(used,end,&mut|failure,at|original.observe_android_failure(failure,at))
        }));
        let _=release.send(());
    }
    let Some(slot)=book.android_observations.as_mut()else{inner.unknown(owner);return;};
    if !slot.joined && !slot.failed{
        // Resources is exclusively held: verify the fixed return slot before
        // polling its handle, not after obtaining a tail-bearing result.
        if slot.returned.is_some(){slot.failed=true;inner.unknown(owner);return;}
        let result=join_with_clock(&mut slot.handle,inner,owner).await;
        let joined=result.is_ok();
        let safe=matches!(&result,Ok(data) if data.observations && data.retained_bytes.is_some());
        let integrity=matches!(&result,Ok(data) if data.integrity);
        slot.returned=Some(result);slot.joined=joined;slot.failed=!joined;
        if joined{slot.handle.take();}
        // No native_worker_lost after any moved tail. A lost observation keeps
        // its original book/return and conservative charge, never probes it.
        if !safe || slot.failed{owner.resource_unknown.store(true,Ordering::SeqCst);inner.unknown(owner);}
        else if !integrity{inner.stop(owner,Reason::ToolchainMismatch);}
    }
}

pub(super) async fn join_start_close(inner:&Arc<Inner>,owner:&Arc<Session>)->bool{
    let Some(close)=owner.android_close.as_ref()else{return false;};
    let mut handle=close.handle.lock().await;
    if close.join_seen.load(Ordering::SeqCst){drop(handle);return close.known();}
    if handle.is_none(){return false;}
    let joined=loop{
        let wake=owner.wake.notified();let end=inner.endpoint(owner);
        tokio::select!{
            joined=std::future::poll_fn(|context|close.poll_original(&mut handle,context))=>break joined,
            _=wake=>{},_=clock_wait(end)=>{},
            _=owner.android_control_tick(),if end.is_some()=>{},
        }
    };
    if joined{handle.take();}
    drop(handle);
    // Distinct post-retirement control snapshot is NEGATIVE ONLY. Frozen
    // syscall/native results remain the only positive close facts.
    let known=close.known() && inner.endpoint(owner).is_some();
    if !known{owner.resource_unknown.store(true,Ordering::SeqCst);inner.unknown(owner);}
    known
}
