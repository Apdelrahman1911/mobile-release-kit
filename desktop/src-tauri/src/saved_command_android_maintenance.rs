//! Private installed maintenance on the SAME saved registration ControlSlot.
//! One IPC worker, one existing-kind async coordinator, one main Preparation.
//! This module is not public UI activation or Installer permission.
use super::*;
#[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
pub(crate) use selected::{State,Request,Checked,Snapshot,Handle,Admitted,Completion,Status,Phase,OriginalClock};
#[cfg(not(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper"))))]
#[derive(Default)]
pub(super) struct State;
#[cfg(not(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper"))))]
impl State{
    pub(super) fn busy(&self)->bool{false}
    pub(super) fn unknown(&self)->bool{false}
    pub(super) fn empty(&self)->bool{true}
    pub(super) fn stop(&mut self,_reason:wire::Reason,_at:Instant)->bool{false}
    pub(super) fn reconcile(&mut self,_inner:&Inner)->bool{false}
    pub(super) fn retained_bytes(&self)->Option<usize>{Some(std::mem::size_of::<Self>())}
    pub(super) fn sources_match(&self,_sources:&android_sources::Sources)->bool{true}
    pub(super) fn invalidation_failure(&self)->Option<(wire::Reason,Instant)>{None}
}

#[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
mod selected{
    use super::super::*;
    use mrk_macos_installed_native::{android_registration as native,android_maintenance_client as transport,
        android_service_management as management,vault_helper_wire::ClockBridge};
    use std::sync::OnceLock;
    const HEARTBEAT:Duration=Duration::from_millis(5);
    const TASK_STORAGE:usize=64*1024;
    pub(crate) const CONFIRMATION:&str="Stop the installed Android helper and prepare this application to quit";

    /// Fixed explicit application-level consent, not arbitrary project/copy input.
    /// The native shell is the only production caller; this is not in its IPC
    /// handler table until the complete integrated/native path is activated.
    pub(crate) struct Request{at:Instant,operation:[u8;16],id:String}
    impl Request{
        pub(crate) fn confirmed(value:&str)->Result<Self,BridgeError>{
            let at=Instant::now();
            if value!=CONFIRMATION{return Err(unavailable());}
            let mut operation=[0;16];getrandom::fill(&mut operation).map_err(|_|unavailable())?;
            if operation==[0;16]{return Err(unavailable());}
            let id=operation.iter().map(|byte|format!("{byte:02x}")).collect();
            Ok(Self{at,operation,id})
        }
    }
    pub(crate) fn unavailable()->BridgeError{BridgeError::new("macos_maintenance_unavailable",
        "Installed maintenance is unavailable for this original application or unsettled work.")}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub(crate) enum Phase{Preparing,Unregistering,Settling,Prepared,Refused,Unknown}
    #[derive(Clone,Copy)]
    pub(crate) struct Status{
        pub(crate) operation:[u8;16],pub(crate) generation:u32,pub(crate) phase:Phase,pub(crate) reason:wire::Reason,
        pub(crate) started_or_uncertain:bool,pub(crate) unregister_accepted:bool,pub(crate) not_registered:bool,
    }
    #[derive(Default)]
    pub(crate) struct State{generation:u32,active:Option<Arc<Original>>,last:Option<Status>}
    pub(crate) struct Snapshot{
        owner:Weak<Inner>,document:Weak<()>,request:Request,pickers:[Option<Arc<crate::asset_session::OriginalWork>>;3],
        source_generation:u32,cohort:Mutex<Option<AdmissionCohort>>,
    }
    pub(crate) struct Checked{snapshot:Snapshot}
    impl Snapshot{
        pub(crate) fn check_originals(self)->Result<Checked,BridgeError>{
            for original in self.pickers.iter().flatten(){
                if !original.android_source_selected_settled(){return Err(unavailable());}
            }
            Ok(Checked{snapshot:self})
        }
    }
    impl Checked{
        pub(crate) fn picker_originals(&self)->&[Option<Arc<crate::asset_session::OriginalWork>>;3]{&self.snapshot.pickers}
    }
    #[derive(Default)]
    struct FailureProjection{imported:Option<(u64,Instant,wire::Reason)>,exported:Option<(u64,wire::Reason)>}
    /// One original conservative bracket. The coordinator never borrows client,
    /// identity or AppKit custody to publish STOP/deadline contractions.
    pub(crate) struct OriginalClock{bridge:ClockBridge,projection:Mutex<FailureProjection>}
    impl OriginalClock{
        fn capture(control:&Control,signal:&native::Signal)->Option<Self>{
            let bridge=ClockBridge::capture()?;let origin=bridge.earlier_endpoint(control.admitted)?;
            let bounds=native::Bounds{origin,work:origin.checked_add(native::WORK_NS)?,hard:origin.checked_add(native::HARD_NS)?};
            if !bounds.valid() || bridge.earlier_endpoint(control.work)!=Some(bounds.work)
                || bridge.earlier_endpoint(control.hard)!=Some(bounds.hard) || signal.arm(bounds).is_err(){return None;}
            Some(Self{bridge,projection:Mutex::new(FailureProjection::default())})
        }
        pub(crate) fn bridge(&self)->&ClockBridge{&self.bridge}
        pub(crate) fn synchronize(&self,control:&Control,signal:&native::Signal){
            control.advance(Instant::now());
            let mut projection=match self.projection.try_lock(){Ok(p)=>p,Err(TryLockError::WouldBlock)=>return,
                Err(_)=>{signal.clock_unknown();control.poisoned();return;}};
            if let Some((reason,first))=control.failure(){
                if first>Instant::now(){signal.clock_unknown();control.poisoned();return;}
                // Never re-export an imported lower bound through the bracket:
                // otherwise each heartbeat would subtract the bracket width.
                if projection.imported.is_none_or(|(_,bound,_)|first<bound){
                    signal.local_failure(&self.bridge,first,control.unknown.load(Ordering::SeqCst));
                    projection.exported=self.bridge.earlier_endpoint(first).map(|raw|(raw,reason));
                }
            }
            if control.unknown.load(Ordering::SeqCst){
                if let Some(first)=signal.first(){signal.failure_at(first,true);}else{signal.clock_unknown();}
            }
            let frozen=signal.snapshot();
            if let Some(raw)=frozen.first{
                let Some(first)=self.bridge.earlier_instant_data(raw)else{signal.clock_unknown();control.poisoned();return;};
                let reason=projection.exported.filter(|(value,_)|*value==raw).map(|(_,reason)|reason)
                    .or_else(||projection.imported.filter(|(value,_,_)|*value==raw).map(|(_,_,reason)|reason))
                    .unwrap_or(wire::Reason::ServiceUnavailable);
                projection.imported=Some((raw,first,reason));control.stop_at(reason,first);
            }
            let Some(end)=frozen.cleanup.and_then(|raw|self.bridge.earlier_instant_data(raw))else{
                signal.clock_unknown();control.poisoned();return;
            };
            // Normal R only narrows. It does not call failure_at/stop_at.
            control.narrow_maintenance(end);
            if frozen.unknown{control.poisoned();}
        }
    }
    struct Original{
        owner:Weak<Inner>,document:Weak<()>,operation:[u8;16],generation:u32,
        pickers:[Option<Arc<crate::asset_session::OriginalWork>>;3],source_generation:u32,
        cohort:AdmissionCohort,control:Arc<Control>,reservation:OnceLock<usize>,
        signal:Arc<native::Signal>,clock:OnceLock<OriginalClock>,client:Mutex<Option<transport::Client>>,
        preparation:service_setup::Preparation,
        worker:AsyncMutex<Option<JoinHandle<WorkerReturn>>>,returned:Mutex<Option<Result<WorkerReturn,tokio::task::JoinError>>>,
        worker_joined:AtomicBool,coordinator:Mutex<Option<JoinHandle<bool>>>,
        coordinator_return:Mutex<Option<Result<bool,tokio::task::JoinError>>>,coordinator_joined:AtomicBool,
        joined_at:OnceLock<Instant>,accepted:AtomicBool,
    }
    struct WorkerReturn{facts:service_setup::MaintenanceRun,first:Option<(wire::Reason,Instant)>}
    #[derive(Clone)]
    pub(crate) struct Handle{original:Arc<Original>}
    impl Handle{
        pub(crate) fn same(&self,other:&Self)->bool{Arc::ptr_eq(&self.original,&other.original)}
        pub(crate) fn can_exit(&self)->bool{self.original.accepted.load(Ordering::SeqCst) && self.original.known_return()}
    }
    pub(crate) struct Admitted{handle:Handle,release:Option<oneshot::Sender<()>>}
    impl Admitted{
        pub(crate) fn handle(&self)->Handle{self.handle.clone()}
        pub(crate) fn release(mut self)->Result<(),BridgeError>{
            if self.release.take().is_none_or(|sender|sender.send(()).is_err()){
                self.handle.original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());return Err(unavailable());
            }Ok(())
        }
    }
    impl Drop for Admitted{fn drop(&mut self){if self.release.is_some(){
        self.handle.original.control.stop_at(wire::Reason::Cancelled,Instant::now());
    }}}
    /// Compare fresh finality samples without renewing the original interval.
    /// Upper bounds alone must not accept a sample preceding the recorded return.
    fn timely_sample(previous:Instant,now:Instant,endpoint:Instant)->bool{
        previous<=now && now<endpoint
    }
    /// Issued only by the original finalization below. DATA fields are not a
    /// constructor; the document must consume this exact one-shot result.
    pub(crate) struct Completion{status:Status,at:Instant,endpoint:Instant}
    impl Completion{
        pub(crate) fn status(&self)->Status{self.status}
        pub(crate) fn may_reopen(&self)->bool{self.status.phase==Phase::Refused && !self.status.started_or_uncertain}
        pub(crate) fn request_quit(&self)->bool{self.status.phase==Phase::Prepared
            && timely_sample(self.at,Instant::now(),self.endpoint)}
    }
    impl Original{
        fn same_owner(&self,inner:&Inner)->bool{self.owner.as_ptr()==inner as *const Inner
            && self.document.upgrade().is_some_and(|document|inner.android_original_document_matches(Some(&document)))}
        fn synchronize(&self){
            // Accepted publisher F lives in the SAME cohort before watch
            // projection. Import it even while the IPC worker is in native code.
            let _=WorkGate{slot:self.cohort.slot.clone(),control:self.control.clone()}.try_work();
            if let Some(clock)=self.clock.get(){clock.synchronize(&self.control,&self.signal);}
            else{self.control.advance(Instant::now());}
        }
        fn known_return(&self)->bool{
            if !self.worker_joined.load(Ordering::SeqCst) || self.control.unknown.load(Ordering::SeqCst)
                || self.signal.unknown() || !self.preparation.known_return(){return false;}
            let Ok(worker)=self.worker.try_lock()else{return false;};
            let Ok(returned)=self.returned.try_lock()else{return false;};
            worker.is_none() && matches!(returned.as_ref(),Some(Ok(value)) if value.facts.known && value.facts.retained.is_some())
        }
        fn status(&self)->Status{
            let partial=self.preparation.maintenance_partial();
            let facts=self.preparation.maintenance_return();
            let unknown=self.control.unknown.load(Ordering::SeqCst);
            Status{operation:self.operation,generation:self.generation,
                phase:if unknown{Phase::Unknown}else if self.worker_joined.load(Ordering::SeqCst){Phase::Settling}
                    else if partial.0{Phase::Unregistering}else{Phase::Preparing},
                reason:if unknown{wire::Reason::CleanupUnknown}else{self.control.failure().map_or(wire::Reason::None,|(reason,_)|reason)},
                started_or_uncertain:facts.is_some_and(|value|value.started_or_uncertain),
                unregister_accepted:partial.0 || facts.is_some_and(|value|value.unregister_accepted),
                not_registered:partial.1 || facts.is_some_and(|value|value.not_registered)}
        }
    }
    impl State{
        pub(crate) fn busy(&self)->bool{self.active.is_some()}
        pub(crate) fn unknown(&self)->bool{self.active.as_ref().is_some_and(|original|original.control.unknown.load(Ordering::SeqCst))}
        pub(crate) fn empty(&self)->bool{self.active.is_none() && self.last.is_none()}
        pub(crate) fn retained_bytes(&self)->Option<usize>{self.active.is_none().then_some(std::mem::size_of::<Self>())}
        pub(crate) fn sources_match(&self,sources:&android_sources::Sources)->bool{
            self.active.as_ref().is_none_or(|original|sources.same_census_originals(&original.pickers)
                && sources.census_generation()==original.source_generation)
        }
        pub(crate) fn invalidation_failure(&self)->Option<(wire::Reason,Instant)>{
            self.active.as_ref().and_then(|original|WorkGate{slot:original.cohort.slot.clone(),control:original.control.clone()}.first())
        }
        pub(crate) fn stop(&mut self,reason:wire::Reason,at:Instant)->bool{
            let Some(original)=&self.active else{return false;};
            let before=original.control.failure();let unknown=original.control.unknown.load(Ordering::SeqCst);
            original.control.stop_at(reason,at);original.synchronize();
            before!=original.control.failure() || unknown!=original.control.unknown.load(Ordering::SeqCst)
        }
        pub(crate) fn reconcile(&mut self,inner:&Inner)->bool{
            let Some(original)=self.active.as_ref().cloned()else{return false;};
            original.synchronize();let mut changed=original.control.dirty.swap(false,Ordering::SeqCst);
            if original.coordinator_joined.load(Ordering::SeqCst){
                original.preparation.tick(false);
                if !original.worker_joined.load(Ordering::SeqCst){
                    if let Ok(mut worker)=original.worker.try_lock(){
                        let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));let mut cx=TaskContext::from_waker(&waker);
                        let _=poll_worker(&original,&mut worker,&mut cx);
                    }
                }
                return changed;
            }
            let mut slot=match original.coordinator.try_lock(){Ok(slot)=>slot,Err(TryLockError::WouldBlock)=>return changed,
                Err(_)=>{original.control.poisoned();return true;}};
            let mut returned=match original.coordinator_return.try_lock(){Ok(value)=>value,Err(TryLockError::WouldBlock)=>return changed,
                Err(_)=>{original.control.poisoned();return true;}};
            if returned.is_some(){original.control.poisoned();return true;}
            let Some(handle)=slot.as_mut()else{original.control.poisoned();return true;};
            let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));let mut cx=TaskContext::from_waker(&waker);
            let Poll::Ready(result)=Pin::new(handle).poll(&mut cx)else{return changed;};
            let known=matches!(result,Ok(true));*returned=Some(result);slot.take();
            original.coordinator_joined.store(true,Ordering::SeqCst);drop(returned);drop(slot);changed=true;
            let at=Instant::now();original.synchronize();
            if !known || !original.known_return() || at>=original.control.endpoint(){original.control.mark_unknown(at);return changed;}
            if !original.same_owner(inner){original.control.stop_at(wire::Reason::DocumentLost,at);}
            if original.joined_at.set(at).is_err(){original.control.poisoned();}
            changed
        }
    }
    fn poll_worker(original:&Original,slot:&mut Option<JoinHandle<WorkerReturn>>,cx:&mut TaskContext<'_>)->Poll<bool>{
        if original.worker_joined.load(Ordering::SeqCst){return Poll::Ready(original.returned.try_lock()
            .is_ok_and(|returned|matches!(returned.as_ref(),Some(Ok(value)) if value.facts.known)));}
        let mut returned=match original.returned.try_lock(){Ok(value)=>value,Err(TryLockError::WouldBlock)=>return Poll::Pending,
            Err(_)=>{original.control.poisoned();return Poll::Ready(false);}};
        if returned.is_some(){original.control.poisoned();return Poll::Ready(false);}
        let Some(handle)=slot.as_mut()else{original.control.poisoned();return Poll::Ready(false);};
        let Poll::Ready(result)=Pin::new(handle).poll(cx)else{return Poll::Pending;};
        let known=matches!(&result,Ok(value) if value.facts.known && value.facts.retained.is_some());
        if let Ok(value)=&result{if let Some((reason,at))=value.first{original.control.stop_at(reason,at);}}
        *returned=Some(result);slot.take();original.worker_joined.store(true,Ordering::SeqCst);drop(returned);
        original.synchronize();if !known{original.control.mark_unknown(Instant::now());}
        Poll::Ready(known && !original.control.unknown.load(Ordering::SeqCst))
    }
    fn worker(original:Arc<Original>,mut enter:oneshot::Receiver<()>)->WorkerReturn{
        loop{
            original.control.advance(Instant::now());
            if original.control.failure().is_some() || original.control.unknown.load(Ordering::SeqCst){break;}
            match enter.try_recv(){Ok(())=>break,Err(oneshot::error::TryRecvError::Empty)=>std::thread::park_timeout(HEARTBEAT),
                Err(oneshot::error::TryRecvError::Closed)=>{original.control.stop_at(wire::Reason::ServiceUnavailable,Instant::now());break;}}
        }
        if original.reservation.get().is_none_or(|bytes|*bytes>OWNED_LIMIT){original.control.poisoned();}
        let clock=OriginalClock::capture(&original.control,&original.signal);
        if clock.is_none() || original.clock.set(clock.unwrap()).is_err(){original.control.poisoned();
            return WorkerReturn{facts:service_setup::MaintenanceRun::default(),first:original.control.failure()};}
        original.synchronize();
        let mut client=match original.client.try_lock(){Ok(client)=>client,Err(_)=>{original.control.poisoned();
            return WorkerReturn{facts:service_setup::MaintenanceRun::default(),first:original.control.failure()};}};
        if client.is_some(){original.control.poisoned();}
        else{*client=transport::Client::new(original.signal.clone(),original.operation);}
        let facts=if let Some(client)=client.as_mut(){
            original.preparation.run_maintenance(client,original.clock.get().unwrap(),&original.signal)
        }else{original.control.poisoned();service_setup::MaintenanceRun::default()};
        original.control.changed();WorkerReturn{facts,first:original.control.failure()}
    }
    async fn coordinate(original:Arc<Original>,mut release:oneshot::Receiver<()>,worker_enter:oneshot::Sender<()>)->bool{
        let mut worker_enter=Some(worker_enter);let mut released=false;let mut worker=original.worker.lock().await;
        let gate=WorkGate{slot:original.cohort.slot.clone(),control:original.control.clone()};
        let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));
        loop{
            original.synchronize();original.preparation.tick(true);
            if Instant::now()>=original.control.endpoint(){original.control.mark_unknown(Instant::now());return false;}
            if original.control.failure().is_some() || original.control.unknown.load(Ordering::SeqCst){worker_enter.take();}
            if !released && worker_enter.is_some(){match release.try_recv(){
                Ok(())=>released=true,Err(oneshot::error::TryRecvError::Empty)=>{},
                Err(oneshot::error::TryRecvError::Closed)=>{original.control.stop_at(wire::Reason::Cancelled,Instant::now());worker_enter.take();}
            }}
            if released && worker_enter.is_some() && gate.try_work()==Some(true){
                let same=original.owner.upgrade().is_some_and(|inner|original.same_owner(&inner));
                if !same{original.control.stop_at(wire::Reason::DocumentLost,Instant::now());worker_enter.take();}
                else if worker_enter.take().is_none_or(|sender|sender.send(()).is_err()){original.control.poisoned();}
            }
            let joined={let mut cx=TaskContext::from_waker(&waker);poll_worker(&original,&mut worker,&mut cx)};
            if let Poll::Ready(known)=joined{drop(worker);return known && original.known_return()
                && Instant::now()<original.control.endpoint();}
            tokio::time::sleep(HEARTBEAT).await;
        }
    }
    fn retained(inner:&Inner,registry:&Registry,document:&Arc<()>,checked:&Checked,
        census:&crate::asset_session::MacosMaintenanceCensus<'_>)->Option<usize>{
        if registry.active.is_some() || registry.prepared.is_some() || registry.recovery_review.is_some() || registry.recovery.is_some()
            || inner.toolchain.is_some() || registry.android_registration.active.is_some() || registry.android_registration.review.is_some(){return None;}
        #[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer")))]
        if inner.ios_observation.try_lock().ok()?.is_some(){return None;}
        #[cfg(all(test,debug_assertions,feature="development-runtime",not(feature="desktop-shell")))]
        if inner.fixture.try_lock().ok()?.is_some(){return None;}
        let mut bytes=census.for_originals(document,checked.picker_originals())?.checked_add(arc_bytes::<Inner>()?)?
            .checked_add(SIGNAL_STORAGE)?.checked_add(inner.android_registration_control.retained_bytes()?)?
            .checked_add(inner.runtime.android_registration_retained_heap_bytes(document)?)?
            .checked_add(registry.android_sources.retained_data_bytes()?.checked_sub(std::mem::size_of::<android_sources::Sources>())?)?
            .checked_add(registry.android_catalog.registration_retained_bytes()?.checked_sub(std::mem::size_of::<android_catalog::Catalog>())?)?
            .checked_add(registry.android_registration.maintenance_retained_bytes()?.checked_sub(std::mem::size_of::<Registration>())?)?
            .checked_add(std::mem::size_of::<Checked>())?.checked_add(checked.snapshot.request.id.capacity())?
            .checked_add(arc_bytes::<()>()?)?;
        if let Some(dispatcher)=inner.android_service_dispatcher.get(){let _=dispatcher;bytes=bytes.checked_add(arc_bytes::<service_setup::Dispatcher>()?)?;}
        if let Some(last)=&registry.last{
            let Context::AndroidBuild(context)=&last.context else{return None;};
            if last.stage.is_some_and(|stage|!matches!(stage,Stage::AndroidBuild(_))){return None;}
            bytes=bytes.checked_add(last.operation_id.capacity())?.checked_add(last.owner_generation.capacity())?.checked_add(context.retained_heap_bytes()?)?;
            if let Some(terminal)=&last.result{let Terminal::AndroidBuild(terminal)=terminal else{return None;};bytes=bytes.checked_add(terminal.retained_heap_bytes()?)?;}
        }
        Some(bytes)
    }
    impl SavedCommandOwner{
        pub(crate) fn maintenance_snapshot(&self,document:&Arc<()>,request:Request)->Result<Snapshot,BridgeError>{
            let registry=self.inner.lock();
            if !cfg!(feature="macos-installed-desktop-image") || !management::signing_profile_configured()
                || !self.inner.android_original_document_matches(Some(document)) || self.inner.android_service_dispatcher.get().is_none()
                || registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
                || registry.active.is_some() || registry.prepared.is_some() || registry.recovery_review.is_some() || registry.recovery.is_some()
                || registry.android_catalog.busy() || registry.android_sources.busy() || registry.android_registration.busy()
                || registry.android_registration.review.is_some() || registry.android_registration.unknown()
                || self.inner.android_registration_control.is_unknown() || self.inner.poisoned.load(Ordering::SeqCst){return Err(unavailable());}
            let epoch=self.inner.android_registration_control.epoch()?;
            let pickers=registry.android_sources.census_originals().ok_or_else(unavailable)?;
            let source_generation=registry.android_sources.census_generation();
            let cohort=self.inner.android_registration_control.claim(epoch,None)?;
            Ok(Snapshot{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),request,pickers,source_generation,
                cohort:Mutex::new(Some(cohort))})
        }
        pub(crate) fn admit_maintenance(&self,document:&Arc<()>,checked:&Checked,census:&crate::asset_session::MacosMaintenanceCensus<'_>)
            ->Result<Admitted,BridgeError>{
            let mut registry=self.inner.lock();let snapshot=&checked.snapshot;
            if snapshot.owner.as_ptr()!=Arc::as_ptr(&self.inner) || snapshot.document.as_ptr()!=Arc::as_ptr(document)
                || !self.inner.android_original_document_matches(Some(document)) || registry.disabled || registry.exhausted
                || registry.stopping || registry.document_lost || self.inner.poisoned.load(Ordering::SeqCst)
                || registry.android_catalog.busy() || registry.android_sources.busy() || registry.android_registration.busy()
                || !registry.android_sources.same_census_originals(&snapshot.pickers)
                || registry.android_sources.census_generation()!=snapshot.source_generation{return Err(unavailable());}
            let prior=retained(&self.inner,&registry,document,checked,census).ok_or_else(unavailable)?;
            let generation=registry.android_registration.maintenance.generation.checked_add(1).filter(|value|*value<u32::MAX).ok_or_else(unavailable)?;
            let dispatcher=self.inner.android_service_dispatcher.get().cloned().ok_or_else(unavailable)?;
            let executor=tokio::runtime::Handle::try_current().map_err(|_|unavailable())?;
            let mut claim=snapshot.cohort.try_lock().map_err(|_|unavailable())?;
            let cohort=claim.take().ok_or_else(unavailable)?;
            if !self.inner.android_registration_control.current_claim(&cohort){return Err(unavailable());}
            let work=snapshot.request.at.checked_add(WORK).ok_or_else(unavailable)?;
            let hard=snapshot.request.at.checked_add(HARD).ok_or_else(unavailable)?;
            if Instant::now()>=work{return Err(unavailable());}
            let(stop,_)=watch::channel(false);let(audit,_)=watch::channel(hard);
            let control=Arc::new(Control{lane:ControlLane::Maintenance,owner:Arc::downgrade(&self.inner),id:snapshot.request.id.clone(),
                generation,admitted:snapshot.request.at,work,hard,slot:Arc::downgrade(&self.inner.android_registration_control),
                cohort:cohort.identity.clone(),epoch:cohort.epoch,first:Mutex::new(None),unknown:AtomicBool::new(false),
                dirty:AtomicBool::new(false),latches:AtomicUsize::new(0),stop,audit});
            let whole=prior.checked_add(arc_bytes::<Original>().ok_or_else(unavailable)?)
                .and_then(|bytes|bytes.checked_add(control.retained_bytes()?))
                .and_then(|bytes|bytes.checked_add(arc_bytes::<native::Signal>()?))
                .and_then(|bytes|bytes.checked_add(service_setup::Preparation::reservation_bytes()?))
                .and_then(|bytes|bytes.checked_add(transport::Client::project_owned_upper_bound()?))
                .and_then(|bytes|bytes.checked_add(12*SIGNAL_STORAGE+TASK_STORAGE))
                .filter(|bytes|*bytes<=OWNED_LIMIT).ok_or_else(unavailable)?;
            let original=Arc::new(Original{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),
                operation:snapshot.request.operation,generation,pickers:snapshot.pickers.clone(),source_generation:snapshot.source_generation,
                cohort,control:control.clone(),reservation:OnceLock::new(),signal:Arc::new(native::Signal::reserved()),
                clock:OnceLock::new(),client:Mutex::new(None),preparation:service_setup::Preparation::for_maintenance(
                    WorkGate{slot:self.inner.android_registration_control.clone(),control:control.clone()},dispatcher,snapshot.request.operation),
                worker:AsyncMutex::new(None),returned:Mutex::new(None),worker_joined:AtomicBool::new(false),
                coordinator:Mutex::new(None),coordinator_return:Mutex::new(None),coordinator_joined:AtomicBool::new(false),
                joined_at:OnceLock::new(),accepted:AtomicBool::new(false)});
            let(release,enter)=oneshot::channel();let(worker_enter,worker_wait)=oneshot::channel();
            let worker_task={let original=original.clone();move||worker(original,worker_wait)};
            let coordinator=coordinate(original.clone(),enter,worker_enter);
            let task_bytes=std::mem::size_of_val(&worker_task).checked_add(std::mem::size_of_val(&coordinator))
                .and_then(|bytes|bytes.checked_add(4*std::mem::size_of::<WorkerReturn>()))
                .and_then(|bytes|bytes.checked_add(std::mem::size_of::<Completion>())).ok_or_else(unavailable)?;
            if task_bytes>TASK_STORAGE{return Err(unavailable());}
            original.reservation.set(whole).map_err(|_|unavailable())?;
            if !self.inner.android_registration_control.install(control,&original.cohort,None){return Err(unavailable());}
            registry.android_registration.maintenance.generation=generation;
            registry.android_registration.maintenance.active=Some(original.clone());
            let publish=||->Result<(),()>{
                let mut worker=original.worker.try_lock().map_err(|_|())?;
                let mut owner=original.coordinator.try_lock().map_err(|_|())?;
                *worker=Some(executor.spawn_blocking(worker_task));*owner=Some(executor.spawn(coordinator));Ok(())
            };
            if publish().is_err(){original.control.poisoned();}
            self.inner.bump(&mut registry);
            // Even publication failure returns its retained original to Document,
            // which closes launches before releasing or reporting this admission.
            Ok(Admitted{handle:Handle{original},release:Some(release)})
        }
        pub(crate) fn maintenance_status(&self,handle:&Handle)->Status{
            self.reconcile();handle.original.status()
        }
        pub(crate) fn finalize_maintenance(&self,document:&Arc<()>,handle:&Handle,live:bool)->Option<Completion>{
            self.reconcile();let mut registry=self.inner.lock();let original=&handle.original;
            if !registry.android_registration.maintenance.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,original))
                || original.accepted.load(Ordering::SeqCst) || original.document.as_ptr()!=Arc::as_ptr(document)
                || !original.coordinator_joined.load(Ordering::SeqCst){return None;}
            let joined=*original.joined_at.get()?;original.synchronize();
            if !original.known_return() || original.control.unknown.load(Ordering::SeqCst){return None;}
            let mut book=self.inner.android_registration_control.book.try_lock().ok()?;
            if self.inner.android_registration_control.is_unknown() || book.review.is_some() || book.admission.is_some()
                || !book.original.as_ref().is_some_and(|current|Arc::ptr_eq(current,&original.control))
                || !book.cohort.as_ref().is_some_and(|cohort|cohort.identity.as_ptr()==Arc::as_ptr(&original.control.cohort)){
                drop(book);original.control.poisoned();return None;}
            if ControlSlot::pending(&book) || original.control.latches.load(Ordering::SeqCst)!=0{return None;}
            if let Some((reason,at))=book.cohort.as_ref().and_then(|cohort|cohort.first){
                if original.control.failure().is_none_or(|(_,first)|at<first){
                    drop(book);original.control.stop_at(reason,at);return None;
                }
            }
            // Publisher.accept releases this SAME book before delivering F.
            // No pending/latch and exact epoch/cohort make this the real final cut.
            original.synchronize();let at=Instant::now();let first=original.control.failure();
            let endpoint=original.control.endpoint();
            if !timely_sample(joined,at,endpoint) || original.control.unknown.load(Ordering::SeqCst){
                drop(book);original.control.mark_unknown(at);return None;}
            let returned_guard=original.returned.try_lock().ok()?;
            let Some(Ok(returned))=returned_guard.as_ref()else{drop(book);original.control.poisoned();return None;};
            if returned.first.is_some_and(|(_,at)|first.is_none_or(|(_,before)|at<before)){
                drop(book);original.control.poisoned();return None;}
            if first.is_none() && (!live || !original.same_owner(&self.inner) || book.epoch!=original.control.epoch
                || book.cohort.as_ref().is_some_and(|cohort|cohort.first.is_some())
                || !registry.android_sources.same_census_originals(&original.pickers)
                || registry.android_sources.census_generation()!=original.source_generation){return None;}
            if !registry.android_registration.service.adopt_finalized_preparation(&original.preparation){
                drop(book);original.control.poisoned();return None;}
            let prepared=first.is_none() && returned.facts.prepared();
            let mut status=original.status();status.phase=if prepared{Phase::Prepared}else{Phase::Refused};
            status.reason=first.map_or(if prepared{wire::Reason::None}else{wire::Reason::ServiceUnavailable},|(reason,_)|reason);
            original.accepted.store(true,Ordering::SeqCst);book.original=None;book.cohort=None;
            registry.android_registration.maintenance.last=Some(status);registry.android_registration.maintenance.active=None;
            drop(returned_guard);drop(book);self.inner.android_registration_control.wake.notify_all();self.inner.bump(&mut registry);
            Some(Completion{status,at,endpoint})
        }
    }
    #[cfg(test)]
    mod tests{
        use super::*;
        #[test]
        fn finality_samples_cannot_regress_or_reach_the_original_endpoint(){
            // Timestamp DATA only: no Completion or native finality is granted.
            let joined=Instant::now();let endpoint=joined+Duration::from_secs(1);
            assert!(timely_sample(joined,joined,endpoint));
            assert!(timely_sample(joined,joined+Duration::from_millis(1),endpoint));
            assert!(!timely_sample(joined+Duration::from_nanos(1),joined,endpoint));
            assert!(!timely_sample(joined,endpoint,endpoint));
            assert!(!timely_sample(joined,endpoint+Duration::from_nanos(1),endpoint));
            assert!(!timely_sample(joined,joined,joined));
        }
        #[test]
        fn prepared_requires_all_original_facts_and_partial_unregister_never_reopens(){
            let yes=service_setup::MaintenanceRun{known:true,checked:true,started_or_uncertain:true,tail_received:true,
                unregister_accepted:true,not_registered:true,callback_retired:true,peer_ended:true,retained:Some(1)};
            assert!(yes.prepared());
            for value in [service_setup::MaintenanceRun{known:false,..yes},service_setup::MaintenanceRun{checked:false,..yes},
                service_setup::MaintenanceRun{started_or_uncertain:false,..yes},
                service_setup::MaintenanceRun{tail_received:false,..yes},service_setup::MaintenanceRun{unregister_accepted:false,..yes},
                service_setup::MaintenanceRun{not_registered:false,..yes},service_setup::MaintenanceRun{callback_retired:false,..yes},
                service_setup::MaintenanceRun{peer_ended:false,..yes},service_setup::MaintenanceRun{retained:None,..yes}]{
                assert!(!value.prepared());
            }
            let at=Instant::now();let status=Status{operation:[1;16],generation:1,phase:Phase::Refused,reason:wire::Reason::ServiceUnavailable,
                started_or_uncertain:true,unregister_accepted:true,not_registered:true};
            let completion=Completion{status,at,endpoint:at+Duration::from_secs(1)};
            assert!(!completion.may_reopen() && !completion.request_quit());
            let closed=Completion{status:Status{phase:Phase::Prepared,..status},at,endpoint:at};
            assert!(!closed.request_quit()); // no fresh interval from a completion projection
        }
    }
}
