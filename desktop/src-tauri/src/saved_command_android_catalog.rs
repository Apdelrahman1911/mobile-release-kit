//! Closed protected-catalog transaction inside SavedCommandOwner. It reads only
//! bounded registration headers; it owns no process, arbitrary runner or tool
//! execution. Its original blocking worker and independent absolute-deadline
//! coordinator are both retained before DocumentBinding releases GO.
use super::*;
use crate::android_toolchain_catalog as wire;
use std::sync::{Weak, TryLockError};

const WORK: Duration = Duration::from_secs(60);
const HARD: Duration = Duration::from_secs(70);
#[derive(Default)]
pub(super) struct Catalog {
    generation: u32,
    capability: Option<Availability>,
    retired: Option<wire::Reason>,
    active: Option<Arc<Operation>>,
    published: Option<Arc<Published>>,
    last: Option<Arc<Operation>>,
    selected: Option<Arc<Selection>>,
}
pub(super) struct Selection {
    produced: Arc<Published>,
    data: android_wire::MacToolchainSelection,
}
struct Published { original: Arc<Operation>, entries: Vec<wire::Entry> }
struct WorkerReturn { entries: Option<Vec<wire::Entry>>, originals_closed: bool, native_bytes: Option<usize> }
struct Operation {
    original: Weak<Inner>, document: Weak<()>, generation: u32, id: String,
    admitted: Instant, work: Instant, hard: Instant,
    stop: watch::Sender<bool>, audit: watch::Sender<Instant>,
    first: Mutex<Option<(wire::Reason,Instant)>>, unknown: AtomicBool, dirty: AtomicBool,
    worker: AsyncMutex<Option<JoinHandle<WorkerReturn>>>,
    worker_return: Mutex<Option<Result<WorkerReturn,tokio::task::JoinError>>>,
    coordinator: Mutex<Option<JoinHandle<bool>>>,
    coordinator_return: Mutex<Option<Result<bool,tokio::task::JoinError>>>,
    final_seen: AtomicBool, accepted_final: AtomicBool, worker_join_seen: AtomicBool,
    #[cfg(all(target_os="macos",target_arch="aarch64"))]
    native: Mutex<crate::installed_runtime::AndroidCatalogSlots>,
}
pub(crate) struct Admitted { status: wire::Status, release: Option<oneshot::Sender<()>>, original: Arc<Operation> }
impl Admitted {
    /// The only effect-release edge. DocumentBinding must drop its original
    /// admission lock before this method; dropping it instead requests STOP.
    pub(crate) fn release(self) -> Result<wire::Status,BridgeError> {
        if self.release.is_some_and(|release|release.send(()).is_err()) {
            // The Registry still retains this exact operation and both original
            // join slots. A lost delivery is not an invocation or cleanup receipt.
            self.original.stop_at(wire::Reason::Cancelled,Instant::now());
            return Err(wire::unavailable());
        }
        Ok(self.status)
    }
}
impl Operation {
    fn original_matches(&self, inner:&Inner) -> bool {
        self.original.upgrade().is_some_and(|original| std::ptr::eq(original.as_ref(),inner))
            && self.document.upgrade().is_some_and(|document| inner.android_original_document_matches(Some(&document)))
    }
    fn stop_at(&self, reason:wire::Reason, at:Instant) {
        let at=at.max(self.admitted).min(self.work);
        let mut changed=false;
        let deadline=match self.first.lock() {
            Ok(mut first) => {
                if first.is_none_or(|(_,before)|at<before) { *first=Some((reason,at));changed=true; }
                first.as_ref().map_or(self.hard,|(_,at)|(*at+SETTLEMENT).min(self.hard))
            },
            Err(_) => { self.unknown.store(true,Ordering::SeqCst);changed=true;self.admitted },
        };
        self.audit.send_if_modified(|current| if deadline<*current { *current=deadline;true } else {false});
        self.stop.send_replace(true);
        if changed {
            self.dirty.store(true,Ordering::SeqCst);
            if let Some(inner)=self.original.upgrade(){inner.changes.send_modify(|_|{});inner.changed.notify_one();}
        }
    }
    fn failure(&self) -> Option<(wire::Reason,Instant)> {
        match self.first.lock() {
            Ok(first)=>*first,
            Err(_)=>{self.unknown.store(true,Ordering::SeqCst);Some((wire::Reason::CleanupUnknown,self.admitted))},
        }
    }
    fn endpoint(&self) -> Instant {
        self.failure().map_or(self.hard,|(_,at)|(at+SETTLEMENT).min(self.hard))
    }
    // Once the aggregate coordinator has returned, late Ready still has to be
    // consumed from the retained original handle. It cannot clear Unknown or
    // publish a catalog; this is observation, never another worker/watchdog.
    fn poll_late_worker(&self) {
        if !self.final_seen.load(Ordering::SeqCst) || self.worker_join_seen.load(Ordering::SeqCst) {return;}
        let Ok(mut slot)=self.worker.try_lock() else{return;};
        let Some(handle)=slot.as_mut() else{return;};
        let waker=Waker::from(Arc::new(FinalWake(self.original.clone())));
        let mut context=TaskContext::from_waker(&waker);
        if let Poll::Ready(result)=Pin::new(handle).poll(&mut context) {
            self.worker_join_seen.store(true,Ordering::SeqCst);
            if !record_join(&self.worker_return,result){self.unknown.store(true,Ordering::SeqCst);}
        }
    }
    fn known_originals(&self) -> bool {
        if self.unknown.load(Ordering::SeqCst) || !self.worker_join_seen.load(Ordering::SeqCst) {return false;}
        let returned=self.worker_return.lock().is_ok_and(|result|matches!(result.as_ref(),
            Some(Ok(WorkerReturn{originals_closed:true,native_bytes:Some(0),..}))));
        #[cfg(all(target_os="macos",target_arch="aarch64"))]
        {returned && self.native.try_lock().is_ok_and(|native|native.settled() && native.retained_bytes()==Some(0))}
        #[cfg(not(all(target_os="macos",target_arch="aarch64")))]
        {let _=returned;false}
    }
}
impl Selection {
    pub(super) fn data(&self) -> &android_wire::MacToolchainSelection { &self.data }
    pub(super) fn matches_owner(&self,inner:&Inner) -> bool {
        let original=&self.produced.original;
        original.accepted_final.load(Ordering::SeqCst) && original.final_seen.load(Ordering::SeqCst)
            && original.original_matches(inner) && original.known_originals()
            && original.failure().is_none() && self.data.valid()
            && original.generation==self.data.catalog_generation
            && self.produced.entries.iter().any(|entry|entry.selection==self.data)
    }
}
impl Catalog {
    pub(super) fn selection(&self) -> Option<&Arc<Selection>> {self.selected.as_ref()}
    pub(super) fn selection_matches(&self,selected:Option<&Arc<Selection>>,inner:&Inner) -> bool {
        match (self.selected.as_ref(),selected) {
            (Some(current),Some(selected))=>Arc::ptr_eq(current,selected) && selected.matches_owner(inner),
            (None,None)=>true,
            _=>false,
        }
    }
    pub(super) fn busy(&self) -> bool {self.active.is_some()}
    pub(super) fn unknown(&self) -> bool {self.active.as_ref().is_some_and(|o|o.unknown.load(Ordering::SeqCst))}
    pub(super) fn stop(&mut self,reason:wire::Reason,at:Instant) -> bool {
        let changed=self.selected.is_some()||self.published.is_some()||self.active.is_some();
        if self.selected.is_some()||self.published.is_some(){self.retired=Some(reason);}
        self.selected=None;
        self.published=None;
        if let Some(active)=&self.active {active.stop_at(reason,at);}
        changed
    }
    pub(super) fn exhaust(&mut self) {
        self.stop(wire::Reason::CleanupUnknown,Instant::now());
        if let Some(active)=&self.active {active.unknown.store(true,Ordering::SeqCst);}
    }
    /// Called with Registry already held. Polls only the retained original
    /// coordinator handle, never filesystem/native work or a replacement task.
    pub(super) fn reconcile(&mut self,inner:&Inner) -> bool {
        let Some(original)=self.active.as_ref().cloned() else {return false;};
        let mut changed=original.dirty.swap(false,Ordering::SeqCst);
        if Instant::now()>=original.endpoint() {
            changed|=!original.unknown.swap(true,Ordering::SeqCst);
            original.stop_at(wire::Reason::TimedOut,original.work);
        }
        if original.final_seen.load(Ordering::SeqCst) {original.poll_late_worker();return changed;}
        let mut slot=match original.coordinator.try_lock() {
            Ok(slot)=>slot,
            Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>return changed|!original.unknown.swap(true,Ordering::SeqCst),
        };
        let Some(handle)=slot.as_mut() else {return changed|!original.unknown.swap(true,Ordering::SeqCst);};
        let waker=Waker::from(Arc::new(FinalWake(original.original.clone())));
        let mut context=TaskContext::from_waker(&waker);
        let Poll::Ready(result)=Pin::new(handle).poll(&mut context) else {return changed;};
        original.final_seen.store(true,Ordering::SeqCst);
        let positive=matches!(&result,Ok(true));
        if !record_join(&original.coordinator_return,result) || !positive || !original.known_originals()
            || Instant::now()>=original.endpoint() {
            original.unknown.store(true,Ordering::SeqCst);original.poll_late_worker();return true;
        }
        original.accepted_final.store(true,Ordering::SeqCst);
        let entries=original.worker_return.lock().ok().and_then(|returned|match returned.as_ref(){
            Some(Ok(returned))=>returned.entries.clone(), _=>None,
        });
        self.published=if original.failure().is_none() && original.original_matches(inner) {
            entries.map(|entries|Arc::new(Published{original:original.clone(),entries}))
        } else {None};
        self.last=Some(original.clone());
        self.active=None;
        true
    }
    fn status(&self,inner:&Inner,revision:u32,availability:Availability) -> Result<wire::Status,BridgeError> {
        let active=self.active.as_ref();
        let operation=active.or(self.last.as_ref());
        let reason=if active.is_none() && self.published.is_none() && self.retired.is_some(){self.retired.unwrap()}else{operation.map_or(wire::Reason::NotInspected,|op| {
            if op.unknown.load(Ordering::SeqCst) {wire::Reason::CleanupUnknown}
            else {op.failure().map_or(wire::Reason::None,|first|first.0)}
        })};
        let phase=if active.is_some(){
            if self.unknown(){wire::Phase::Unknown} else if active.is_some_and(|op|op.failure().is_some()){wire::Phase::Stopping}
            else {wire::Phase::Reading}
        } else if self.published.is_some(){wire::Phase::Ready}
        else if operation.is_some(){
            if matches!(reason,wire::Reason::Cancelled|wire::Reason::DocumentLost|wire::Reason::Shutdown){wire::Phase::Cancelled}
            else {wire::Phase::Refused}
        } else {wire::Phase::Idle};
        let entries=self.published.as_ref().filter(|p|p.original.original_matches(inner))
            .map_or_else(Vec::new,|p|p.entries.clone());
        let selected=self.selected.as_ref().filter(|s|s.matches_owner(inner)).map(|s|s.data.clone());
        let status=wire::Status{schema_version:1,status_revision:revision,catalog_generation:self.generation,
            operation_id:operation.map(|o|o.id.clone()),availability:availability.android(),phase,reason,entries,selected};
        crate::edit_protocol::bounded(&status,wire::STATUS_LIMIT)?;
        Ok(status)
    }
}

#[cfg(all(target_os="macos",target_arch="aarch64"))]
fn worker(original:Arc<Operation>,enter:oneshot::Receiver<()>) -> WorkerReturn {
    let go=enter.blocking_recv().is_ok();
    let mut native=match original.native.lock() {
        Ok(native)=>native,
        Err(error)=>{original.unknown.store(true,Ordering::SeqCst);let mut native=error.into_inner();native.mark_interrupted();native},
    };
    let mut entries=None;
    if go && !*original.stop.borrow() && Instant::now()<original.work && !original.unknown.load(Ordering::SeqCst) {
        // Catch only this original worker's Rust unwind so independent known
        // descriptor closes are still attempted. Panic never becomes success.
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            native.inspect_once(original.generation,original.work,&original.stop.subscribe())));
        match result {
            Ok(Ok(value))=>entries=Some(value),
            Ok(Err(failure))=>{
                let at=native.first_failure().map_or(Instant::now(),|(_,at)|at);
                original.stop_at(if failure==AdmissionFailure::Deadline {wire::Reason::TimedOut}else{wire::Reason::CatalogUnavailable},at);
            },
            Err(_)=>{native.mark_interrupted();original.unknown.store(true,Ordering::SeqCst);
                original.stop_at(wire::Reason::CleanupUnknown,Instant::now());},
        }
    } else if original.failure().is_none() {original.stop_at(wire::Reason::Cancelled,Instant::now());}
    if let Some((_,at))=native.first_failure(){original.stop_at(wire::Reason::CatalogUnavailable,at);}
    let closed=native.settle_originals(original.endpoint(),&mut |failure,at| {
        original.stop_at(if failure==AdmissionFailure::Deadline {wire::Reason::TimedOut}
            else if failure==AdmissionFailure::Unknown {wire::Reason::CleanupUnknown}
            else {wire::Reason::CatalogUnavailable},at);
    })==CloseOutcome::Settled && native.settled();
    if let Some((_,at))=native.first_failure(){original.stop_at(wire::Reason::CatalogUnavailable,at);}
    let native_bytes=native.retained_bytes();
    if !closed || native_bytes!=Some(0) {original.unknown.store(true,Ordering::SeqCst);}
    WorkerReturn{entries,originals_closed:closed,native_bytes}
}
#[cfg(all(target_os="macos",target_arch="aarch64"))]
async fn coordinate(original:Arc<Operation>,enter:oneshot::Receiver<()>,release:oneshot::Sender<()>) -> bool {
    let mut stopped=original.stop.subscribe();
    let mut changed=original.audit.subscribe();
    let ready=tokio::select!{
        value=enter=>value.is_ok(),
        _=stopped.changed()=>false,
        _=tokio::time::sleep_until(tokio::time::Instant::from_std(original.work))=>{
            original.stop_at(wire::Reason::TimedOut,original.work);false
        },
    };
    let current=original.original.upgrade().is_some_and(|inner|{
        let registry=inner.lock();
        !registry.disabled && !registry.exhausted && !registry.stopping && !registry.document_lost && !inner.poisoned.load(Ordering::SeqCst)
            && registry.android_catalog.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,&original))
            && original.original_matches(&inner)
    });
    if ready && current && !*original.stop.borrow() && Instant::now()<original.work {
        if release.send(()).is_err(){original.stop_at(wire::Reason::Cancelled,Instant::now());}
    } else {original.stop_at(wire::Reason::Cancelled,Instant::now());drop(release);}
    // This coordinator is the aggregate watchdog, independent of the blocking
    // native reader. It never holds Registry or the native book while waiting.
    let mut worker=original.worker.lock().await;
    let Some(handle)=worker.as_mut() else {original.unknown.store(true,Ordering::SeqCst);return false;};
    loop {
        let now=Instant::now();
        if now>=original.work && original.failure().is_none(){original.stop_at(wire::Reason::TimedOut,original.work);}
        if now>=original.endpoint(){original.unknown.store(true,Ordering::SeqCst);return false;}
        let deadline=if original.failure().is_some(){original.endpoint()}else{original.work};
        tokio::select!{
            returned=&mut *handle=>{
                original.worker_join_seen.store(true,Ordering::SeqCst);
                let joined=returned.is_ok();
                if !record_join(&original.worker_return,returned)||!joined{original.unknown.store(true,Ordering::SeqCst);return false;}
                return original.known_originals() && Instant::now()<original.endpoint();
            },
            _=changed.changed()=>{},
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))=>{},
        }
    }
}
impl SavedCommandOwner {
    fn catalog_gate(&self,r:&Registry,gate:Availability) -> Availability {
        if r.disabled||r.exhausted||self.inner.poisoned.load(Ordering::SeqCst)||r.android_catalog.unknown()
            ||gate==Availability::CleanupUnknown {return Availability::CleanupUnknown;}
        if r.stopping||gate==Availability::Shutdown{return Availability::Shutdown;}
        if r.document_lost||gate==Availability::DocumentLost{return Availability::DocumentLost;}
        if self.inner.domain!=SavedCommandDomain::AndroidBuild
            || !cfg!(all(target_os="macos",target_arch="aarch64")){return Availability::UnsupportedPlatform;}
        if !self.inner.android_runtime_selected(None){return Availability::RuntimeUnqualified;}
        if r.active.is_some()||r.android_catalog.busy()||r.android_sources.busy()||gate==Availability::Busy{return Availability::Busy;}
        gate
    }
    fn catalog_snapshot(&self,r:&mut Registry,gate:android_wire::Availability) -> Result<wire::Status,BridgeError> {
        let availability=self.catalog_gate(r,Availability::from_android(gate));
        if r.android_catalog.capability!=Some(availability){
            r.android_catalog.capability=Some(availability);self.inner.bump(r);
        }
        if r.exhausted || self.inner.poisoned.load(Ordering::SeqCst){return Err(BridgeError::cleanup_unknown());}
        r.android_catalog.status(&self.inner,r.revision,availability)
    }
    pub(crate) fn android_catalog_status(&self,gate:android_wire::Availability) -> Result<wire::Status,BridgeError> {
        self.reconcile();let mut r=self.inner.lock();self.catalog_snapshot(&mut r,gate)
    }
    pub(crate) fn refresh_android_catalog(&self,document:&Arc<()>,admitted_at:Instant,gate:android_wire::Availability) -> Result<Admitted,BridgeError> {
        self.reconcile();let mut r=self.inner.lock();
        let availability=self.catalog_gate(&r,Availability::from_android(gate));
        if availability!=Availability::Available||!self.inner.android_original_document_matches(Some(document)){
            return Err(if availability==Availability::Busy{self.inner.domain.busy()}else{wire::unavailable()});
        }
        #[cfg(not(all(target_os="macos",target_arch="aarch64")))]
        {let _=admitted_at;Err(wire::unavailable())}
        #[cfg(all(target_os="macos",target_arch="aarch64"))]
        {
            let executor=tokio::runtime::Handle::try_current().map_err(|_|wire::unavailable())?;
            let generation=match r.android_catalog.generation.checked_add(1).filter(|g|*g<u32::MAX) {
                Some(next)=>next,
                None=>{r.disabled=true;r.android_catalog.exhaust();self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            let id=nonce(SavedCommandDomain::AndroidBuild)?;
            if r.android_catalog.last.as_ref().is_some_and(|last|last.id==id){return Err(wire::unavailable());}
            let work=admitted_at.checked_add(WORK).ok_or_else(wire::unavailable)?;
            let hard=admitted_at.checked_add(HARD).ok_or_else(wire::unavailable)?;
            if Instant::now()>=work{return Err(wire::unavailable());}
            self.inner.retire_prepared(&mut r,Reason::ContextChanged);
            r.android_catalog.selected=None;r.android_catalog.published=None;r.android_catalog.retired=None;
            let (stop,_)=watch::channel(false);let (audit,audit_read)=watch::channel(hard);
            let original=Arc::new(Operation{original:Arc::downgrade(&self.inner),document:Arc::downgrade(document),
                generation,id,admitted:admitted_at,work,hard,stop,audit,first:Mutex::new(None),unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),
                worker:AsyncMutex::new(None),worker_return:Mutex::new(None),coordinator:Mutex::new(None),coordinator_return:Mutex::new(None),
                final_seen:AtomicBool::new(false),accepted_final:AtomicBool::new(false),worker_join_seen:AtomicBool::new(false),
                native:Mutex::new(crate::installed_runtime::AndroidCatalogSlots::new(audit_read))});
            let (release,enter)=oneshot::channel();let (native_release,native_enter)=oneshot::channel();
            // Publish the prearmed original before any fallible roster access
            // or task creation. A missing/cancelled/panicked worker never leaves
            // its native frame detached or becomes a successful transaction.
            r.android_catalog.generation=generation;
            r.android_catalog.active=Some(original.clone());
            let mut worker_slot=match original.worker.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.unknown.store(true,Ordering::SeqCst);r.disabled=true;self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            let mut coordinator_slot=match original.coordinator.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.unknown.store(true,Ordering::SeqCst);r.disabled=true;self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            *worker_slot=Some(executor.spawn_blocking({let original=original.clone();move||worker(original,native_enter)}));
            *coordinator_slot=Some(executor.spawn(coordinate(original.clone(),enter,native_release)));
            drop(coordinator_slot);drop(worker_slot);
            self.inner.bump(&mut r);
            let status=self.catalog_snapshot(&mut r,gate)?;
            drop(r);
            self.reconcile(); // Arm the actual coordinator completion waker before GO.
            Ok(Admitted{status,release:Some(release),original})
        }
    }
    pub(crate) fn select_android_catalog(&self,input:wire::Select,gate:android_wire::Availability) -> Result<wire::Status,BridgeError> {
        self.reconcile();let mut r=self.inner.lock();
        if self.catalog_gate(&r,Availability::from_android(gate))!=Availability::Available{return Err(wire::unavailable());}
        let produced=r.android_catalog.published.as_ref().cloned().ok_or_else(wire::invalid)?;
        if !produced.original.accepted_final.load(Ordering::SeqCst)||!produced.original.original_matches(&self.inner)
            ||!produced.original.known_originals(){return Err(wire::invalid());}
        let data=produced.entries.iter().find(|entry|input.matches(entry)).map(|entry|entry.selection.clone()).ok_or_else(wire::invalid)?;
        self.inner.retire_prepared(&mut r,Reason::ContextChanged);
        r.android_catalog.selected=Some(Arc::new(Selection{produced,data}));
        self.inner.bump(&mut r);
        self.catalog_snapshot(&mut r,gate)
    }
    pub(crate) fn cancel_android_catalog(&self,input:wire::Cancel,gate:android_wire::Availability) -> Result<wire::Status,BridgeError> {
        let mut r=self.inner.lock();
        let original=r.android_catalog.active.as_ref().or(r.android_catalog.last.as_ref()).filter(|op|
            op.generation==input.catalog_generation&&op.id==input.operation_id).cloned().ok_or_else(wire::invalid)?;
        if r.android_catalog.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,&original)){
            original.stop_at(wire::Reason::Cancelled,Instant::now());self.inner.bump(&mut r);
        }
        drop(r);self.android_catalog_status(gate)
    }
}

#[cfg(all(test,not(all(target_os="macos",target_arch="aarch64"))))]
mod tests {
    use super::*;
    #[test]
    fn catalog_unknown_and_earlier_failure_retain_the_original_slot_without_a_build_session() {
        // Inert original-control DATA only. This unsupported-target test opens
        // no native frame/file, creates no worker and never fakes native finality.
        let app=SavedCommandOwner::new(RuntimeConfig::packaged(std::path::PathBuf::from("/unopened-catalog-model")),SavedCommandDomain::AndroidBuild);
        let document=Arc::new(());app.bind_original_android_document(&document);
        let admitted=Instant::now();let work=admitted+WORK;let hard=admitted+HARD;
        let (stop,_)=watch::channel(false);let (audit,cutoff)=watch::channel(hard);
        let original=Arc::new(Operation{original:Arc::downgrade(&app.inner),document:Arc::downgrade(&document),
            generation:1,id:"a".repeat(32),admitted,work,hard,stop,audit,
            first:Mutex::new(None),unknown:AtomicBool::new(true),dirty:AtomicBool::new(false),
            worker:AsyncMutex::new(None),worker_return:Mutex::new(None),coordinator:Mutex::new(None),
            coordinator_return:Mutex::new(None),final_seen:AtomicBool::new(false),accepted_final:AtomicBool::new(false),worker_join_seen:AtomicBool::new(false)});
        original.stop_at(wire::Reason::TimedOut,work);
        original.stop_at(wire::Reason::CatalogUnavailable,admitted+Duration::from_secs(1));
        assert_eq!(*cutoff.borrow(),admitted+Duration::from_secs(1)+SETTLEMENT);
        original.stop_at(wire::Reason::Cancelled,admitted+Duration::from_secs(5));
        assert_eq!(*cutoff.borrow(),admitted+Duration::from_secs(1)+SETTLEMENT);
        {
            let mut registry=app.inner.lock();registry.android_catalog.generation=1;
            registry.android_catalog.active=Some(original.clone());
            assert!(registry.active.is_none() && !original.known_originals());
        }
        assert!(app.busy() && app.disabled() && !app.can_exit());
        app.context_changed();
        let registry=app.inner.lock();
        assert!(registry.active.is_none() && registry.android_catalog.unknown());
        assert!(Arc::ptr_eq(registry.android_catalog.active.as_ref().unwrap(),&original));
        assert!(registry.android_catalog.selected.is_none());
        assert!(registry.android_catalog.published.is_none());
    }
}
