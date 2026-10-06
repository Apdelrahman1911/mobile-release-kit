//! Original picked-source inspection/registration companion of SavedCommandOwner.
//! Inspection and protected-copy registration retain separate original workers,
//! source books, native client custody and independently joined coordinators.
//! No bool, renderer id, source EOF or worker return creates a join/consent grant.
use super::*;
use crate::android_registration_app_protocol as wire;
use std::sync::{Weak, TryLockError};
use android_sources::SourceSnapshot;
#[path = "saved_command_android_service_setup.rs"]
pub(super) mod service_setup;
#[path = "saved_command_android_maintenance.rs"]
pub(super) mod maintenance;
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
#[path = "saved_command_android_registration_client.rs"]
mod client;
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
use crate::installed_runtime::{AndroidRegistrationSourceSlots, AndroidRegistrationSourceReview, AdmissionFailure, CloseOutcome};
const WORK:Duration=Duration::from_secs(wire::WORK_SECONDS);
const HARD:Duration=Duration::from_secs(wire::FINALITY_SECONDS);
const REVIEW:Duration=Duration::from_secs(wire::REVIEW_SECONDS);
const OWNED_LIMIT:usize=64*1024*1024;
// Same bounded control-only class as the Document census. This accounts for
// this owner's watches/oneshots and wake cells; it is NOT a native SDK bound,
// allocator/RSS estimate, payload allowance or source/service custody receipt.
const SIGNAL_STORAGE:usize=4*1024;

/// The SAME Saved Inner control book survives an empty active mirror. Every
/// publisher reserves here before reading F and before Document/Registry locks.
pub(crate) struct ControlSlot {
    book: Mutex<ControlBook>, wake: std::sync::Condvar, unknown: AtomicBool,
    // Test observation only; no control/callback/authority can be injected.
    #[cfg(test)] wait_entries: AtomicUsize,
    #[cfg(test)] wait_observed: std::sync::Condvar,
}
#[derive(Default)]
struct ControlBook {
    original: Option<Arc<Control>>, epoch: u64, next: u64,
    pending: [Option<PendingPublisher>; 10],
    cohort: Option<CohortRecord>, admission: Option<CohortRecord>, review: Option<ReviewRoute>, cancel: Option<PendingCancel>,
}
#[derive(Clone, Copy)]
struct PendingPublisher { serial: u64, accepted: bool }
struct CohortRecord { identity: Weak<()>, epoch: u64, first: Option<(wire::Reason, Instant)> }
struct ReviewRoute {
    original: Weak<Operation>, reviewed: Weak<Review>, operation_id: String,
    review_id: String, generation: u32, epoch: u64,
}
struct PendingCancel { serial: u64, original: Weak<Control>, reviewed: Option<Weak<Review>> }
#[derive(Clone, Copy)]
pub(crate) enum PublisherKind { General, CredentialLock, Quit }
/// Move-only. Drop is lost projection/Unknown, never conditional rejection or
/// an accepted event receipt. Call reject/finish only after original adjudication.
pub(crate) struct Publisher {
    slot: Arc<ControlSlot>, index: usize, serial: u64, at: Instant,
    accepted: bool, finished: bool,
}
/// Dedicated exact-original cancellation lane. A stale wire ID cannot reserve
/// it, and dropping a reserved projection is Unknown rather than cancellation
/// completion. It is independent of the ten lifecycle publisher records.
pub(crate) struct CancelPublisher {
    slot: Arc<ControlSlot>, serial: u64, original: Arc<Control>,
    reviewed: Option<Weak<Review>>, at: Instant, finished: bool,
}
impl Default for ControlSlot {
    fn default() -> Self { Self { book: Mutex::new(ControlBook::default()),
        wake: std::sync::Condvar::new(), unknown: AtomicBool::new(false),
        #[cfg(test)] wait_entries: AtomicUsize::new(0),
        #[cfg(test)] wait_observed: std::sync::Condvar::new(),
    } }
}
impl ControlSlot {
    pub(crate) fn poisoned(&self) {
        self.unknown.store(true, Ordering::SeqCst);
        let book = self.book.lock().unwrap_or_else(|error| error.into_inner());
        let original = book.original.clone().or_else(|| book.review.as_ref()
            .and_then(|route|route.original.upgrade()).map(|original|original.control.clone()));
        drop(book);
        self.wake.notify_all();
        if let Some(original) = original { original.poisoned(); }
    }
    pub(crate) fn is_unknown(&self) -> bool { self.unknown.load(Ordering::SeqCst) || self.book.is_poisoned() }
    fn pending(book: &ControlBook) -> bool { book.pending.iter().any(Option::is_some) || book.cancel.is_some() }
    pub(crate) fn epoch(&self) -> Result<u64, BridgeError> {
        let book = self.book.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if self.is_unknown() { return Err(BridgeError::cleanup_unknown()); }
        if Self::pending(&book) { return Err(BridgeError::new("busy", "Wait for the original lifecycle projection.")); }
        Ok(book.epoch)
    }
    pub(crate) fn matches_epoch(&self, epoch: u64) -> bool { self.epoch().is_ok_and(|current| current == epoch) }
    pub(crate) fn can_exit(&self) -> bool {
        self.book.try_lock().is_ok_and(|book| !self.is_unknown() && !Self::pending(&book)
            && book.admission.is_none() && book.cohort.is_none() && book.original.is_none())
    }
    /// Pure lifecycle projections are not resource work. Nested original
    /// Document reconciliation/ensure_idle must not reject its own ticket.
    /// Admission itself remains work and every registration entry/finality
    /// gate separately demands no pending publishers (including foreign ones).
    pub(super) fn owns_work(&self) -> bool {
        !self.book.try_lock().is_ok_and(|book| !self.is_unknown() && book.admission.is_none()
            && book.cohort.is_none() && book.original.is_none())
    }
    pub(crate) fn reserve(self: &Arc<Self>, kind: PublisherKind, mandatory: bool) -> Result<Publisher, BridgeError> {
        let mut book = match self.book.lock() {
            Ok(book) => book,
            Err(error) => { drop(error.into_inner()); self.poisoned(); return Err(BridgeError::cleanup_unknown()); },
        };
        if self.is_unknown() { return Err(BridgeError::cleanup_unknown()); }
        let index = match kind {
            PublisherKind::General => (0..8).find(|index| book.pending[*index].is_none()),
            PublisherKind::CredentialLock => book.pending[8].is_none().then_some(8),
            PublisherKind::Quit => book.pending[9].is_none().then_some(9),
        };
        let Some(index) = index else {
            drop(book);
            if mandatory { self.poisoned(); return Err(BridgeError::cleanup_unknown()); }
            return Err(BridgeError::new("busy", "The bounded lifecycle publisher slots are occupied."));
        };
        let Some(serial) = book.next.checked_add(1) else {
            drop(book); self.poisoned(); return Err(BridgeError::cleanup_unknown());
        };
        book.next = serial; book.pending[index] = Some(PendingPublisher { serial, accepted: false });
        drop(book);
        // Deliberately AFTER reservation and BEFORE any original application lock.
        let at = Instant::now();
        self.wake.notify_all();
        Ok(Publisher { slot: self.clone(), index, serial, at, accepted: false, finished: false })
    }
    fn counted(original: &Arc<Control>) -> Option<ControlLatch> {
        original.latches.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1)).ok()?;
        Some(ControlLatch { control: original.clone() })
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let book = self.book.try_lock().ok()?;
        if self.is_unknown() || Self::pending(&book) { return None; }
        Self::allocation_bytes(book.review.as_ref().map(|route| (&route.operation_id, &route.review_id)))
    }
    // Allocation arithmetic only. Eligibility and the original route lock stay
    // in retained_bytes; inert DATA cannot create a ReviewRoute or admission.
    fn allocation_bytes(review: Option<(&String, &String)>) -> Option<usize> {
        let mut bytes = arc_bytes::<Self>()?.checked_add(SIGNAL_STORAGE)?;
        if let Some((operation_id, review_id)) = review {
            bytes = bytes.checked_add(operation_id.capacity())?.checked_add(review_id.capacity())?;
        }
        Some(bytes)
    }
}
impl ReviewRoute {
    fn matches(&self,review:&Arc<Review>)->bool {
        self.reviewed.as_ptr()==Arc::as_ptr(review) && self.original.as_ptr()==Arc::as_ptr(&review.original)
            && self.operation_id==review.original.data.operation_id && self.review_id==review.public.review_id
            && self.generation==review.original.data.registration_generation && self.epoch==review.original.control.epoch
    }
}
impl ControlSlot {
    pub(crate) fn reserve_cancel(self:&Arc<Self>,input:&wire::Cancel)->Result<Option<CancelPublisher>,BridgeError> {
        self.reserve_cancel_lane(&input.operation_id,input.registration_generation,ControlLane::Sources)
    }
    pub(crate) fn reserve_service_cancel(self:&Arc<Self>,input:&wire::ServiceCancel)->Result<Option<CancelPublisher>,BridgeError> {
        self.reserve_cancel_lane(&input.operation_id,input.setup_generation,ControlLane::Service)
    }
    fn reserve_cancel_lane(self:&Arc<Self>,id:&str,generation:u32,lane:ControlLane)->Result<Option<CancelPublisher>,BridgeError> {
        let mut book=match self.book.lock(){Ok(book)=>book,
            Err(error)=>{drop(error.into_inner());self.poisoned();return Err(BridgeError::cleanup_unknown());}};
        let target=if let Some(original)=book.original.as_ref().filter(|original|original.id==id && original.generation==generation && original.lane==lane) {
            Some((original.clone(),None))
        } else if let Some(route)=book.review.as_ref().filter(|route|
            lane==ControlLane::Sources && route.operation_id==id && route.generation==generation) {
            let Some(original)=route.original.upgrade() else {drop(book);self.poisoned();return Err(wire::unconfirmed());};
            Some((original.control.clone(),Some(route.reviewed.clone())))
        } else { None };
        // Transfer already consumed the old inspection route: this Cancel is
        // inert, even if a different original currently occupies the mirror.
        let Some((original,reviewed))=target else{return Ok(None);};
        if book.cancel.is_some(){return Err(BridgeError::new("busy","The original cancellation is being projected."));}
        let Some(serial)=book.next.checked_add(1) else {drop(book);self.poisoned();return Err(wire::unconfirmed());};
        book.next=serial;
        book.cancel=Some(PendingCancel{serial,original:Arc::downgrade(&original),reviewed:reviewed.clone()});
        drop(book);
        let at=Instant::now(); // AFTER dedicated reservation, BEFORE Document.
        original.stop_at(wire::Reason::Cancelled,at);
        self.wake.notify_all();
        Ok(Some(CancelPublisher{slot:self.clone(),serial,original,reviewed,at,finished:false}))
    }
}
impl CancelPublisher {
    pub(crate) fn at(&self)->Instant{self.at}
    fn matches(&self,original:&Arc<Operation>)->bool{Arc::ptr_eq(&self.original,&original.control)}
    pub(crate) fn finish(mut self) {
        let mut book=match self.slot.book.lock(){Ok(book)=>book,
            Err(error)=>{drop(error.into_inner());self.slot.poisoned();return;}};
        let exact=book.cancel.as_ref().is_some_and(|pending|pending.serial==self.serial
            && pending.original.as_ptr()==Arc::as_ptr(&self.original)
            && match (&pending.reviewed,&self.reviewed){(None,None)=>true,
                (Some(a),Some(b))=>Weak::ptr_eq(a,b),_=>false});
        if !exact{drop(book);self.slot.poisoned();return;}
        book.cancel=None;self.finished=true;drop(book);self.slot.wake.notify_all();
    }
}
impl Drop for CancelPublisher {
    fn drop(&mut self){if !self.finished{self.slot.poisoned();}}
}
impl Publisher {
    pub(crate) fn at(&self) -> Instant { self.at }
    pub(crate) fn accepted(&self) -> bool { self.accepted && !self.finished }
    pub(crate) fn same_slot(&self, slot: &Arc<ControlSlot>) -> bool { Arc::ptr_eq(&self.slot, slot) }
    pub(crate) fn accept(&mut self, reason: wire::Reason) -> Result<(), BridgeError> {
        if self.accepted || self.finished { self.slot.poisoned(); return Err(BridgeError::cleanup_unknown()); }
        let mut book = self.slot.book.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !book.pending[self.index].is_some_and(|pending| pending.serial == self.serial && !pending.accepted) {
            drop(book); self.slot.poisoned(); return Err(BridgeError::cleanup_unknown());
        }
        let Some(epoch) = book.epoch.checked_add(1) else {
            drop(book); self.slot.poisoned(); return Err(BridgeError::cleanup_unknown());
        };
        book.epoch = epoch;
        book.pending[self.index].as_mut().unwrap().accepted = true;
        if let Some(cohort) = &mut book.cohort {
            if cohort.first.is_none_or(|(_, prior)| self.at < prior) { cohort.first = Some((reason, self.at)); }
        }
        if let Some(admission) = &mut book.admission {
            if admission.first.is_none_or(|(_, prior)| self.at < prior) { admission.first = Some((reason, self.at)); }
        }
        let selected = book.original.clone().or_else(|| book.review.as_ref()
            .and_then(|route| route.original.upgrade()).map(|original| original.control.clone()));
        let original = match selected.as_ref() {
            Some(original) => match ControlSlot::counted(original) {
                Some(original) => Some(original),
                None => { drop(book); self.slot.poisoned(); return Err(BridgeError::cleanup_unknown()); },
            },
            None => None,
        };
        self.accepted = true;
        drop(book);
        // No Document/Registry/native book is needed to STOP the armed original.
        if let Some(original) = original { original.control.stop_at(reason, self.at); }
        self.slot.wake.notify_all();
        Ok(())
    }
    fn resolve(&mut self, accepted: bool) {
        let mut book = match self.slot.book.lock() {
            Ok(book) => book,
            Err(error) => { drop(error.into_inner()); self.slot.poisoned(); return; },
        };
        if self.accepted != accepted || !book.pending[self.index].is_some_and(|pending|
            pending.serial == self.serial && pending.accepted == accepted) {
            drop(book); self.slot.poisoned(); return;
        }
        book.pending[self.index] = None; self.finished = true;
        drop(book); self.slot.wake.notify_all();
    }
    pub(crate) fn reject(mut self) { self.resolve(false); }
    pub(crate) fn finish(mut self) { self.resolve(true); }
}
impl Drop for Publisher {
    fn drop(&mut self) { if !self.finished { self.slot.poisoned(); } }
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum ControlLane { Sources, Service, Maintenance }
pub(super) struct Control {
    lane:ControlLane,
    owner:Weak<Inner>,id:String,generation:u32,admitted:Instant,work:Instant,hard:Instant,
    slot:Weak<ControlSlot>,cohort:Arc<()>,epoch:u64,
    first:Mutex<Option<(wire::Reason,Instant)>>,unknown:AtomicBool,dirty:AtomicBool,
    latches:std::sync::atomic::AtomicUsize,
    stop:watch::Sender<bool>,audit:watch::Sender<Instant>,
}
/// Short control-only resolution borrow, never resource/native custody. Counted
/// under the mirror lock before clone leaves it. The SAME final owner cannot
/// retire that mirror while an already resolved event still owes its F latch.
struct ControlLatch { control:Arc<Control> }
impl Drop for ControlLatch {
    fn drop(&mut self){
        if self.control.latches.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|count|count.checked_sub(1)).is_err(){
            self.control.poisoned();
        }else{self.control.changed();}
    }
}
impl Control {
    fn changed(&self){
        self.dirty.store(true,Ordering::SeqCst);
        if let Some(owner)=self.owner.upgrade(){owner.changes.send_modify(|_|{});owner.changed.notify_one();}
    }
    fn poisoned(&self){
        // A lost first-F cell cannot invent a later cutoff. Keep the same
        // original, expose Unknown and intersect with the conservative T.
        let newly_unknown=!self.unknown.swap(true,Ordering::SeqCst);
        let stopped=self.stop.send_if_modified(|stop|if !*stop{*stop=true;true}else{false});
        let shortened=self.audit.send_if_modified(|end|if self.admitted<*end{*end=self.admitted;true}else{false});
        if newly_unknown||stopped||shortened{self.changed();}
    }
    fn mark_unknown(&self,at:Instant){self.stop_at(wire::Reason::CleanupUnknown,at);}
    fn failure(&self)->Option<(wire::Reason,Instant)>{
        match self.first.lock(){Ok(first)=>*first,Err(_)=>{self.poisoned();Some((wire::Reason::CleanupUnknown,self.admitted))}}
    }
    fn endpoint(&self)->Instant{
        let end=self.failure().and_then(|(_,first)|first.checked_add(SETTLEMENT)).map_or(self.hard,|end|end.min(self.hard));
        end.min(*self.audit.borrow())
    }
    /// Same original audit only. Normal resident retirement is NOT failure.
    fn narrow_maintenance(&self,end:Instant)->bool{
        if self.lane!=ControlLane::Maintenance || end<=self.admitted || end>self.hard{
            self.poisoned();return false;
        }
        let shortened=self.audit.send_if_modified(|old|if end<*old{*old=end;true}else{false});
        if shortened{self.changed();}
        Instant::now()<self.endpoint() && !self.unknown.load(Ordering::SeqCst)
    }
    fn stop_at(&self,reason:wire::Reason,at:Instant){
        // The supplied captured F is never resampled or rounded forward to T.
        // A request arriving after W cannot hide the earlier work deadline.
        let unknown=reason==wire::Reason::CleanupUnknown;
        let (reason,at)=if at>self.work{(wire::Reason::TimedOut,self.work)}else{(reason,at)};
        let newly_unknown=unknown && !self.unknown.swap(true,Ordering::SeqCst);
        let earlier=match self.first.lock(){
            Ok(mut first)=>if first.is_none_or(|(_,before)|at<before){*first=Some((reason,at));true}else{false},
            Err(_)=>{self.poisoned();return;},
        };
        let end=self.endpoint();
        let shortened=self.audit.send_if_modified(|current|if end<*current{*current=end;true}else{false});
        let stopped=self.stop.send_if_modified(|stop|if !*stop{*stop=true;true}else{false});
        if earlier||newly_unknown||shortened||stopped{self.changed();}
    }
    fn advance(&self,now:Instant){
        if now>=self.work && self.failure().is_none(){self.stop_at(wire::Reason::TimedOut,self.work);}
        if now>=self.endpoint(){self.mark_unknown(now);}
    }
    fn matches(&self,input:&wire::Cancel)->bool{self.id==input.operation_id&&self.generation==input.registration_generation}
    fn retained_bytes(&self)->Option<usize>{
        let _first=self.first.try_lock().ok()?;
        if self.unknown.load(Ordering::SeqCst) || self.latches.load(Ordering::SeqCst)!=0{return None;}
        arc_bytes::<Self>()?.checked_add(self.id.capacity())?.checked_add(SIGNAL_STORAGE)
    }
}
impl ControlSlot {
    fn install(&self,original:Arc<Control>,claim:&AdmissionCohort,reviewed:Option<&Arc<Review>>)->bool{
        let Ok(mut book)=self.book.try_lock()else{return false;};
        if self.is_unknown() || Self::pending(&book) || book.original.is_some() || book.epoch != claim.epoch
            || book.cohort.is_some() || original.epoch != claim.epoch || !Arc::ptr_eq(&original.cohort,&claim.identity)
            || !book.admission.as_ref().is_some_and(|a|a.identity.as_ptr()==Arc::as_ptr(&claim.identity) && a.first.is_none()) {return false;}
        // Consume ONLY the exact finalized Review. Cancel reserved first makes
        // pending true; transfer first removes this route, so an old inspection
        // operationId is inert even while the new Control is not yet published.
        if !match (reviewed,book.review.as_ref()) {
            (None,None)=>true,
            (Some(review),Some(route))=>route.matches(review) && route.epoch==claim.epoch
                && Instant::now()<review.expires && review.original.control.failure().is_none(),
            _=>false,
        } { return false; }
        book.review=None; book.cohort=book.admission.take();
        claim.entered.store(true,Ordering::SeqCst); book.original=Some(original);true
    }
    fn clear_review(&self,review:&Arc<Review>) {
        let mut book=match self.book.lock(){Ok(book)=>book,
            Err(error)=>{drop(error.into_inner());self.poisoned();return;}};
        if !book.review.as_ref().is_some_and(|route|route.matches(review)) {
            drop(book);self.poisoned();return;
        }
        book.review=None;drop(book);self.wake.notify_all();
    }
    pub(super) fn empty(&self)->bool{self.book.try_lock().is_ok_and(|book|!self.is_unknown()
        && book.original.is_none() && book.cohort.is_none() && book.admission.is_none() && book.review.is_none() && !Self::pending(&book))}
}

/// One move-only admission original: Snapshot -> Checked -> Operation. The
/// short book holds identity/first-F DATA even before an active mirror exists.
struct AdmissionCohort { slot: Arc<ControlSlot>, identity: Arc<()>, epoch: u64, entered: AtomicBool }
impl Drop for AdmissionCohort {
    fn drop(&mut self) {
        if self.entered.load(Ordering::SeqCst) { return; } // retirement is explicit, never Drop proof
        let mut book = match self.slot.book.lock() { Ok(book)=>book,
            Err(error)=>{drop(error.into_inner());self.slot.poisoned();return;} };
        if book.admission.as_ref().is_some_and(|a| a.identity.as_ptr() == Arc::as_ptr(&self.identity)) {
            book.admission = None;
        }
        drop(book); self.slot.wake.notify_all();
    }
}
#[derive(Clone)]
pub(crate) struct WorkGate { slot: Arc<ControlSlot>, control: Arc<Control> }
impl WorkGate {
    /// Same-original nonblocking cut for independently runnable coordinators.
    /// Pending is a reversible wait, not failure; accepted cohort F is imported
    /// even before its publisher reaches Control/watch projection.
    fn try_work(&self) -> Option<bool> {
        self.control.advance(Instant::now());
        if self.slot.is_unknown() || self.control.unknown.load(Ordering::SeqCst) {
            self.control.poisoned(); return None;
        }
        let book = match self.slot.book.try_lock() {
            Ok(book) => book, Err(TryLockError::WouldBlock) => return Some(false),
            Err(TryLockError::Poisoned(_)) => { self.control.poisoned(); return None; }
        };
        let cohort = book.cohort.as_ref().filter(|value|
            value.identity.as_ptr() == Arc::as_ptr(&self.control.cohort));
        if let Some((reason, at)) = cohort.and_then(|value| value.first) {
            drop(book); self.control.stop_at(reason, at); return None;
        }
        if self.slot.is_unknown() || !cohort.is_some_and(|value| value.epoch == self.control.epoch)
            || book.epoch != self.control.epoch
            || !book.original.as_ref().is_some_and(|value| Arc::ptr_eq(value, &self.control)) {
            drop(book); self.control.poisoned(); return None;
        }
        let failure = match self.control.first.try_lock() {
            Ok(first) => *first, Err(TryLockError::WouldBlock) => return Some(false),
            Err(TryLockError::Poisoned(_)) => { drop(book); self.control.poisoned(); return None; }
        };
        if failure.is_some() { return None; }
        let ready = !ControlSlot::pending(&book) && !self.control.unknown.load(Ordering::SeqCst);
        let at = Instant::now();
        drop(book);
        if at >= self.control.work || self.control.lane==ControlLane::Maintenance && at>=self.control.endpoint() {
            self.control.advance(at); None
        } else { Some(ready) }
    }
    /// The caller retains the SAME short book at its Proceed admission cut.
    /// Exact Cancel can have completed its whole projection while WORK waited
    /// for that book: pending is now clear but actual Control.first still stops
    /// this original. Snapshot only; poison/watch delivery belongs after unlock.
    fn admission_failure(&self, _book: &ControlBook) -> Result<Option<(wire::Reason, Instant)>, ()> {
        match self.control.first.lock() {
            Ok(first) => Ok(*first),
            Err(error) => { drop(error.into_inner()); Err(()) },
        }
    }
    /// Import accepted F from the durable SAME cohort before observing the
    /// projected Control. Publisher.accept/poisoned intentionally unlock before
    /// STOP/watch delivery; cleanup cannot use stale H in that projection gap.
    /// Pending without acceptance is neither a failure nor a cleanup WAIT.
    fn import_retained(&self, require_cohort: bool) {
        let (first, unknown) = match self.slot.book.lock() {
            Ok(book) => {
                let cohort = book.cohort.as_ref().filter(|cohort|
                    cohort.identity.as_ptr() == Arc::as_ptr(&self.control.cohort));
                (cohort.and_then(|cohort| cohort.first), self.slot.is_unknown()
                    || (require_cohort || book.cohort.is_some()) && cohort.is_none())
            },
            Err(error) => { drop(error.into_inner()); (None, true) },
        };
        // The short book is gone before any watch/owner notification.
        if let Some((reason, at)) = first { self.control.stop_at(reason, at); }
        if unknown { self.control.poisoned(); }
    }
    /// Source WORK can really WAIT. No watch::Ref, Doc/Registry/native lock is
    /// acquired here. The SAME worker-only source custody guard may stay held.
    pub(crate) fn work(&self) -> Result<(), (wire::Reason, Instant)> {
        loop {
            let now = Instant::now(); self.control.advance(now);
            if let Some(first) = self.control.failure() { return Err(first); }
            if self.control.unknown.load(Ordering::SeqCst) || self.slot.is_unknown() {
                self.control.poisoned(); return Err((wire::Reason::CleanupUnknown, self.control.admitted));
            }
            let mut book = match self.slot.book.lock() {
                Ok(book) => book,
                Err(error) => { drop(error.into_inner()); self.control.poisoned(); return Err((wire::Reason::CleanupUnknown, self.control.admitted)); },
            };
            if self.slot.is_unknown() || self.control.unknown.load(Ordering::SeqCst) {
                drop(book); self.control.poisoned();
                return Err((wire::Reason::CleanupUnknown, self.control.admitted));
            }
            let cohort = book.cohort.as_ref().filter(|c| c.identity.as_ptr() == Arc::as_ptr(&self.control.cohort));
            let first = cohort.and_then(|c| c.first);
            let current = cohort.is_some_and(|c| c.epoch == self.control.epoch) && book.epoch == self.control.epoch;
            if let Some((reason, at)) = first {
                drop(book); self.control.stop_at(reason, at); continue;
            }
            if !current {
                // An accepted epoch change always carries its original F in
                // this cohort. Missing identity/F is Unknown, not a late new F.
                drop(book); self.slot.poisoned(); continue;
            }
            if !ControlSlot::pending(&book) {
                match self.admission_failure(&book) {
                    Ok(Some(first)) => { drop(book); return Err(first); },
                    Err(()) => { drop(book); self.control.poisoned();
                        return Err((wire::Reason::CleanupUnknown, self.control.admitted)); },
                    Ok(None) => {},
                }
                if self.slot.is_unknown() || self.control.unknown.load(Ordering::SeqCst) {
                    drop(book); self.control.poisoned();
                    return Err((wire::Reason::CleanupUnknown, self.control.admitted));
                }
                // Lock contention is part of the original W, not free time.
                let entered_at = Instant::now();
                if entered_at >= self.control.work
                    || self.control.lane==ControlLane::Maintenance && entered_at>=self.control.endpoint() {
                    drop(book); self.control.advance(entered_at); continue;
                }
                return Ok(());
            }
            let end=if self.control.lane==ControlLane::Maintenance {
                self.control.work.min(self.control.endpoint())
            }else{self.control.work};
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() { drop(book); continue; }
            #[cfg(test)] {
                self.slot.wait_entries.fetch_add(1, Ordering::SeqCst);
                self.slot.wait_observed.notify_all();
            }
            book = match self.slot.wake.wait_timeout(book, remaining) {
                Ok((book, _)) => book,
                Err(error) => { drop(error.into_inner()); self.control.poisoned(); return Err((wire::Reason::CleanupUnknown, self.control.admitted)); },
            };
            drop(book);
        }
    }
    pub(crate) fn first(&self) -> Option<(wire::Reason, Instant)> { self.import_retained(false); self.control.failure() }
    pub(crate) fn note(&self, reason: wire::Reason, at: Instant) { self.control.stop_at(reason, at); self.slot.wake.notify_all(); }
    /// CLEANUP never WAITs and never skips a release merely because STOP/pending.
    /// A last WORK return after W is still failure at original W, even when the
    /// native next checkpoint has already switched to Cleanup.
    pub(crate) fn cleanup_expired(&self, first: Option<(wire::Reason, Instant)>) -> bool {
        self.import_retained(true);
        if let Some((reason, at)) = first { self.note(reason, at); }
        let now = Instant::now(); self.control.advance(now);
        now >= self.control.endpoint()
    }
    pub(crate) fn publishable(&self) -> bool {
        let now=Instant::now(); self.control.advance(now);
        self.control.failure().is_none() && !self.control.unknown.load(Ordering::SeqCst)
            && now < self.control.work && self.slot.matches_epoch(self.control.epoch)
    }
    pub(crate) fn retained_bytes(&self) -> usize { std::mem::size_of::<Self>() }
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn source_work(&self)->Result<(),AdmissionFailure>{self.work().map_err(|(reason,_)|match reason{
        wire::Reason::TimedOut=>AdmissionFailure::Deadline,wire::Reason::CleanupUnknown=>AdmissionFailure::Unknown,
        wire::Reason::InputLimit|wire::Reason::ResultLimit=>AdmissionFailure::Bounds,_=>AdmissionFailure::Stopped,
    })}
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn source_first(&self)->Option<(AdmissionFailure,Instant)>{self.first().map(|(reason,at)|(match reason{
        wire::Reason::TimedOut=>AdmissionFailure::Deadline,wire::Reason::CleanupUnknown=>AdmissionFailure::Unknown,
        wire::Reason::InputLimit|wire::Reason::ResultLimit=>AdmissionFailure::Bounds,_=>AdmissionFailure::Stopped,
    },at))}
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn source_note(&self,failure:AdmissionFailure,at:Instant){
        source_failure(&self.control,failure,at);self.slot.wake.notify_all();
    }
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(crate) fn source_cleanup_expired(&self,first:Option<(AdmissionFailure,Instant)>)->bool{
        if let Some((failure,at))=first{self.source_note(failure,at);}
        self.cleanup_expired(None)
    }
}
impl ControlSlot {
    pub(crate) fn idle_for_saved_observation(&self) -> bool { self.empty() }
    fn claim(self: &Arc<Self>, epoch: u64, reviewed:Option<&Arc<Review>>) -> Result<AdmissionCohort, BridgeError> {
        let mut book=self.book.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if self.is_unknown(){return Err(BridgeError::cleanup_unknown());}
        if Self::pending(&book) || book.epoch != epoch || book.original.is_some() || book.cohort.is_some()
            || book.admission.is_some(){return Err(wire::unavailable());}
        if !match (reviewed,book.review.as_ref()) {
            (None,None)=>true,(Some(review),Some(route))=>route.matches(review) && route.epoch==epoch,
            _=>false,
        } {return Err(wire::unavailable());}
        let identity=Arc::new(());
        book.admission=Some(CohortRecord{identity:Arc::downgrade(&identity),epoch,first:None});
        Ok(AdmissionCohort{slot:self.clone(),identity,epoch,entered:AtomicBool::new(false)})
    }
    fn current_claim(&self, claim:&AdmissionCohort) -> bool {
        self.book.lock().is_ok_and(|book|!self.is_unknown() && !Self::pending(&book) && book.epoch==claim.epoch
            && book.admission.as_ref().is_some_and(|a|a.identity.as_ptr()==Arc::as_ptr(&claim.identity) && a.first.is_none()))
    }
}

enum Request {Inspect(wire::Inspect),Register(wire::Register)}
impl Request {
    fn context(&self)->&android_wire::Prepare{match self{Self::Inspect(input)=>&input.context,Self::Register(input)=>&input.context}}
    fn generation(&self)->u32{match self{Self::Inspect(input)=>input.registration_generation,Self::Register(input)=>input.registration_generation}}
    fn source_generation(&self)->u32{match self{Self::Inspect(input)=>input.source_generation,Self::Register(input)=>input.source_generation}}
    fn retained_heap_bytes(&self)->Option<usize>{
        self.context().retained_heap_bytes()?.checked_add(match self{Self::Inspect(_)=>0,Self::Register(input)=>input.review_id.capacity()})
    }
}
/// First short-lock snapshot only. It has no native/worker/finality authority.
pub(crate) struct Snapshot {
    owner:Weak<Inner>,document:Weak<()>,at:Instant,source:Arc<SourceSnapshot>,request:Request,
    reviewed:Option<Arc<Review>>,saved:crate::asset_session::ValidatedSavedInput,cohort:Mutex<Option<AdmissionCohort>>,
}
/// Constructed ONLY by the real selected-picker proof outside BOTH app locks.
/// The census later borrows this same fixed array; admission borrows this
/// Checked value rather than moving a value whose originals are still borrowed.
pub(crate) struct Checked {
    snapshot:Snapshot,id:String,review_id:String,instance:String,
}
impl Snapshot {
    pub(crate) fn check_originals(self)->Result<Checked,BridgeError>{
        if !self.source.originals_settled(){return Err(wire::unavailable());}
        // Entropy is outside Document/Registry; original T already includes it.
        let id=nonce(SavedCommandDomain::AndroidBuild)?;
        // Register consumes the exact finalized Review, including its proposed
        // immutable instance. Only the new operation gets new entropy; changing
        // the proposal here would silently authorize an unreviewed copy.
        let (review_id,instance)=match (&self.request,&self.reviewed) {
            (Request::Inspect(_),None)=>(nonce(SavedCommandDomain::AndroidBuild)?,nonce(SavedCommandDomain::AndroidBuild)?),
            (Request::Register(input),Some(review)) if input.review_id==review.public.review_id =>
                (review.public.review_id.clone(),review.original.instance.clone()),
            _=>return Err(wire::invalid()),
        };
        if id==review_id || id==instance || review_id==instance{return Err(wire::unavailable());}
        Ok(Checked{snapshot:self,id,review_id,instance})
    }
}
impl Checked {
    pub(crate) fn picker_originals(&self)->&[Arc<crate::asset_session::OriginalWork>;3]{self.snapshot.source.picker_originals()}
    pub(crate) fn context(&self)->&android_wire::Prepare{self.snapshot.request.context()}
    fn retained_bytes(&self)->Option<usize>{
        checked_allocation_bytes(&self.snapshot.request,&self.id,&self.review_id,&self.instance,&self.snapshot.source)
    }
}
struct SourceReturn {
    known:bool,entered:bool,first:Option<(wire::Reason,Instant)>,retained_bytes:Option<usize>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    review:Option<AndroidRegistrationSourceReview>,
}
struct Reservation {whole:usize,source:usize}
struct Operation {
    owner:Weak<Inner>,document:Weak<()>,source:Arc<SourceSnapshot>,data:wire::Operation,
    saved:crate::asset_session::ValidatedSavedInput,cohort:AdmissionCohort,
    review_id:String,instance:String,control:Arc<Control>,
    reservation:std::sync::OnceLock<Reservation>,settling:AtomicBool,
    source_handle:AsyncMutex<Option<JoinHandle<SourceReturn>>>,
    source_return:Mutex<Option<Result<SourceReturn,tokio::task::JoinError>>>,source_join_seen:AtomicBool,
    coordinator:Mutex<Option<JoinHandle<bool>>>,
    coordinator_return:Mutex<Option<Result<bool,tokio::task::JoinError>>>,final_seen:AtomicBool,joined_at:std::sync::OnceLock<Instant>,accepted:AtomicBool,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    sources:Mutex<AndroidRegistrationSourceSlots>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    client:Option<client::ClientOriginal>,
}
/// A borrow of the actual joined original, not a current-input authority.
/// Only Document can pair this DATA with a newly sampled private saved witness.
pub(crate) struct Finalization { original: Arc<Operation> }
impl Finalization {
    pub(crate) fn context(&self)->&android_wire::Prepare{&self.original.data.context}
}
struct Review {
    original:Arc<Operation>,public:wire::Review,accepted_at:Instant,expires:Instant,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    source:AndroidRegistrationSourceReview,
}
struct Last {data:wire::Operation,phase:wire::Phase,reason:wire::Reason,report:Option<wire::Report>}
#[derive(Default)]
pub(super) struct Registration {
    generation:u32,active:Option<Arc<Operation>>,review:Option<Arc<Review>>,last:Option<Last>,
    capability:Option<(Availability,wire::Prerequisite)>,
    service:service_setup::State,maintenance:maintenance::State,
}
enum InvokeEntry {
    Inspection(oneshot::Sender<()>),
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    Registration(oneshot::Sender<client::BeginPreparation>),
}
impl InvokeEntry {
    fn release(self)->bool { match self {
        Self::Inspection(sender)=>sender.send(()).is_ok(),
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        Self::Registration(sender)=>sender.send(client::BeginPreparation).is_ok(),
    } }
}
pub(crate) struct Admitted {status:wire::Status,release:Option<InvokeEntry>,original:Arc<Operation>}
impl Admitted {
    /// Inspection GO or Register BeginPreparation, only AFTER Document unlocks.
    /// Register source/transfer GO remains behind same-peer Ready and reproof.
    pub(crate) fn release(mut self)->Result<wire::Status,BridgeError>{
        // This original is already owned. Conditional pending must not become
        // a false ContextChanged failure here. Deliver its sole GO; the SAME
        // source worker commits entry through WorkGate and genuinely waits on
        // the original W/H. No new task, observation, consent or clock is made.
        let Some(release)=self.release.take()else{self.original.control.mark_unknown(Instant::now());return Err(wire::unconfirmed());};
        if !release.release(){
            let at=Instant::now();self.original.control.stop_at(wire::Reason::Cancelled,at);
            return Err(wire::unconfirmed());
        }
        Ok(self.status.clone())
    }
}
impl Drop for Admitted {
    fn drop(&mut self){
        // Dropping an unacknowledged invoke does not abandon the original.
        if self.release.is_some(){let at=Instant::now();self.original.control.stop_at(wire::Reason::Cancelled,at);}
    }
}
fn arc_bytes<T>()->Option<usize>{
    let (layout,_)=std::alloc::Layout::new::<[usize;2]>().extend(std::alloc::Layout::new::<T>()).ok()?;
    Some(layout.pad_to_align().size())
}
fn source_projection_bytes(values:&Vec<wire::Source>)->Option<usize>{
    values.iter().try_fold(values.capacity().checked_mul(std::mem::size_of::<wire::Source>())?,
        |bytes,value|bytes.checked_add(value.version.as_ref().map_or(0,String::capacity)))
}
fn operation_projection_bytes(value:&wire::Operation)->Option<usize>{
    value.operation_id.capacity().checked_add(value.context.retained_heap_bytes()?)
}
fn report_bytes(value:&wire::Report)->Option<usize>{
    let mut bytes=source_projection_bytes(&value.sources)?
        .checked_add(value.problems.items.capacity().checked_mul(std::mem::size_of::<wire::Problem>())?)?;
    if let Some(accounting)=&value.accounting{
        bytes=bytes.checked_add(accounting.written_bytes.capacity())?
            .checked_add(accounting.observed_logical_bytes.capacity())?.checked_add(accounting.observed_allocated_bytes.capacity())?;
    }Some(bytes)
}
fn prerequisite_reason(value:wire::Prerequisite)->wire::Reason{match value{
    wire::Prerequisite::Ready=>wire::Reason::None,wire::Prerequisite::SupplierUnavailable=>wire::Reason::SupplierUnavailable,
    wire::Prerequisite::SigningUnavailable=>wire::Reason::SigningUnavailable,wire::Prerequisite::ApprovalRequired=>wire::Reason::ApprovalRequired,
    wire::Prerequisite::ApprovalDenied=>wire::Reason::ApprovalDenied,wire::Prerequisite::ServiceUnavailable=>wire::Reason::ServiceUnavailable,
    wire::Prerequisite::FreshServiceUnavailable=>wire::Reason::FreshServiceUnavailable,
}}
fn prerequisite(service:&service_setup::State)->wire::Prerequisite{
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    {
        if !crate::android_supplier_macos::available(){return wire::Prerequisite::SupplierUnavailable;}
        return service.prerequisite();
    }
    #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=service;wire::Prerequisite::ServiceUnavailable}
}
impl Operation {
    fn same_owner(&self,inner:&Inner)->bool{
        self.owner.as_ptr()==inner as *const Inner
            && self.document.upgrade().is_some_and(|document|inner.android_original_document_matches(Some(&document)))
    }
    fn known_source_return(&self)->bool{
        if !self.source_join_seen.load(Ordering::SeqCst) || self.control.unknown.load(Ordering::SeqCst){return false;}
        let Ok(handle)=self.source_handle.try_lock()else{return false;};
        let Ok(returned)=self.source_return.try_lock()else{return false;};
        handle.is_none() && matches!(returned.as_ref(),Some(Ok(value)) if value.known && value.retained_bytes.is_some())
    }
    fn known_return(&self)->bool {
        if !self.known_source_return(){return false;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if let Some(client)=&self.client{return client.known_return();}
        self.data.kind==wire::Kind::Inspection
    }
    fn retained_bytes(&self)->Option<usize>{
        if !self.accepted.load(Ordering::SeqCst) || !self.final_seen.load(Ordering::SeqCst)
            || !self.source_join_seen.load(Ordering::SeqCst) || self.control.unknown.load(Ordering::SeqCst){return None;}
        let source_handle=self.source_handle.try_lock().ok()?;
        let coordinator=self.coordinator.try_lock().ok()?;
        let returned=self.source_return.try_lock().ok()?;
        let final_return=self.coordinator_return.try_lock().ok()?;
        if source_handle.is_some() || coordinator.is_some() || !matches!(final_return.as_ref(),Some(Ok(true))){return None;}
        let Some(Ok(returned))=returned.as_ref()else{return None;};
        if !returned.known{return None;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if returned.review.is_some(){return None;} // The final Review owns it now.
        retained_operation_allocation_bytes(&self.data,&self.review_id,&self.instance,&self.control,&self.source,returned.retained_bytes?)
    }
}
impl Registration {
    pub(super) fn sources_match(&self,sources:&android_sources::Sources)->bool{
        self.maintenance.sources_match(sources) && self.service.sources_match(sources) && self.active.as_ref().is_none_or(|original|sources.same_snapshot(&original.source))
            && self.review.as_ref().is_none_or(|review|sources.same_snapshot(&review.original.source))
    }
    pub(super) fn invalidation_failure(&self) -> Option<(wire::Reason, Instant)> {
        self.active.as_ref().or_else(|| self.review.as_ref().map(|review| &review.original))
            .and_then(|original| WorkGate { slot: original.cohort.slot.clone(), control: original.control.clone() }.first())
            .or_else(||self.service.invalidation_failure()).or_else(||self.maintenance.invalidation_failure())
    }
    pub(super) fn busy(&self)->bool{self.active.is_some() || self.service.busy() || self.maintenance.busy()}
    pub(super) fn unknown(&self)->bool{
        self.maintenance.unknown() || self.service.unknown() || self.active.as_ref().is_some_and(|value|value.control.unknown.load(Ordering::SeqCst))
            || self.review.as_ref().is_some_and(|review|review.original.control.unknown.load(Ordering::SeqCst)
                || review.original.control.failure().is_some() && review.accepted_at>=review.original.control.endpoint())
    }
    pub(super) fn installation_empty(&self)->bool{self.active.is_none()&&self.review.is_none()&&self.last.is_none()&&self.service.empty()&&self.maintenance.empty()}
    pub(super) fn registration_matches(&self,registration:u32)->bool{
        self.service.registration_matches(registration) && self.active.as_ref().is_none_or(|value|value.source.registration==registration)
            && self.review.as_ref().is_none_or(|value|value.original.source.registration==registration)
    }
    pub(super) fn stop(&mut self,reason:wire::Reason,at:Instant)->bool{
        // Observe a late negative before retiring Review DATA. In particular
        // context/shutdown must not discard an original that became Unknown
        // between final publication and this separate invalidation request.
        let mut changed=self.negative_review_at(at);
        changed|=self.service.stop(reason,at);
        changed|=self.maintenance.stop(reason,at);
        changed|=self.review.is_some();
        if let Some(review)=self.review.take(){
            review.original.cohort.slot.clear_review(&review);
            self.last=Some(Last{data:review.original.data.clone(),phase:if reason==wire::Reason::Cancelled{
                wire::Phase::Cancelled}else{wire::Phase::Refused},reason,report:None});
        }
        if let Some(original)=&self.active{
            let before=original.control.failure();let unknown=original.control.unknown.load(Ordering::SeqCst);
            original.control.stop_at(reason,at);
            changed|=before!=original.control.failure() || unknown!=original.control.unknown.load(Ordering::SeqCst);
        }
        changed
    }
    pub(super) fn exhaust(&mut self,at:Instant)->bool{
        self.stop(wire::Reason::CleanupUnknown,at)
    }
    fn expire(&mut self,at:Instant)->bool{
        if self.review.as_ref().is_some_and(|review|at>=review.expires){self.stop(wire::Reason::ReviewExpired,at)}else{false}
    }
    fn negative_review_at(&mut self,at:Instant)->bool{
        let Some(review)=self.review.as_ref()else{return false;};
        let failure=review.original.control.failure();
        if review.original.control.unknown.load(Ordering::SeqCst)
            || failure.is_some() && review.accepted_at>=review.original.control.endpoint(){
            // A late earlier-F can put the already observed join outside its
            // original cleanup cutoff. Retain the SAME original and frozen joins;
            // neither prior Review nor later known return can erase Unknown.
            let original=review.original.clone();original.control.mark_unknown(at);
            original.cohort.slot.clear_review(review);
            original.cohort.slot.poisoned();
            self.review=None;self.active=Some(original);return true;
        }
        if let Some((reason,_))=failure{
            review.original.cohort.slot.clear_review(review);
            self.last=Some(Last{data:review.original.data.clone(),phase:if reason==wire::Reason::Cancelled{
                wire::Phase::Cancelled}else{wire::Phase::Refused},reason,report:None});
            self.review=None;return true;
        }
        false
    }
    fn same_review(&self,input:&wire::Register,source:&SourceSnapshot,at:Instant)->Option<Arc<Review>>{
        let review=self.review.as_ref()?;
        if review.expires.checked_duration_since(review.accepted_at)!=Some(REVIEW)
            || at>=review.expires || review.public.review_id!=input.review_id || review.public.context!=input.context
            || review.public.source_generation!=input.source_generation || self.generation!=input.registration_generation
            || review.original.source.registration!=source.registration || review.original.source.project!=source.project
            || review.original.source.project_id!=source.project_id || review.original.source.roots()!=source.roots()
            || !review.original.source.picker_originals().iter().zip(source.picker_originals()).all(|(old,new)|Arc::ptr_eq(old,new))
            || !review.original.accepted.load(Ordering::SeqCst) || review.original.control.failure().is_some()
            || review.original.control.unknown.load(Ordering::SeqCst){return None;}
        Some(review.clone())
    }
    fn maintenance_retained_bytes(&self)->Option<usize>{
        if self.active.is_some() || self.review.is_some(){return None;}
        registration_allocation_bytes(self.service.retained_bytes()?,self.last.as_ref())?
            .checked_add(self.maintenance.retained_bytes()?.checked_sub(std::mem::size_of::<maintenance::State>())?)
    }
    fn retained_bytes(&self,source:&SourceSnapshot)->Option<usize>{
        if self.active.is_some(){return None;}
        let mut bytes=registration_allocation_bytes(self.service.retained_bytes()?,self.last.as_ref())?
            .checked_add(self.maintenance.retained_bytes()?.checked_sub(std::mem::size_of::<maintenance::State>())?)?;
        if let Some(review)=&self.review{
            // A usable Review can retain only the SAME selected picker set.
            // Drift hooks retire it before a new selection is published. A
            // known prior failure retains only Last DATA, never hidden pickers.
            if !review.original.source.picker_originals().iter().zip(source.picker_originals()).all(|(old,new)|Arc::ptr_eq(old,new)){return None;}
            bytes=bytes.checked_add(retained_review_projection_bytes(review.original.retained_bytes()?,&review.public)?)?;
            #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
            {bytes=bytes.checked_add(review.source.retained_bytes()?.checked_sub(std::mem::size_of::<AndroidRegistrationSourceReview>())?)?;}
        }
        Some(bytes)
    }
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn source_failure(control:&Control,failure:AdmissionFailure,at:Instant){
    let reason=match failure{
        AdmissionFailure::Deadline=>wire::Reason::TimedOut,AdmissionFailure::Stopped=>wire::Reason::Cancelled,
        AdmissionFailure::Bounds=>wire::Reason::InputLimit,AdmissionFailure::Unknown=>wire::Reason::CleanupUnknown,
        _=>wire::Reason::SourceRefused,
    };
    control.stop_at(reason,at);
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn inspection_source_task(original:Arc<Operation>,enter:oneshot::Receiver<()>)->impl FnOnce()->SourceReturn{
    move||inspect_source(original,enter)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn inspect_source(original:Arc<Operation>,enter:oneshot::Receiver<()>)->SourceReturn{
    // The source book remains on the SAME Operation; even a panic/lost return
    // cannot drop an unresolved native/FD book with a detached worker closure.
    let go=enter.blocking_recv().is_ok();
    let mut sources=match original.sources.lock(){
        Ok(sources)=>sources,
        Err(_)=>{
            original.control.mark_unknown(Instant::now());
            return SourceReturn{known:false,entered:false,first:original.control.failure(),retained_bytes:None,review:None};
        },
    };
    let now=Instant::now();original.control.advance(now);
    if original.reservation.get().is_none_or(|reservation|reservation.whole>OWNED_LIMIT){original.control.mark_unknown(now);}
    let entry_gate=WorkGate{slot:original.cohort.slot.clone(),control:original.control.clone()};
    let gate_clear=go && entry_gate.work().is_ok();
    let entered_at=Instant::now();original.control.advance(entered_at);
    let entered=gate_clear && original.control.failure().is_none() && !original.control.unknown.load(Ordering::SeqCst)
        && original.data.kind==wire::Kind::Inspection && entered_at<original.control.work;
    if entered{
        let mut publish=|failure,at|source_failure(&original.control,failure,at);
        if let Err(failure)=sources.inspect_once(original.source.roots(),&original.instance,
            original.control.work,&original.control.stop.subscribe(),&mut publish){
            // SourceSlots normally already published its earlier original F.
            // Preserve that point; never substitute time of owner projection.
            let at=sources.first_failure().map_or_else(Instant::now,|(_,at)|at);
            source_failure(&original.control,failure,at);
        }
    }else if original.control.failure().is_none(){
        original.control.stop_at(wire::Reason::Cancelled,entered_at);
    }
    original.settling.store(true,Ordering::SeqCst);original.control.changed();
    let closed=sources.settle_originals(&mut |failure|{
        if let Some((failure,at))=failure{source_failure(&original.control,failure,at);}
        let now=Instant::now();original.control.advance(now);
        now>=original.control.endpoint()
    });
    if let Some((failure,at))=sources.first_failure(){source_failure(&original.control,failure,at);}
    let known=closed==CloseOutcome::Settled && sources.settled();
    let review=if known && entered && original.control.failure().is_none()
        && !original.control.unknown.load(Ordering::SeqCst){
        match sources.take_inspection_review(){
            Ok(review)=>Some(review),
            Err(failure)=>{source_failure(&original.control,failure,Instant::now());None},
        }
    }else{None};
    // Frozen only on this actual source worker after consuming source/native
    // closes. This scalar and Review are NOT a source-join receipt.
    let retained_bytes=sources.retained_bytes();
    let source_bytes=retained_bytes.and_then(|bytes|bytes.checked_add(review.as_ref().map_or(Some(0),AndroidRegistrationSourceReview::retained_bytes)?));
    if !known || source_bytes.is_none() || original.reservation.get().is_none_or(|reservation|
        source_bytes.is_none_or(|bytes|bytes>reservation.source)){
        original.control.mark_unknown(Instant::now());
    }
    SourceReturn{known,entered,first:original.control.failure(),retained_bytes,review}
}
fn poll_source(original:&Operation,slot:&mut Option<JoinHandle<SourceReturn>>,
    context:&mut TaskContext<'_>,at:Instant)->Poll<bool>{
    poll_source_cells(&original.control,&original.source_join_seen,&original.source_return,slot,context,at)
}
// Actual original-cell consumption, shared by the inspection and Register
// coordinators. A worker-return value or is_finished() is not a consumed join.
fn poll_source_cells(control:&Control,joined:&AtomicBool,
    returned_cell:&Mutex<Option<Result<SourceReturn,tokio::task::JoinError>>>,
    slot:&mut Option<JoinHandle<SourceReturn>>,context:&mut TaskContext<'_>,at:Instant)->Poll<bool>{
    let mut returned=match returned_cell.try_lock(){
        Ok(returned)=>returned,Err(TryLockError::WouldBlock)=>return Poll::Pending,
        Err(TryLockError::Poisoned(_))=>{control.mark_unknown(at);return Poll::Ready(false);},
    };
    if joined.load(Ordering::SeqCst) || returned.is_some(){
        control.mark_unknown(at);return Poll::Ready(false);
    }
    let Some(handle)=slot.as_mut()else{control.mark_unknown(at);return Poll::Ready(false);};
    let Poll::Ready(value)=Pin::new(handle).poll(context)else{return Poll::Pending;};
    let known=matches!(&value,Ok(data) if data.known && data.retained_bytes.is_some());
    *returned=Some(value);joined.store(true,Ordering::SeqCst);
    slot.take();
    if !known{control.mark_unknown(at);}
    Poll::Ready(known)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
async fn coordinate_inspection(original:Arc<Operation>,enter:oneshot::Receiver<()>,source_release:oneshot::Sender<()>)->bool{
    let mut stopped=original.control.stop.subscribe();let mut changed=original.control.audit.subscribe();
    let go=tokio::select!{
        value=enter=>value.is_ok(),
        _=stopped.changed()=>false,
        _=tokio::time::sleep_until(tokio::time::Instant::from_std(original.control.work))=>false,
    };
    let current=original.owner.upgrade().is_some_and(|owner|{
        let registry=owner.lock();
        !registry.disabled && !registry.exhausted && !registry.stopping && !registry.document_lost
            && !owner.poisoned.load(Ordering::SeqCst) && original.same_owner(&owner)
            && registry.android_registration.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,&original))
            && registry.android_sources.same_snapshot(&original.source)
    });
    let at=Instant::now();original.control.advance(at);
    if go && current && original.control.failure().is_none() && !original.control.unknown.load(Ordering::SeqCst)
        && at<original.control.work{
        if source_release.send(()).is_err(){original.control.mark_unknown(Instant::now());}
    }else{
        if original.control.failure().is_none(){original.control.stop_at(wire::Reason::ContextChanged,at);}
        drop(source_release);
    }
    // Only this original coordinator consumes the SAME original source handle.
    // There is no source-created receipt and no source-side Finish interface.
    let mut slot=original.source_handle.lock().await;
    loop{
        let at=Instant::now();original.control.advance(at);
        let end=original.control.endpoint();
        if at>=end{original.control.mark_unknown(at);return false;}
        let known=tokio::select!{
            known=std::future::poll_fn(|context|{
                let observed=Instant::now();poll_source(&original,&mut slot,context,observed)
            })=>Some(known),
            value=changed.changed()=>{if value.is_err(){original.control.mark_unknown(Instant::now());}None},
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(end))=>None,
        };
        if let Some(known)=known{
            drop(slot);
            let at=Instant::now();original.control.advance(at);
            return known && original.known_return() && at<original.control.endpoint();
        }
    }
}
impl Registration {
    /// Observer, not a supplied-time reducer. Capture each new observation at
    /// its actual edge; all *_at reducers preserve that captured point and every
    /// earlier original F. Only SAME JoinHandles are polled here, never native
    /// books or source settlement.
    pub(super) fn reconcile(&mut self,inner:&Inner)->bool{
        let at=Instant::now();
        let mut changed=self.negative_review_at(at);
        changed|=self.service.reconcile(inner);
        changed|=self.maintenance.reconcile(inner);
        changed|=self.expire(at);
        if self.active.is_none(){return changed;}
        let original=self.active.as_ref().unwrap().clone();
        original.control.advance(at);
        changed|=original.control.dirty.swap(false,Ordering::SeqCst);
        if original.final_seen.load(Ordering::SeqCst){
            // Generic Saved reconciliation only observes actual joins. It may
            // NOT publish using an old saved stamp. Document performs the final
            // reentry with its freshly held original Edit Registry below.
            // A late return is observed once on its SAME retained handle.
            // Sticky Unknown prevents any new Review or rewritten success.
            if !original.source_join_seen.load(Ordering::SeqCst){
                if let Ok(mut slot)=original.source_handle.try_lock(){
                    if slot.is_some(){
                        let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));
                        let mut context=TaskContext::from_waker(&waker);
                        let _=poll_source(&original,&mut slot,&mut context,at);
                    }
                }
            }
            #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
            if let Some(client)=&original.client{client.observe_late(&original);}
            return changed;
        }
        let mut slot=match original.coordinator.try_lock(){
            Ok(slot)=>slot,Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>{original.control.mark_unknown(at);return true;},
        };
        let mut returned=match original.coordinator_return.try_lock(){
            Ok(returned)=>returned,Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>{original.control.mark_unknown(at);return true;},
        };
        if returned.is_some(){original.control.mark_unknown(at);return true;}
        let Some(handle)=slot.as_mut()else{original.control.mark_unknown(at);return true;};
        let waker=Waker::from(Arc::new(FinalWake(original.owner.clone())));
        let mut context=TaskContext::from_waker(&waker);
        let Poll::Ready(result)=Pin::new(handle).poll(&mut context)else{return changed;};
        let positive=matches!(&result,Ok(true));*returned=Some(result);
        original.final_seen.store(true,Ordering::SeqCst);slot.take();
        drop(returned);drop(slot);
        // This is the actual final-return observation, AFTER polling and
        // recording that SAME handle, not the earlier sweep/start point.
        let joined_at=Instant::now();
        self.finish_join_observation(inner,&original,positive,joined_at)
    }
    fn finish_join_observation(&mut self,inner:&Inner,original:&Arc<Operation>,positive:bool,at:Instant)->bool{
        if !positive || !original.known_return() || original.control.unknown.load(Ordering::SeqCst)
            || at>=original.control.endpoint(){original.control.mark_unknown(at);return true;}
        if !original.same_owner(inner){original.control.stop_at(wire::Reason::DocumentLost,at);}
        // Freeze the real SAME coordinator-join observation once, not a sweep
        // timestamp or a future status call. This is still not publication.
        if original.joined_at.set(at).is_err(){original.control.mark_unknown(at);}
        true
    }
    fn finalize_under_document(&mut self,inner:&Inner,request:&Finalization,
        current:Option<&crate::asset_session::ValidatedSavedInput>,gate:android_wire::Availability)->bool {
        let original=&request.original;
        if !self.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,original))
            || original.accepted.load(Ordering::SeqCst) || original.control.unknown.load(Ordering::SeqCst){return false;}
        let Some(joined_at)=original.joined_at.get().copied() else{return false;};
        let at=Instant::now();original.control.advance(at);
        if !original.known_return() || joined_at>=original.control.endpoint() || at>=original.control.endpoint(){
            original.control.mark_unknown(at);return true;
        }
        let mut source_return=match original.source_return.try_lock(){Ok(returned)=>returned,
            Err(TryLockError::WouldBlock)=>return false,
            Err(TryLockError::Poisoned(_))=>{original.control.mark_unknown(at);return true;}};
        let Some(Ok(source))=source_return.as_mut() else{original.control.mark_unknown(at);return true;};
        if source.first.is_some_and(|(_,first)|original.control.failure().is_none_or(|(_,current)|current>first)){
            original.control.mark_unknown(at);return true;
        }
        // SourceReturn is joined DATA, NOT the worker-only sources/native book.
        // No pending publisher, Document path or census ever locks that book.
        let mut book=match inner.android_registration_control.book.try_lock(){Ok(book)=>book,
            Err(TryLockError::WouldBlock)=>return false,
            Err(TryLockError::Poisoned(error))=>{
                drop(error.into_inner());original.control.poisoned();return true;
            }};
        if inner.android_registration_control.is_unknown()
            || !book.original.as_ref().is_some_and(|held|Arc::ptr_eq(held,&original.control))
            || !book.cohort.as_ref().is_some_and(|cohort|cohort.identity.as_ptr()==Arc::as_ptr(&original.control.cohort))
            || book.review.is_some(){drop(book);original.cohort.slot.poisoned();return true;}
        if ControlSlot::pending(&book) || original.control.latches.load(Ordering::SeqCst)!=0{return false;}
        let at=Instant::now();original.control.advance(at);
        if original.control.unknown.load(Ordering::SeqCst) || at>=original.control.endpoint(){
            original.control.mark_unknown(at);return true;
        }
        let failure=original.control.failure();
        if failure.is_none() {
            // Busy (including an unanswered native question) is reversible, not
            // a lifecycle F. The original W/H continue while publication waits.
            if gate==android_wire::Availability::Busy{return false;}
            if book.epoch!=original.control.epoch || book.cohort.as_ref().is_some_and(|cohort|cohort.first.is_some()) {
                drop(book);original.cohort.slot.poisoned();return true;
            }
            // The stamp sample can have overlapped pending which rejected just
            // before this lock. Missing fresh proof with no F withholds finality;
            // it must not turn that reversible wait into a false Unknown/STOP.
            if gate!=android_wire::Availability::Available
                || !current.is_some_and(|current|original.saved.same_binding(current)){return false;}
        }
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            if let Some(client)=&original.client {
                let Some((phase,reason,report))=client.report(original) else {
                    drop(book);original.control.mark_unknown(at);return true;
                };
                if source.review.is_some() || !client.finalize_preparation(&mut self.service){drop(book);original.control.mark_unknown(at);return true;}
                self.last=Some(Last{data:original.data.clone(),phase,reason,report:Some(report)});
                self.review=None;original.accepted.store(true,Ordering::SeqCst);
                book.original=None;book.cohort=None;self.active=None;
                drop(book);inner.android_registration_control.wake.notify_all();return true;
            }
            let setup=prerequisite(&self.service);
            let sources=source.review.as_ref().map_or_else(Vec::new,AndroidRegistrationSourceReview::sources);
            if failure.is_none() && setup==wire::Prerequisite::Ready {
                let Some(expires)=at.checked_add(REVIEW) else{original.control.mark_unknown(at);return true;};
                let Some(source)=source.review.take() else{original.control.mark_unknown(at);return true;};
                let public=wire::Review{review_id:original.review_id.clone(),source_generation:original.source.generation,
                    context:original.data.context.clone(),consent_version:wire::CONSENT,license_acknowledgment_required:true,sources};
                let review=Arc::new(Review{original:original.clone(),public,accepted_at:at,expires,source});
                // Final original Control retirement and finalized Review route
                // are ONE short-book publication, under current Document/Edit.
                // A Cancel can observe neither a mirror gap nor a new identity.
                book.review=Some(ReviewRoute{original:Arc::downgrade(original),reviewed:Arc::downgrade(&review),
                    operation_id:original.data.operation_id.clone(),review_id:original.review_id.clone(),
                    generation:original.data.registration_generation,epoch:original.control.epoch});
                self.review=Some(review);self.last=None;
            }else{
                let reason=failure.map_or_else(||prerequisite_reason(setup),|(reason,_)|reason);
                let problem=match reason{
                    wire::Reason::SupplierUnavailable=>wire::Problem::SupplierUnavailable,
                    wire::Reason::InputLimit|wire::Reason::ResultLimit=>wire::Problem::Bounds,
                    wire::Reason::Cancelled|wire::Reason::TimedOut=>wire::Problem::Stopped,
                    wire::Reason::SigningUnavailable|wire::Reason::ApprovalRequired|wire::Reason::ApprovalDenied
                        |wire::Reason::ServiceUnavailable|wire::Reason::FreshServiceUnavailable=>wire::Problem::Unavailable,
                    _=>wire::Problem::Inventory,
                };
                // All actual source/coordinator returns and joins were verified.
                // Only closed comparison DATA can be discarded on known refusal.
                source.review=None;
                self.last=Some(Last{data:original.data.clone(),phase:if reason==wire::Reason::Cancelled{
                    wire::Phase::Cancelled}else{wire::Phase::Refused},reason,
                    report:Some(wire::Report{sources,protected_copy:wire::ProtectedCopy::NotCreated,accounting:None,
                        problems:wire::Problems{recorded:1,shown:1,omitted:0,first:Some(problem),items:vec![problem]}})});
                self.review=None;
            }
            original.accepted.store(true,Ordering::SeqCst);
            book.original=None;book.cohort=None;self.active=None;
            drop(book);inner.android_registration_control.wake.notify_all();true
        }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {drop(book);original.control.mark_unknown(at);true}
    }
    fn status(&self,revision:u32,availability:Availability,setup:wire::Prerequisite)->Result<wire::Status,BridgeError>{
        let (phase,reason,operation,review,report)=if let Some(original)=&self.active{
            let unknown=original.control.unknown.load(Ordering::SeqCst);
            let failure=original.control.failure();
            (if unknown{wire::Phase::Unknown}else if failure.is_some(){wire::Phase::Stopping}
                else if original.settling.load(Ordering::SeqCst){wire::Phase::Settling}else{
                    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
                    if let Some(client)=&original.client{client.phase()}else{wire::Phase::Inspecting}
                    #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
                    {wire::Phase::Inspecting}
                },
            if unknown{wire::Reason::CleanupUnknown}else{failure.map_or(wire::Reason::None,|(reason,_)|reason)},
            Some(original.data.clone()),None,None)
        }else if let Some(review)=&self.review{
            // A control writer may have completed after reconcile's short
            // sweep. Never serialize usable consent over a negative original.
            let failure=review.original.control.failure();
            let unknown=review.original.control.unknown.load(Ordering::SeqCst)
                || failure.is_some() && review.accepted_at>=review.original.control.endpoint();
            if unknown{
                (wire::Phase::Unknown,wire::Reason::CleanupUnknown,Some(review.original.data.clone()),None,None)
            }else if let Some((reason,_))=failure{
                (if reason==wire::Reason::Cancelled{wire::Phase::Cancelled}else{wire::Phase::Refused},
                    reason,Some(review.original.data.clone()),None,None)
            }else if availability!=Availability::Available || setup!=wire::Prerequisite::Ready
                || !review.original.cohort.slot.matches_epoch(review.original.control.epoch) {
                // Withhold actionable Review DATA while a conditional predicate
                // is unresolved. Do not consume it or invent a STOP; rejection
                // exposes this SAME Review and its unchanged expiry again.
                (wire::Phase::Settling,wire::Reason::None,Some(review.original.data.clone()),None,None)
            }else{
                (wire::Phase::Review,wire::Reason::None,Some(review.original.data.clone()),Some(review.public.clone()),None)
            }
        }else if let Some(last)=&self.last{
            (last.phase,last.reason,Some(last.data.clone()),None,last.report.clone())
        }else{(wire::Phase::Idle,if setup==wire::Prerequisite::Ready{wire::Reason::NotInspected}else{prerequisite_reason(setup)},None,None,None)};
        wire::Status{schema_version:1,status_revision:revision,registration_generation:self.generation,
            availability:if phase==wire::Phase::Unknown{android_wire::Availability::CleanupUnknown}else{availability.android()},
            prerequisite:setup,phase,reason,operation,review,report}.bounded()
    }
}

impl SavedCommandOwner {
    fn registration_gate(&self,registry:&Registry,gate:Availability)->Availability{
        if registry.disabled || registry.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || self.inner.android_registration_control.is_unknown() || registry.android_sources.unknown() || registry.android_catalog.unknown() || registry.android_registration.unknown()
            || gate==Availability::CleanupUnknown{return Availability::CleanupUnknown;}
        if registry.stopping || gate==Availability::Shutdown{return Availability::Shutdown;}
        if registry.document_lost || gate==Availability::DocumentLost{return Availability::DocumentLost;}
        if self.inner.domain!=SavedCommandDomain::AndroidBuild
            || !cfg!(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))){
            return Availability::UnsupportedPlatform;
        }
        if !self.inner.android_runtime_selected(None){return Availability::RuntimeUnqualified;}
        if registry.active.is_some() || registry.prepared.is_some() || registry.android_sources.busy()
            || registry.android_catalog.busy() || registry.android_registration.busy() || gate==Availability::Busy{return Availability::Busy;}
        gate
    }
    fn registration_status_locked(&self,registry:&mut Registry,gate:android_wire::Availability,at:Instant)->Result<wire::Status,BridgeError>{
        let setup=prerequisite(&registry.android_registration.service);
        if registry.android_registration.negative_review_at(at){self.inner.bump(registry);}
        let mut availability=self.registration_gate(registry,Availability::from_android(gate));
        if availability==Availability::Available && setup!=wire::Prerequisite::Ready{availability=Availability::RuntimeUnqualified;}
        let capability=(availability,setup);
        if registry.android_registration.capability!=Some(capability){
            registry.android_registration.capability=Some(capability);self.inner.bump(registry);
        }
        if registry.exhausted || self.inner.poisoned.load(Ordering::SeqCst){return Err(BridgeError::cleanup_unknown());}
        registry.android_registration.status(registry.revision,availability,setup)
    }
    pub(crate) fn android_tool_registration_status(&self,gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        self.reconcile();let mut registry=self.inner.lock();let at=Instant::now();
        self.registration_status_locked(&mut registry,gate,at)
    }
    pub(crate) fn android_registration_finalization(&self)->Option<Finalization>{
        self.reconcile();
        let registry=self.inner.lock();
        registry.android_registration.active.as_ref().filter(|original|
            original.final_seen.load(Ordering::SeqCst) && original.joined_at.get().is_some()
                && !original.accepted.load(Ordering::SeqCst) && !original.control.unknown.load(Ordering::SeqCst))
            .map(|original|Finalization{original:original.clone()})
    }
    pub(crate) fn finalize_android_registration(&self,request:&Finalization,
        current:Option<&crate::asset_session::ValidatedSavedInput>,gate:android_wire::Availability){
        let mut registry=self.inner.lock();
        if registry.android_registration.finalize_under_document(&self.inner,request,current,gate){self.inner.bump(&mut registry);}
    }
    pub(crate) fn snapshot_android_tool_inspection(&self,document:&Arc<()>,at:Instant,input:wire::Inspect,
        registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:android_wire::Availability)->Result<Snapshot,BridgeError>{
        self.registration_snapshot(document,at,Request::Inspect(input),registration,project,saved,gate)
    }
    pub(crate) fn snapshot_android_tool_registration(&self,document:&Arc<()>,at:Instant,input:wire::Register,
        registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:android_wire::Availability)->Result<Snapshot,BridgeError>{
        self.registration_snapshot(document,at,Request::Register(input),registration,project,saved,gate)
    }
    fn registration_snapshot(&self,document:&Arc<()>,at:Instant,request:Request,
        registration:u32,project:RegisteredRoot,saved:crate::asset_session::ValidatedSavedInput,gate:android_wire::Availability)->Result<Snapshot,BridgeError>{
        let registry=self.inner.lock();
        if self.registration_gate(&registry,Availability::from_android(gate))!=Availability::Available
            || !self.inner.android_original_document_matches(Some(document)){return Err(wire::unavailable());}
        let source=registry.android_sources.snapshot().ok_or_else(wire::unavailable)?;
        if source.project_id!=request.context().project_id || source.project!=project || source.registration!=registration
            || source.generation!=request.source_generation() || registry.android_registration.generation!=request.generation(){
            return Err(wire::invalid());
        }
        if !saved.matches(document,registration,&project,request.context()){return Err(wire::invalid());}
        let reviewed=match &request{
            Request::Inspect(_)=>None,
            Request::Register(input)=>Some(registry.android_registration.same_review(input,&source,at).ok_or_else(wire::invalid)?),
        };
        let cohort=self.inner.android_registration_control.claim(saved.epoch(),reviewed.as_ref())?;
        Ok(Snapshot{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),at,source:Arc::new(source),request,reviewed,saved,cohort:Mutex::new(Some(cohort))})
    }
    /// Second phase, under the SAME current Document guard and registered root.
    /// Root has revalidated current saved inputs and supplies that exact context.
    /// This method only borrows Checked/Census, so their live original-array
    /// borrow cannot be moved or replaced during this admission.
    pub(crate) fn admit_android_tool_registration(&self,document:&Arc<()>,checked:&Checked,
        current:crate::asset_session::ValidatedSavedInput,registration:u32,project:&RegisteredRoot,
        census:&crate::asset_session::AndroidRegistrationCensus<'_>,gate:android_wire::Availability)
        ->Result<Admitted,BridgeError>{
        let snapshot=&checked.snapshot;
        let mut registry=self.inner.lock();
        if self.registration_gate(&registry,Availability::from_android(gate))!=Availability::Available
            || snapshot.owner.as_ptr()!=Arc::as_ptr(&self.inner) || snapshot.document.as_ptr()!=Arc::as_ptr(document)
            || !self.inner.android_original_document_matches(Some(document))
            || !registry.android_sources.same_snapshot(&snapshot.source)
            || snapshot.source.registration!=registration || &snapshot.source.project!=project
            || !current.matches(document,registration,project,snapshot.request.context()) || !snapshot.saved.same_binding(&current)
            || snapshot.request.generation()!=registry.android_registration.generation{return Err(wire::invalid());}
        if let Request::Register(input)=&snapshot.request{
            let checked_at=Instant::now();
            let current_review=registry.android_registration.same_review(input,&snapshot.source,checked_at).ok_or_else(wire::invalid)?;
            if !snapshot.reviewed.as_ref().is_some_and(|before|Arc::ptr_eq(before,&current_review)){return Err(wire::invalid());}
            #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
            return client::admit(self,document,&mut registry,checked,current,census,gate,current_review);
            #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
            return Err(wire::unavailable());
        }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {let _=(census,checked);Err(wire::unavailable())}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            let source_budget=AndroidRegistrationSourceSlots::reservation(crate::android_supplier_macos_source::SourcePhase::Inspection)
                .ok_or_else(wire::unavailable)?;
            let source_reservation=source_budget.bytes();
            let work=snapshot.at.checked_add(WORK).ok_or_else(wire::unavailable)?;
            let hard=snapshot.at.checked_add(HARD).ok_or_else(wire::unavailable)?;
            let observed=Instant::now();
            if observed>=work{return Err(wire::unavailable());}
            let generation=match registry.android_registration.generation.checked_add(1).filter(|generation|*generation<u32::MAX){
                Some(generation)=>generation,None=>{
                    registry.android_registration.exhaust(observed);registry.disabled=true;self.inner.bump(&mut registry);
                    return Err(BridgeError::cleanup_unknown());
                },
            };
            if registry.android_registration.last.as_ref().is_some_and(|last|last.data.operation_id==checked.id)
                || registry.android_registration.review.as_ref().is_some_and(|review|
                    review.original.data.operation_id==checked.id || review.public.review_id==checked.review_id
                    || review.source.instance()==checked.instance){return Err(wire::unavailable());}
            let previous=registration_retained_bytes(&self.inner,&registry,document,checked,census).ok_or_else(wire::unavailable)?;
            let executor=tokio::runtime::Handle::try_current().map_err(|_|wire::unavailable())?;
            let cohort=snapshot.cohort.lock().map_err(|_|wire::unconfirmed())?.take().ok_or_else(wire::invalid)?;
            if !self.inner.android_registration_control.current_claim(&cohort){return Err(wire::invalid());}
            let (stop,_)=watch::channel(false);let (audit,audit_read)=watch::channel(hard);
            let control=Arc::new(Control{lane:ControlLane::Sources,owner:Arc::downgrade(&self.inner),id:checked.id.clone(),generation,
                admitted:snapshot.at,work,hard,slot:Arc::downgrade(&self.inner.android_registration_control),cohort:cohort.identity.clone(),epoch:cohort.epoch,first:Mutex::new(None),unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),
                latches:std::sync::atomic::AtomicUsize::new(0),stop,audit});
            let data=wire::Operation{operation_id:checked.id.clone(),registration_generation:generation,
                source_generation:snapshot.source.generation,kind:wire::Kind::Inspection,context:snapshot.request.context().clone()};
            let total=operation_admission_bytes(previous,&data,&checked.review_id,&checked.instance,&control,source_reservation)
                .ok_or_else(wire::unavailable)?;
            let original=Arc::new(Operation{owner:Arc::downgrade(&self.inner),document:Arc::downgrade(document),
                source:snapshot.source.clone(),data,saved:current,cohort,review_id:checked.review_id.clone(),instance:checked.instance.clone(),
                control:control.clone(),reservation:std::sync::OnceLock::new(),settling:AtomicBool::new(false),
                source_handle:AsyncMutex::new(None),source_return:Mutex::new(None),source_join_seen:AtomicBool::new(false),
                coordinator:Mutex::new(None),coordinator_return:Mutex::new(None),final_seen:AtomicBool::new(false),joined_at:std::sync::OnceLock::new(),accepted:AtomicBool::new(false),
                client:None,sources:Mutex::new(AndroidRegistrationSourceSlots::new_registered(audit_read,
                    WorkGate{slot:self.inner.android_registration_control.clone(),control:control.clone()},source_budget))});
            let (release,enter)=oneshot::channel();let (source_release,source_enter)=oneshot::channel();
            let source_worker=inspection_source_task(original.clone(),source_enter);
            let coordinator=coordinate_inspection(original.clone(),enter,source_release);
            let whole=inspection_admission_bytes(total,std::mem::size_of_val(&source_worker),std::mem::size_of_val(&coordinator))
                .ok_or_else(wire::unavailable)?;
            original.reservation.set(Reservation{whole,source:source_reservation}).map_err(|_|wire::unavailable())?;
            // All typed original slots, comparison operands and whole retained
            // census have been charged BEFORE either task or payload GO exists.
            // A lost reply from here on is unconfirmed, never pre-GO unavailable.
            if !self.inner.android_registration_control.install(control,&original.cohort,snapshot.reviewed.as_ref()){
                return Err(wire::unavailable());
            }
            registry.android_registration.review=None;
            registry.android_registration.generation=generation;
            registry.android_registration.active=Some(original.clone());
            let mut source_slot=match original.source_handle.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.control.mark_unknown(observed);registry.disabled=true;self.inner.bump(&mut registry);return Err(wire::unconfirmed());},
            };
            let mut coordinator_slot=match original.coordinator.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.control.mark_unknown(observed);registry.disabled=true;self.inner.bump(&mut registry);return Err(wire::unconfirmed());},
            };
            *source_slot=Some(executor.spawn_blocking(source_worker));
            *coordinator_slot=Some(executor.spawn(coordinator));
            drop(source_slot);drop(coordinator_slot);self.inner.bump(&mut registry);
            let status=match self.registration_status_locked(&mut registry,gate,observed){
                Ok(status)=>status,Err(_)=>{
                    // GO/reply loss after publication is an original negative,
                    // not pre-admission unavailable. Latch before reply/GO drop.
                    let failed_at=Instant::now();original.control.stop_at(wire::Reason::ResultLimit,failed_at);
                    return Err(wire::unconfirmed());
                },
            };
            Ok(Admitted{status,release:Some(InvokeEntry::Inspection(release)),original})
        }
    }
    pub(crate) fn cancel_android_tool_registration(&self,input:&wire::Cancel,publication:Option<&CancelPublisher>,
        gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        let mut registry=self.inner.lock();
        if let Some(publication)=publication {
            if !publication.original.matches(input) || !Arc::ptr_eq(&publication.slot,&self.inner.android_registration_control){
                publication.slot.poisoned();return Err(wire::unconfirmed());
            }
            if registry.android_registration.review.as_ref().is_some_and(|review|publication.matches(&review.original)
                && publication.reviewed.as_ref().is_some_and(|exact|exact.as_ptr()==Arc::as_ptr(review))) {
                registry.android_registration.stop(wire::Reason::Cancelled,publication.at());self.inner.bump(&mut registry);
            }
        }
        // An unmatched/stale Cancel is inert, including an old inspection ID
        // after transfer. It cannot be retargeted to the current registration.
        let observed=Instant::now();
        self.registration_status_locked(&mut registry,gate,observed).map_err(|_|wire::unconfirmed())
    }
}
/// Shared checked whole-owner expression for both production paths and the
/// catalogue DATA budget gate. `previous` is always the actual current
/// census, including an old full Review AND its retained closed-source original.
fn operation_admission_bytes(previous:usize,data:&wire::Operation,review_id:&String,instance:&String,
    control:&Control,phase_storage:usize)->Option<usize>{
    bounded_operation_sum(previous,operation_allocation_bytes(data,review_id,instance,control,phase_storage)?)
}
fn operation_allocation_bytes(data:&wire::Operation,review_id:&String,instance:&String,
    control:&Control,phase_storage:usize)->Option<usize>{
    arc_bytes::<Operation>()?.checked_add(operation_projection_bytes(data)?)?
        .checked_add(review_id.capacity())?.checked_add(instance.capacity())?
        .checked_add(control.retained_bytes()?)?.checked_add(phase_storage)?
        .checked_add(3usize.checked_mul(wire::STATUS_LIMIT)?)?
        .checked_add(3usize.checked_mul(wire::REQUEST_LIMIT)?)
}
fn bounded_operation_sum(previous:usize,added:usize)->Option<usize>{
    previous.checked_add(added).filter(|bytes|*bytes<=OWNED_LIMIT)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn inspection_task_bytes(source:usize,coordinator:usize)->Option<usize>{
    source.checked_add(coordinator)?
        .checked_add(2usize.checked_mul(std::mem::size_of::<SourceReturn>())?)?
        .checked_add(std::mem::size_of::<Finalization>())?
        .checked_add(2usize.checked_mul(SIGNAL_STORAGE)?)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn inspection_admission_bytes(base:usize,source:usize,coordinator:usize)->Option<usize>{
    bounded_operation_sum(base,inspection_task_bytes(source,coordinator)?)
}
// These are only the existing retained additions, not lifecycle predicates or
// constructors. Production keeps every identity/join/known-return gate above.
fn checked_allocation_bytes(request:&Request,id:&String,review_id:&String,instance:&String,source:&SourceSnapshot)->Option<usize>{
    std::mem::size_of::<Checked>().checked_add(request.retained_heap_bytes()?)?
        .checked_add(id.capacity())?.checked_add(review_id.capacity())?.checked_add(instance.capacity())?
        .checked_add(arc_bytes::<()>()?)? // SAME move-only admission identity allocation.
        .checked_add(arc_bytes::<SourceSnapshot>()?)?
        .checked_add(source.retained_bytes()?.checked_sub(std::mem::size_of::<SourceSnapshot>())?)
}
fn retained_operation_allocation_bytes(data:&wire::Operation,review_id:&String,instance:&String,control:&Control,
    source:&SourceSnapshot,returned_bytes:usize)->Option<usize>{
    arc_bytes::<Operation>()?.checked_add(operation_projection_bytes(data)?)?
        .checked_add(review_id.capacity())?.checked_add(instance.capacity())?
        .checked_add(control.retained_bytes()?)?.checked_add(arc_bytes::<()>()?)? // SAME Operation/cohort identity, counted once.
        .checked_add(arc_bytes::<SourceSnapshot>()?)?
        .checked_add(source.retained_bytes()?.checked_sub(std::mem::size_of::<SourceSnapshot>())?)?
        .checked_add(returned_bytes)
}
fn registration_allocation_bytes(service_bytes:usize,last:Option<&Last>)->Option<usize>{
    let mut bytes=std::mem::size_of::<Registration>()
        .checked_add(service_bytes.checked_sub(std::mem::size_of::<service_setup::State>())?)?;
    if let Some(last)=last{
        bytes=bytes.checked_add(operation_projection_bytes(&last.data)?)?
            .checked_add(last.report.as_ref().map_or(Some(0),report_bytes)?)?;
    }
    Some(bytes)
}
fn retained_review_projection_bytes(original_bytes:usize,public:&wire::Review)->Option<usize>{
    arc_bytes::<Review>()?.checked_add(original_bytes)?
        .checked_add(public.review_id.capacity())?.checked_add(public.context.retained_heap_bytes()?)?
        .checked_add(source_projection_bytes(&public.sources)?)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn registration_base_retained_bytes(document_bytes:usize,control_bytes:usize,runtime_heap:usize,sources_bytes:usize,
    catalog_bytes:usize,registration_bytes:usize,checked_bytes:usize)->Option<usize>{
    document_bytes.checked_add(arc_bytes::<Inner>()?)?.checked_add(SIGNAL_STORAGE)?
        .checked_add(control_bytes)?.checked_add(runtime_heap)?
        .checked_add(sources_bytes.checked_sub(std::mem::size_of::<android_sources::Sources>())?)?
        .checked_add(catalog_bytes.checked_sub(std::mem::size_of::<android_catalog::Catalog>())?)?
        .checked_add(registration_bytes.checked_sub(std::mem::size_of::<Registration>())?)?
        .checked_add(checked_bytes)
}

#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn registration_retained_bytes(inner:&Inner,registry:&Registry,document:&Arc<()>,checked:&Checked,
    census:&crate::asset_session::AndroidRegistrationCensus<'_>)->Option<usize>{
    // No hidden source/Review/native disposal or reconciliation in a census.
    // Prepared/active work is an admission conflict; stable Last is visited.
    if registry.active.is_some() || registry.prepared.is_some() || registry.recovery_review.is_some()
        || registry.recovery.is_some() || inner.toolchain.is_some(){return None;}
    #[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
        not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer")))]
    if inner.ios_observation.try_lock().ok()?.is_some(){return None;}
    #[cfg(all(test,debug_assertions,feature="development-runtime",not(feature="desktop-shell")))]
    if inner.fixture.try_lock().ok()?.is_some(){return None;}
    let binding=inner.android_document.try_lock().ok()?;
    if !binding.as_ref().is_some_and(|bound|bound.as_ptr()==Arc::as_ptr(document)){return None;}
    let control=inner.android_registration_control.book.try_lock().ok()?;
    // A settled Review retires its control mirror. A leftover mirror with no
    // active original is unresolved structure, not spare capacity for a new GO.
    if control.original.is_some() || ControlSlot::pending(&control) || inner.android_registration_control.is_unknown(){return None;}
    drop(control);
    let mut bytes=registration_base_retained_bytes(census.for_originals(document,checked.picker_originals())?,
        inner.android_registration_control.retained_bytes()?,inner.runtime.android_registration_retained_heap_bytes(document)?,
        registry.android_sources.retained_data_bytes()?,registry.android_catalog.registration_retained_bytes()?,
        registry.android_registration.retained_bytes(&checked.snapshot.source)?,checked.retained_bytes()?)?;
    if inner.android_service_dispatcher.get().is_some(){bytes=bytes.checked_add(arc_bytes::<service_setup::Dispatcher>()?)?;}
    #[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
        not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer")))]
    {bytes=bytes.checked_add(arc_bytes::<()>()?)?;} // Actual retained iOS fixture identity, even when its option is absent.
    if let Some(last)=&registry.last{
        let Context::AndroidBuild(context)=&last.context else{return None;};
        if last.stage.is_some_and(|stage|!matches!(stage,Stage::AndroidBuild(_))){return None;}
        bytes=bytes.checked_add(last.operation_id.capacity())?.checked_add(last.owner_generation.capacity())?
            .checked_add(context.retained_heap_bytes()?)?;
        if let Some(terminal)=&last.result{
            let Terminal::AndroidBuild(terminal)=terminal else{return None;};
            bytes=bytes.checked_add(terminal.retained_heap_bytes()?)?;
        }
    }
    (bytes<=OWNED_LIMIT).then_some(bytes)
}

#[cfg(all(test,target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
impl SavedCommandOwner {
    pub(crate) fn assert_android_catalogue_whole_owner_data_contract(){
        catalogue_budget_tests::genuine_catalogue_fits_fresh_inspect_retained_review_and_register_data();
    }
}

#[cfg(all(test,target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
mod catalogue_budget_tests {
    use super::*;
    use crate::android_supplier_macos_source::SourcePhase;

    fn sum(values:&[usize])->usize{
        values.iter().try_fold(0usize,|bytes,next|bytes.checked_add(*next)).unwrap()
    }
    fn control_data(slot:&Arc<ControlSlot>,lane:ControlLane,id:String,generation:u32)->Arc<Control>{
        let admitted=Instant::now();let work=admitted.checked_add(WORK).unwrap();let hard=admitted.checked_add(HARD).unwrap();
        let (stop,_)=watch::channel(false);let (audit,_)=watch::channel(hard);
        // No claim/install, AdmissionCohort, owner, GO, retirement or receipt.
        Arc::new(Control{lane,owner:Weak::new(),id,generation,admitted,work,hard,
            slot:Arc::downgrade(slot),cohort:Arc::new(()),epoch:0,first:Mutex::new(None),
            unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),
            latches:std::sync::atomic::AtomicUsize::new(0),stop,audit})
    }
    // Return-type inference only: never invoke either function item and never
    // create an Operation, closure value, coordinator future or executor.
    fn returned2<A,B,R,F:FnOnce(A,B)->R>(_:F)->usize{std::mem::size_of::<R>()}
    fn returned3<A,B,C,R,F:FnOnce(A,B,C)->R>(_:F)->usize{std::mem::size_of::<R>()}

    #[test]
    fn genuine_catalogue_fits_fresh_inspect_retained_review_and_register(){
        genuine_catalogue_fits_fresh_inspect_retained_review_and_register_data();
    }
    pub(super) fn genuine_catalogue_fits_fresh_inspect_retained_review_and_register_data(){
        let project_id="synthetic-catalogue-budget-project";
        let project=RegisteredRoot{path:"/synthetic-catalogue-budget-project-never-opened".into(),
            identity:crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let context=android_wire::Prepare{project_id:project_id.to_owned(),draft_revision:1,baseline_generation:1,
            saved_config:android_wire::Content{bytes:32,sha256:"a".repeat(64)},
            saved_version:android_wire::SavedVersion{source:"version.properties".to_owned(),bytes:20,
                sha256:"b".repeat(64),name:"1.0.0".to_owned(),build:1},
            artifact_validation:android_wire::ArtifactValidation{mode:android_wire::ValidationMode::StructureAndVersion,
                upload_certificate_sha256:None},signing:None};
        let document=Arc::new(());
        let roots=AndroidRegistrationSourceSlots::catalogue_maximal_roots_data();
        let census=crate::asset_session::catalogue_census_data(project_id,&project,&roots);
        let (sources,current,old)=android_sources::Sources::catalogue_allocation_data(project_id,&project,&roots,&census.pickers);
        assert!(!Arc::ptr_eq(&current,&old));
        assert!(current.picker_originals().iter().zip(old.picker_originals()).zip(&census.pickers)
            .all(|((current,old),picker)|Arc::ptr_eq(current,old)&&Arc::ptr_eq(current,picker)));

        let slot=Arc::new(ControlSlot::default());
        let old_id="0".repeat(32);let old_review_id="1".repeat(32);let old_instance="2".repeat(32);
        let inspect_id="3".repeat(32);let inspect_review_id="4".repeat(32);let inspect_instance="5".repeat(32);
        let register_id="6".repeat(32);let service_id="7".repeat(32);
        let old_control=control_data(&slot,ControlLane::Sources,old_id.clone(),2);
        let inspect_control=control_data(&slot,ControlLane::Sources,inspect_id.clone(),3);
        let register_control=control_data(&slot,ControlLane::Sources,register_id.clone(),3);
        let service_control=control_data(&slot,ControlLane::Service,service_id.clone(),1);
        let service=service_setup::CatalogueServiceData::new(wire::ServiceOperation{operation_id:service_id,
            setup_generation:1,source_generation:1,action:wire::ServiceAction::Check,context:context.clone()},service_control);
        let service_bytes=service.retained_bytes().unwrap();
        // The previous completed setup retains a dispatcher/manager charge.
        // These actual type/bound rows do not construct either native object.
        let dispatcher=arc_bytes::<service_setup::Dispatcher>().unwrap();
        let resources=std::path::Path::new(crate::macos_install_paths::PAYLOAD_EXECUTABLE)
            .parent().unwrap().parent().unwrap().join("Resources");
        let runtime=RuntimeConfig::packaged(resources);
        let runtime_heap=runtime.android_registration_retained_heap_bytes(&document).unwrap();
        let catalog=android_catalog::Catalog::default(); // No prior catalogue selection is needed.
        let catalog_bytes=catalog.registration_retained_bytes().unwrap();
        let sources_bytes=sources.retained_data_bytes().unwrap();

        let inspection=AndroidRegistrationSourceSlots::reservation(SourcePhase::Inspection).unwrap();
        let reproof=AndroidRegistrationSourceSlots::reservation(SourcePhase::Reproof).unwrap();
        let source=crate::android_supplier_macos::with_compiled_catalogue_data(|recipe,observed,provider,payload|
            AndroidRegistrationSourceSlots::catalogue_allocation_data(recipe,&roots,observed,provider,payload,
                old_instance.clone(),old_control.audit.subscribe(),inspection));
        let old_data=wire::Operation{operation_id:old_id,registration_generation:2,source_generation:1,
            kind:wire::Kind::Inspection,context:context.clone()};
        let public=wire::Review{review_id:old_review_id.clone(),source_generation:1,context:context.clone(),
            consent_version:wire::CONSENT,license_acknowledgment_required:true,sources:source.public_sources()};
        assert!(public.sources.iter().all(|source|!source.complete && source.compatibility==wire::Compatibility::Unavailable));
        let old_source_bytes=source.source_bytes();let source_review_bytes=source.review_bytes();
        let old_operation=retained_operation_allocation_bytes(&old_data,&old_review_id,&old_instance,
            &old_control,&old,old_source_bytes).unwrap();
        let old_review=sum(&[retained_review_projection_bytes(old_operation,&public).unwrap(),
            source_review_bytes.checked_sub(std::mem::size_of::<AndroidRegistrationSourceReview>()).unwrap()]);
        // Actual separate route String allocations, never a forged ReviewRoute.
        let route_operation=old_data.operation_id.clone();let route_review=public.review_id.clone();
        let fresh_slot=ControlSlot::allocation_bytes(None).unwrap();
        assert_eq!(slot.retained_bytes(),Some(fresh_slot));
        let review_slot=ControlSlot::allocation_bytes(Some((&route_operation,&route_review))).unwrap();
        assert_eq!(review_slot-fresh_slot,sum(&[route_operation.capacity(),route_review.capacity()]));

        let inspect_request=Request::Inspect(wire::Inspect{registration_generation:2,source_generation:1,context:context.clone()});
        let register_request=Request::Register(wire::Register{registration_generation:2,source_generation:1,
            review_id:old_review_id.clone(),context:context.clone()});
        let checked_inspect=checked_allocation_bytes(&inspect_request,&inspect_id,&inspect_review_id,&inspect_instance,&current).unwrap();
        let checked_register=checked_allocation_bytes(&register_request,&register_id,&old_review_id,&old_instance,&current).unwrap();
        let registration=registration_allocation_bytes(service_bytes,None).unwrap(); // Successful review publication clears Last.
        let observation_identity=if cfg!(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",
            feature="macos-installed-observation",not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),
            not(feature="macos-installed-installer"))){arc_bytes::<()>().unwrap()}else{0};
        let previous=|control_bytes,checked_bytes,review_bytes|sum(&[
            registration_base_retained_bytes(census.bytes,control_bytes,runtime_heap,sources_bytes,catalog_bytes,
                registration.checked_add(review_bytes).unwrap(),checked_bytes).unwrap(),dispatcher,observation_identity]);
        let fresh_previous=previous(fresh_slot,checked_inspect,0);
        let inspect_previous=previous(review_slot,checked_inspect,old_review);
        let register_previous=previous(review_slot,checked_register,old_review);
        let inspect_data=wire::Operation{operation_id:inspect_id,registration_generation:3,source_generation:1,
            kind:wire::Kind::Inspection,context:context.clone()};
        let register_data=wire::Operation{operation_id:register_id,registration_generation:3,source_generation:1,
            kind:wire::Kind::Registration,context};
        let source_task=returned2(inspection_source_task);let coordinator=returned3(coordinate_inspection);
        let inspection_tasks=inspection_task_bytes(source_task,coordinator).unwrap();
        let client=client::catalogue_client_rows(reproof.bytes());
        let inspect_added=operation_allocation_bytes(&inspect_data,&inspect_review_id,&inspect_instance,&inspect_control,inspection.bytes()).unwrap();
        let register_added=operation_allocation_bytes(&register_data,&old_review_id,&old_instance,&register_control,client.phase).unwrap();
        let cases=[
            ("fresh_inspect",fresh_previous,fresh_slot,checked_inspect,0,inspection.bytes(),inspect_added,inspection_tasks,
                sum(&[fresh_previous,inspect_added,inspection_tasks])),
            ("inspect_retained_review",inspect_previous,review_slot,checked_inspect,old_review,inspection.bytes(),inspect_added,inspection_tasks,
                sum(&[inspect_previous,inspect_added,inspection_tasks])),
            ("register_retained_review",register_previous,review_slot,checked_register,old_review,client.phase,register_added,0,
                sum(&[register_previous,register_added])),
        ];
        let (inspection_source,proposal_work)=inspection.catalogue_allocation_components();
        let (reproof_source,reproof_work)=reproof.catalogue_allocation_components();
        // Bounded numeric output only. ALL three raw checked totals are printed
        // before any whole-owner fit assertion, so over-cap remains evidence.
        eprintln!("catalogue_budget document_rows={:?}",census.rows);
        eprintln!("catalogue_budget common document={} owner_cells={} runtime_heap={} sources_heap={} catalog_heap={} service_heap={} dispatcher={} observation_identity={}",
            census.bytes,sum(&[arc_bytes::<Inner>().unwrap(),SIGNAL_STORAGE]),runtime_heap,
            sources_bytes.checked_sub(std::mem::size_of::<android_sources::Sources>()).unwrap(),
            catalog_bytes.checked_sub(std::mem::size_of::<android_catalog::Catalog>()).unwrap(),
            service_bytes.checked_sub(std::mem::size_of::<service_setup::State>()).unwrap(),dispatcher,observation_identity);
        eprintln!("catalogue_budget source inspection={} proposal_work={} reproof={} reproof_work={} old_source={} old_operation={} source_review={} proposal_heap={} old_review={} source_task={} coordinator={} inspection_tasks={}",
            inspection_source,proposal_work,reproof_source,reproof_work,old_source_bytes,old_operation,source_review_bytes,
            source.document_heap_bytes(),old_review,source_task,coordinator,inspection_tasks);
        eprintln!("catalogue_budget register client={} preparation={} settled={} phase={} tasks={} task_reserved={}",
            client.client,client.preparation,client.settled,client.phase,client.tasks,client.task_reserved);
        for (name,previous,control,checked,review,phase,added,tasks,total) in cases{
            eprintln!("catalogue_budget case={} previous={} control_slot={} checked={} retained_review={} phase={} new_owner={} final_tasks={} total={} limit={} headroom={} over={}",
                name,previous,control,checked,review,phase,added.checked_sub(phase).unwrap(),tasks,total,OWNED_LIMIT,
                OWNED_LIMIT.saturating_sub(total),total.saturating_sub(OWNED_LIMIT));
        }

        assert_eq!(inspection_source,reproof_source);
        assert_eq!(client.phase,sum(&[reproof.bytes().checked_add(client.settled).unwrap().max(client.preparation),client.client]));
        assert!(client.tasks<=client.task_reserved,"actual registration tasks exceed already-charged TASK_STORAGE");
        assert!(sum(&[old_source_bytes,source_review_bytes])<=inspection.bytes(),"full post-freeze source DATA exceeds original reservation");
        let admitted=[
            operation_admission_bytes(fresh_previous,&inspect_data,&inspect_review_id,&inspect_instance,&inspect_control,inspection.bytes())
                .and_then(|base|inspection_admission_bytes(base,source_task,coordinator)),
            operation_admission_bytes(inspect_previous,&inspect_data,&inspect_review_id,&inspect_instance,&inspect_control,inspection.bytes())
                .and_then(|base|inspection_admission_bytes(base,source_task,coordinator)),
            operation_admission_bytes(register_previous,&register_data,&old_review_id,&old_instance,&register_control,client.phase),
        ];
        for ((name,_,_,_,_,_,_,_,total),admitted) in cases.into_iter().zip(admitted){
            assert_eq!(admitted,(total<=OWNED_LIMIT).then_some(total),"{name}: actual production capped expression");
            assert!(total<=OWNED_LIMIT,"{name}: genuine catalogue exceeds unchanged whole-owner cap");
        }
        // Only the missing inspection final-addition boundaries; existing
        // base-operation, A-C phase/shape/parser regressions stay unchanged.
        let exact_base=OWNED_LIMIT.checked_sub(inspection_tasks).unwrap();
        assert_eq!(inspection_admission_bytes(exact_base,source_task,coordinator),Some(OWNED_LIMIT));
        assert_eq!(inspection_admission_bytes(exact_base+1,source_task,coordinator),None);
        assert_eq!(inspection_admission_bytes(usize::MAX,source_task,coordinator),None);
        assert_eq!(inspection_task_bytes(usize::MAX,1),None);
        assert_eq!(inspection_admission_bytes(0,usize::MAX,1),None);
        // Every holder above remains alive across all three sums. No fixture
        // calls native/source entry, sets accepted/returned flags, or admits GO.
        assert!(slot.book.lock().unwrap().original.is_none());
        assert!(!old_control.unknown.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod lifecycle_book_tests {
    // Inert control DATA and scoped std WAIT workers only. No Document, runtime,
    // source/native book, Review or positive production qualification is made.
    use super::*;

    #[test]
    fn whole_operation_budget_keeps_previous_charge_and_rejects_cap_or_overflow() {
        // Arithmetic only: neither these scalar inputs nor a Linux sizeof
        // prove the complete real-catalogue macOS admission high-water.
        assert_eq!(bounded_operation_sum(OWNED_LIMIT - 1, 1), Some(OWNED_LIMIT));
        assert_eq!(bounded_operation_sum(OWNED_LIMIT - 1, 2), None);
        assert_eq!(bounded_operation_sum(OWNED_LIMIT, 1), None);
        assert_eq!(bounded_operation_sum(usize::MAX, 1), None);
        assert_eq!(bounded_operation_sum(1, usize::MAX), None);
        assert_eq!(bounded_operation_sum(27, 53), Some(80));
        let (_slot, control, _cohort, _gate) = control_at(Instant::now());
        let data = wire::Operation { operation_id: "inert-budget-operation".to_owned(), registration_generation: 7,
            source_generation: 3, kind: wire::Kind::Inspection, context: android_wire::Prepare {
                project_id: "inert-budget-project".to_owned(), draft_revision: 1, baseline_generation: 1,
                saved_config: android_wire::Content { bytes: 32, sha256: "a".repeat(64) },
                saved_version: android_wire::SavedVersion { source: "version.properties".to_owned(), bytes: 20,
                    sha256: "b".repeat(64), name: "1.0.0".to_owned(), build: 1 },
                artifact_validation: android_wire::ArtifactValidation { mode: android_wire::ValidationMode::StructureAndVersion,
                    upload_certificate_sha256: None }, signing: None } };
        let review_id = "inert-review".to_owned(); let instance = "c".repeat(32);
        let added = arc_bytes::<Operation>().unwrap() + operation_projection_bytes(&data).unwrap()
            + review_id.capacity() + instance.capacity() + control.retained_bytes().unwrap()
            + 53 + 3 * wire::STATUS_LIMIT + 3 * wire::REQUEST_LIMIT;
        assert_eq!(operation_admission_bytes(27, &data, &review_id, &instance, &control, 53), Some(27 + added));
        assert_eq!(operation_admission_bytes(OWNED_LIMIT - added, &data, &review_id, &instance, &control, 53), Some(OWNED_LIMIT));
        assert_eq!(operation_admission_bytes(OWNED_LIMIT - added + 1, &data, &review_id, &instance, &control, 53), None);
        assert_eq!(operation_admission_bytes(27, &data, &review_id, &instance, &control, usize::MAX), None);
    }

    pub(super) fn control_at(admitted:Instant)->(Arc<ControlSlot>,Arc<Control>,AdmissionCohort,WorkGate) {
        control_in_lane(admitted,ControlLane::Sources)
    }
    pub(super) fn control_in_lane(admitted:Instant,lane:ControlLane)->(Arc<ControlSlot>,Arc<Control>,AdmissionCohort,WorkGate) {
        let slot=Arc::new(ControlSlot::default());
        let cohort=slot.claim(0,None).unwrap();
        let work=admitted+WORK;let hard=admitted+HARD;
        let (stop,_)=watch::channel(false);let (audit,_)=watch::channel(hard);
        let control=Arc::new(Control{lane,owner:Weak::new(),id:"inspection-original".to_owned(),generation:7,
            admitted,work,hard,slot:Arc::downgrade(&slot),cohort:cohort.identity.clone(),epoch:cohort.epoch,
            first:Mutex::new(None),unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),
            latches:AtomicUsize::new(0),stop,audit});
        assert!(slot.install(control.clone(),&cohort,None));
        let gate=WorkGate{slot:slot.clone(),control:control.clone()};
        (slot,control,cohort,gate)
    }

    fn observed_real_wait(slot:&ControlSlot)->bool {
        let end=Instant::now()+Duration::from_secs(3);
        let mut book=slot.book.lock().unwrap();
        while slot.wait_entries.load(Ordering::SeqCst)==0 {
            let remaining=end.saturating_duration_since(Instant::now());
            if remaining.is_zero(){return false;}
            book=slot.wait_observed.wait_timeout(book,remaining).unwrap().0;
        }
        // WORK publishes the counter while holding this SAME mutex. The test
        // cannot acquire it until the actual Condvar wait releases that guard.
        ControlSlot::pending(&book)
    }

    #[test]
    fn actual_worker_wait_resumes_same_original_after_conditional_rejection() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        std::thread::scope(|scope| {
            // Local to the scope body: panic drops this pending publisher and
            // wakes the original through poison BEFORE scoped worker joining.
            let publisher=slot.reserve(PublisherKind::General,false).unwrap();
            let worker=scope.spawn(move||gate.work());
            let waiting=observed_real_wait(&slot);
            let first=control.failure();let stopped=*control.stop.borrow();
            let epoch=slot.book.lock().unwrap().epoch;
            publisher.reject();
            let result=worker.join().unwrap();
            assert!(waiting);assert_eq!((first,stopped,epoch),(None,false,0));assert!(result.is_ok());
            assert_eq!(slot.epoch().unwrap(),0);assert!(control.failure().is_none());
        });
    }

    #[test]
    fn actual_worker_wait_expires_at_original_w_with_publisher_still_pending() {
        let admitted=Instant::now()-WORK+Duration::from_secs(2);
        let (slot,control,_cohort,gate)=control_at(admitted);
        assert!(Instant::now()<control.work);
        std::thread::scope(|scope| {
            let publisher=slot.reserve(PublisherKind::General,false).unwrap();
            let (returned,observe)=std::sync::mpsc::sync_channel(1);
            let worker=scope.spawn(move|| {
                let result=gate.work();
                let _=returned.send(());
                result
            });
            let waiting=observed_real_wait(&slot);
            // Test scheduling notice only, never a join receipt. On timeout
            // reject/wake before joining, so a WAIT regression cannot leak a
            // detached worker or leave a publisher alive through scope unwind.
            let returned_before_rejection=observe.recv_timeout(Duration::from_secs(4)).is_ok();
            let still_pending=ControlSlot::pending(&slot.book.lock().unwrap());
            publisher.reject();
            let result=worker.join().unwrap();
            assert!(waiting && returned_before_rejection && still_pending);
            assert_eq!(result,Err((wire::Reason::TimedOut,control.work)));
            assert_eq!(control.failure(),Some((wire::Reason::TimedOut,control.work)));
            assert_eq!(slot.epoch().unwrap(),0);
        });
    }

    #[test]
    fn rejected_conditional_preserves_the_same_original_without_f_or_epoch_change() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        assert!(ControlSlot::pending(&slot.book.lock().unwrap()));
        assert!(control.failure().is_none() && !*control.stop.borrow());
        assert_eq!(slot.book.lock().unwrap().epoch,0);
        publisher.reject();
        assert_eq!(slot.epoch().unwrap(),0);
        assert!(gate.work().is_ok());
        assert!(control.failure().is_none() && !*control.stop.borrow());
    }

    #[test]
    fn accepted_event_keeps_original_f_after_pending_projection_finishes() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        let mut publisher=slot.reserve(PublisherKind::General,false).unwrap();let first=publisher.at();
        publisher.accept(wire::Reason::ContextChanged).unwrap();
        assert!(slot.epoch().is_err()); // Publication still owes its original projection.
        assert_eq!(gate.work(),Err((wire::Reason::ContextChanged,first)));
        publisher.finish();
        assert_eq!(slot.epoch().unwrap(),1);
        assert_eq!(control.failure(),Some((wire::Reason::ContextChanged,first)));
        assert_eq!(control.endpoint(),(first+SETTLEMENT).min(control.hard));
    }

    #[test]
    fn original_w_expires_while_a_conditional_publisher_is_still_pending() {
        let admitted=Instant::now()-WORK-Duration::from_secs(1);
        let (slot,control,_cohort,gate)=control_at(admitted);
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        assert_eq!(gate.work(),Err((wire::Reason::TimedOut,control.work)));
        publisher.reject();
        assert_eq!(slot.epoch().unwrap(),0);
        assert_eq!(control.failure(),Some((wire::Reason::TimedOut,control.work)));
    }

    #[test]
    fn cleanup_imports_retained_f_before_stop_projection_and_never_waits_on_pending() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        // Pause the real accept ordering after SAME-book F publication but
        // before Control/watch projection. A mapped F may precede original T.
        let first=control.admitted-Duration::from_secs(1);
        slot.book.lock().unwrap().cohort.as_mut().unwrap().first=Some((wire::Reason::ContextChanged,first));
        assert!(control.failure().is_none() && !*control.stop.borrow());
        assert!(!gate.cleanup_expired(None));
        assert_eq!(control.failure(),Some((wire::Reason::ContextChanged,first)));
        assert_eq!(control.endpoint(),first+SETTLEMENT);
        // This outstanding conditional record cannot defer an independent
        // cleanup decision. Rejecting it does not erase the retained prior F.
        publisher.reject();
        assert_eq!(gate.first(),Some((wire::Reason::ContextChanged,first)));
    }

    #[test]
    fn cleanup_imports_durable_unknown_without_waiting_for_projected_control() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        slot.unknown.store(true,Ordering::SeqCst); // Poison publication/STOP gap.
        assert!(!control.unknown.load(Ordering::SeqCst));
        assert!(gate.cleanup_expired(None));
        assert!(control.unknown.load(Ordering::SeqCst));
        assert!(control.endpoint()<=control.admitted);
    }

    #[test]
    fn pending_and_admission_hold_exit_but_only_admission_is_resource_work() {
        let slot=Arc::new(ControlSlot::default());
        assert!(slot.can_exit() && !slot.owns_work() && slot.retained_bytes().is_some());
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        assert!(!slot.can_exit() && !slot.owns_work() && slot.retained_bytes().is_none());
        publisher.reject();
        let cohort=slot.claim(0,None).unwrap();
        assert!(!slot.can_exit() && slot.owns_work());
        drop(cohort);
        assert!(slot.can_exit() && !slot.owns_work());
        let mut publisher=slot.reserve(PublisherKind::General,false).unwrap();
        publisher.accept(wire::Reason::ContextChanged).unwrap();publisher.finish();
        assert_eq!(slot.epoch().unwrap(),1); // Persists through an empty mirror.
        assert!(!slot.matches_epoch(0) && slot.can_exit());
    }

    #[test]
    fn general_saturation_preserves_dedicated_lock_and_quit_lanes() {
        let slot=Arc::new(ControlSlot::default());
        let publishers:Vec<_>=(0..8).map(|_|slot.reserve(PublisherKind::General,false).unwrap()).collect();
        assert!(matches!(slot.reserve(PublisherKind::General,false),Err(error) if error.code=="busy"));
        assert!(!slot.is_unknown());
        let lock=slot.reserve(PublisherKind::CredentialLock,true).unwrap();
        let quit=slot.reserve(PublisherKind::Quit,true).unwrap();
        lock.reject();quit.reject();for publisher in publishers{publisher.reject();}
        assert!(slot.can_exit());
        let lost=slot.reserve(PublisherKind::General,false).unwrap();drop(lost);
        assert!(slot.is_unknown() && !slot.can_exit() && slot.retained_bytes().is_none());
    }

    #[test]
    fn cancel_matches_operation_and_generation_not_an_unrelated_renderer_id() {
        let (slot,control,_cohort,_gate)=control_at(Instant::now());
        let wrong_id=wire::Cancel{operation_id:"review-or-old-operation".to_owned(),registration_generation:7};
        let wrong_generation=wire::Cancel{operation_id:control.id.clone(),registration_generation:6};
        assert!(slot.reserve_cancel(&wrong_id).unwrap().is_none());
        assert!(slot.reserve_cancel(&wrong_generation).unwrap().is_none());
        assert!(control.failure().is_none());
        let exact=wire::Cancel{operation_id:control.id.clone(),registration_generation:7};
        let publication=slot.reserve_cancel(&exact).unwrap().unwrap();
        assert_eq!(control.failure(),Some((wire::Reason::Cancelled,publication.at())));
        assert!(slot.book.lock().unwrap().cancel.is_some());
        publication.finish();assert!(slot.book.lock().unwrap().cancel.is_none());
    }

    #[test]
    fn service_and_source_cancel_never_cross_route_even_with_identical_wire_comparisons() {
        for lane in [ControlLane::Sources,ControlLane::Service]{
            let(slot,control,_cohort,_gate)=control_in_lane(Instant::now(),lane);
            let source=wire::Cancel{operation_id:control.id.clone(),registration_generation:control.generation};
            let service=wire::ServiceCancel{operation_id:control.id.clone(),setup_generation:control.generation};
            let wrong=if lane==ControlLane::Sources{slot.reserve_service_cancel(&service)}else{slot.reserve_cancel(&source)};
            assert!(wrong.unwrap().is_none());assert!(control.failure().is_none());
            assert!(slot.book.lock().unwrap().cancel.is_none());
            let exact=if lane==ControlLane::Sources{slot.reserve_cancel(&source)}else{slot.reserve_service_cancel(&service)};
            let publication=exact.unwrap().unwrap();
            assert_eq!(control.failure(),Some((wire::Reason::Cancelled,publication.at())));
            publication.finish();assert!(slot.book.lock().unwrap().cancel.is_none());
        }
    }


    #[test]
    fn maintenance_uses_same_control_but_not_source_or_service_cancel_ids() {
        let(slot,control,_cohort,gate)=control_in_lane(Instant::now()-Duration::from_secs(2),ControlLane::Maintenance);
        let source=wire::Cancel{operation_id:control.id.clone(),registration_generation:control.generation};
        let service=wire::ServiceCancel{operation_id:control.id.clone(),setup_generation:control.generation};
        assert!(slot.reserve_cancel(&source).unwrap().is_none());
        assert!(slot.reserve_service_cancel(&service).unwrap().is_none());
        assert!(control.failure().is_none() && !*control.stop.borrow());
        let publisher=slot.reserve(PublisherKind::General,false).unwrap();
        let cutoff=control.admitted+Duration::from_secs(3);
        assert!(control.narrow_maintenance(cutoff));
        assert!(control.narrow_maintenance(control.hard));
        assert_eq!(control.endpoint(),cutoff);
        assert!(control.failure().is_none() && !*control.stop.borrow()); // R is not F.
        assert_eq!(gate.try_work(),Some(false)); // SAME pending publication still gates work.
        let expired=control.admitted+Duration::from_secs(1);
        assert!(!control.narrow_maintenance(expired));
        assert!(!control.narrow_maintenance(control.hard)); // Later input cannot renew the earlier cut.
        assert_eq!(control.endpoint(),expired);
        assert_eq!(gate.try_work(),None);
        assert!(gate.work().is_err() && control.unknown.load(Ordering::SeqCst));
        publisher.reject();
    }

    #[test]
    fn completed_cancel_between_initial_read_and_book_admission_is_not_proceed() {
        let (slot,control,_cohort,gate)=control_at(Instant::now());
        // Deterministically stage the lock-wait interleaving without a worker
        // scheduler/test hook: this is WORK's actual initial negative snapshot.
        assert!(control.failure().is_none());
        let exact=wire::Cancel{operation_id:control.id.clone(),registration_generation:7};
        let publication=slot.reserve_cancel(&exact).unwrap().unwrap();let first=publication.at();
        publication.finish();
        let book=slot.book.lock().unwrap();
        assert!(!ControlSlot::pending(&book) && book.epoch==control.epoch);
        assert!(book.cohort.as_ref().unwrap().first.is_none());
        // The real Proceed-cut helper must see the completed Cancel even
        // though neither pending nor global epoch/cohort-F can reveal it.
        assert_eq!(gate.admission_failure(&book),Ok(Some((wire::Reason::Cancelled,first))));
        drop(book);
        assert_eq!(gate.work(),Err((wire::Reason::Cancelled,first)));
    }
}
