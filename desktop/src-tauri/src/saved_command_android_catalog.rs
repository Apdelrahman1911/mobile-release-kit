//! M2 protected-catalog transaction inside SavedCommandOwner. Routine Refresh
//! freezes metadata-only rows; full Recover is explicit and Choose is separate.
//! Original reader/coordinator and ONE close-tail slot are retained before GO.
//! No worker/DTO/renderer can mint an original selection or a join receipt.
use super::*;
use crate::android_toolchain_catalog as wire;
use std::sync::{Weak,TryLockError};
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
use crate::{installed_runtime::{LeasedAndroidCatalogSlots,CatalogMode,CatalogCandidate,RowCode},
    android_shared_lease_macos::{AppCloseTail,OriginalUseIdentity}};
const WORK:Duration=Duration::from_secs(60);
const HARD:Duration=Duration::from_secs(70);
#[derive(Default)]
pub(super) struct Catalog {
    generation:u32,capability:Option<Availability>,retired:Option<wire::Reason>,
    active:Option<Arc<Operation>>,published:Option<Arc<Published>>,
    last:Option<Arc<Operation>>,selected:Option<Arc<Selection>>,
}
pub(super) struct Selection {produced:Arc<Published>,data:android_wire::MacToolchainSelection}
struct Published {original:Arc<Operation>,entries:Vec<wire::Row>}
#[derive(Clone,Copy,PartialEq,Eq)]
enum RowKind {Busy,Interrupted,Refused,Metadata,Recovered}
struct FrozenRow {instance:String,occupants:u8,kind:RowKind,metadata:Option<wire::Entry>}
struct FrozenRows {rows:Vec<FrozenRow>,recovered:Option<android_wire::MacToolchainSelection>}
struct WorkerReturn {
    rows:Option<FrozenRows>,entered:bool,observations:bool,retained_bytes:Option<usize>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    tail:Option<AppCloseTail>,
}
/// Public only to this parent owner's private consuming witness, never a shell
/// constructor or an ID/Boolean factory.
pub(super) struct Operation {
    original:Weak<Inner>,document:Weak<()>,generation:u32,id:String,
    admitted:Instant,work:Instant,hard:Instant,pre_go_reservation:Option<usize>,
    stop:watch::Sender<bool>,audit:watch::Sender<Instant>,
    first:Mutex<Option<(wire::Reason,Instant)>>,unknown:AtomicBool,dirty:AtomicBool,
    worker:AsyncMutex<Option<JoinHandle<WorkerReturn>>>,
    worker_return:Mutex<Option<Result<WorkerReturn,tokio::task::JoinError>>>,
    coordinator:Mutex<Option<JoinHandle<bool>>>,
    coordinator_return:Mutex<Option<Result<bool,tokio::task::JoinError>>>,
    final_seen:AtomicBool,accepted_final:AtomicBool,worker_join_seen:AtomicBool,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    native:Mutex<LeasedAndroidCatalogSlots>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    control:Arc<AndroidUseControl>,
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    close:Arc<AndroidCloseSlot>,
}
pub(crate) struct Admitted {status:wire::Status,release:Option<oneshot::Sender<()>>,original:Arc<Operation>}
impl Admitted {
    /// DocumentBinding releases its admission lock BEFORE this sole GO edge.
    pub(crate) fn release(self)->Result<wire::Status,BridgeError>{
        if self.release.is_some_and(|release|release.send(()).is_err()){
            self.original.stop_at(wire::Reason::Cancelled,Instant::now());
            // Already admitted: never misclassify an unknown original as a
            // pre-admission unavailable error that would let UI ownership go.
            return Err(BridgeError::new("android_catalog_unconfirmed","The original catalog release was not confirmed."));
        }
        Ok(self.status)
    }
}
fn selected_bytes(value:&android_wire::MacToolchainSelection)->Option<usize>{
    [&value.instance,&value.record_sha256,&value.inventory_sha256,&value.os_provider_sha256]
        .iter().try_fold(0usize,|n,s|n.checked_add(s.capacity()))
}
fn versions_bytes(value:&wire::Versions)->Option<usize>{
    [&value.jdk_vendor,&value.jdk_version,&value.gradle_version,&value.agp_version,
        &value.sdk_platform,&value.sdk_build_tools_version].iter().try_fold(0usize,|n,s|n.checked_add(s.capacity()))
}
impl FrozenRows {
    fn retained_bytes(&self)->Option<usize>{
        let mut bytes=std::mem::size_of::<Self>().checked_add(self.rows.capacity().checked_mul(std::mem::size_of::<FrozenRow>())?)?;
        for row in &self.rows {
            bytes=bytes.checked_add(row.instance.capacity())?;
            if let Some(value)=&row.metadata{bytes=bytes.checked_add(selected_bytes(&value.selection)?)?.checked_add(versions_bytes(&value.versions)?)?;}
        }
        if let Some(recovered)=&self.recovered{bytes=bytes.checked_add(selected_bytes(recovered)?)?;}
        Some(bytes)
    }
    // Constructs bounded frozen DATA; a pre-tail call is validation only.
    // Only the final Ready reconciler may publish these rows. Metadata never
    // upgrades itself: only the matching full-recovery candidate can do that.
    fn publish(&self,generation:u32)->Option<Vec<wire::Row>>{
        if self.rows.len()>wire::ENTRY_LIMIT{return None;}
        let mut entries=Vec::with_capacity(self.rows.len());let mut verified=0usize;
        for row in &self.rows {
            if entries.iter().any(|before:&wire::Row|before.instance==row.instance){return None;}
            let (status,versions,recovery,selection)=match row.kind {
                RowKind::Busy|RowKind::Interrupted|RowKind::Refused=>{
                    if row.metadata.is_some(){return None;}
                    (match row.kind{RowKind::Busy=>wire::RowStatus::Busy,RowKind::Interrupted=>wire::RowStatus::Interrupted,_=>wire::RowStatus::Refused},None,None,None)
                },
                RowKind::Metadata=>{
                    let m=row.metadata.as_ref()?;
                    (wire::RowStatus::RecoveryRequired,Some(m.versions.clone()),Some(wire::Comparison::of(&m.selection)),None)
                },
                RowKind::Recovered=>{
                    let m=row.metadata.as_ref()?;
                    if self.recovered.as_ref()!=Some(&m.selection){return None;}
                    verified=verified.checked_add(1)?;
                    (wire::RowStatus::VerifiedThisSession,Some(m.versions.clone()),None,Some(m.selection.clone()))
                },
            };
            let value=wire::Row{instance:row.instance.clone(),occupants:row.occupants,status,versions,recovery,selection};
            if !value.valid(generation){return None;}entries.push(value);
        }
        if verified!=usize::from(self.recovered.is_some()){return None;}
        Some(entries)
    }
    fn recovery_selection(&self,input:&wire::Recover)->Option<android_wire::MacToolchainSelection>{
        let row=self.rows.iter().find(|row|row.kind==RowKind::Metadata && row.instance==input.instance)?;
        let selected=&row.metadata.as_ref()?.selection;
        input.matches_selection(selected).then(||selected.clone())
    }
}
impl Operation {
    fn original_matches(&self,inner:&Inner)->bool{
        self.original.upgrade().is_some_and(|original|std::ptr::eq(original.as_ref(),inner))
            && self.document.upgrade().is_some_and(|document|inner.android_original_document_matches(Some(&document)))
    }
    fn changed(&self){
        self.dirty.store(true,Ordering::SeqCst);
        if let Some(inner)=self.original.upgrade(){inner.changes.send_modify(|_|{});inner.changed.notify_one();}
    }
    fn mark_unknown(&self){
        self.unknown.store(true,Ordering::SeqCst);
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        self.control.mark_unknown();
        self.changed();
    }
    fn local_failure(&self)->Option<(wire::Reason,Instant)>{
        match self.first.lock(){
            Ok(first)=>*first,
            Err(_)=>{self.mark_unknown();Some((wire::Reason::CleanupUnknown,self.admitted))},
        }
    }
    fn stop_at(&self,reason:wire::Reason,at:Instant){
        // Preserve the genuine LOCAL captured point before the old local clamp.
        // Inverse-mapped remote F is never fed into this method.
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        self.control.local(at,at,reason==wire::Reason::CleanupUnknown);
        let at=at.max(self.admitted).min(self.work);
        let mut changed=false;
        match self.first.lock(){
            Ok(mut first)=>if first.is_none_or(|(_,before)|at<before){*first=Some((reason,at));changed=true;},
            Err(_)=>{self.mark_unknown();changed=true;},
        }
        if reason==wire::Reason::CleanupUnknown{self.mark_unknown();}
        let end=self.endpoint();
        changed|=self.audit.send_if_modified(|current|if end<*current{*current=end;true}else{false});
        changed|=self.stop.send_if_modified(|value|if !*value{*value=true;true}else{false});
        if changed{self.changed();}
    }
    fn failure(&self)->Option<(wire::Reason,Instant)>{
        let local=self.local_failure();
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            let data=self.control.data();
            let raw=data.failure.and_then(|f|f.first_instant);
            let first=match(local.map(|(_,at)|at),raw){(Some(a),Some(b))=>Some(a.min(b)),(a,b)=>a.or(b)};
            return first.map(|at|(local.map_or(wire::Reason::CatalogUnavailable,|(reason,_)|reason),at));
        }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {local}
    }
    fn endpoint(&self)->Instant{
        let local=self.local_failure().map(|(_,at)|at);
        let end=local.and_then(|at|at.checked_add(SETTLEMENT)).map_or(self.hard,|end|end.min(self.hard));
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {return self.control.cutoff(local,end);}
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {end}
    }
    fn sample_control(&self){
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            let data=self.control.data();
            if data.unknown && !self.unknown.swap(true,Ordering::SeqCst){self.changed();}
            let end=self.endpoint();
            let mut changed=self.audit.send_if_modified(|current|if end<*current{*current=end;true}else{false});
            if data.unknown || data.local_first.is_some() || data.failure.is_some_and(|f|f.first.is_some()){
                changed|=self.stop.send_if_modified(|value|if !*value{*value=true;true}else{false});
            }
            if changed{self.changed();}
        }
    }
    fn tick(&self,now:Instant){
        self.sample_control();
        if now>=self.work && self.failure().is_none(){self.stop_at(wire::Reason::TimedOut,self.work);}
        if now>=self.endpoint() && !self.unknown.load(Ordering::SeqCst){self.mark_unknown();}
    }
    fn known_observations(&self)->bool{
        self.worker_join_seen.load(Ordering::SeqCst) && self.worker_return.lock().is_ok_and(|returned|
            matches!(returned.as_ref(),Some(Ok(value)) if value.observations && value.retained_bytes.is_some()))
    }
    fn known_originals(&self)->bool{
        if self.unknown.load(Ordering::SeqCst) || !self.known_observations(){return false;}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {return self.close.known();}
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {false}
    }
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn join_witness_matches(&self,identity:&OriginalUseIdentity)->bool{
        self.control.identity().same_original(identity) && !self.unknown.load(Ordering::SeqCst)
            && self.known_observations() && self.worker.try_lock().is_ok_and(|slot|slot.is_none())
    }
    /// Only after a lost/returned coordinator: consume a late actual Ready
    /// result from its SAME original handle. Never launch close or repair F.
    fn poll_late_originals(&self){
        if !self.final_seen.load(Ordering::SeqCst){return;}
        if !self.worker_join_seen.load(Ordering::SeqCst){
            if let Ok(mut slot)=self.worker.try_lock(){
                if slot.is_some(){
                    let waker=Waker::from(Arc::new(FinalWake(self.original.clone())));
                    let mut context=TaskContext::from_waker(&waker);
                    let _=poll_android_original(&mut slot,&self.worker_return,&self.worker_join_seen,
                        &mut context,||self.mark_unknown());
                }
            }
        }
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        if !self.close.join_seen.load(Ordering::SeqCst){
            if let Ok(mut slot)=self.close.handle.try_lock(){
                if slot.is_some(){
                    let waker=Waker::from(Arc::new(FinalWake(self.original.clone())));
                    let mut context=TaskContext::from_waker(&waker);
                    let _=self.close.poll_original(&mut slot,&mut context);
                }
            }
        }
    }
}
impl Selection {
    pub(super) fn data(&self)->&android_wire::MacToolchainSelection{&self.data}
    pub(super) fn matches_owner(&self,inner:&Inner)->bool{
        let original=&self.produced.original;
        original.accepted_final.load(Ordering::SeqCst) && original.final_seen.load(Ordering::SeqCst)
            && original.original_matches(inner) && original.known_originals() && original.failure().is_none()
            && self.data.valid() && original.generation==self.data.catalog_generation
            && self.produced.entries.iter().any(|entry|entry.status==wire::RowStatus::VerifiedThisSession
                && entry.selection.as_ref()==Some(&self.data))
    }
}
impl Catalog {
    /// Finite prior/current Catalog holdings for the app-M2 admission census.
    /// No lifecycle mutation, native/book access or post-tail probing. The
    /// worker froze its positive retained charge BEFORE moving the close tail;
    /// that conservative charge is retained, never changed to zero by release.
    #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
    pub(super) fn registration_retained_bytes(&self)->Option<usize>{
        fn arc<T>()->Option<usize>{
            let (layout,_)=std::alloc::Layout::new::<[usize;2]>().extend(std::alloc::Layout::new::<T>()).ok()?;
            Some(layout.pad_to_align().size())
        }
        fn visit_operation(value:&Arc<Operation>,seen:&mut [usize;4],used:&mut usize)->Option<usize>{
            let identity=Arc::as_ptr(value) as usize;
            if seen[..*used].contains(&identity){return Some(0);}
            if *used==seen.len(){return None;}seen[*used]=identity;*used+=1;
            if value.unknown.load(Ordering::SeqCst) || !value.final_seen.load(Ordering::SeqCst)
                || !value.accepted_final.load(Ordering::SeqCst) || !value.worker_join_seen.load(Ordering::SeqCst){return None;}
            let source=value.worker.try_lock().ok()?;
            let coordinator=value.coordinator.try_lock().ok()?;
            let _first=value.first.try_lock().ok()?;
            let source_return=value.worker_return.try_lock().ok()?;
            let coordinator_return=value.coordinator_return.try_lock().ok()?;
            if source.is_some() || coordinator.is_some()
                || !matches!(coordinator_return.as_ref(),Some(Ok(true))) || !value.close.retained_known(){return None;}
            let Some(Ok(returned))=source_return.as_ref()else{return None;};
            if !returned.observations || returned.tail.is_some(){return None;}
            // The frozen charge includes the Operation inline cells but not
            // its Arc control cells. Spare native/row capacities are not lost.
            arc::<Operation>()?.checked_add(returned.retained_bytes?.checked_sub(std::mem::size_of::<Operation>())?)
        }
        fn visit_publication(value:&Arc<Published>,publications:&mut [usize;2],publications_used:&mut usize,
            operations:&mut [usize;4],operations_used:&mut usize)->Option<usize>{
            let identity=Arc::as_ptr(value) as usize;
            if publications[..*publications_used].contains(&identity){return Some(0);}
            if *publications_used==publications.len(){return None;}
            publications[*publications_used]=identity;*publications_used+=1;
            let mut bytes=arc::<Published>()?
                .checked_add(value.entries.capacity().checked_mul(std::mem::size_of::<wire::Row>())?)?
                .checked_add(visit_operation(&value.original,operations,operations_used)?)?;
            if value.entries.len()>wire::ENTRY_LIMIT{return None;}
            for row in &value.entries{
                bytes=bytes.checked_add(row.instance.capacity())?;
                if let Some(versions)=&row.versions{bytes=bytes.checked_add(versions_bytes(versions)?)?;}
                if let Some(selected)=&row.selection{bytes=bytes.checked_add(selected_bytes(selected)?)?;}
                if let Some(comparison)=&row.recovery{
                    bytes=[&comparison.instance,&comparison.record_sha256,&comparison.inventory_sha256,&comparison.os_provider_sha256]
                        .into_iter().try_fold(bytes,|sum,text|sum.checked_add(text.capacity()))?;
                }
            }
            Some(bytes)
        }
        let mut operations=[0;4];let mut operations_used=0;
        let mut publications=[0;2];let mut publications_used=0;
        let mut bytes=std::mem::size_of::<Self>();
        for value in [self.active.as_ref(),self.last.as_ref()].into_iter().flatten(){
            bytes=bytes.checked_add(visit_operation(value,&mut operations,&mut operations_used)?)?;
        }
        if let Some(value)=&self.published{
            bytes=bytes.checked_add(visit_publication(value,&mut publications,&mut publications_used,&mut operations,&mut operations_used)?)?;
        }
        if let Some(value)=&self.selected{
            bytes=bytes.checked_add(arc::<Selection>()?)?.checked_add(selected_bytes(&value.data)?)?
                .checked_add(visit_publication(&value.produced,&mut publications,&mut publications_used,&mut operations,&mut operations_used)?)?;
        }
        Some(bytes)
    }
    pub(super) fn selection(&self)->Option<&Arc<Selection>>{self.selected.as_ref()}
    pub(super) fn selection_matches(&self,selected:Option<&Arc<Selection>>,inner:&Inner)->bool{
        match(self.selected.as_ref(),selected){
            (Some(current),Some(selected))=>Arc::ptr_eq(current,selected)&&selected.matches_owner(inner),
            (None,None)=>true,_=>false,
        }
    }
    pub(super) fn busy(&self)->bool{self.active.is_some()}
    pub(super) fn unknown(&self)->bool{self.active.as_ref().is_some_and(|o|o.unknown.load(Ordering::SeqCst))}
    pub(super) fn stop(&mut self,reason:wire::Reason,at:Instant)->bool{
        let changed=self.selected.is_some()||self.published.is_some()||self.active.is_some();
        if self.selected.is_some()||self.published.is_some(){self.retired=Some(reason);}
        self.selected=None;self.published=None;
        if let Some(active)=&self.active{active.stop_at(reason,at);}
        changed
    }
    pub(super) fn exhaust(&mut self){
        self.stop(wire::Reason::CleanupUnknown,Instant::now());
        if let Some(active)=&self.active{active.mark_unknown();}
    }
    /// Called with Registry held: only original control and frozen return DATA
    /// plus the exact original coordinator handle. Never native/book getters.
    pub(super) fn reconcile(&mut self,inner:&Inner)->bool{
        if self.active.is_none(){
            // A post-retirement control observation is a negative-only veto.
            // It never extends a deadline or retrospectively certifies a close.
            if let Some(published)=self.published.as_ref(){
                let original=published.original.clone();original.sample_control();
                if !original.known_originals() || original.failure().is_some(){
                    original.mark_unknown();self.selected=None;self.published=None;
                    self.active=Some(original);return true;
                }
            }
            return false;
        }
        let Some(original)=self.active.as_ref().cloned()else{return false;};
        original.tick(Instant::now());
        let mut changed=original.dirty.swap(false,Ordering::SeqCst);
        if original.final_seen.load(Ordering::SeqCst){original.poll_late_originals();return changed;}
        let mut slot=match original.coordinator.try_lock(){
            Ok(slot)=>slot,Err(TryLockError::WouldBlock)=>return changed,
            Err(TryLockError::Poisoned(_))=>{original.mark_unknown();return true;},
        };
        if slot.is_none(){original.mark_unknown();return true;}
        let waker=Waker::from(Arc::new(FinalWake(original.original.clone())));
        let mut context=TaskContext::from_waker(&waker);
        let Poll::Ready(recorded)=poll_android_original(&mut slot,&original.coordinator_return,
            &original.final_seen,&mut context,||original.mark_unknown())else{return changed;};
        let positive=original.coordinator_return.lock().is_ok_and(|returned|matches!(returned.as_ref(),Some(Ok(true))));
        if !recorded || !positive || !original.known_originals(){
            original.mark_unknown();original.poll_late_originals();return true;
        }
        original.sample_control();
        if Instant::now()>=original.endpoint() || original.unknown.load(Ordering::SeqCst){
            original.mark_unknown();return true;
        }
        // Strict actual coordinator Ready/finality edge. Selection remains a
        // separate later Choose, even after full Recover has now finalized.
        let mut entries=if original.failure().is_none() && original.original_matches(inner){
            match original.worker_return.lock(){
                Ok(returned)=>match returned.as_ref(){
                    Some(Ok(value))=>value.rows.as_ref().and_then(|rows|rows.publish(original.generation)),
                    _=>None,
                },
                Err(_)=>None,
            }
        }else{None};
        original.sample_control();
        if !original.known_originals() || Instant::now()>=original.endpoint(){
            original.mark_unknown();return true;
        }
        if original.failure().is_some(){entries=None;}
        else if entries.is_none() || !original.original_matches(inner){original.mark_unknown();return true;}
        original.accepted_final.store(true,Ordering::SeqCst);
        slot.take();
        self.published=entries.map(|entries|Arc::new(Published{original:original.clone(),entries}));
        self.last=Some(original.clone());self.active=None;changed=true;
        changed
    }
    fn status(&self,inner:&Inner,revision:u32,availability:Availability)->Result<wire::Status,BridgeError>{
        let active=self.active.as_ref();let operation=active.or(self.last.as_ref());
        let reason=if active.is_none()&&self.published.is_none()&&self.retired.is_some(){self.retired.unwrap()}
            else{operation.map_or(wire::Reason::NotInspected,|op|{
                if op.unknown.load(Ordering::SeqCst){wire::Reason::CleanupUnknown}
                else{op.failure().map_or(wire::Reason::None,|first|first.0)}
            })};
        let phase=if active.is_some(){
            if self.unknown(){wire::Phase::Unknown}else if active.is_some_and(|op|op.failure().is_some()){wire::Phase::Stopping}
            else{wire::Phase::Reading}
        }else if self.published.is_some(){wire::Phase::Ready}
        else if operation.is_some(){
            if matches!(reason,wire::Reason::Cancelled|wire::Reason::DocumentLost|wire::Reason::Shutdown){wire::Phase::Cancelled}
            else{wire::Phase::Refused}
        }else{wire::Phase::Idle};
        let entries=self.published.as_ref().filter(|p|p.original.original_matches(inner))
            .map_or_else(Vec::new,|p|p.entries.clone());
        let selected=self.selected.as_ref().filter(|s|s.matches_owner(inner)).map(|s|s.data.clone());
        let status=wire::Status{schema_version:1,status_revision:revision,catalog_generation:self.generation,
            operation_id:operation.map(|o|o.id.clone()),availability:availability.android(),phase,reason,entries,selected};
        crate::edit_protocol::bounded(&status,wire::STATUS_LIMIT)?;Ok(status)
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn freeze_candidate(candidate:CatalogCandidate,generation:u32)->Option<FrozenRows>{
    if candidate.rows.len()>wire::ENTRY_LIMIT{return None;}
    let mut rows=Vec::with_capacity(candidate.rows.len());
    for row in candidate.rows {
        let mut instance=String::with_capacity(32);
        const HEX:&[u8;16]=b"0123456789abcdef";
        for byte in row.instance{instance.push(HEX[usize::from(byte>>4)]as char);instance.push(HEX[usize::from(byte&15)]as char);}
        if !(1..=7).contains(&row.occupants)||rows.iter().any(|before:&FrozenRow|before.instance==instance){return None;}
        let kind=match row.code{RowCode::Busy=>RowKind::Busy,RowCode::Interrupted=>RowKind::Interrupted,
            RowCode::Refused=>RowKind::Refused,RowCode::RecoveryRequired=>RowKind::Metadata,RowCode::VerifiedCandidate=>RowKind::Recovered};
        let metadata=row.metadata.map(|value|wire::Entry{selection:value.selection,versions:value.versions});
        if matches!(kind,RowKind::Metadata|RowKind::Recovered)!=metadata.is_some()
            || metadata.as_ref().is_some_and(|m|!m.selection.valid()||m.selection.catalog_generation!=generation||m.selection.instance!=instance){return None;}
        rows.push(FrozenRow{instance,occupants:row.occupants,kind,metadata});
    }
    let result=FrozenRows{rows,recovered:candidate.recovery};
    // Pre-tail DATA validation only; these temporary rows are never published.
    result.publish(generation)?;Some(result)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn pre_tail_charge(original:&Operation,native:&LeasedAndroidCatalogSlots,rows:Option<&FrozenRows>)->Option<usize>{
    // Snapshot BEFORE tail movement, never re-query a retired book. These
    // positive retained books/metadata charges do not become fake zero at close.
    // Reserve publication/status comparison copies additively, not instead of
    // worker/native/tool data or the close ledger and fixed result/handle slot.
    original.pre_go_reservation?.checked_add(original.id.capacity())?
        .checked_add(std::mem::size_of::<WorkerReturn>())?
        .checked_add(native.retained_bytes()?)?
        .checked_add(AndroidUseControl::retained_control_charge()?)?
        .checked_add(AndroidCloseSlot::fixed_charge()?)?
        .checked_add(rows.map_or(Some(0),FrozenRows::retained_bytes)?)?
        .checked_add(3usize.checked_mul(wire::STATUS_LIMIT)?)?
        .checked_add(wire::ENTRY_LIMIT.checked_mul(std::mem::size_of::<crate::installed_runtime::CatalogRow>())?)
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn observe_native(original:&Operation,failure:AdmissionFailure,at:Instant){
    original.stop_at(match failure{AdmissionFailure::Deadline=>wire::Reason::TimedOut,
        AdmissionFailure::Unknown=>wire::Reason::CleanupUnknown,_=>wire::Reason::CatalogUnavailable},at);
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
fn worker(original:Arc<Operation>,enter:oneshot::Receiver<()>)->WorkerReturn{
    let go=enter.blocking_recv().is_ok();
    let mut native=match original.native.lock(){
        Ok(native)=>native,Err(error)=>{original.mark_unknown();let mut native=error.into_inner();native.mark_interrupted();native},
    };
    if !go || *original.stop.borrow() || Instant::now()>=original.work || original.unknown.load(Ordering::SeqCst){
        if original.failure().is_none(){original.stop_at(wire::Reason::Cancelled,Instant::now());}
        // This constructor NEVER entered its query/native inspector. Distinct
        // no-entry DATA, not a synthetic native freeze/close or helper receipt.
        let retained_bytes=pre_tail_charge(&original,&native,None);
        return WorkerReturn{rows:None,entered:false,observations:original.control.unarmed()&&retained_bytes.is_some(),
            retained_bytes,tail:None};
    }
    let first=original.local_failure().map(|(_,at)|at);
    let inspected=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        native.inspect_once(original.generation,original.admitted,original.work,original.hard,first,&original.stop.subscribe())));
    let rows=match inspected{
        Ok(Ok(value))=>match freeze_candidate(value,original.generation){
            Some(rows)=>Some(rows),None=>{original.stop_at(wire::Reason::CleanupUnknown,Instant::now());None},
        },
        Ok(Err(issue))=>{
            let at=native.first_failure().map_or_else(Instant::now,|(_,at)|at);
            observe_native(&original,crate::installed_runtime::android_lease_admission_issue(issue),at);None
        },
        Err(_)=>{native.mark_interrupted();original.stop_at(wire::Reason::CleanupUnknown,Instant::now());None},
    };
    if let Some((failure,at))=native.first_failure(){observe_native(&original,failure,at);}
    let cleanup=original.endpoint();
    let observed=native.settle_observations(cleanup,&original.audit.subscribe(),
        &mut|failure,at|observe_native(&original,failure,at))==CloseOutcome::Settled && native.observations_settled();
    if let Some((failure,at))=native.first_failure(){observe_native(&original,failure,at);}
    let retained_bytes=pre_tail_charge(&original,&native,rows.as_ref());
    if !observed || retained_bytes.is_none(){
        original.mark_unknown();return WorkerReturn{rows,entered:true,observations:false,retained_bytes,tail:None};
    }
    // Last native/book operation. Every row/common dependent observation is
    // frozen before ANY original SH consuming close may enter.
    let tail=native.take_close_tail();
    match tail{
        Ok(tail)=>WorkerReturn{rows,entered:true,observations:true,retained_bytes,tail:Some(tail)},
        Err(_)=>{original.mark_unknown();WorkerReturn{rows,entered:true,observations:false,retained_bytes,tail:None}},
    }
}
#[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
async fn coordinate(original:Arc<Operation>,enter:oneshot::Receiver<()>,release:oneshot::Sender<()>)->bool{
    let mut stopped=original.stop.subscribe();let mut changed=original.audit.subscribe();
    let ready=tokio::select!{
        value=enter=>value.is_ok(),
        _=stopped.changed()=>false,
        _=tokio::time::sleep_until(tokio::time::Instant::from_std(original.work))=>{
            original.stop_at(wire::Reason::TimedOut,original.work);false
        },
    };
    let current=original.original.upgrade().is_some_and(|inner|{
        let registry=inner.lock();
        !registry.disabled&&!registry.exhausted&&!registry.stopping&&!registry.document_lost&&!inner.poisoned.load(Ordering::SeqCst)
            && registry.android_catalog.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,&original))
            && original.original_matches(&inner)
    });
    if ready&&current&&!*original.stop.borrow()&&Instant::now()<original.work{
        if release.send(()).is_err(){original.stop_at(wire::Reason::Cancelled,Instant::now());}
    }else{original.stop_at(wire::Reason::Cancelled,Instant::now());drop(release);}
    // Existing sole coordinator remains independent of both original blocking
    // workers. It retains and actually consumes each SAME JoinHandle. Reaching
    // H marks Unknown, but never substitutes timeout for a missing Ready.
    let mut worker=original.worker.lock().await;
    if worker.is_none(){original.mark_unknown();return false;}
    let recorded=loop{
        original.tick(Instant::now());
        let unknown=original.unknown.load(Ordering::SeqCst);
        let deadline=if unknown{None}else{Some(if original.failure().is_some(){original.endpoint()}else{original.work})};
        tokio::select!{
            recorded=std::future::poll_fn(|context|poll_android_original(&mut worker,&original.worker_return,
                &original.worker_join_seen,context,||original.mark_unknown()))=>break recorded,
            _=changed.changed()=>{},
            _=clock_wait(deadline)=>{},
            _=tokio::time::sleep(android_leased::CONTROL_POLL),if !unknown=>{},
        }
    };
    if recorded{worker.take();}
    drop(worker);
    if !recorded||!original.known_observations()||original.unknown.load(Ordering::SeqCst){
        original.mark_unknown();return false;
    }
    let mut close_started=false;let mut no_entry=false;
    let prepared={
        let mut returned=match original.worker_return.lock(){Ok(returned)=>returned,Err(_)=>{original.mark_unknown();return false;}};
        match returned.as_mut(){
            Some(Ok(value)) if value.entered&&value.tail.is_some()=>{
                let joins=AndroidOriginalJoins(AndroidJoinedOriginal::Catalog(original.clone()));
                close_started=original.close.start(&mut value.tail,joins);close_started
            },
            Some(Ok(value)) if !value.entered&&value.tail.is_none()=>{no_entry=true;true},
            _=>false,
        }
    };
    // The synchronous no-entry witness may inspect frozen worker-return DATA;
    // release that return's mutex before it accepts the genuine join.
    let prepared=prepared && (!no_entry || original.close.finish_unentered(
        AndroidOriginalJoins(AndroidJoinedOriginal::Catalog(original.clone()))));
    if !prepared{original.mark_unknown();return false;}
    if close_started{
        // No Registry/Document/native/resource-book lock is held. Only this
        // original independent handle/control slot is borrowed while waiting.
        let mut handle=original.close.handle.lock().await;
        if handle.is_none(){original.mark_unknown();return false;}
        let recorded=loop{
            original.tick(Instant::now());
            let unknown=original.unknown.load(Ordering::SeqCst);
            let deadline=if unknown{None}else{Some(original.endpoint())};
            tokio::select!{
                recorded=std::future::poll_fn(|context|original.close.poll_original(&mut handle,context))=>break recorded,
                _=changed.changed()=>{},
                _=clock_wait(deadline)=>{},
                _=tokio::time::sleep(android_leased::CONTROL_POLL),if !unknown=>{},
            }
        };
        if recorded{handle.take();}
        drop(handle);
    }
    // After first tail entry: frozen actual returns + same retained control
    // only. No wrapper/native-book bytes/settled/failure lookup is permitted.
    original.sample_control();
    original.known_originals()&&Instant::now()<original.endpoint()
}
impl SavedCommandOwner {
    fn catalog_gate(&self,r:&Registry,gate:Availability)->Availability{
        if r.disabled||r.exhausted||self.inner.poisoned.load(Ordering::SeqCst)||r.android_catalog.unknown()
            ||r.android_sources.unknown()||r.android_registration.unknown()
            ||gate==Availability::CleanupUnknown{return Availability::CleanupUnknown;}
        if r.stopping||gate==Availability::Shutdown{return Availability::Shutdown;}
        if r.document_lost||gate==Availability::DocumentLost{return Availability::DocumentLost;}
        if self.inner.domain!=SavedCommandDomain::AndroidBuild
            || !cfg!(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))){return Availability::UnsupportedPlatform;}
        if !self.inner.android_runtime_selected(None){return Availability::RuntimeUnqualified;}
        if r.active.is_some()||r.android_catalog.busy()||r.android_sources.busy()
            ||r.android_registration.busy()||gate==Availability::Busy{return Availability::Busy;}
        gate
    }
    fn catalog_snapshot(&self,r:&mut Registry,gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        let availability=self.catalog_gate(r,Availability::from_android(gate));
        if r.android_catalog.capability!=Some(availability){r.android_catalog.capability=Some(availability);self.inner.bump(r);}
        if r.exhausted||self.inner.poisoned.load(Ordering::SeqCst){return Err(BridgeError::cleanup_unknown());}
        r.android_catalog.status(&self.inner,r.revision,availability)
    }
    pub(crate) fn android_catalog_status(&self,gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        self.reconcile();let mut r=self.inner.lock();self.catalog_snapshot(&mut r,gate)
    }
    pub(crate) fn refresh_android_catalog(&self,document:&Arc<()>,admitted_at:Instant,gate:android_wire::Availability)->Result<Admitted,BridgeError>{
        self.admit_android_catalog(document,admitted_at,None,gate)
    }
    pub(crate) fn recover_android_catalog(&self,document:&Arc<()>,admitted_at:Instant,input:wire::Recover,
        gate:android_wire::Availability)->Result<Admitted,BridgeError>{
        self.admit_android_catalog(document,admitted_at,Some(input),gate)
    }
    fn admit_android_catalog(&self,document:&Arc<()>,admitted_at:Instant,recover:Option<wire::Recover>,
        gate:android_wire::Availability)->Result<Admitted,BridgeError>{
        self.reconcile();let mut r=self.inner.lock();
        let availability=self.catalog_gate(&r,Availability::from_android(gate));
        if availability!=Availability::Available||!self.inner.android_original_document_matches(Some(document)){
            return Err(if availability==Availability::Busy{self.inner.domain.busy()}else{wire::unavailable()});
        }
        #[cfg(not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper"))))]
        {let _=(admitted_at,recover);Err(wire::unavailable())}
        #[cfg(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),not(feature="macos-android-registration-helper")))]
        {
            let recovery=if let Some(input)=recover{
                if !crate::android_build_protocol::Profile::current().is_some_and(crate::android_supplier_macos::available_for){return Err(wire::unavailable());}
                let produced=r.android_catalog.published.as_ref().ok_or_else(wire::invalid)?;
                if !produced.original.accepted_final.load(Ordering::SeqCst)||!produced.original.original_matches(&self.inner)
                    ||!produced.original.known_originals()||produced.original.failure().is_some()
                    ||!produced.entries.iter().any(|row|input.matches_recovery(row)){return Err(wire::invalid());}
                let returned=produced.original.worker_return.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                match returned.as_ref(){
                    Some(Ok(value))=>Some(value.rows.as_ref().and_then(|rows|rows.recovery_selection(&input)).ok_or_else(wire::invalid)?),
                    _=>return Err(wire::invalid()),
                }
            }else{None};
            let executor=tokio::runtime::Handle::try_current().map_err(|_|wire::unavailable())?;
            let generation=match r.android_catalog.generation.checked_add(1).filter(|g|*g<u32::MAX){
                Some(next)=>next,None=>{r.disabled=true;r.android_catalog.exhaust();self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            let id=nonce(SavedCommandDomain::AndroidBuild)?;
            if r.android_catalog.last.as_ref().is_some_and(|last|last.id==id){return Err(wire::unavailable());}
            let work=admitted_at.checked_add(WORK).ok_or_else(wire::unavailable)?;
            let hard=admitted_at.checked_add(HARD).ok_or_else(wire::unavailable)?;
            if Instant::now()>=work{return Err(wire::unavailable());}
            let (stop,_)=watch::channel(false);let (audit,audit_read)=watch::channel(hard);
            let native=LeasedAndroidCatalogSlots::new(recovery.map_or(CatalogMode::Refresh,CatalogMode::Recover),audit_read);
            let control=AndroidUseControl::reserved(native.original_identity(),native.query_signal(),native.original_clock_slot(),
                mrk_macos_installed_native::android_catalog_query::Role::Catalog,admitted_at,work,hard);
            let close=AndroidCloseSlot::reserved(executor.clone(),control.clone());
            // Pre-GO additive fixed/native/control publication reservation.
            // Later deep retained charges are EXTRA, not substituted zeros.
            let pre_go_reservation=std::mem::size_of::<Operation>().checked_add(id.capacity())
                .and_then(|bytes|bytes.checked_add(native.retained_bytes()?))
                .and_then(|bytes|bytes.checked_add(AndroidUseControl::retained_control_charge()?))
                .and_then(|bytes|bytes.checked_add(AndroidCloseSlot::fixed_charge()?))
                .and_then(|bytes|bytes.checked_add(3usize.checked_mul(wire::STATUS_LIMIT)?));
            if pre_go_reservation.is_none(){return Err(wire::unavailable());}
            let original=Arc::new(Operation{original:Arc::downgrade(&self.inner),document:Arc::downgrade(document),
                generation,id,admitted:admitted_at,work,hard,pre_go_reservation,stop,audit,
                first:Mutex::new(None),unknown:AtomicBool::new(false),dirty:AtomicBool::new(false),
                worker:AsyncMutex::new(None),worker_return:Mutex::new(None),coordinator:Mutex::new(None),
                coordinator_return:Mutex::new(None),final_seen:AtomicBool::new(false),accepted_final:AtomicBool::new(false),
                worker_join_seen:AtomicBool::new(false),native:Mutex::new(native),control,close});
            let (release,enter)=oneshot::channel();let (native_release,native_enter)=oneshot::channel();
            self.inner.retire_prepared(&mut r,Reason::ContextChanged);
            r.android_catalog.selected=None;r.android_catalog.published=None;r.android_catalog.retired=None;
            // Original roster/close/result slots are published BEFORE task
            // creation or either GO. No post-admission error means unavailable.
            r.android_catalog.generation=generation;r.android_catalog.active=Some(original.clone());
            let mut worker_slot=match original.worker.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.mark_unknown();r.disabled=true;self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            let mut coordinator_slot=match original.coordinator.try_lock(){
                Ok(slot)=>slot,Err(_)=>{original.mark_unknown();r.disabled=true;self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());},
            };
            *worker_slot=Some(executor.spawn_blocking({let original=original.clone();move||worker(original,native_enter)}));
            *coordinator_slot=Some(executor.spawn(coordinate(original.clone(),enter,native_release)));
            drop(coordinator_slot);drop(worker_slot);self.inner.bump(&mut r);
            let status=self.catalog_snapshot(&mut r,gate).map_err(|_|BridgeError::new(
                "android_catalog_unconfirmed","The admitted original catalog status was not confirmed."))?;
            drop(r);self.reconcile(); // Retain actual completion wake before GO.
            Ok(Admitted{status,release:Some(release),original})
        }
    }
    pub(crate) fn select_android_catalog(&self,input:wire::Select,gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        self.reconcile();let mut r=self.inner.lock();
        if self.catalog_gate(&r,Availability::from_android(gate))!=Availability::Available{return Err(wire::unavailable());}
        let produced=r.android_catalog.published.as_ref().cloned().ok_or_else(wire::invalid)?;
        if !produced.original.accepted_final.load(Ordering::SeqCst)||!produced.original.original_matches(&self.inner)
            ||!produced.original.known_originals()||produced.original.failure().is_some(){return Err(wire::invalid());}
        let data=produced.entries.iter().find(|row|input.matches(row)).and_then(|row|row.selection.clone()).ok_or_else(wire::invalid)?;
        self.inner.retire_prepared(&mut r,Reason::ContextChanged);
        r.android_catalog.selected=Some(Arc::new(Selection{produced,data}));self.inner.bump(&mut r);
        self.catalog_snapshot(&mut r,gate).map_err(|_|BridgeError::new(
            "android_catalog_unconfirmed","The original tool selection result was not confirmed."))
    }
    pub(crate) fn cancel_android_catalog(&self,input:wire::Cancel,gate:android_wire::Availability)->Result<wire::Status,BridgeError>{
        let mut r=self.inner.lock();
        let original=r.android_catalog.active.as_ref().or(r.android_catalog.last.as_ref()).filter(|op|
            op.generation==input.catalog_generation&&op.id==input.operation_id).cloned().ok_or_else(wire::invalid)?;
        if r.android_catalog.active.as_ref().is_some_and(|active|Arc::ptr_eq(active,&original)){
            original.stop_at(wire::Reason::Cancelled,Instant::now());self.inner.bump(&mut r);
        }
        drop(r);self.android_catalog_status(gate).map_err(|_|BridgeError::new(
            "android_catalog_unconfirmed","The original catalog cancellation result was not confirmed."))
    }
}
#[cfg(all(test,not(all(target_os="macos",target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
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
            generation:1,id:"a".repeat(32),admitted,work,hard,pre_go_reservation:None,stop,audit,
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

#[cfg(test)]
mod frozen_row_data_tests {
    use super::*;
    fn entry()->wire::Entry{
        wire::Entry{selection:android_wire::MacToolchainSelection{instance:"a".repeat(32),owner_uid:501,catalog_generation:2,
            record_sha256:"b".repeat(64),inventory_sha256:"c".repeat(64),os_provider_sha256:"d".repeat(64)},
            versions:wire::Versions{jdk_vendor:"Example".into(),jdk_version:"21".into(),gradle_version:"8.13".into(),
                agp_version:"8.9.2".into(),sdk_platform:"35".into(),sdk_build_tools_version:"35.0.0".into()}}
    }
    #[test]
    fn metadata_union_requires_explicit_full_recovery_before_any_selection_data(){
        let mut data=FrozenRows{rows:vec![FrozenRow{instance:"a".repeat(32),occupants:7,kind:RowKind::Metadata,metadata:Some(entry())}],
            recovered:None};
        let rows=data.publish(2).unwrap();
        assert_eq!(rows[0].status,wire::RowStatus::RecoveryRequired);
        assert!(rows[0].selection.is_none()&&rows[0].recovery.is_some());
        data.rows[0].kind=RowKind::Recovered;
        assert!(data.publish(2).is_none());
        data.recovered=Some(entry().selection);
        assert_eq!(data.publish(2).unwrap()[0].status,wire::RowStatus::VerifiedThisSession);
        // Even that is only DATA: actual Selection requires the real accepted
        // Operation final edge, same original document and frozen close result.
        data.recovered.as_mut().unwrap().inventory_sha256="e".repeat(64);
        assert!(data.publish(2).is_none());
        assert!(data.retained_bytes().is_some_and(|bytes|bytes>0));
    }
    #[test]
    fn negative_union_rows_are_visible_and_never_claim_versions_or_selection(){
        let data=FrozenRows{rows:vec![
            FrozenRow{instance:"1".repeat(32),occupants:1,kind:RowKind::Busy,metadata:None},
            FrozenRow{instance:"2".repeat(32),occupants:2,kind:RowKind::Interrupted,metadata:None},
            FrozenRow{instance:"3".repeat(32),occupants:4,kind:RowKind::Refused,metadata:None},
        ],recovered:None};
        let rows=data.publish(2).unwrap();assert_eq!(rows.len(),3);
        assert!(rows.iter().all(|row|row.selection.is_none()&&row.recovery.is_none()&&row.versions.is_none()));
    }
}

/// Read-only loan of the same published catalog original. It is not a build
/// capability, a new catalog worker, or a renderer-deserializable root identity.
pub(crate) struct ArtifactToolLoan {original:Arc<Inner>,selected:Arc<Selection>}
impl ArtifactToolLoan {
    pub(crate) fn current(&self)->bool {
        let Ok(r)=self.original.registry.try_lock() else{return false;};
        !self.original.poisoned.load(Ordering::SeqCst)&&!r.disabled&&!r.exhausted&&!r.stopping&&!r.document_lost
            &&!r.android_catalog.unknown()&&!r.android_catalog.busy()&&!r.android_registration.unknown()
            &&!r.android_registration.busy()&&!self.original.android_registration_control.is_unknown()
            &&r.android_catalog.selection().is_some_and(|v|Arc::ptr_eq(v,&self.selected))&&self.selected.matches_owner(&self.original)
    }
    pub(crate) fn selected_data(&self)->Option<&android_wire::MacToolchainSelection>{self.current().then_some(self.selected.data())}
}
impl SavedCommandOwner {
    pub(crate) fn artifact_tool_loan(&self,document:&Arc<()>)->Result<Option<Arc<ArtifactToolLoan>>,BridgeError>{
        if self.inner.domain!=SavedCommandDomain::AndroidBuild||!self.inner.android_original_document_matches(Some(document)){return Err(BridgeError::cleanup_unknown());}
        let r=self.inner.lock();
        if r.disabled||r.exhausted||r.stopping||r.document_lost||r.android_catalog.unknown()||r.android_catalog.busy()
            ||r.android_registration.unknown()||r.android_registration.busy()||self.inner.android_registration_control.is_unknown()
            ||self.inner.poisoned.load(Ordering::SeqCst){return Err(BridgeError::cleanup_unknown());}
        match r.android_catalog.selection(){None=>Ok(None),Some(selected) if selected.matches_owner(&self.inner)=>
            Ok(Some(Arc::new(ArtifactToolLoan{original:self.inner.clone(),selected:selected.clone()}))),Some(_)=>Err(BridgeError::cleanup_unknown())}
    }
}
