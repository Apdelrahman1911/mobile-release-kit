//! Local Store domain on the original saved-command Session. No new supervisor.
use super::*;

impl Inner {
    pub(super) fn store_installed_selected(&self) -> bool {
        matches!(self.domain,SavedCommandDomain::AppleProvisioning|SavedCommandDomain::LocalStorePreflight|SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile) && cfg!(all(feature="desktop-shell",feature="custom-protocol",
            not(feature="development-runtime"),not(feature="macos-installed-installer"),not(feature="macos-android-registration-helper"),target_os="macos"))
            && store_wire::Profile::current().is_some() && match self.domain {SavedCommandDomain::AppleProvisioning=>self.runtime.apple_provisioning_installed_profile_available(),SavedCommandDomain::LocalStorePrepare=>self.runtime.local_store_prepare_installed_profile_available(),SavedCommandDomain::LocalStoreReconcile=>self.runtime.local_store_reconcile_installed_profile_available(),SavedCommandDomain::LocalStorePreflight=>self.runtime.local_store_preflight_installed_profile_available(),_=>false}
    }
}
impl SavedCommandOwner {
    pub(crate) fn local_store_preflight(runtime: RuntimeConfig) -> Self {Self::new(runtime,SavedCommandDomain::LocalStorePreflight)}
    pub(crate) fn prepare_store(&self,input:store_wire::Prepare,registration:u32,project:RegisteredRoot,
        gate:store_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<store_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;
        self.prepare_bound(Context::LocalStorePreflight(input.context()),registration,project,Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)),None)?.store()
    }
    pub(crate) fn prepared_store_material(&self,operation:&str,generation:&str)->Result<Arc<SelectedStoreMaterial>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;
        let registry=self.inner.lock();
        let prepared=registry.prepared.as_ref().filter(|p|p.projection.operation_id==operation&&p.projection.owner_generation==generation).ok_or_else(||self.inner.domain.invalid_owner())?;
        match &prepared.material{Some(PrivateSigningMaterial::Store(value))=>Ok(value.clone()),_=>Err(self.inner.domain.invalid_owner())}
    }
    pub(crate) fn start_store(&self,input:store_wire::Start,admitted_at:Instant,registered:Option<(u32,RegisteredRoot)>,
        gate:store_wire::Availability,material:Arc<SelectedStoreMaterial>)->Result<crate::local_store_preflight_owner::Admitted,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;
        // Parsed consent is not permission: match the same prepared private loan
        // before the existing owner may publish GO or private material.
        if !material.accepts_access_consent(&input){return Err(self.inner.domain.invalid_owner());}
        let admitted=self.start_bound(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},admitted_at,registered,
            Availability::from_store(gate),Some(PrivateSigningMaterial::Store(material)))?;
        Ok(crate::local_store_preflight_owner::Admitted::new(admitted.status.store()?,admitted.release))
    }
    pub(crate) fn status_store(&self,gate:store_wire::Availability)->Result<store_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;self.status(Availability::from_store(gate))?.store()
    }
    pub(crate) fn cancel_store(&self,operation:&str,generation:&str,gate:store_wire::Availability)->Result<store_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;self.cancel(operation,generation,Availability::from_store(gate))?.store()
    }
}

// The real close attempt always runs, even after POST fails. A later close
// cannot erase the original audit/identity/deadline failure.
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
fn checked_close_outcome(post_ok:bool,closed:CloseOutcome)->CloseOutcome {
    if post_ok { closed } else { CloseOutcome::Unknown }
}

pub(super) fn installed_final(book: &Resources) -> bool {
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        if !book.store_selected {
            return book.store_installed.is_none() && !book.store_started && !book.store_joined && !book.store_failed
                && book.store_settlement.is_none() && book.store_return.is_none();
        }
        book.store_started && book.store_joined && !book.store_failed && book.store_settlement.is_none()
            && matches!(book.store_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.store_installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { !book.store_selected && !book.store_started && !book.store_joined && !book.store_failed }
}

pub(super) fn closure_ready(r: &Registry, owner: &Session, claimed: bool, direct_returned: bool) -> bool {
    direct_returned && matches!(owner.domain,SavedCommandDomain::AppleProvisioning|SavedCommandDomain::LocalStorePreflight|SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile) && original_session(r, owner)
        && (!claimed || r.active.as_ref().is_some_and(|a| a.accepted && a.terminal
            && match a.projection.result.as_ref(){Some(Terminal::AppleProvisioning(t))=>owner.domain==SavedCommandDomain::AppleProvisioning&&t.lifetime.settled(),Some(Terminal::LocalStorePreflight(t))=>owner.domain==SavedCommandDomain::LocalStorePreflight&&t.lifetime.settled(),Some(Terminal::LocalStorePrepare(t))=>owner.domain==SavedCommandDomain::LocalStorePrepare&&t.lifetime.settled(),Some(Terminal::LocalStoreReconcile(t))=>owner.domain==SavedCommandDomain::LocalStoreReconcile&&t.lifetime.settled(),_=>false}))
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    matches!(owner.domain,SavedCommandDomain::AppleProvisioning|SavedCommandDomain::LocalStorePreflight|SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile) && inner.store_installed_selected()
        && inner.qualified(owner.android_selection.as_ref())
        && final_clock_clear(r, owner, now) && !inner.poisoned.load(Ordering::SeqCst)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current(owner.domain) == Some(owner.profile)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn transfer_installed(book: &Resources, inner: &Inner, owner: &Session) -> Result<(), BridgeError> {
    if !book.store_selected || !book.inspection_started || !book.inspection_joined || book.inspection_failed
        || book.inspection.is_some() || book.inspection_error.is_some() || book.acquisition_started
        || book.acquisition_joined || book.acquisition_failed || book.acquisition.is_some() || book.acquisition_error.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    let native = book.store_installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !claim_clear(inner, &r, owner, now) { return Err(owner.domain.unavailable()); }
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}

pub(super) async fn settle_installed(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    if !matches!(owner.domain,SavedCommandDomain::AppleProvisioning|SavedCommandDomain::LocalStorePreflight|SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile) { return; }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { let _ = (book, inner, owner); }
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let Some(native) = book.store_installed.clone() else {
            if book.store_selected { inner.unknown(owner); }
            return;
        };
        if !book.store_started {
            let returned = (|| {
                let slots = match native.try_lock() {
                    Ok(slots) => slots, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let startup = match owner.startup.try_lock() {
                    Ok(startup) => startup, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let r = inner.lock();
                closure_ready(&r, owner, startup.attempted,
                    if owner.domain==SavedCommandDomain::AppleProvisioning{apple_provisioning::consumers_returned(book,&startup,owner,slots.no_child_effect())}else{offline_consumers_returned(book, &startup, slots.no_child_effect())})
            })();
            if !book.store_selected || !returned { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            let original_owner = owner.clone();
            let (release, enter) = oneshot::channel();
            book.store_started = true;
            book.store_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                let mut slots = match native.lock() { Ok(slots) => slots,
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots } };
                #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
                {
                    let post = if slots.no_child_effect() { Ok(()) } else { slots.check_claimed_before_settlement(&mut |first|original_owner.native_cleanup_expired(first)) };
                    if let Err(failure)=post { original_owner.publish_native_failure(Some((failure,Instant::now()))); }
                    let closed=slots.settle_originals(&mut |first| original_owner.native_cleanup_expired(first));
                    // Independent consuming close even after Store POST/close failure.
                    let source_ok=!matches!(original_owner.domain,SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile)||local_history::finish_prepare_sources(&original_owner);
                    checked_close_outcome(post.is_ok()&&source_ok,closed)
                }
                #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
                { slots.settle_originals() }
            }));
            let _ = release.send(());
        }
        if !book.store_joined && !book.store_failed {
            if book.store_settlement.is_none() { inner.unknown(owner); return; }
            let result = join_with_clock(&mut book.store_settlement, inner, owner).await;
            let joined = result.is_ok();
            if book.store_return.is_some() { book.store_failed = true; }
            else { book.store_return = Some(result); book.store_joined = joined; book.store_failed = !joined; }
            if joined { book.store_settlement.take(); } else { native_worker_lost(book, owner); }
        }
        if !installed_final(book) { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn acquire_installed(inner:&Inner,owner:&Session,native:&Arc<Mutex<StoreRuntimeSlots>>){
    if !matches!(owner.domain,SavedCommandDomain::AppleProvisioning|SavedCommandDomain::LocalStorePreflight|SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile) || !inner.store_installed_selected(){inner.stop(owner,Reason::RuntimeUnavailable);return;}
    if matches!(owner.domain,SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile)&&local_history::prepare_source_post(owner).is_err(){inner.stop(owner,Reason::ContextChanged);return;}
    if owner.domain==SavedCommandDomain::AppleProvisioning && apple_provisioning::work_current(owner).is_err(){inner.stop(owner,Reason::ContextChanged);return;}
    let mut slots=match native.lock(){Ok(slots)=>slots,Err(_)=>{inner.unknown(owner);return;}};
    let mut loan=match slots.prepare_loan(&mut |first|owner.publish_native_failure(first)){
        Ok(loan)=>loan,Err(failure)=>{owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;}
    };
    let selected=loan.python_runtime();
    let mut command=Command::new(&selected.python);
    command.args(["-I","-S","-B"]).arg(&selected.bootstrap).arg(&selected.core).current_dir(&selected.cwd)
        .env_clear().env("LANG","C").env("LC_ALL","C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    if matches!(owner.domain,SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile)&&local_history::prepare_child(owner,&mut command).is_err(){loan.record_closed_spawn_gate();inner.stop(owner,Reason::ContextChanged);return;}
    if crate::runtime::macos_installed_environment(&mut command).is_err(){loan.record_closed_spawn_gate();inner.stop(owner,Reason::RuntimeUnavailable);return;}
    if let Err(failure)=loan.check_before_or_after_use(){
        loan.record_closed_spawn_gate();owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;
    }
    let mut startup=match owner.startup.lock(){Ok(startup)=>startup,Err(_)=>{loan.record_closed_spawn_gate();inner.unknown(owner);return;}};
    let mut r=inner.lock();let now=Instant::now();inner.advance_locked(&mut r,owner,now);
    if !claim_clear(inner,&r,owner,now){loan.record_closed_spawn_gate();return;}
    if startup.attempted||startup.returned||startup.failed||startup.child.is_some(){
        loan.record_closed_spawn_gate();owner.resource_unknown.store(true,Ordering::SeqCst);inner.unknown_locked(&mut r,owner);return;
    }
    startup.attempted=true;drop(r);
    match command.spawn(){
        Ok(child)=>{startup.child=Some(child);startup.returned=true;},
        Err(_)=>{startup.failed=true;owner.resource_unknown.store(true,Ordering::SeqCst);drop(startup);inner.stop(owner,Reason::RuntimeUnavailable);inner.unknown(owner);return;}
    }
    // Drop the pre_exec Arc loan held inside Command, retaining the actual
    // child first. Original source POST is still before writer GO publication.
    drop(command);drop(startup);
    if matches!(owner.domain,SavedCommandDomain::LocalStorePrepare|SavedCommandDomain::LocalStoreReconcile)&&local_history::prepare_source_post(owner).is_err(){inner.stop(owner,Reason::ContextChanged);}
    if owner.domain==SavedCommandDomain::AppleProvisioning {
        drop(loan);drop(slots);
        if apple_provisioning::work_current(owner).is_err(){inner.stop(owner,Reason::ContextChanged);}
    }
    // Lexical borrow ends, not ownership: the same claimed Book remains in
    // Session.resources until original child/writer/reader/task joins and POST.
}

// Payload/context originals are counted separately by Document's existing
// census. Bound the simultaneous copied DATA and original owner control cells,
// not process RSS or the trusted installed Book's separate128MiB reservation.
pub(crate) fn document_backing_bytes()->Option<usize>{
    let cells=[std::mem::size_of::<Inner>(),std::mem::size_of::<Registry>(),
        std::mem::size_of::<Prepared>(),std::mem::size_of::<Active>(),
        std::mem::size_of::<Session>(),std::mem::size_of::<Resources>(),
        std::mem::size_of::<Startup>()];
    let mut total=0usize;for size in cells{total=total.checked_add(size)?;}
    // Current request/body+serialized request, 2queued frames+decoder+terminal+
    // public projection/status. Four context copies bound by actual IPC limit.
    for (count,size) in [(2usize,store_wire::REQUEST_LIMIT),(6,store_wire::RESPONSE_LIMIT),
        (2,store_wire::STATUS_LIMIT),(4,store_wire::IPC_LIMIT),(6,4096),(1,1024),
        (3,4096),(32,std::mem::size_of::<usize>()*8),
        // Apple borrows two additional scalar slices, plus bounded typed header
        // rows. Original Payload/Fields storage is already in Document census.
        (2,std::mem::size_of::<(&str,&[u8])>()),(2,1024),(1,46)]{
        total=total.checked_add(count.checked_mul(size)?)?;
    }
    Some(total)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    #[test]
    fn local_store_failed_post_or_unknown_close_never_becomes_complete(){
        assert_eq!(checked_close_outcome(true,CloseOutcome::Settled),CloseOutcome::Settled);
        assert_eq!(checked_close_outcome(false,CloseOutcome::Settled),CloseOutcome::Unknown);
        assert_eq!(checked_close_outcome(true,CloseOutcome::Unknown),CloseOutcome::Unknown);
        assert_eq!(checked_close_outcome(false,CloseOutcome::Unknown),CloseOutcome::Unknown);
    }
    #[test]
    fn local_store_original_clock_and_private_backing_are_bounded(){
        let now=Instant::now();let clocks=Clocks::new(SavedCommandDomain::LocalStorePreflight,now);
        assert_eq!(clocks.work-now,Duration::from_secs(1200));
        assert_eq!(clocks.finality-now,Duration::from_secs(1210));
        let stop=now+Duration::from_secs(100);
        assert_eq!(clocks.settlement(Some(stop)),stop+SETTLEMENT);
        assert!(clocks.settlement(Some(clocks.work+Duration::from_secs(9)))<=clocks.finality);
        let backing=document_backing_bytes().unwrap();assert!(backing>store_wire::REQUEST_LIMIT);
        assert!(backing<1024*1024); // No native-control bytes hidden in private/doc census.
    }
}
