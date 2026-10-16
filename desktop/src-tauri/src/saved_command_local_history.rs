//! One local history domain in the same original saved Session. This source is
//! not a generic RPC/callback runner; native phases below are a closed sequence.
use super::*;
impl Inner {
    pub(super) fn history_installed_selected(&self)->bool{
        self.domain==SavedCommandDomain::LocalReleaseHistory && cfg!(all(feature="desktop-shell",feature="custom-protocol",
            not(feature="development-runtime"),not(feature="macos-installed-installer"),not(feature="macos-android-registration-helper"),target_os="macos"))
            && history_wire::Profile::current().is_some() && self.runtime.local_release_history_installed_profile_available()
    }
}
impl SavedCommandOwner {
    pub(crate) fn local_release_history(runtime:RuntimeConfig)->Self{Self::new(runtime,SavedCommandDomain::LocalReleaseHistory)}
    pub(crate) fn prepare_history(&self,input:history_wire::Prepare,registration:u32,root:RegisteredRoot,gate:history_wire::Availability,
        consent:Arc<crate::asset_session::LocalHistoryConsent>)->Result<history_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        let status=self.prepare(Context::LocalReleaseHistory(input.context()),registration,root,Availability::from_history(gate))?;
        let mut r=self.inner.lock();
        let p=r.prepared.as_mut().ok_or_else(||self.inner.domain.invalid_owner())?;
        if p.local_history.is_some(){return Err(self.inner.domain.invalid_owner());}
        p.local_history=Some(consent);status.history()
    }
    pub(crate) fn prepared_history_consent(&self,operation:&str,generation:&str)->Result<Arc<crate::asset_session::LocalHistoryConsent>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        let r=self.inner.lock();let p=r.prepared.as_ref().filter(|p|p.projection.operation_id==operation&&p.projection.owner_generation==generation)
            .ok_or_else(||self.inner.domain.invalid_owner())?;
        p.local_history.clone().ok_or_else(||self.inner.domain.invalid_owner())
    }
    pub(crate) fn start_history(&self,input:history_wire::Start,admitted_at:Instant,registered:Option<(u32,RegisteredRoot)>,gate:history_wire::Availability)
        ->Result<crate::local_release_history_owner::Admitted,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        self.prepared_history_consent(&input.operation_id,&input.owner_generation)?;
        let a=self.start(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},admitted_at,registered,Availability::from_history(gate))?;
        Ok(crate::local_release_history_owner::Admitted::new(a.status.history()?,a.release))
    }
    pub(crate) fn status_history(&self,gate:history_wire::Availability)->Result<history_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;self.status(Availability::from_history(gate))?.history()
    }
    pub(crate) fn cancel_history(&self,operation:&str,generation:&str,gate:history_wire::Availability)->Result<history_wire::Status,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;self.cancel(operation,generation,Availability::from_history(gate))?.history()
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
        if !book.history_selected {
            return book.history_installed.is_none() && !book.history_started && !book.history_joined && !book.history_failed
                && book.history_settlement.is_none() && book.history_return.is_none();
        }
        book.history_started && book.history_joined && !book.history_failed && book.history_settlement.is_none()
            && matches!(book.history_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.history_installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { !book.history_selected && !book.history_started && !book.history_joined && !book.history_failed }
}

pub(super) fn closure_ready(r: &Registry, owner: &Session, claimed: bool, direct_returned: bool) -> bool {
    direct_returned && owner.domain == SavedCommandDomain::LocalReleaseHistory && original_session(r, owner)
        && (!claimed || r.active.as_ref().is_some_and(|a| a.accepted && a.terminal
            && matches!(a.projection.result.as_ref(), Some(Terminal::LocalReleaseHistory(t)) if t.lifetime.settled())))
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    owner.domain == SavedCommandDomain::LocalReleaseHistory && inner.history_installed_selected()
        && inner.qualified(owner.android_selection.as_ref())
        && final_clock_clear(r, owner, now) && !inner.poisoned.load(Ordering::SeqCst)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current(owner.domain) == Some(owner.profile)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn transfer_installed(book: &Resources, inner: &Inner, owner: &Session) -> Result<(), BridgeError> {
    if !book.history_selected || !book.inspection_started || !book.inspection_joined || book.inspection_failed
        || book.inspection.is_some() || book.inspection_error.is_some() || book.acquisition_started
        || book.acquisition_joined || book.acquisition_failed || book.acquisition.is_some() || book.acquisition_error.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    let native = book.history_installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !claim_clear(inner, &r, owner, now) { return Err(owner.domain.unavailable()); }
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}

pub(super) async fn settle_installed(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    if owner.domain != SavedCommandDomain::LocalReleaseHistory { return; }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { let _ = (book, inner, owner); }
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let Some(native) = book.history_installed.clone() else {
            if book.history_selected { inner.unknown(owner); }
            return;
        };
        if !book.history_started {
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
                    offline_consumers_returned(book, &startup, slots.no_child_effect()))
            })();
            if !book.history_selected || !returned { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            let original_owner = owner.clone();
            let (release, enter) = oneshot::channel();
            book.history_started = true;
            book.history_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                let mut slots = match native.lock() { Ok(slots) => slots,
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots } };
                #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
                {
                    let post = if slots.no_child_effect() { Ok(()) } else { slots.capability().and_then(|capability| capability.check_before_settlement(&mut |first|original_owner.native_cleanup_expired(first))) };
                    if let Err(failure)=post { original_owner.publish_native_failure(Some((failure,Instant::now()))); }
                    let closed=slots.settle_originals(&mut |first| original_owner.native_cleanup_expired(first));
                    let sources=native::finish_sources(&original_owner);
                    checked_close_outcome(post.is_ok()&&sources,closed)
                }
                #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
                { slots.settle_originals() }
            }));
            let _ = release.send(());
        }
        if !book.history_joined && !book.history_failed {
            if book.history_settlement.is_none() { inner.unknown(owner); return; }
            let result = join_with_clock(&mut book.history_settlement, inner, owner).await;
            let joined = result.is_ok();
            if book.history_return.is_some() { book.history_failed = true; }
            else { book.history_return = Some(result); book.history_joined = joined; book.history_failed = !joined; }
            if joined { book.history_settlement.take(); } else { native_worker_lost(book, owner); }
        }
        if !installed_final(book) { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn acquire_installed(inner:&Inner,owner:&Session,native:&Arc<Mutex<LocalHistoryRuntimeSlots>>){
    if owner.domain!=SavedCommandDomain::LocalReleaseHistory || !inner.history_installed_selected(){inner.stop(owner,Reason::RuntimeUnavailable);return;}
    if native::check_source(owner).is_err(){inner.stop(owner,Reason::ContextChanged);return;}
    let mut slots=match native.lock(){Ok(slots)=>slots,Err(_)=>{inner.unknown(owner);return;}};
    let capability=match slots.capability(){
        Ok(capability)=>capability,Err(failure)=>{owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;}
    };
    let stop=owner.stop.subscribe();
    let selected=match capability.prepare_once_observed(owner.clocks.work,&stop,&mut |first|owner.publish_native_failure(first)){
        Ok(selected)=>selected,Err(failure)=>{owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;}
    };
    let mut command=Command::new(&selected.python);
    command.args(["-I","-S","-B"]).arg(&selected.bootstrap).arg(&selected.core).current_dir(&selected.cwd)
        .env_clear().env("LANG","C").env("LC_ALL","C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    if let Err(failure)=capability.claim_once(){
        owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;
    }
    if native::child_command(owner,&mut command).is_err(){capability.record_closed_spawn_gate();inner.stop(owner,Reason::ContextChanged);return;}
    if crate::runtime::macos_installed_environment(&mut command).is_err(){capability.record_closed_spawn_gate();inner.stop(owner,Reason::RuntimeUnavailable);return;}
    if let Err(failure)=capability.check_before_or_after_use(owner.clocks.work,&stop){
        capability.record_closed_spawn_gate();owner.publish_native_failure(Some((failure,Instant::now())));inner.stop(owner,Reason::RuntimeUnavailable);return;
    }
    let mut startup=match owner.startup.lock(){Ok(startup)=>startup,Err(_)=>{capability.record_closed_spawn_gate();inner.unknown(owner);return;}};
    let mut r=inner.lock();let now=Instant::now();inner.advance_locked(&mut r,owner,now);
    if !claim_clear(inner,&r,owner,now){capability.record_closed_spawn_gate();return;}
    if startup.attempted||startup.returned||startup.failed||startup.child.is_some(){
        capability.record_closed_spawn_gate();owner.resource_unknown.store(true,Ordering::SeqCst);inner.unknown_locked(&mut r,owner);return;
    }
    startup.attempted=true;drop(r);
    match command.spawn(){
        Ok(child)=>{startup.child=Some(child);startup.returned=true;},
        Err(_)=>{startup.failed=true;owner.resource_unknown.store(true,Ordering::SeqCst);drop(startup);inner.stop(owner,Reason::RuntimeUnavailable);inner.unknown(owner);}
    }
    // Lexical borrow ends, not ownership: the same claimed Book remains in
    // Session.resources until original child/writer/reader/task joins and POST.
}


/// One pending phase at a time; no queue of caller-selected native operations.
pub(super) struct State {route:Mutex<Route>,changed:Notify,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    native:Mutex<native::State>,
}
struct Route {original:Option<(String,String)>,received:u8,completed:u8,pending:Option<history_wire::Event>,reply_writing:bool,failed:bool}
impl State {
    pub(super) fn new()->Self{Self{route:Mutex::new(Route{original:None,received:0,completed:0,pending:None,reply_writing:false,failed:false}),changed:Notify::new(),
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        native:Mutex::new(native::State::new()),}}
    pub(super) fn receive(&self,event:history_wire::Event)->Result<(),BridgeError>{
        let mut r=self.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if r.failed||r.original.is_none()||r.pending.is_some()||!(r.received==r.completed||r.reply_writing&&r.received==r.completed+1)||r.received>=3{
            r.failed=true;return Err(BridgeError::protocol());
        }
        r.received+=1;r.pending=Some(event);drop(r);self.changed.notify_one();Ok(())
    }
}
pub(super) fn decode(owner:&Session,decoder:&mut history_wire::Decoder,bytes:&[u8])->Result<Frame,BridgeError>{
    let Context::LocalReleaseHistory(context)=&owner.context else{return Err(BridgeError::protocol());};
    let r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let(nonce,digest)=r.original.as_ref().ok_or_else(BridgeError::protocol)?;
    decoder.decode(bytes,&owner.id,&owner.generation,context,nonce,digest).map(Frame::LocalReleaseHistory)
}
pub(super) fn request(owner:&Session,context:&history_wire::Context,profile:history_wire::Profile,runtime:&VerifiedRuntime)->Result<Vec<u8>,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    {native::request(owner,context,profile,runtime)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    {let _=(owner,context,profile,runtime);Err(BridgeError::protocol())}
}
pub(super) async fn write_phases(inner:&Arc<Inner>,owner:&Arc<Session>,writer:&mut ChildStdin)->Result<(),BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    {native::write_phases(inner,owner,writer).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    {let _=(inner,owner,writer);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[path="saved_command_history_native.rs"]
mod native;
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn acquire_sources(owner:&Session,runtime:&Arc<Mutex<LocalHistoryRuntimeSlots>>)->Result<(),BridgeError>{
    native::acquire_sources(owner,runtime)
}

#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(crate) use native::{Claim as LocalHistoryClaim,HelperClaim as LocalHistoryHelperClaim};

pub(super) fn sources_final(owner:&Session)->bool{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    {native::sources_final(owner)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    {let _=owner;false}
}
