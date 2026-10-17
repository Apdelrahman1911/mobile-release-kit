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
        let consent=self.prepared_history_consent(&input.operation_id,&input.owner_generation)?;
        if !input.consents(consent.consent()){return Err(history_wire::invalid());}
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
    candidate_close:AsyncMutex<Option<JoinHandle<bool>>>,candidate_close_started:AtomicBool,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    native:Mutex<native::State>,
}
enum PhaseEvent {IOSCandidate(ios_wire::CandidateEvent),Reconcile(reconcile_wire::Event),Execute(execute_wire::Event),Prepare(prepare_wire::Event),History(history_wire::Event),Candidate(android_wire::CandidateEvent)}
struct Route {reconcile_head:Option<u32>,authorization:Option<String>,original:Option<(String,String)>,received:u8,completed:u8,pending:Option<PhaseEvent>,reply_writing:bool,failed:bool}
impl Route {
    fn candidate_replies_complete(&self)->bool{
        self.original.is_some()&&!self.failed&&!self.reply_writing&&self.received==4&&self.completed==4&&self.pending.is_none()
    }
    fn reconcile_replies_complete(&self,settlement:bool)->bool{
        self.original.is_some()&&self.authorization.is_some()&&!self.failed&&!self.reply_writing
            &&self.received==(if settlement{3}else{2})&&self.completed==self.received&&self.pending.is_none()
            &&self.reconcile_head.is_some_and(|head|(6..=if settlement{512}else{513}).contains(&head))
    }

}
impl State {
    pub(super) fn new()->Self{Self{route:Mutex::new(Route{reconcile_head:None,authorization:None,original:None,received:0,completed:0,pending:None,reply_writing:false,failed:false}),changed:Notify::new(),candidate_close:AsyncMutex::new(None),candidate_close_started:AtomicBool::new(false),
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        native:Mutex::new(native::State::new()),}}
    pub(super) fn receive(&self,event:history_wire::Event)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::History(event),3)}
    pub(super) fn receive_ios_candidate(&self,event:ios_wire::CandidateEvent)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::IOSCandidate(event),4)}
    pub(super) fn receive_candidate(&self,event:android_wire::CandidateEvent)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::Candidate(event),4)}
    pub(super) fn receive_prepare(&self,event:prepare_wire::Event)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::Prepare(event),4)}
    pub(super) fn receive_reconcile(&self,event:reconcile_wire::Event,settlement:bool)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::Reconcile(event),if settlement{3}else{2})}
    pub(super) fn receive_execute(&self,event:execute_wire::Event)->Result<(),BridgeError>{self.receive_phase(PhaseEvent::Execute(event),4)}
    fn receive_phase(&self,event:PhaseEvent,limit:u8)->Result<(),BridgeError>{
        let mut r=self.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if r.failed||r.original.is_none()||r.pending.is_some()||!(r.received==r.completed||r.reply_writing&&r.received==r.completed+1)||r.received>=limit{
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

#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) fn acquire_candidate_sources(owner:&Session,runtime:&Arc<Mutex<AndroidNativeBooks>>)->Result<(),BridgeError>{native::acquire_candidate_sources(owner,runtime)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) fn candidate_request(owner:&Session,context:&android_wire::Context,profile:android_wire::Profile,runtime:&VerifiedRuntime,
    binding:&android_wire::ToolchainBinding,signing:&android_wire::Content)->Result<Vec<u8>,BridgeError>{native::candidate_request(owner,context,profile,runtime,binding,signing)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn candidate_child(owner:&Session,command:&mut Command)->Result<(),BridgeError>{native::child_command(owner,command)?;native::check_source(owner)}
pub(super) fn candidate_complete(owner:&Session)->bool{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {owner.history.route.try_lock().is_ok_and(|r|r.candidate_replies_complete())&&native::candidate_helpers_complete(owner)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=owner;false}
}
pub(super) fn ios_candidate_decoder(owner:&Session,context:&ios_wire::Context)->Result<ios_wire::FrameDecoder,BridgeError>{
    let route=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let(nonce,digest)=route.original.as_ref().ok_or_else(BridgeError::protocol)?;
    if route.failed||!owner.candidate_ios(){return Err(BridgeError::protocol());}
    ios_wire::FrameDecoder::new_candidate(&owner.id,&owner.generation,context,nonce,digest)
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn acquire_ios_candidate_sources(owner:&Session,runtime:&Arc<Mutex<IOSNativeBooks>>)->Result<(),BridgeError>{
    #[cfg(not(feature="macos-android-registration-helper"))]{native::acquire_ios_candidate_sources(owner,runtime)}
    #[cfg(feature="macos-android-registration-helper")]{let _=(owner,runtime);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn ios_candidate_request(owner:&Session,context:&ios_wire::Context,profile:ios_wire::Profile,runtime:&VerifiedRuntime,
    binding:&ios_wire::ToolchainBinding,tools:&ios_wire::SigningToolBindings,signing:&ios_wire::Content)->Result<Vec<u8>,BridgeError>{
    #[cfg(not(feature="macos-android-registration-helper"))]{native::ios_candidate_request(owner,context,profile,runtime,binding,tools,signing)}
    #[cfg(feature="macos-android-registration-helper")]{let _=(owner,context,profile,runtime,binding,tools,signing);Err(BridgeError::protocol())}
}
pub(super) fn candidate_decoder(owner:&Session,context:&android_wire::Context,profile:android_wire::Profile,selected:&android_wire::MacToolchainSelection)->Result<android_wire::FrameDecoder,BridgeError>{
    let route=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let(nonce,digest)=route.original.as_ref().ok_or_else(BridgeError::protocol)?;
    if route.failed{return Err(BridgeError::protocol());}
    android_wire::FrameDecoder::new_candidate(&owner.id,&owner.generation,context,profile,selected,nonce,digest)
}
/// Stopped is only a quiet next-phase wait, never interrupted private IO or
/// a dropped native helper future. Terminal/finality remain separate facts.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(super) enum CandidateWrite {Complete,Stopped}
pub(super) async fn write_candidate(owner:&Arc<Session>,writer:&mut ChildStdin,material:&PrivateSigningMaterial,header:&[u8])->Result<CandidateWrite,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::write_candidate(owner,writer,material,header).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,writer,material,header);Err(BridgeError::protocol())}
}
pub(super) async fn write_ios_candidate(owner:&Arc<Session>,writer:&mut ChildStdin,material:&PrivateSigningMaterial,header:&[u8])->Result<CandidateWrite,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::write_ios_candidate(owner,writer,material,header).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,writer,material,header);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) async fn finish_candidate(inner:&Arc<Inner>,owner:&Arc<Session>)->bool{
    if !owner.candidate_android()&&owner.domain!=SavedCommandDomain::LocalStoreExecute{return true;}
    // Called only after the genuine Android close-tail join. Own source books
    // remain separate; no Resources or retired Android Book is borrowed here.
    if owner.history.candidate_close_started.swap(true,Ordering::SeqCst){return false;}
    let mut handle=owner.history.candidate_close.lock().await;
    if handle.is_some(){return false;}
    let original=owner.clone();let(release,enter)=oneshot::channel();
    *handle=Some(tokio::task::spawn_blocking(move||{
        if enter.blocking_recv().is_err(){return false;}native::finish_sources(&original)
    }));let _=release.send(());
    match join_with_clock(&mut handle,inner,owner).await{
        Ok(closed)=>{handle.take();closed&&native::sources_final(owner)},Err(_)=>false,
    }
}

#[cfg(test)]
mod candidate_route_tests {
    use super::*;
    #[test]
    fn ios_candidate_phase_data_cannot_complete_four_original_replies(){
        let mut route=Route{reconcile_head:None,authorization:None,original:Some(("a".repeat(32),"b".repeat(64))),received:4,completed:3,
            pending:Some(PhaseEvent::IOSCandidate(ios_wire::CandidateEvent::InputsReady(ios_wire::CandidateHead{sequence:3,sha256:"c".repeat(64)}))),reply_writing:false,failed:false};
        assert!(!route.candidate_replies_complete());route.pending=None;assert!(!route.candidate_replies_complete());
        route.completed=4;route.reply_writing=true;assert!(!route.candidate_replies_complete());
        route.reply_writing=false;assert!(route.candidate_replies_complete());route.failed=true;assert!(!route.candidate_replies_complete());
    }
    #[test]
    fn local_candidate_create_phase_events_are_not_acknowledged_native_completion(){
        // DATA state predicate only: no owner/IO/helper/native receipt is minted.
        let mut route=Route{reconcile_head:None,authorization:None,original:Some(("a".repeat(32),"b".repeat(64))),received:4,completed:3,
            pending:Some(PhaseEvent::Candidate(android_wire::CandidateEvent::InputsReady(android_wire::CandidateHead{sequence:3,sha256:"c".repeat(64)}))),reply_writing:false,failed:false};
        assert!(!route.candidate_replies_complete());route.pending=None;route.reply_writing=true;assert!(!route.candidate_replies_complete());
        route.completed=4;assert!(!route.candidate_replies_complete());route.reply_writing=false;assert!(route.candidate_replies_complete());
        route.failed=true;assert!(!route.candidate_replies_complete());route.failed=false;route.original=None;assert!(!route.candidate_replies_complete());
    }
}

// Local Prepare shares original lease/helper ownership, never History's runtime.
pub(super) fn decode_prepare(owner:&Session,decoder:&mut prepare_wire::Decoder,bytes:&[u8])->Result<prepare_wire::Frame,BridgeError>{
    let Context::LocalStorePrepare(context)=&owner.context else{return Err(BridgeError::protocol());};
    let route=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if route.failed{return Err(BridgeError::protocol());}
    let(nonce,digest)=route.original.as_ref().ok_or_else(BridgeError::protocol)?;
    decoder.decode(bytes,&owner.id,&owner.generation,context,nonce,digest)
}
pub(super) fn prepare_request(owner:&Session,runtime:&VerifiedRuntime)->Result<Vec<u8>,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::prepare_request(owner,runtime)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,runtime);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn acquire_prepare_sources(owner:&Session,runtime:&Arc<Mutex<StoreRuntimeSlots>>)->Result<(),BridgeError>{
    #[cfg(not(feature="macos-android-registration-helper"))]{native::acquire_prepare_sources(owner,runtime)}
    #[cfg(feature="macos-android-registration-helper")]{let _=(owner,runtime);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn prepare_child(owner:&Session,command:&mut Command)->Result<(),BridgeError>{native::child_command(owner,command)?;native::check_source(owner)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn prepare_source_post(owner:&Session)->Result<(),BridgeError>{native::check_source(owner)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn finish_prepare_sources(owner:&Session)->bool{native::finish_sources(owner)}
pub(super) fn prepare_complete(owner:&Session)->bool{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {owner.domain==SavedCommandDomain::LocalStorePrepare&&owner.history.route.try_lock().is_ok_and(|r|r.candidate_replies_complete())&&native::prepare_helpers_complete(owner)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=owner;false}
}
pub(super) async fn write_prepare(owner:&Arc<Session>,writer:&mut ChildStdin,material:&PrivateSigningMaterial,header:&[u8])->Result<CandidateWrite,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::write_prepare(owner,writer,material,header).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,writer,material,header);Err(BridgeError::protocol())}
}

// Local Prepare shares original lease/helper ownership, never History's runtime.
pub(super) fn decode_execute(owner:&Session,decoder:&mut execute_wire::Decoder,bytes:&[u8])->Result<execute_wire::Frame,BridgeError>{
    let Context::LocalStoreExecute(context)=&owner.context else{return Err(BridgeError::protocol());};
    let route=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if route.failed{return Err(BridgeError::protocol());}
    let(nonce,digest)=route.original.as_ref().ok_or_else(BridgeError::protocol)?;
    decoder.decode(bytes,&owner.id,&owner.generation,context,nonce,digest)
}
pub(super) fn execute_request(owner:&Session,runtime:&VerifiedRuntime,binding:&android_wire::ToolchainBinding)->Result<Vec<u8>,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::execute_request(owner,runtime,binding)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,runtime,binding);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
pub(super) fn acquire_execute_sources(owner:&Session,runtime:&Arc<Mutex<ExecuteNativeBooks>>)->Result<(),BridgeError>{
    #[cfg(not(feature="macos-android-registration-helper"))]{native::acquire_execute_sources(owner,runtime)}
    #[cfg(feature="macos-android-registration-helper")]{let _=(owner,runtime);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn execute_child(owner:&Session,command:&mut Command)->Result<(),BridgeError>{native::child_command(owner,command)?;native::check_source(owner)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn execute_source_post(owner:&Session)->Result<(),BridgeError>{native::check_source(owner)}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn finish_execute_sources(owner:&Session)->bool{native::finish_sources(owner)}
pub(super) fn execute_complete(owner:&Session)->bool{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {owner.domain==SavedCommandDomain::LocalStoreExecute&&owner.history.route.try_lock().is_ok_and(|r|r.candidate_replies_complete())&&native::execute_helpers_complete(owner)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=owner;false}
}
pub(super) async fn write_execute(owner:&Arc<Session>,writer:&mut ChildStdin,material:&PrivateSigningMaterial,header:&[u8])->Result<CandidateWrite,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::write_execute(owner,writer,material,header).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,writer,material,header);Err(BridgeError::protocol())}
}

pub(super) fn execute_decoder(owner:&Session)->Result<execute_wire::Decoder,BridgeError>{
    let r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if r.failed||r.original.is_none(){return Err(BridgeError::protocol());}
    execute_wire::Decoder::new(r.authorization.as_deref().ok_or_else(BridgeError::protocol)?)
}

// Reconcile shares original lease/helper ownership, never History's runtime.
pub(super) fn decode_reconcile(owner:&Session,decoder:&mut reconcile_wire::Decoder,bytes:&[u8])->Result<reconcile_wire::Frame,BridgeError>{
    let Context::LocalStoreReconcile(context)=&owner.context else{return Err(BridgeError::protocol());};
    let route=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if route.failed{return Err(BridgeError::protocol());}
    let(nonce,digest)=route.original.as_ref().ok_or_else(BridgeError::protocol)?;
    decoder.decode(bytes,&owner.id,&owner.generation,context,nonce,digest)
}
pub(super) fn reconcile_request(owner:&Session,runtime:&VerifiedRuntime)->Result<Vec<u8>,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::reconcile_request(owner,runtime)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,runtime);Err(BridgeError::protocol())}
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn acquire_reconcile_sources(owner:&Session,runtime:&Arc<Mutex<StoreRuntimeSlots>>)->Result<(),BridgeError>{
    #[cfg(not(feature="macos-android-registration-helper"))]{native::acquire_reconcile_sources(owner,runtime)}
    #[cfg(feature="macos-android-registration-helper")]{let _=(owner,runtime);Err(BridgeError::protocol())}
}
pub(super) fn reconcile_complete(owner:&Session)->bool{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {owner.domain==SavedCommandDomain::LocalStoreReconcile&&owner.history.route.try_lock().is_ok_and(|r|r.reconcile_replies_complete(owner.recovery_settlement()))&&native::reconcile_helpers_complete(owner)}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=owner;false}
}
pub(super) async fn write_reconcile(owner:&Arc<Session>,writer:&mut ChildStdin,material:&PrivateSigningMaterial,header:&[u8])->Result<CandidateWrite,BridgeError>{
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
    {native::write_reconcile(owner,writer,material,header).await}
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper"))))]
    {let _=(owner,writer,material,header);Err(BridgeError::protocol())}
}


pub(super) fn reconcile_decoder(owner:&Session)->Result<reconcile_wire::Decoder,BridgeError>{
    let r=owner.history.route.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    if r.failed||r.original.is_none(){return Err(BridgeError::protocol());}
    reconcile_wire::Decoder::new(r.authorization.as_deref().ok_or_else(BridgeError::protocol)?)
}
#[cfg(test)]
mod reconcile_route_tests {
    use super::*;
    #[test]
    fn local_reconcile_actual_ack_head_not_terminal_count_controls_route_completion(){
        let mut r=Route{reconcile_head:None,authorization:Some("23456789-1234-4234-8234-123456789abc".into()),original:Some(("a".repeat(32),"b".repeat(64))),
            received:2,completed:1,pending:None,reply_writing:true,failed:false};
        assert!(!r.reconcile_replies_complete(false));r.completed=2;r.reply_writing=false;assert!(!r.reconcile_replies_complete(false));
        for head in [6,512,513]{r.reconcile_head=Some(head);assert!(r.reconcile_replies_complete(false));}
        for head in [0,5,514]{r.reconcile_head=Some(head);assert!(!r.reconcile_replies_complete(false));}
        r.reconcile_head=Some(6);r.failed=true;assert!(!r.reconcile_replies_complete(false));r.failed=false;
        r.pending=Some(PhaseEvent::Reconcile(reconcile_wire::Event::LeaseReady));assert!(!r.reconcile_replies_complete(false));r.pending=None;
        r.authorization=None;assert!(!r.reconcile_replies_complete(false));
    }
    #[test]
    fn local_recovery_route_requires_actual_third_ack_without_pending_write(){
        let mut r=Route{reconcile_head:Some(6),authorization:Some("23456789-1234-4234-8234-123456789abc".into()),original:Some(("a".repeat(32),"b".repeat(64))),
            received:2,completed:2,pending:None,reply_writing:false,failed:false};
        assert!(r.reconcile_replies_complete(false));assert!(!r.reconcile_replies_complete(true));
        r.received=3;assert!(!r.reconcile_replies_complete(true));r.completed=3;assert!(r.reconcile_replies_complete(true));
        assert!(!r.reconcile_replies_complete(false));
        for head in [6,512]{r.reconcile_head=Some(head);assert!(r.reconcile_replies_complete(true));}
        r.reconcile_head=Some(513);assert!(!r.reconcile_replies_complete(true));r.reconcile_head=Some(6);
        r.reply_writing=true;assert!(!r.reconcile_replies_complete(true));r.reply_writing=false;
        r.pending=Some(PhaseEvent::Reconcile(reconcile_wire::Event::LeaseReady));assert!(!r.reconcile_replies_complete(true));r.pending=None;
        r.failed=true;assert!(!r.reconcile_replies_complete(true));r.failed=false;r.authorization=None;assert!(!r.reconcile_replies_complete(true));
    }

}
