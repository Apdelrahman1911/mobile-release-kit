//! GitLocal is a closed arm of the ORIGINAL Supervisor. It owns no second
//! driver/watchdog/process group. Its eight finite state jobs are retained in
//! the same Resources and genuinely joined before public retirement.
use super::*;
use crate::git_local_protocol as wire;
#[path="supervisor_git_fetch.rs"]
mod fetch;
pub(crate) use fetch::GitLocalFetchHold;
#[path="supervisor_git_push.rs"]
mod push;
pub(crate) use push::GitLocalPushHold;
#[cfg(any(target_os="linux",target_os="macos"))]
use crate::git_local_state::{Completion,Original};
#[cfg(any(target_os="linux",target_os="macos"))]
use crate::application_state_store::{NativeUse,StateError,Cleanup,Effect,Durability};
#[cfg(any(target_os="linux",target_os="macos"))]
#[path="supervisor_git_local_jobs.rs"]
mod jobs;

#[derive(Clone,Copy)]
pub(crate) struct Endpoints {pub(crate) work:Instant,pub(crate) hard:Instant}
impl Endpoints {
    pub(crate) fn at(start:Instant)->Option<Self> {Some(Self {
        work:start.checked_add(Duration::from_secs(wire::WORK_SECONDS))?,
        hard:start.checked_add(Duration::from_secs(wire::HARD_SECONDS))?,
    })}
    pub(crate) fn first_failure(self,at:Instant)->Instant {
        at.min(self.work).checked_add(Duration::from_secs(10)).unwrap_or(self.hard).min(self.hard)
    }
}
pub(crate) struct GitLocalAdmission {
    pub(super) invocation:Invocation,pub(super) endpoints:Endpoints,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(super) slots:Arc<Mutex<crate::installed_runtime::GitLocalRuntimeSlots>>,
}
pub(super) struct Invocation {
    pub(super) gate:crate::asset_session::GitLocalGate,
    pub(super) context:wire::Context,pub(super) action:wire::Action,pub(super) phase:wire::Phase,
    pub(super) receipt:Arc<Mutex<GitLocalReceipt>>,
    request:Mutex<Option<Arc<wire::Request>>>,child_reply:Mutex<Option<wire::Terminal>>,
    candidate:Mutex<Option<Arc<wire::Candidate>>>,ack_returned:AtomicBool,control_closed:Mutex<Option<ControlClosed>>,
    publication:Mutex<Option<GitLocalPublication>>,
    fetch_keep:Mutex<Option<wire::fetch_worker::Keep>>,
    upstream_ack:Mutex<Option<String>>,
    fetch_go_claimed:AtomicBool,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(super) observation:std::sync::OnceLock<Arc<crate::shell::installed_observation::git_fetch::Control>>,
    fetch_joined:Arc<std::sync::OnceLock<fetch::JoinedControl>>,
    push_go_claimed:AtomicBool,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(super) push_observation:std::sync::OnceLock<Arc<crate::shell::installed_observation::git_push::Control>>,
    push_joined:Arc<std::sync::OnceLock<push::JoinedControl>>,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(super) sources:Arc<Mutex<crate::asset_source::GitLocalSources>>,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    slots:Arc<Mutex<crate::installed_runtime::GitLocalRuntimeSlots>>,
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    clock:Mutex<Option<mrk_macos_installed_native::vault_helper_wire::ClockBridge>>,
}
/// DATA progress alone cannot mint either of the following private witnesses.
/// Publication only permits the exact original old-FD successor comparison;
/// it is deliberately NOT journal finality or a successful operation receipt.
pub(crate) struct GitLocalPublication {
    request:Arc<wire::Request>,candidate:Arc<wire::Candidate>,publication:wire::Publication,
    fetch_keep:Option<wire::fetch_worker::Keep>,fetch_returned:Option<wire::fetch_worker::Returned>,
    push_returned:Option<wire::push_worker::Returned>,
    upstream_returned:Option<crate::git_upstream_protocol::FinalData>,
}
impl GitLocalPublication {
    pub(crate) fn upstream_for(&self,id:&str,native:&wire::Native,review:&wire::Review,sources:&crate::git_upstream_protocol::Sources)
        ->Result<(&crate::git_upstream_protocol::Intent,&crate::git_upstream_protocol::FinalData),crate::asset_commands::Reason> {
        let bad=crate::asset_commands::Reason::SourceChanged;
        let i=self.candidate.intent.upstream_details().ok_or(bad)?;
        let d=self.upstream_returned.as_ref().ok_or(bad)?;
        if self.request.action.kind()!=wire::Kind::SetUpstream || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            ||self.request.upstream_sources.as_ref()!=Some(sources)||!self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            ||!self.candidate.intent.matches(review)||!d.valid(i)||self.publication==wire::Publication::NotReported
            ||crate::git_upstream_protocol::effect(self.publication)!=Some(d.effect_phase.as_str()) {return Err(bad)}
        Ok((i,d))
    }

    pub(crate) fn push_for(&self,id:&str,native:&wire::Native,review:&wire::Review)
        ->Result<(&crate::git_push_protocol::Intent,&wire::push_worker::Returned),crate::asset_commands::Reason> {
        let bad=crate::asset_commands::Reason::SourceChanged;
        let intent=self.candidate.intent.push_details().ok_or(bad)?;
        let returned=self.push_returned.as_ref().ok_or(bad)?;
        if !self.request.action.kind().is_push() || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || self.request.initialization.is_some() || self.request.fetch_target.is_some()
            || self.fetch_keep.is_some() || self.fetch_returned.is_some()
            || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || !self.candidate.intent.matches(review) || self.publication!=wire::Publication::PushReturned
            || !returned.valid(intent) {return Err(bad)}
        Ok((intent,returned))
    }
    pub(crate) fn fetch_for(&self,id:&str,native:&wire::Native,review:&wire::Review,keep:&wire::fetch_worker::Keep)
        ->Result<(&crate::git_fetch_protocol::Intent,&wire::fetch_worker::Returned),crate::asset_commands::Reason> {
        let bad=crate::asset_commands::Reason::SourceChanged;
        let intent=self.candidate.intent.fetch_details().ok_or(bad)?;
        let returned=self.fetch_returned.as_ref().ok_or(bad)?;
        if self.request.action.kind()!=wire::Kind::Fetch || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || self.request.initialization.is_some() || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || !self.candidate.intent.matches(review) || self.publication!=wire::Publication::FetchReturned
            || self.push_returned.is_some() || self.fetch_keep.as_ref()!=Some(keep) || !keep.valid(intent,native) || !returned.valid(intent,native) {return Err(bad)}
        Ok((intent,returned))
    }
    pub(crate) fn init_for(&self,id:&str,native:&crate::git_init_protocol::Native,review:&wire::Review)
        ->Result<&crate::git_init_protocol::Intent,crate::asset_commands::Reason> {
        if self.request.action.kind()!=wire::Kind::Initialize || self.request.id!=id || self.request.native.is_some()
            || self.request.initialization.as_ref()!=Some(native) || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || !self.candidate.intent.matches(review) || self.publication!=wire::Publication::InitReturned {
            return Err(crate::asset_commands::Reason::SourceChanged)
        }
        self.candidate.intent.init_details().ok_or(crate::asset_commands::Reason::SourceChanged)
    }

    pub(crate) fn intent_for(&self,id:&str,native:&wire::Native,review:&wire::Review)
        ->Result<&wire::Intent,crate::asset_commands::Reason> {
        if matches!(self.request.action.kind(),wire::Kind::BranchSwitch|wire::Kind::BranchRename|wire::Kind::FastForward|wire::Kind::Initialize|wire::Kind::Fetch|wire::Kind::Push|wire::Kind::PushNewBranch|wire::Kind::SetUpstream) || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || !self.request.binding.as_ref().is_some_and(|b| &b.review==review)
            || !self.candidate.intent.matches(review) {return Err(crate::asset_commands::Reason::SourceChanged)}
        Ok(&self.candidate.intent)
    }
    pub(crate) fn rename_for(&self,id:&str,native:&wire::Native,review:&wire::Review,sources:&crate::git_rename_protocol::Sources)
        ->Result<(&crate::git_rename_protocol::Intent,wire::Publication),crate::asset_commands::Reason> {
        if self.request.action.kind()!=wire::Kind::BranchRename || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || self.request.rename_sources.as_ref()!=Some(sources) || !self.candidate.intent.matches(review)
            || self.publication==wire::Publication::NotReported || crate::git_rename_protocol::effect(self.publication).is_none() {
            return Err(crate::asset_commands::Reason::SourceChanged)
        }
        Ok((self.candidate.intent.rename_details().ok_or(crate::asset_commands::Reason::SourceChanged)?,self.publication))
    }
    pub(crate) fn fast_forward_for(&self,id:&str,native:&wire::Native,review:&wire::Review,sources:&crate::git_fast_forward_protocol::Sources)
        ->Result<(&crate::git_fast_forward_protocol::Intent,wire::Publication),crate::asset_commands::Reason> {
        if self.request.action.kind()!=wire::Kind::FastForward || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || self.request.fast_forward_sources.as_ref()!=Some(sources) || !self.candidate.intent.matches(review)
            || self.publication==wire::Publication::NotReported || crate::git_fast_forward_protocol::effect(self.publication).is_none() {
            return Err(crate::asset_commands::Reason::SourceChanged)
        }
        Ok((self.candidate.intent.fast_forward_details().ok_or(crate::asset_commands::Reason::SourceChanged)?,self.publication))
    }
    pub(crate) fn switch_for(&self,id:&str,native:&wire::Native,review:&wire::Review,sources:&crate::git_switch_protocol::Sources)
        ->Result<(&crate::git_switch_protocol::Intent,wire::Publication),crate::asset_commands::Reason> {
        if self.request.action.kind()!=wire::Kind::BranchSwitch || self.request.id!=id || self.request.native.as_ref()!=Some(native)
            || !self.request.binding.as_ref().is_some_and(|b|&b.review==review)
            || self.request.switch_sources.as_ref()!=Some(sources) || !self.candidate.intent.matches(review)
            || self.publication==wire::Publication::NotReported || crate::git_switch_protocol::effect(self.publication).is_none() {
            return Err(crate::asset_commands::Reason::SourceChanged)
        }
        Ok((self.candidate.intent.switch_details().ok_or(crate::asset_commands::Reason::SourceChanged)?,self.publication))
    }
}
/// Created only from management_ready + the SAME actual Resources after the
/// process/source/native/driver/watchdog and prior state jobs returned. Final
/// journal CAS and NativeUse-retire are later distinct jobs, not this witness.
#[cfg(any(target_os="linux",target_os="macos"))]
pub(crate) struct GitLocalNativeJoined {
    native_use:Arc<NativeUse>,original:Arc<Original>,completion:Completion,
    switch_final:Option<crate::git_switch_protocol::FinalData>,
    rename_final:Option<crate::git_rename_protocol::FinalData>,
    fast_forward_final:Option<crate::git_fast_forward_protocol::FinalData>,
    fetch_final:Option<crate::git_fetch_state::FinalData>,
    push_final:Option<crate::git_push_state::FinalData>,
    upstream_final:Option<crate::git_upstream_protocol::FinalData>,
}
#[cfg(any(target_os="linux",target_os="macos"))]
impl GitLocalNativeJoined {
    pub(crate) fn matches(&self,native_use:&Arc<NativeUse>,original:&Arc<Original>)->bool {
        Arc::ptr_eq(&self.native_use,native_use)&&Arc::ptr_eq(&self.original,original)
    }
    pub(crate) fn completion(&self)->Completion {self.completion}
    pub(crate) fn upstream_final(&self)->Option<&crate::git_upstream_protocol::FinalData>{self.upstream_final.as_ref()}
    pub(crate) fn push_final(&self)->Option<&crate::git_push_state::FinalData> {self.push_final.as_ref()}
    pub(crate) fn fetch_final(&self)->Option<&crate::git_fetch_state::FinalData> {self.fetch_final.as_ref()}
    pub(crate) fn rename_final(&self)->Option<&crate::git_rename_protocol::FinalData> {self.rename_final.as_ref()}
    pub(crate) fn fast_forward_final(&self)->Option<&crate::git_fast_forward_protocol::FinalData> {self.fast_forward_final.as_ref()}
    pub(crate) fn switch_final(&self)->Option<&crate::git_switch_protocol::FinalData> {self.switch_final.as_ref()}
}
#[derive(Clone)]
pub(crate) enum GitLocalReceipt {
    Pending,RetainedUnknown,Settled {outcome:Result<wire::Terminal,BridgeError>,was_unknown:bool},
}
pub(crate) struct GitLocalTicket {owner:Arc<Owner>,receipt:Arc<Mutex<GitLocalReceipt>>}
impl GitLocalTicket {
    pub(crate) fn operation_id(&self)->&str {&self.owner.id}
    pub(crate) fn stop(&self) {self.owner.fail(BridgeError::new("cancelled","The original local Git action was stopped."));}
    pub(crate) fn agent_stop_at(&self,at:Instant) {
        let mut state=lock(&self.owner.state);if state.terminal {return;}
        state.fail_at(BridgeError::new("cancelled","The original local Git action was stopped."),at);
        drop(state);self.owner.stop.send_replace(true);self.owner.changed.notify_waiters();
    }
    pub(crate) fn receipt(&self)->GitLocalReceipt {lock(&self.receipt).clone()}
    pub(crate) fn settled(&self)->bool {matches!(&*lock(&self.receipt),GitLocalReceipt::Settled {was_unknown:false,..})}
    pub(crate) fn pending_stage(&self)->crate::git_read_protocol::Phase {
        use crate::git_read_protocol::Phase;
        let s=lock(&self.owner.state);
        if s.unknown {Phase::CleanupUnknown} else if s.error.is_some() {Phase::Stopping}
        else if self.owner.preflight_go_claimed.load(Ordering::SeqCst) {Phase::Running} else {Phase::Starting}
    }
}
impl GitLocalAdmission {
    pub(crate) fn reserve(gate:crate::asset_session::GitLocalGate,action:wire::Action,phase:wire::Phase,at:Instant)->Result<Self,BridgeError> {
        let endpoints=Endpoints::at(at).ok_or_else(BridgeError::timeout)?;
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {
            let mut slots=crate::installed_runtime::GitLocalRuntimeSlots::new();
            slots.reserve_once().map_err(|_|BridgeError::unavailable("The bounded local Git storage is unavailable."))?;
            let slots=Arc::new(Mutex::new(slots));
            Ok(Self {invocation:Invocation {context:gate.context(),gate,action,phase,
                receipt:Arc::new(Mutex::new(GitLocalReceipt::Pending)),request:Mutex::new(None),child_reply:Mutex::new(None),
                candidate:Mutex::new(None),ack_returned:AtomicBool::new(false),control_closed:Mutex::new(None),publication:Mutex::new(None),
                fetch_keep:Mutex::new(None),upstream_ack:Mutex::new(None),fetch_go_claimed:AtomicBool::new(false),
                #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))] observation:std::sync::OnceLock::new(),fetch_joined:Arc::new(std::sync::OnceLock::new()),
                push_go_claimed:AtomicBool::new(false),
                #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))] push_observation:std::sync::OnceLock::new(),push_joined:Arc::new(std::sync::OnceLock::new()),
                sources:Arc::new(Mutex::new(crate::asset_source::GitLocalSources::new())),slots:slots.clone(),clock:Mutex::new(None)},
                endpoints,slots})
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=(gate,action,phase,endpoints);Err(BridgeError::unavailable("Local Git writes are unavailable on this installed runtime."))}
    }
    pub(crate) fn reservation_bytes(kind:wire::Kind)->Option<usize> {
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {crate::installed_runtime::GitLocalRuntimeSlots::working_reservation_bytes()?
            .checked_add(std::mem::size_of::<Self>()+std::mem::size_of::<Owner>()+std::mem::size_of::<Resources>())?
            .checked_add(if kind==wire::Kind::Initialize {crate::git_init_protocol::MANIFEST_BACKING}else{0})?
            .checked_add(match kind {wire::Kind::Fetch=>wire::fetch_worker::REMOTE_BACKING,wire::Kind::Push|wire::Kind::PushNewBranch=>wire::push_worker::REMOTE_BACKING,_=>0})}
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=kind;None}
    }
}
impl Supervisor {
    pub(crate) fn git_push_profile_available(&self)->bool {self.git_push_profile_available_for(wire::Kind::Push)}
    pub(crate) fn git_push_profile_available_for(&self,kind:wire::Kind)->bool {selected(Profile::GitLocal)&&self.inner.runtime.git_push_profile_available_for(kind)}
    pub(crate) fn git_fetch_profile_available(&self)->bool {selected(Profile::GitLocal)&&self.inner.runtime.git_fetch_profile_available()}
    pub(crate) fn git_local_profile_available(&self)->bool {
        selected(Profile::GitLocal)&&self.inner.runtime.git_local_profile_available()
    }
    pub(crate) fn start_git_local(&self,admission:GitLocalAdmission)->Result<GitLocalTicket,BridgeError> {
        if !self.git_local_profile_available()
            || admission.invocation.action.kind()==wire::Kind::Fetch && !self.inner.runtime.git_fetch_profile_available()
            || admission.invocation.action.kind().is_push() && !self.inner.runtime.git_push_profile_available_for(admission.invocation.action.kind()) {
            return Err(BridgeError::unavailable("The fixed local Git writer or selected remote runtime is unavailable."))}
        let receipt=admission.invocation.receipt.clone();
        let owner=self.admit(AdmissionRequest::GitLocal(admission),CompletionTarget::GitLocal)?;
        Ok(GitLocalTicket {owner,receipt})
    }
}
pub(super) fn selected(profile:Profile)->bool {
    cfg!(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),
        feature="desktop-shell",feature="custom-protocol",not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher")))
        && matches!(profile,Profile::GitLocal)
}
fn source_error(reason:crate::asset_commands::Reason)->BridgeError {
    use crate::asset_commands::Reason;
    match reason {Reason::CleanupUnknown=>BridgeError::cleanup_unknown(),
        Reason::UserCancelled=>BridgeError::new("cancelled","The original Git action was stopped."),
        Reason::SourceChanged=>BridgeError::new("git_stale_observation","The original Git sources changed."),
        _=>BridgeError::unavailable("This repository or Git provider is not supported by the local write profile.")}
}
fn host_error(error:crate::service_protocol::Error)->BridgeError {
    use crate::service_protocol::Error;
    match error {Error::StateUnknown=>BridgeError::cleanup_unknown(),
        Error::RecoveryRequired=>BridgeError::new("git_recovery_required","Preserve the prior Git action and resolve its pending state first."),
        Error::Expired=>BridgeError::timeout(),Error::Busy=>BridgeError::new("busy","The original private state owner is busy."),
        Error::Conflict=>BridgeError::new("git_stale_observation","The original project state changed."),
        _=>BridgeError::unavailable("The private local Git operation state is unavailable.")}
}
#[cfg(any(target_os="linux",target_os="macos"))]
fn state_error(error:StateError)->BridgeError {
    if error.effect==Effect::Unknown || error.durability==Durability::Unknown || error.cleanup==Cleanup::Unknown {
        BridgeError::cleanup_unknown()
    } else {host_error(error.code)}
}
impl Invocation {
    fn observation_stderr(&self,id:&str,bytes:&[u8])->bool {
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if let Some(c)=self.push_observation.get(){return c.stderr_allowed(id,bytes)}
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if let Some(c)=self.observation.get(){return c.stderr_allowed(id,bytes)}
        let _=id;bytes.is_empty()
    }
    pub(super) fn request(&self)->Result<Arc<wire::Request>,BridgeError> {
        self.request.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone().ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(super) fn unknown(&self) {*lock(&self.receipt)=GitLocalReceipt::RetainedUnknown;
        #[cfg(any(target_os="linux",target_os="macos"))] self.gate.agent_retired(&GitLocalReceipt::RetainedUnknown);}
    pub(super) fn retire(&self,outcome:Result<(),BridgeError>,was_unknown:bool) {
        let mut receipt=lock(&self.receipt);
        if was_unknown || !matches!(*receipt,GitLocalReceipt::Pending)
            || outcome.as_ref().is_err_and(|e|e.code=="cleanup_unknown") {*receipt=GitLocalReceipt::RetainedUnknown;drop(receipt);
            #[cfg(any(target_os="linux",target_os="macos"))] self.gate.agent_retired(&GitLocalReceipt::RetainedUnknown);return}
        let reply=self.child_reply.lock().ok().and_then(|s|s.clone());
        if self.action.kind()==wire::Kind::Fetch {
            let control=reply.as_ref().and_then(|v|v.fetch_control.clone()).or_else(||
                (!self.fetch_go_claimed.load(Ordering::SeqCst)).then_some(crate::github_connection_protocol::GitHubReadControl {
                    reason:crate::github_connection_protocol::Reason::None,credential_expires_at:None,cooldown_seconds:None,cooldown_blocked:false }));
            let Some(control)=control.filter(|v|v.valid()) else {*receipt=GitLocalReceipt::RetainedUnknown;return};
            if self.fetch_joined.set(fetch::joined_control(Instant::now(),control)).is_err() {*receipt=GitLocalReceipt::RetainedUnknown;return}
        }
        if self.action.kind().is_push() {
            let control=reply.as_ref().and_then(|v|v.push_control.clone()).or_else(||
                (!self.push_go_claimed.load(Ordering::SeqCst)).then_some(crate::github_connection_protocol::GitHubReadControl {
                    reason:crate::github_connection_protocol::Reason::None,credential_expires_at:None,cooldown_seconds:None,cooldown_blocked:false }));
            let Some(control)=control.filter(|v|v.valid()) else {*receipt=GitLocalReceipt::RetainedUnknown;return};
            if self.push_joined.set(push::joined_control(Instant::now(),control)).is_err() {*receipt=GitLocalReceipt::RetainedUnknown;return}
        }
        let result=match (outcome,reply) {
            (Ok(()),Some(reply))=>Ok(reply),
            (Err(error),Some(reply)) if error.code=="git_local_refused" && reply.child_declared_settled()
                && (reply.status!=crate::git_read_protocol::Outcome::Ok || reply.result["state"]!="succeeded")=>Ok(reply),
            (Err(error),_)=>Err(error),_=>Err(BridgeError::protocol()),
        };
        *receipt=GitLocalReceipt::Settled {outcome:result,was_unknown:false};
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if let Some(c)=self.push_observation.get(){match self.request(){Ok(r)=>c.retired(&r,&receipt),Err(_)=>c.fail()}}

        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if let Some(c)=self.observation.get(){match self.request(){Ok(r)=>c.retired(&r,&receipt),Err(_)=>c.fail()}}

        #[cfg(any(target_os="linux",target_os="macos"))] self.gate.agent_retired(&receipt);
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(super) fn inspect(&self,runtime:&RuntimeConfig,owner:&Owner,preparing:Option<&crate::git_local_state::Ack>)
        ->Result<VerifiedRuntime,BridgeError> {
        let root=self.gate.check_current(&owner.id)?;let stop=owner.stop.subscribe();
        let selected={let mut native=self.slots.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if self.action.kind()==wire::Kind::Fetch {native.arm_fetch_once().map_err(|_|BridgeError::cleanup_unknown())?;}
            if self.action.kind().is_push() {native.arm_push_once().map_err(|_|BridgeError::cleanup_unknown())?;}
            let armed=native.arm_acl_once(owner.endpoint(),&stop);owner.observe_native_failure(native.first_failure());
            armed.map_err(|_|BridgeError::cleanup_unknown())?;
            let result=runtime.resolve_git_local_installed_for(self.action.kind(),&mut native,owner.endpoint(),&stop);
            owner.observe_native_failure(native.first_failure());result?};
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.action.kind()==wire::Kind::Fetch {
            if let Some(c)=runtime.fetch_observation()? {
                if !self.gate.observation_matches(&c){return Err(BridgeError::invalid())}
                self.observation.set(c.clone()).map_err(|_|BridgeError::cleanup_unknown())?;
                self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?
                    .configure_fetch_observation(c).map_err(source_error)?;
            }
        }
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.action.kind().is_push() {
            if let Some(c)=runtime.push_observation()? {
                if !self.gate.push_observation_matches(&c){return Err(BridgeError::invalid())}
                self.push_observation.set(c.clone()).map_err(|_|BridgeError::cleanup_unknown())?;
                self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?
                    .configure_push_observation(c).map_err(source_error)?;
            }
        }
        let review=self.gate.review();
        // Initialization's exclusive private mkdir is an effect. Refuse the
        // wrong/missing original Preparing ACK BEFORE entering SourceBook,
        // not merely while formatting the later child request.
        if self.action.kind()==wire::Kind::Initialize && !matches!((self.phase,review.as_ref(),preparing),
            (wire::Phase::Prepare,None,None)|(wire::Phase::Apply,Some(_),Some(_))) {
            return Err(BridgeError::cleanup_unknown())
        }
        let (snapshot,switch_sources,rename_sources,fast_forward_sources,initialization,upstream_sources)={let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            let mut cut=||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint();
            let result=if let wire::Action::Upstream(action)=&self.action {
                sources.inspect_upstream(&root,crate::installed_runtime::GitLocalRuntimeSlots::source_runtime_fd_bound(),&owner.id,action,review.as_ref(),&mut cut)
            }else{sources.inspect(&root,crate::installed_runtime::GitLocalRuntimeSlots::source_runtime_fd_bound(),
                &owner.id,self.action.kind(),review.as_ref(),&mut cut)};
            observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?;
            (if self.action.kind()==wire::Kind::Initialize {None}else{Some(sources.native_snapshot().map_err(source_error)?.clone())},
                sources.switch_projection().map_err(source_error)?.cloned(),sources.rename_projection().map_err(source_error)?.cloned(),sources.fast_forward_projection().map_err(source_error)?.cloned(),sources.init_projection().map_err(source_error)?.cloned(),sources.upstream_snapshot().map_err(source_error)?) };
        let binding=match (self.phase,review,preparing) {
            (wire::Phase::Prepare,None,None)=>None,
            (wire::Phase::Apply,Some(review),Some(ack))=>Some(wire::ApplyBinding {review,journal_revision:ack.revision.0}),
            _=>return Err(BridgeError::cleanup_unknown()),
        };
        let ends=owner.git_local_endpoints.ok_or_else(BridgeError::cleanup_unknown)?;
        let mut clock=mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture().ok_or_else(BridgeError::cleanup_unknown)?;
        let clock_data=wire::Clock {work_end_ns:clock.endpoint(ends.work).ok_or_else(BridgeError::cleanup_unknown)?,
            hard_end_ns:clock.endpoint(ends.hard).ok_or_else(BridgeError::cleanup_unknown)?};
        let request=Arc::new(if self.action.kind()==wire::Kind::Initialize {
            wire::Request::from_init_original(&owner.id,&self.action,&self.context,initialization.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding)?
        } else if self.action.kind()==wire::Kind::SetUpstream {
            wire::Request::from_upstream_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding,upstream_sources.ok_or_else(BridgeError::protocol)?)?
        } else if self.action.kind().is_push() {
            wire::Request::from_push_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,
                clock_data,binding,self.gate.push_target(&owner.id)?)?
        } else if self.action.kind()==wire::Kind::Fetch {
            wire::Request::from_fetch_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,
                clock_data,binding,self.gate.fetch_target(&owner.id)?)?
        } else if self.action.kind()==wire::Kind::FastForward {
            wire::Request::from_fast_forward_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding,fast_forward_sources)?
        } else if self.action.kind()==wire::Kind::BranchSwitch {
            wire::Request::from_switch_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding,switch_sources)?
        } else if self.action.kind()==wire::Kind::BranchRename {
            wire::Request::from_rename_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding,rename_sources)?
        } else {wire::Request::from_original(&owner.id,&self.action,&self.context,snapshot.as_ref().ok_or_else(BridgeError::protocol)?,clock_data,binding)?});
        let mut slot=self.request.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let mut bridge=self.clock.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some()||bridge.is_some() {return Err(BridgeError::cleanup_unknown())}
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.observation.get().is_some_and(|c|!c.observed(&request)){return Err(BridgeError::invalid())}
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if self.push_observation.get().is_some_and(|c|!c.observed(&request)){return Err(BridgeError::invalid())}
        *slot=Some(request);*bridge=Some(clock);drop(bridge);drop(slot);
        self.gate.check_current(&owner.id)?;Ok(selected)
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    pub(super) fn before_go(&self,owner:&Owner)->Result<(),BridgeError> {self.post_before_effect(owner)}
    pub(super) fn before_candidate(&self,owner:&Owner)->Result<(),BridgeError> {
        if self.phase!=wire::Phase::Apply {return Err(BridgeError::protocol())}
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {
            if self.action.kind()==wire::Kind::SetUpstream {
                self.gate.check_current(&owner.id)?;
                let candidate=self.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone().ok_or_else(BridgeError::protocol)?;
                let stop=owner.stop.subscribe();
                let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                let result=sources.before_upstream_candidate(&candidate.intent,&mut ||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint());
                observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?;
            }
            if self.action.kind()==wire::Kind::Initialize {
                self.gate.check_current(&owner.id)?;
                let candidate=self.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone().ok_or_else(BridgeError::protocol)?;
                let stop=owner.stop.subscribe();
                {let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                    let result=sources.capture_init(&candidate.intent,&mut ||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint());
                    observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?;}
            }
            if self.action.kind()==wire::Kind::Fetch {
                self.gate.check_current(&owner.id)?;
                let candidate=self.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone().ok_or_else(BridgeError::protocol)?;
                let stop=owner.stop.subscribe();
                let keep={let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                    let result=sources.prepare_fetch_keep(&candidate.intent,&mut ||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint());
                    observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?;
                    sources.fetch_keep().map_err(source_error)?.cloned().ok_or_else(BridgeError::cleanup_unknown)?};
                let mut slot=self.fetch_keep.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                if slot.is_some(){return Err(BridgeError::cleanup_unknown())}*slot=Some(keep);
            }
            self.post_before_effect(owner)
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=owner;Err(BridgeError::unavailable("The original Git writer is unavailable."))}
    }
    pub(super) fn after_candidate(&self,owner:&Owner)->Result<(),BridgeError> {
        if self.action.kind()!=wire::Kind::SetUpstream{return Ok(())}
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {
            self.gate.check_current(&owner.id)?;
            let candidate=self.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone().ok_or_else(BridgeError::protocol)?;
            let stop=owner.stop.subscribe();
            let digest={let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                let result=sources.create_upstream_directories(&candidate.intent,&mut ||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint());
                observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?};
            self.gate.check_current(&owner.id)?;
            let mut slot=self.upstream_ack.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if slot.is_some(){return Err(BridgeError::cleanup_unknown())}*slot=Some(digest);Ok(())
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=owner;Err(BridgeError::unavailable("The original local Git writer is unavailable."))}
    }
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    fn post_before_effect(&self,owner:&Owner)->Result<(),BridgeError> {
        self.gate.check_current(&owner.id)?;let stop=owner.stop.subscribe();
        {let mut native=self.slots.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            let result=native.capability().map_err(|_|BridgeError::cleanup_unknown())?
                .post_original(owner.endpoint(),&stop,&mut |f|owner.observe_native_failure(f));
            owner.observe_native_failure(native.first_failure());result.map_err(|_|BridgeError::cleanup_unknown())?;}
        {let mut sources=self.sources.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            let result=sources.post(&mut ||owner.failed()||*stop.borrow()||Instant::now()>=owner.endpoint());
            observe_source_failure(owner,sources.first_failure());result.map_err(source_error)?;}
        // Never acquire Doc under the source/native mutex. The exact current
        // publisher/stamp/NativeReady is checked again immediately after IO.
        self.gate.check_current(&owner.id)?;Ok(())
    }
    pub(super) fn decode_before_close(&self,owner:&Owner,r:&Resources)->Result<(),BridgeError> {
        let output=r.out_end.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let stderr=r.err_end.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        if r.waited.is_none_or(|s|!s.success()) || r.writer.is_some()||r.stdout.is_some()||r.stderr.is_some()
            || r.failed_writer.is_some()||r.failed_stdout.is_some()||r.failed_stderr.is_some()
            || !output.eof||output.overflow||!stderr.eof||stderr.overflow||!self.observation_stderr(&owner.id,&stderr.bytes)
            || r.history_post.is_some()||r.history_post_join_failed {return Err(BridgeError::cleanup_unknown())}
        let request=self.request()?;
        let candidate=self.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone();
        let terminal=request.terminal(&output.bytes,candidate.as_deref())?;
        let closed=*self.control_closed.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if !control_terminal_matches(closed,r.write_end.as_ref(),owner.failed(),&terminal) {
            return Err(BridgeError::cleanup_unknown())
        }
        if !terminal.child_declared_settled() {return Err(BridgeError::cleanup_unknown())}
        if terminal.publication!=wire::Publication::NotReported {
            let candidate=candidate.ok_or_else(BridgeError::cleanup_unknown)?;
            #[cfg(any(target_os="linux",target_os="macos"))]
            let revision=r.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?
                .jobs.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.candidate_ack()?
                .ok_or_else(BridgeError::cleanup_unknown)?.revision.0;
            #[cfg(not(any(target_os="linux",target_os="macos")))]
            let revision=0;
            if !self.ack_returned.load(Ordering::SeqCst)
                || revision!=request.binding.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.journal_revision+1 {
                return Err(BridgeError::cleanup_unknown())
            }
            let mut slot=self.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if slot.is_some() {return Err(BridgeError::cleanup_unknown())}
            *slot=Some(GitLocalPublication {request:request.clone(),candidate:candidate.clone(),publication:terminal.publication,
                fetch_keep:self.fetch_keep.lock().map_err(|_|BridgeError::cleanup_unknown())?.clone(),
                fetch_returned:terminal.fetch_publication.clone(),push_returned:terminal.push_transmission.clone(),
                upstream_returned:if request.action.kind()==wire::Kind::SetUpstream {Some(crate::git_upstream_protocol::final_data(&terminal,candidate.intent.upstream_details().ok_or_else(BridgeError::protocol)?)?)}else{None}});
        }
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        if let Some(first)=terminal.first_failure_ns {
            let at=self.clock.lock().map_err(|_|BridgeError::cleanup_unknown())?.as_mut()
                .ok_or_else(BridgeError::cleanup_unknown)?.failure_bound(first).ok_or_else(BridgeError::cleanup_unknown)?;
            lock(&owner.state).fail_at(BridgeError::new("git_local_refused","The original local Git action did not complete."),at);
            owner.stop.send_replace(true);owner.changed.notify_waiters();
        }
        let mut slot=self.child_reply.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some() {return Err(BridgeError::cleanup_unknown())}*slot=Some(terminal);Ok(())
    }
}

/// Fixed Resources facet, installed at the original Supervisor admission. The
/// one candidate channel has no public producer and no generic command role.
pub(super) struct LocalResources {
    #[cfg(any(target_os="linux",target_os="macos"))]
    jobs:Option<jobs::Jobs>,
    candidate_receive:Option<oneshot::Receiver<Arc<wire::Candidate>>>,
    ack_send:Option<oneshot::Sender<Result<Vec<u8>,BridgeError>>>,
    finalizing:bool,finalized:bool,
}
impl LocalResources {
    pub(super) fn new(_phase:wire::Phase)->Self {Self {
        #[cfg(any(target_os="linux",target_os="macos"))]
        jobs:(_phase==wire::Phase::Apply).then(jobs::Jobs::new),
        candidate_receive:None,ack_send:None,finalizing:false,finalized:false}}
    pub(super) fn complete(&self)->bool {
        #[cfg(any(target_os="linux",target_os="macos"))]
        {self.finalized && self.jobs.as_ref().is_none_or(jobs::Jobs::complete)}
        #[cfg(not(any(target_os="linux",target_os="macos")))]
        {false}
    }
    pub(super) fn jobs_settled(&self)->bool {
        #[cfg(any(target_os="linux",target_os="macos"))]
        {self.jobs.as_ref().is_none_or(jobs::Jobs::all_returned)}
        #[cfg(not(any(target_os="linux",target_os="macos")))]
        {false}
    }
    pub(super) fn candidate_pending(&self)->bool {self.candidate_receive.is_some()}
    pub(super) async fn receive_candidate(&mut self)->Result<Arc<wire::Candidate>,oneshot::error::RecvError> {
        match self.candidate_receive.as_mut() {Some(receiver)=>receiver.await,None=>pending().await}
    }
    #[cfg(any(target_os="linux",target_os="macos"))]
    pub(super) fn preparing(&self)->Result<Option<Arc<crate::git_local_state::Ack>>,BridgeError> {
        self.jobs.as_ref().map(jobs::Jobs::preparing).transpose()
    }
}
#[cfg(any(target_os="linux",target_os="macos"))]
pub(super) async fn startup(r:&mut Resources,inner:&Inner,owner:&Arc<Owner>)->Result<(),BridgeError> {
    let local=r.git_local.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
    if let Some(jobs)=&mut local.jobs {jobs.startup(inner,owner).await?;}Ok(())
}
#[cfg(any(target_os="linux",target_os="macos"))]
pub(super) async fn candidate_returned(r:&mut Resources,inner:&Inner,owner:&Arc<Owner>,candidate:Result<Arc<wire::Candidate>,oneshot::error::RecvError>) {
    let Some(local)=r.git_local.as_mut() else {owner.unknown(inner);return};
    local.candidate_receive.take();
    // A normal pre-candidate refusal closes this channel. Its terminal will be
    // validated after the real wait/EOFs; absence grants neither retry nor GO.
    let Ok(candidate)=candidate else {local.ack_send.take();return};
    let result=async {
        let invocation=owner.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        if owner.failed() {return Err(BridgeError::new("cancelled","The original Git candidate was stopped."))}
        {let mut slot=invocation.candidate.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if slot.is_some() {return Err(BridgeError::protocol())}*slot=Some(candidate.clone());}
        let ack=local.jobs.as_mut().ok_or_else(BridgeError::cleanup_unknown)?.candidate(inner,owner,candidate.clone()).await?;
        // Same actual Doc and owner STOP check AFTER durable CAS. A successful
        // CAS is not permission if its consent/currentness changed meanwhile.
        invocation.gate.check_current(&owner.id)?;
        if owner.failed()||Instant::now()>=owner.endpoint() {return Err(BridgeError::timeout())}
        let request=invocation.request()?;
        if invocation.action.kind()==wire::Kind::SetUpstream {
            let digest=invocation.upstream_ack.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            request.upstream_ack(&candidate,ack.revision.0,digest.as_deref().ok_or_else(BridgeError::cleanup_unknown)?)
        } else if invocation.action.kind().is_push() {
            request.push_ack(&candidate,ack.revision.0)
        } else if invocation.action.kind()==wire::Kind::Fetch {
            let keep=invocation.fetch_keep.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            request.fetch_ack(&candidate,ack.revision.0,keep.as_ref().ok_or_else(BridgeError::cleanup_unknown)?)
        } else {request.ack(&candidate,ack.revision.0)}
    }.await;
    if let Err(error)=&result {owner.fail(error.clone());if error.code=="cleanup_unknown" {owner.unknown(inner)}}
    if !local.ack_send.take().is_some_and(|s|s.send(result).is_ok()) {
        owner.fail(BridgeError::new("io_error","The original Git candidate acknowledgement was not consumed."));
    }
}

/// Called by the EXISTING management observer only AFTER it consumed both
/// original driver/watchdog returns, before Owner::retire releases any debit.
#[cfg(any(target_os="linux",target_os="macos"))]
pub(super) async fn finalize(inner:&Inner,owner:&Arc<Owner>)->bool {
    if !owner.failed() {
        if let Some(local)=owner.git_local.as_ref() {
            if let Err(error)=local.gate.check_current(&owner.id) {owner.fail(error);}
        }
    }
    let mut r=owner.resources.lock().await;
    let Some(local)=r.git_local.as_ref() else {owner.unknown(inner);return false};
    if local.finalized {return true}if local.finalizing {owner.unknown(inner);return false}
    let joined=(|| {
        let state=lock(&owner.state);
        if !state.management_ready()||state.unknown||r.inspection.is_some()||r.acquisition.is_some()
            ||r.writer.is_some()||r.stdout.is_some()||r.stderr.is_some()||r.history_post.is_some()
            ||!native_settled(&r) {return Err(BridgeError::cleanup_unknown())}
        let Some(jobs)=local.jobs.as_ref() else {return Ok(None)};
        if !jobs.all_returned() {return Err(BridgeError::cleanup_unknown())}
        let Some((native_use,original,_))=jobs.original()? else {return Ok(None)};
        let invocation=owner.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let reply=invocation.child_reply.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let has_candidate=jobs.candidate_ack()?.is_some();
        let completion=if has_candidate {
            if state.error.is_none() && matches!(&state.driver_end,Some(DriverEnd::Ready(Ok(ReadOutcome::GitLocal))))
                && reply.as_ref().is_some_and(|v|v.status==crate::git_read_protocol::Outcome::Ok && v.result["state"]=="succeeded") {
                Completion::Succeeded
            }else{Completion::RecoveryRequired}
        }else if owner.preflight_go_claimed.load(Ordering::SeqCst) && reply.is_none() {return Err(BridgeError::cleanup_unknown())}
        else if state.error.as_ref().is_some_and(|e|matches!(e.code.as_str(),"cancelled"|"shutting_down")) {Completion::Cancelled}
        else {Completion::Failed};
        // Historical detail is copied only from this original positive
        // publication after ALL earlier management/source/runtime returns.
        // No candidate/readback/negative result can manufacture this evidence.
        let fast_forward_final=if invocation.action.kind()==wire::Kind::FastForward {
            let publication=invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            match publication.as_ref() {
                Some(p)=>Some(crate::git_fast_forward_protocol::FinalData::from_returned(&p.request,&p.candidate,
                    reply.as_ref().ok_or_else(BridgeError::cleanup_unknown)?,p.publication)?),
                None=>None,
            }
        } else {None};
        let switch_final=if invocation.action.kind()==wire::Kind::BranchSwitch {
            let publication=invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            match publication.as_ref() {
                Some(p)=>Some(crate::git_switch_protocol::FinalData::from_returned(&p.request,&p.candidate,
                    reply.as_ref().ok_or_else(BridgeError::cleanup_unknown)?,p.publication)?),
                None=>None,
            }
        } else {None};
        let rename_final=if invocation.action.kind()==wire::Kind::BranchRename {
            let publication=invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            match publication.as_ref() {
                Some(p)=>Some(crate::git_rename_protocol::FinalData::from_returned(&p.request,&p.candidate,
                    reply.as_ref().ok_or_else(BridgeError::cleanup_unknown)?,p.publication)?),
                None=>None,
            }
        } else {None};
        let fetch_final=if invocation.action.kind()==wire::Kind::Fetch {
            let publication=invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            match publication.as_ref() {
                Some(p)=>Some(crate::git_fetch_state::FinalData::from_returned(&p.request,&p.candidate,
                    reply.as_ref().ok_or_else(BridgeError::cleanup_unknown)?,p.fetch_returned.as_ref().ok_or_else(BridgeError::cleanup_unknown)?)?),
                None=>None,
            }
        } else {None};
        let push_final=if invocation.action.kind().is_push() {
            let publication=invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            match publication.as_ref() {
                Some(p)=>Some(crate::git_push_state::FinalData::from_returned(&p.request,&p.candidate,
                    reply.as_ref().ok_or_else(BridgeError::cleanup_unknown)?,p.push_returned.as_ref().ok_or_else(BridgeError::cleanup_unknown)?)?),
                None=>None,
            }
        } else {None};
        let upstream_final=if invocation.action.kind()==wire::Kind::SetUpstream {
            invocation.publication.lock().map_err(|_|BridgeError::cleanup_unknown())?.as_ref().and_then(|p|p.upstream_returned.clone())
        }else{None};
        Ok(Some(GitLocalNativeJoined {native_use,original,completion,switch_final,rename_final,fast_forward_final,fetch_final,push_final,upstream_final}))
    })();
    let joined=match joined {Ok(value)=>value,Err(error)=>{owner.fail(error);owner.unknown(inner);return false}};
    let local=r.git_local.as_mut().expect("same retained facet");local.finalizing=true;
    if let Some(jobs)=&mut local.jobs {
        if let Err(error)=jobs.finalize(inner,owner,joined).await {owner.fail(error);owner.unknown(inner);return false}
    }
    local.finalized=true;true
}

#[cfg(any(target_os="linux",target_os="macos"))]
fn native_settled(r:&Resources)->bool {
    #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
    {
        let Ok(Some(native))=installed_settlement_slots(r,Profile::GitLocal) else {return false};
        let (inspection,acquisition)=passive_borrows(r);
        if !r.native_started {
            return native.no_child_state().is_some_and(|(never_started,_)|
                passive_never_started_clear(inspection,acquisition,never_started));
        }
        r.native_settlement.is_none()&&matches!(&r.native_return,Some(Ok(CloseOutcome::Settled)))&&native.settled()
    }
    #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
    {let _=r;false}
}
#[cfg(not(any(target_os="linux",target_os="macos")))]
pub(super) async fn startup(_: &mut Resources,_: &Inner,_: &Arc<Owner>)->Result<(),BridgeError> {
    Err(BridgeError::unavailable("The original local Git writer is unavailable."))
}
#[cfg(not(any(target_os="linux",target_os="macos")))]
pub(super) async fn candidate_returned(_: &mut Resources,inner:&Inner,owner:&Arc<Owner>,_:Result<Arc<wire::Candidate>,oneshot::error::RecvError>) {
    owner.unknown(inner);
}
#[cfg(not(any(target_os="linux",target_os="macos")))]
pub(super) async fn finalize(_: &Inner,_: &Arc<Owner>)->bool {false}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
fn observe_source_failure(owner:&Owner,first:Option<(mrk_macos_installed_native::vault_filesystem::Failure,Instant)>) {
    use mrk_macos_installed_native::vault_filesystem::Failure;
    owner.observe_native_failure(first.map(|(f,at)|(match f {
        Failure::Unknown=>crate::installed_runtime::AdmissionFailure::Unknown,
        _=>crate::installed_runtime::AdmissionFailure::Ownership,
    },at)));
}
// Actual Resources.native_settlement body, after all original borrowers joined.
// A STOP permits bounded comparison/close, never new Git commands/publication.
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn settle(owner:&Owner,slots:&Arc<Mutex<crate::installed_runtime::GitLocalRuntimeSlots>>)->CloseOutcome {
    let Some(local)=owner.git_local.as_ref() else {return CloseOutcome::Unknown};
    let declared=local.child_reply.lock().ok().and_then(|s|s.as_ref().map(|v|v.status));
    if declared==Some(crate::git_read_protocol::Outcome::Ok) && !owner.failed() {
        if let Err(error)=local.gate.check_current(&owner.id) {owner.fail(error)}
    }
    let mut native=match slots.lock() {Ok(v)=>v,Err(e)=>{let mut v=e.into_inner();v.mark_interrupted();v}};
    let mut sources=match local.sources.lock() {Ok(v)=>v,Err(e)=>{let mut v=e.into_inner();v.mark_interrupted();v}};
    if declared.is_none()&&!native.no_child_effect() {return CloseOutcome::Unknown}
    if declared.is_some() {
        let publication=match local.publication.lock() {Ok(v)=>v,Err(_)=>return CloseOutcome::Unknown};
        let result=sources.post_returned(publication.as_ref(),&mut || {
            let state=lock(&owner.state);
            state.unknown||Instant::now()>=state.cleanup_endpoint.unwrap_or(state.endpoint).min(state.endpoint)
        });
        observe_source_failure(owner,sources.first_failure());
        if let Err(reason)=result {owner.fail(source_error(reason));}
    }
    // Switch retains its exact target lock until the original runtime closes
    // are known too. All old actions keep their original order. This body is
    // already after process/pipe joins; later management/journal/NativeUse
    // joins are still mandatory, never inferred from a positive publication.
    let (source_closed,runtime_closed)=if matches!(local.action.kind(),wire::Kind::BranchSwitch|wire::Kind::BranchRename|wire::Kind::FastForward|wire::Kind::Fetch|wire::Kind::SetUpstream) {
        let closed=native.settle_originals(&mut |first|owner.native_cleanup_expired(first));
        if !matches!(closed,CloseOutcome::Settled) {if local.action.kind()==wire::Kind::SetUpstream {sources.retain_upstream_unknown();} else if local.action.kind()==wire::Kind::Fetch {sources.retain_fetch_unknown();} else if local.action.kind()==wire::Kind::FastForward {sources.retain_fast_forward_unknown();} else if local.action.kind()==wire::Kind::BranchRename {sources.retain_rename_unknown();} else {sources.retain_switch_unknown();}return CloseOutcome::Unknown}
        (sources.close(&mut |first| {observe_source_failure(owner,first);owner.native_cleanup_expired(None)}).is_ok(),closed)
    } else {
        let closed=sources.close(&mut |first| {observe_source_failure(owner,first);owner.native_cleanup_expired(None)}).is_ok();
        (closed,native.settle_originals(&mut |first|owner.native_cleanup_expired(first)))
    };
    if !source_closed||!sources.settled()||!matches!(runtime_closed,CloseOutcome::Settled) {CloseOutcome::Unknown}
    else {CloseOutcome::Settled}
}

pub(super) struct Channels {
    pub(super) candidate:oneshot::Sender<Arc<wire::Candidate>>,
    pub(super) ack:oneshot::Receiver<Result<Vec<u8>,BridgeError>>,
}
pub(super) fn channels(r:&mut Resources)->Result<Channels,BridgeError> {
    let local=r.git_local.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
    if local.candidate_receive.is_some()||local.ack_send.is_some() {return Err(BridgeError::cleanup_unknown())}
    let (candidate,received)=oneshot::channel();let (ack,acknowledged)=oneshot::channel();
    local.candidate_receive=Some(received);local.ack_send=Some(ack);
    Ok(Channels {candidate,ack:acknowledged})
}
// Private writer evidence, not a public receipt. The stopped case is minted
// only after complete request/GO (and every entered ACK), then actual shutdown.
// Generic WriteEnd::complete stays false on STOP; that false alone proves none
// of this and cannot authorize even a cancelled terminal's native close.
#[derive(Clone,Copy)]
enum ControlClosed {Waited,StoppedAfterGo}
fn control_terminal_matches(closed:Option<ControlClosed>,write:Option<&WriteEnd>,failed:bool,terminal:&wire::Terminal)->bool {
    match (closed,write) {
        (Some(ControlClosed::Waited),Some(end))=>end.complete,
        (Some(ControlClosed::StoppedAfterGo),Some(end))=>!end.complete&&failed
            && matches!(terminal.status,crate::git_read_protocol::Outcome::Cancelled|crate::git_read_protocol::Outcome::TimedOut)
            && terminal.publication==wire::Publication::NotReported&&terminal.result.is_null(),
        _=>false,
    }
}
// One original writer: private request, READY/POST/GO, at most one candidate
// ACK, then keep stdin alive through actual wait. No arbitrary message RPC.
pub(super) async fn write(mut stdin:tokio::process::ChildStdin,request:Arc<wire::Request>,
    ready:oneshot::Receiver<Result<(),BridgeError>>,wait:oneshot::Receiver<()>,
    post:oneshot::Sender<oneshot::Sender<Result<(),BridgeError>>>,ack:oneshot::Receiver<Result<Vec<u8>,BridgeError>>,
    inner:Arc<Inner>,owner:Arc<Owner>,faults:mpsc::Sender<BridgeError>)->WriteEnd {
    let mut stop=owner.stop.subscribe();
    if *stop.borrow()||owner.failed()||Instant::now()>=owner.endpoint() {return WriteEnd {complete:false}}
    let result=tokio::select! {biased;_=stop.changed()=>return WriteEnd {complete:false},v=stdin.write_all(request.bytes())=>v};
    if result.is_err() {owner.fail(BridgeError::new("io_error","The original Git request write failed."));return WriteEnd {complete:false}}
    let ready=tokio::select! {biased;_=stop.changed()=>return WriteEnd {complete:false},v=ready=>v};
    if !matches!(ready,Ok(Ok(()))) {owner.fail(BridgeError::protocol());return WriteEnd {complete:false}}
    let (send,returned)=oneshot::channel();
    if post.send(send).is_err() {owner.fail(BridgeError::cleanup_unknown());return WriteEnd {complete:false}}
    let posted=tokio::select! {biased;_=stop.changed()=>return WriteEnd {complete:false},v=returned=>v};
    if !matches!(posted,Ok(Ok(()))) {owner.fail(BridgeError::cleanup_unknown());return WriteEnd {complete:false}}
    let Some(local)=owner.git_local.as_ref() else {owner.fail(BridgeError::cleanup_unknown());return WriteEnd {complete:false}};
    let go=if request.action.kind().is_push() {
        match local.gate.push_go(&owner.id,&request,|| {
            if local.push_go_claimed.swap(true,Ordering::SeqCst) {return false}
            claim_preflight_go(&inner,&owner,Profile::GitLocal)
        }) {Ok(bytes)=>bytes,Err(error)=>{owner.fail(error);return WriteEnd {complete:false}}}
    } else if request.action.kind()==wire::Kind::Fetch {
        match local.gate.fetch_go(&owner.id,&request,|| {
            if local.fetch_go_claimed.swap(true,Ordering::SeqCst) {return false}
            claim_preflight_go(&inner,&owner,Profile::GitLocal)
        }) {Ok(bytes)=>bytes,Err(error)=>{owner.fail(error);return WriteEnd {complete:false}}}
    } else {
        if let Err(error)=local.gate.claim(&owner.id,||claim_preflight_go(&inner,&owner,Profile::GitLocal)
            .then_some(()).ok_or_else(BridgeError::cleanup_unknown)) {owner.fail(error);return WriteEnd {complete:false}}
        zeroize::Zeroizing::new(request.go())
    };
    let sent=tokio::select! {biased;_=stop.changed()=>false,v=stdin.write_all(&go)=>v.is_ok()};
    drop(go); // Private selected-account token copy is zeroized after the sole write attempt.
    if !sent {owner.fail(BridgeError::new("io_error","The original Git GO write failed."));return WriteEnd {complete:false}}
    let mut wait=wait;let mut ack=ack;let mut ack_pending=request.phase==wire::Phase::Apply;
    let completed=loop {
        enum Next {Stop,Wait(bool),Ack(Result<Result<Vec<u8>,BridgeError>,oneshot::error::RecvError>)}
        let event=tokio::select! {biased;_=stop.changed()=>Next::Stop,v=&mut wait=>Next::Wait(v.is_ok()),v=&mut ack,if ack_pending=>Next::Ack(v)};
        match event {
            Next::Stop=>break (*stop.borrow()&&owner.failed()).then_some(ControlClosed::StoppedAfterGo),
            Next::Wait(value)=>break value.then_some(ControlClosed::Waited),
            Next::Ack(value)=>{
                ack_pending=false;
                match value {
                    // No-candidate terminal closes the channel. The actual
                    // original child wait/terminal still decides its outcome.
                    Err(_)=>{},
                    Ok(Err(error))=>{owner.fail(error);break None},
                    Ok(Ok(bytes))=>{
                        if bytes.len()>match request.action.kind() {wire::Kind::Push|wire::Kind::PushNewBranch=>wire::push_worker::ACK_LIMIT,wire::Kind::Fetch=>wire::fetch_worker::ACK_LIMIT,_=>512}||local.gate.check_current(&owner.id).is_err()||owner.failed()||Instant::now()>=owner.endpoint() {
                            owner.fail(BridgeError::cleanup_unknown());break None
                        }
                        let sent=tokio::select! {biased;_=stop.changed()=>false,v=stdin.write_all(&bytes)=>v.is_ok()};
                        if !sent {owner.fail(BridgeError::new("io_error","The original Git ACK write did not return."));break None}
                        // Only an actually returned complete write, never the
                        // mere durable candidate or scheduled send.
                        if local.ack_returned.swap(true,Ordering::SeqCst) {owner.fail(BridgeError::cleanup_unknown());break None}
                    }
                }
            }
        }
    };
    let closed=stdin.shutdown().await.is_ok();drop(stdin);
    if !closed {let error=BridgeError::new("io_error","The original Git control did not close.");owner.fail(error.clone());let _=faults.try_send(error);}
    if closed {
        if let Some(completed)=completed {
            let Ok(mut slot)=local.control_closed.lock() else {owner.fail(BridgeError::cleanup_unknown());return WriteEnd {complete:false}};
            if slot.is_some() {owner.fail(BridgeError::cleanup_unknown());owner.unknown(&inner);return WriteEnd {complete:false}}
            *slot=Some(completed);
        }
    }
    WriteEnd {complete:matches!(completed,Some(ControlClosed::Waited))&&closed}
}
pub(super) async fn read<T:AsyncRead+Unpin>(mut stdout:T,request:Arc<wire::Request>,
    ready:oneshot::Sender<Result<(),BridgeError>>,candidate:oneshot::Sender<Arc<wire::Candidate>>,
    faults:mpsc::Sender<BridgeError>)->ReadEnd {
    let mut ready=Some(ready);let mut candidate=Some(candidate);let mut first_after_ready=true;
    let mut buffer=[0u8;4096];let mut bytes=Vec::new();let mut total=0usize;let mut eof=false;let mut overflow=false;
    loop {
        match stdout.read(&mut buffer).await {
            Ok(0)=>{eof=true;break},
            Ok(count)=>{
                total=total.saturating_add(count);
                let limit=match request.action.kind() {wire::Kind::Push|wire::Kind::PushNewBranch=>wire::push_worker::OUTPUT_LIMIT,wire::Kind::Fetch=>wire::fetch_worker::OUTPUT_LIMIT,_=>wire::RESPONSE_LIMIT};
                if total>limit {overflow=true;let _=faults.try_send(BridgeError::protocol());continue}
                bytes.extend_from_slice(&buffer[..count]);
                if ready.is_some() {
                    if let Some(index)=bytes.iter().position(|b|*b==b'\n') {
                        let result=request.ready(&bytes[..=index]);
                        if result.is_err() {overflow=true;let _=faults.try_send(BridgeError::protocol());}
                        if let Some(send)=ready.take() {let _=send.send(result);}bytes.drain(..=index);
                    }else if bytes.len()>wire::READY_LIMIT {overflow=true;let _=faults.try_send(BridgeError::protocol());}
                }
                if ready.is_none() && first_after_ready {
                    if let Some(index)=bytes.iter().position(|b|*b==b'\n') {
                        first_after_ready=false;
                        let is_candidate=crate::protocol::strict_json(&bytes[..=index]).is_ok_and(|v|v["kind"]=="candidate");
                        if is_candidate {
                            match request.candidate(&bytes[..=index]) {
                                Ok(value)=>{if !candidate.take().is_some_and(|s|s.send(Arc::new(value)).is_ok()) {overflow=true;let _=faults.try_send(BridgeError::protocol());}},
                                Err(error)=>{overflow=true;let _=faults.try_send(error);candidate.take();},
                            }
                            bytes.drain(..=index);
                        }else{candidate.take();}
                    }
                }
            },
            Err(_)=>{let _=faults.try_send(BridgeError::new("io_error","The original Git output read failed."));break}
        }
    }
    if let Some(send)=ready {let _=send.send(Err(BridgeError::protocol()));}
    ReadEnd {bytes,eof,overflow}
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell",
    feature = "custom-protocol",
    not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher")
))]
pub(super) fn acquire_original(
    inner: &Inner,
    owner: &Arc<Owner>,
    slots: &Arc<Mutex<crate::installed_runtime::GitLocalRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    let mut native = slots
        .lock()
        .map_err(|_| AcquisitionError::unsupported("Git local action runtime custody unavailable"))?;
    let runtime = native.capability().map_err(AcquisitionError::capability)?;
    let stop = owner.stop.subscribe();
    let mut first = None;
    let selected = runtime
        .prepare_once_observed(owner.endpoint(), &stop, &mut |f| {
            first = f;
            owner.observe_native_failure(f);
        })
        .map_err(|e| AcquisitionError::preparation(e).with_macos_first_failure(first))?;
    let mut command = Command::new(&selected.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(&selected.bootstrap)
        .arg(&selected.core)
        .current_dir(&selected.cwd)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::runtime::macos_installed_environment(&mut command).map_err(AcquisitionError::from)?;
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    if !preflight_claim_clear(
        owners.get(&owner.key).is_some_and(|v| Arc::ptr_eq(v, owner)),
        owner.profile,
        Profile::GitLocal,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *stop.borrow(),
    ) {
        return Err(AcquisitionError::unsupported("Original Git local action claim changed"));
    }
    runtime.claim_once().map_err(AcquisitionError::final_claim)?;
    drop(state);
    drop(owners);
    command.spawn().map_err(AcquisitionError::returned_spawn)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(all(
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    ))
))]
pub(super) fn acquire_original(
    _: &Inner,
    _: &Arc<Owner>,
    _: &Arc<Mutex<crate::installed_runtime::GitLocalRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    Err(AcquisitionError::unsupported("The fixed Git local action runtime is unavailable"))
}

#[cfg(test)]
#[path="supervisor_git_local_tests.rs"]
mod tests;

#[cfg(test)]
#[path="git_switch_supervisor_tests.rs"]
mod switch_tests;
