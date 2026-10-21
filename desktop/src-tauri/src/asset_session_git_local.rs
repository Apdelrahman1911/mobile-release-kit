//! Local stage/unstage/whole-index commit under the SAME Document, saved-edit
//! stamp, original registration Publisher and Supervisor. A review is bounded
//! DATA; only its one-use admission below can create the next original work.
use super::*;
use crate::{git_local_protocol as wire,git_read_protocol as read,
    supervisor::{GitLocalAdmission,GitLocalReceipt,GitLocalTicket},
    application_service_host::{ApplicationHost,NativeProject,NativeStateReady,NativeStateTicket},
    edit_owner::SavedEditStamp};
use std::{path::{Path,PathBuf},sync::OnceLock};
#[path="asset_session_git_fetch.rs"]
mod fetch;
#[path="asset_session_git_push.rs"]
mod push;

pub(super) enum Entry {Original {ticket:GitLocalTicket,gate:GitLocalGate},Finished(wire::Projection)}
/// No runtime/source/NativeUse/Publisher/Host backreference survives here.
/// The saved stamp and root only compare the original still-current Document.
pub(super) struct ReadyReview {
    public:wire::Prepared,action:wire::Action,root:asset_source::RegisteredRoot,
    stamp:Arc<SavedEditStamp>,epoch:u64,expires:Instant,
    agent:Option<Arc<crate::service_git_requests::NativeLink>>,
    fetch:Option<crate::github_connection_session::fetch::Pins>,
    push:Option<crate::github_connection_session::push::Pins>,
}
impl Drop for ReadyReview {
    fn drop(&mut self) { if let Some(agent)=&self.agent { agent.review_removed(); } }
}
struct PostPublisher {project:NativeProject,stamp:Arc<SavedEditStamp>}
struct PublisherSlot {value:Option<RegistrationPublisher>,entered:bool,joined:bool,finished:bool}
impl PublisherSlot {
    fn accept_original(&mut self)->Result<(),BridgeError> {
        if self.entered||self.joined||self.finished {return Err(BridgeError::cleanup_unknown())}
        self.entered=true;
        let publisher=self.value.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        // First effect/epoch entry remains latched across Host IO or unwind.
        publisher.accept(crate::android_registration_app_protocol::Reason::ContextChanged)?;
        if !publisher.accepted() {return Err(BridgeError::cleanup_unknown())}Ok(())
    }
}
struct Selection {
    document:Weak<Inner>,root:asset_source::RegisteredRoot,context:wire::Context,
    document_revision:u32,action:wire::Action,phase:wire::Phase,admitted:Instant,
    stamp:Arc<SavedEditStamp>,epoch:u64,review:Option<wire::Review>,
    publisher:Option<Arc<Mutex<PublisherSlot>>>,post:OnceLock<PostPublisher>,ready:OnceLock<Arc<NativeStateReady>>,
    app_data:Option<PathBuf>,agent:Option<Arc<crate::service_git_requests::NativeLink>>,
    fetch:Option<crate::github_connection_session::fetch::Pins>,
    push:Option<crate::github_connection_session::push::Pins>,
}
#[derive(Clone)]
pub(crate) struct GitLocalGate(Arc<Selection>);
fn changed()->BridgeError {BridgeError::new("git_stale_observation","The reviewed project or Git action changed. Refresh and review it again.")}
fn state_error(error:crate::service_protocol::Error)->BridgeError {
    use crate::service_protocol::Error;
    match error {Error::StateUnknown=>BridgeError::cleanup_unknown(),Error::Expired=>BridgeError::timeout(),
        Error::RecoveryRequired=>BridgeError::new("git_recovery_required","Preserve the prior local Git operation and resolve its pending state first."),
        Error::Busy=>BridgeError::new("busy","The original local state owner is busy."),Error::Conflict=>changed(),
        _=>BridgeError::unavailable("Private local Git operation state is unavailable.")}
}
fn same_native(a:&NativeProject,b:&NativeProject)->bool {
    a.runtime_id==b.runtime_id&&a.canonical_root==b.canonical_root&&a.device==b.device&&a.inode==b.inode
        &&a.registration_generation==b.registration_generation&&a.input_revision==b.input_revision
        &&Arc::ptr_eq(&a.document_identity,&b.document_identity)
}
fn scope_current(document:&Arc<Inner>,state:&DocumentState,context:&wire::Context,root:&asset_source::RegisteredRoot,revision:u32)->bool {
    state.lifetime.original_bound()&&!state.lost_observed&&!state.unknown&&!state.exhausted&&!state.stopping
        &&!state.quit_pending&&!state.retiring&&!state.lock_pending&&!state.compatibility_picker_pending&&!state.maintenance.closed()
        &&state.revision==revision&&context.revision==format!("document-{revision}")&&document.bridge.registry_generation()==context.generation
        &&document.bridge.native_project(&context.project_id).is_ok_and(|(g,r)|g==context.generation&&&r==root)
}
impl GitLocalGate {
    pub(crate) fn same_original(&self,other:&Self)->bool {Arc::ptr_eq(&self.0,&other.0)}
    pub(crate) fn agent_arm(&self,id:&str)->Result<(),BridgeError> {
        if let Some(agent)=&self.0.agent {agent.arm(id).map_err(state_error)?;} Ok(())
    }
    pub(crate) fn agent_retired(&self,receipt:&GitLocalReceipt) {
        use crate::service_protocol::OperationState as S;
        let Some(agent)=&self.0.agent else {return};
        let state=match receipt {
            GitLocalReceipt::Pending=>return,
            GitLocalReceipt::RetainedUnknown|GitLocalReceipt::Settled {was_unknown:true,..}=>S::Unknown,
            GitLocalReceipt::Settled {outcome,was_unknown:false}=>match outcome {
                Ok(t) if t.result.get("state").and_then(Value::as_str)==Some("recovery-required")=>S::RecoveryRequired,
                Ok(t) if agent.is_remote()&&t.result.get("state").and_then(Value::as_str)==Some("failed")=>S::Failed,
                Ok(t) if t.status==read::Outcome::Ok=>S::Succeeded,
                Ok(t) if matches!(t.status,read::Outcome::Cancelled|read::Outcome::TimedOut)=>S::Cancelled,
                Err(e) if matches!(e.code.as_str(),"cancelled"|"shutting_down"|"query_timeout")=>S::Cancelled,
                _=>S::Failed,
            },
        };agent.retired(state);
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(crate) fn observation_matches(&self,c:&Arc<crate::shell::installed_observation::git_fetch::Control>)->bool {
        self.0.document.upgrade().is_some_and(|d|c.bound(&d.session_identity))
            &&self.0.root.path==c.project()&&self.0.action.kind()==wire::Kind::Fetch&&self.0.agent.is_none()
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(crate) fn push_observation_matches(&self,c:&Arc<crate::shell::installed_observation::git_push::Control>)->bool {
        self.0.document.upgrade().is_some_and(|d|c.bound(&d.session_identity))
            &&self.0.root.path==c.project()&&self.0.action.kind()==wire::Kind::Push&&self.0.agent.is_none()
    }
    pub(crate) fn context(&self)->wire::Context {self.0.context.clone()}
    pub(crate) fn review(&self)->Option<wire::Review> {self.0.review.clone()}
    pub(crate) fn host(&self)->Result<Arc<ApplicationHost>,BridgeError> {
        Ok(self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?.bridge.application_service.clone())
    }
    pub(crate) fn app_data(&self)->Result<PathBuf,BridgeError> {
        self.0.app_data.clone().ok_or_else(BridgeError::cleanup_unknown)
    }
    fn original_locked(&self,document:&Arc<Inner>,state:&DocumentState,id:&str)->bool {
        self.0.document.upgrade().is_some_and(|d|Arc::ptr_eq(&d,document))
            &&scope_current(document,state,&self.0.context,&self.0.root,self.0.document_revision)
            &&!version_allocation::pending(state)&&!version_enrollment::pending(state)&&!gh_auth::pending(state)&&!git_read::pending(state)
            &&matches!(&state.git_local,Some(Entry::Original {ticket,gate}) if ticket.operation_id()==id&&Arc::ptr_eq(&gate.0,&self.0))
    }
    fn project(&self,document:&Arc<Inner>,epoch:u64)->Result<NativeProject,BridgeError> {
        let (device,inode)=self.0.root.identity.posix().map_err(|_|changed())?.service_identity();
        Ok(NativeProject {runtime_id:self.0.context.project_id.clone(),canonical_root:self.0.root.path.clone(),device,inode,
            registration_generation:self.0.context.generation,document_identity:document.session_identity.clone(),input_revision:epoch})
    }
    fn current_locked(&self,document:&Arc<Inner>,state:&DocumentState,id:&str)->Result<(),BridgeError> {
        let edit=document.bridge.edits.saved_registration_guard(&document.session_identity)?;
        self.current_with_edit_locked(document,state,id,&edit)
    }
    fn current_with_edit_locked(&self,document:&Arc<Inner>,state:&DocumentState,id:&str,edit:&crate::edit_owner::SavedEditGuard<'_>)->Result<(),BridgeError> {
        if !self.original_locked(document,state,id) {return Err(changed())}
        self.fetch_current_locked(state,id)?;self.push_current_locked(state,id)?;
        if let Some(agent)=&self.0.agent {agent.current(id).map_err(state_error)?;}
        let epoch=if let Some(publisher)=&self.0.publisher {
            let publisher=publisher.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if publisher.finished {return Err(changed())}
            publisher.value.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.git_local_epoch()?
        }else{document.android_registration_control.epoch()?};
        let (stamp,expected)=self.0.post.get().map_or((&self.0.stamp,self.0.epoch),|p|(&p.stamp,p.project.input_revision));
        if epoch!=expected||!edit.matches(stamp) {return Err(changed())}
        if let Some(ready)=self.0.ready.get() {
            let current=self.project(document,epoch)?;
            if self.0.post.get().is_none_or(|p|!same_native(&p.project,&current)) {return Err(changed())}
            document.bridge.application_service.native_state_current(ready,&current).map_err(state_error)?;
        }
        Ok(())
    }
    /// Advisory relay observation only. All actual native claims keep their
    /// stricter original gate above. Our accept/finish job owns the publisher
    /// mutex off Doc; its lock or transitional epoch is not external drift.
    fn agent_watch_current_locked(&self,document:&Arc<Inner>,state:&DocumentState,id:&str)->Result<(),BridgeError> {
        if !self.original_locked(document,state,id) {return Err(changed())}
        self.fetch_current_locked(state,id)?;self.push_current_locked(state,id)?;
        if let Some(agent)=&self.0.agent {agent.current(id).map_err(state_error)?;}
        let edit=document.bridge.edits.saved_registration_guard(&document.session_identity)?;
        let (stamp,expected)=self.0.post.get().map_or((&self.0.stamp,self.0.epoch),|p|(&p.stamp,p.project.input_revision));
        if !edit.matches(stamp) {return Err(changed())}
        // Genuine identity/stamp/revoke/Unknown checks happen even while the
        // sole original publisher is in flight. Defer only this epoch sample.
        let Some(epoch)=agent_watch_epoch(&document.android_registration_control,self.0.publisher.as_deref())? else {return Ok(())};
        if epoch!=expected {return Err(changed())}
        if let Some(ready)=self.0.ready.get() {
            let current=self.project(document,epoch)?;
            if self.0.post.get().is_none_or(|p|!same_native(&p.project,&current)) {return Err(changed())}
            document.bridge.application_service.native_state_current(ready,&current).map_err(state_error)?;
        }
        Ok(())
    }
    pub(crate) fn check_current(&self,id:&str)->Result<asset_source::RegisteredRoot,BridgeError> {
        self.claim(id,||Ok(self.0.root.clone()))
    }
    pub(crate) fn claim<T>(&self,id:&str,claim:impl FnOnce()->Result<T,BridgeError>)->Result<T,BridgeError> {
        let document=self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let edit=document.bridge.edits.saved_registration_guard(&document.session_identity)?;
        self.current_with_edit_locked(&document,&state,id,&edit)?;
        // Fixed callers only: Doc -> original Supervisor registry -> state.
        // The supplied body does no filesystem/Host/native IO and no await.
        let result=claim();drop(edit);result
    }
    /// First registered original blocking job. The Doc scope check is finished
    /// BEFORE touching Publisher::accept, which can wait for Host/Store IO.
    pub(crate) fn accept_publisher_off_document(&self,id:&str)->Result<(),BridgeError> {
        self.check_current(id)?;
        let slot=self.0.publisher.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let mut slot=slot.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        // Entered is absorbing on any error/unwind. An error after its epoch
        // advanced must not be relabelled a pre-admission refusal or retried.
        slot.accept_original()
    }
    /// Called only after that actual job returned. All Host methods below are
    /// the existing TRY-only memory ticket APIs. No Store/open/await under Doc.
    pub(crate) fn publisher_joined_begin_host(&self,id:&str,work_end:Instant)->Result<NativeStateTicket,BridgeError> {
        let document=self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?;
        let mut state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if !self.original_locked(&document,&state,id)||Instant::now()>=work_end||self.0.post.get().is_some() {return Err(changed())}
        let mut slot=self.0.publisher.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if !slot.entered||slot.joined||slot.finished {return Err(BridgeError::cleanup_unknown())}
        let publisher=slot.value.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let epoch=publisher.git_local_epoch()?;
        if !publisher.accepted()||self.0.epoch.checked_add(1)!=Some(epoch) {return Err(changed())}
        let edit=document.bridge.edits.saved_registration_guard(&document.session_identity)?;
        if !edit.matches(&self.0.stamp) {return Err(changed())}
        let stamp=Arc::new(edit.stamp()?);drop(edit);
        // Admission already proved every peer idle. Only the actual shared
        // Android owner accepts this publisher; other owners have separate
        // controls and must not receive a foreign publisher or an IO callback.
        document.bridge.android_build.context_changed_published(Some(publisher));
        invalidate_read_data(&mut state);
        let project=self.project(&document,epoch)?;
        let roster=document.bridge.native_roster().map_err(|_|changed())?;
        let host=&document.bridge.application_service;
        host.reserve_native_state_location(self.0.app_data.as_deref().ok_or_else(BridgeError::cleanup_unknown)?,&roster.roots).map_err(state_error)?;
        let ticket=host.begin_native_state_until(project.clone(),work_end).map_err(state_error)?;
        // Retain post-accept facts before returning the one original ticket.
        // This immutable DATA can compare but cannot recreate a NativeReady.
        if self.0.post.set(PostPublisher {project,stamp}).is_err() {return Err(BridgeError::cleanup_unknown())}
        slot.joined=true;Ok(ticket)
    }
    pub(crate) fn host_joined(&self,id:&str,ticket:&NativeStateTicket)->Result<Arc<NativeStateReady>,BridgeError> {
        let document=self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?;
        let state=document.state.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        let edit=document.bridge.edits.saved_registration_guard(&document.session_identity)?;
        self.current_with_edit_locked(&document,&state,id,&edit)?;
        if self.0.ready.get().is_some() {return Err(BridgeError::cleanup_unknown())}
        let post=self.0.post.get().ok_or_else(BridgeError::cleanup_unknown)?;
        let ready=Arc::new(document.bridge.application_service.finish_native_state_retained(ticket,&post.project).map_err(state_error)?);
        let binding=ready.project_binding();
        if binding.canonical_root!=self.0.root.path.to_str().ok_or_else(changed)?
            ||(binding.device,binding.inode)!=(post.project.device,post.project.inode)
            ||ready.retained_bytes().is_none_or(|v|v>32*1024) {return Err(BridgeError::cleanup_unknown())}
        self.0.ready.set(ready.clone()).map_err(|_|BridgeError::cleanup_unknown())?;drop(edit);Ok(ready)
    }
    /// Last original finite job, after final Store write/use retirement joins.
    /// No Doc guard is held if an original publisher resolves or poisons.
    pub(crate) fn finish_publisher_off_document(&self)->Result<(),BridgeError> {
        let document=self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?;
        let mut slot=self.0.publisher.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.finished {return Err(BridgeError::cleanup_unknown())}
        let publisher=slot.value.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        if slot.entered&&!publisher.accepted() {return Err(BridgeError::cleanup_unknown())}
        slot.finished=true;
        let publisher=slot.value.take().ok_or_else(BridgeError::cleanup_unknown)?;
        finish_registration_publisher(publisher);
        if document.android_registration_control.is_unknown() {return Err(BridgeError::cleanup_unknown())}Ok(())
    }
}

#[cfg(test)]
impl DocumentBinding {
    /// Only the real IO-bearing Publisher segment is exercised. This method
    /// does NOT admit a Git operation, create a Gate, open Store or grant GO.
    /// The production Gate::check_current above returns owned DATA, so its Doc
    /// guard is necessarily gone before this same segment can be entered.
    pub(crate) fn git_local_publisher_segment_test(&self,arrived:std::sync::mpsc::SyncSender<()>)->Result<(),BridgeError> {
        let publisher=self.inner.android_registration_control.reserve(RegistrationPublisherKind::General,false)?;
        {let _document=self.lock();} // Genuine Doc, no fabricated native state.
        let mut slot=PublisherSlot {value:Some(publisher),entered:false,joined:false,finished:false};
        arrived.send(()).map_err(|_|BridgeError::cleanup_unknown())?;
        let result=slot.accept_original();
        if let Some(publisher)=slot.value.take() {finish_registration_publisher(publisher);}
        result
    }
}
fn invalidate_read_data(state:&mut DocumentState) {
    state.saved_input=None;state.apple_provisioning_ready=None;
    // Pending reads are excluded at admission. No old read revision is minted
    // from a write, and no refresh/Store or arbitrary context callback runs.
    if !git_read::pending(state) {state.git_read=None;}
    state.evidence.revoke(false);
}
pub(super) fn pending(state:&DocumentState)->bool {matches!(&state.git_local,Some(Entry::Original {ticket,gate}) if !ticket.settled()||gate.0.fetch.is_some()||gate.0.push.is_some())}
pub(super) fn stop(state:&DocumentState) {if let Some(Entry::Original {ticket,..})=&state.git_local {if !ticket.settled(){ticket.stop();}}}
pub(super) fn invalidate(state:&mut DocumentState) {state.git_local_review=None;stop(state);}
pub(super) fn retained_bytes(state:&DocumentState)->Option<usize> {
    if pending(state) {return None}
    let result=if state.git_local.is_some() {read::RESULT_BACKING} else {0};
    result.checked_add(if state.git_local_review.is_some(){wire::REVIEW_BACKING}else{0})?
        .checked_add(fetch::extra_retained(state.git_local_review.as_ref())?.checked_add(push::extra_retained(state.git_local_review.as_ref())?)?)
}
fn reason(error:&BridgeError)->(&'static str,read::Outcome) {
    match error.code.as_str() {
        "cancelled"|"shutting_down"=>("authorization",read::Outcome::Cancelled),"query_timeout"=>("deadline",read::Outcome::TimedOut),
        "git_stale_observation"=>("stale-observation",read::Outcome::Refused),"git_recovery_required"=>("recovery-required",read::Outcome::Refused),
        "runtime_unavailable"=>("unsupported-repository",read::Outcome::Refused),"protocol_error"|"output_limit"=>("response-invalid",read::Outcome::Refused),
        "invalid_request"=>("invalid-input",read::Outcome::Refused),_=>("command-failed",read::Outcome::Refused),
    }
}
fn projection(entry:&Entry)->wire::Projection {
    let Entry::Original {ticket,gate}=entry else {let Entry::Finished(value)=entry else {unreachable!()};return value.clone()};
    let mut value=wire::Projection {operation_id:ticket.operation_id().into(),context:gate.context(),phase:gate.0.phase,
        action:gate.0.action.public(),stage:ticket.pending_stage(),outcome:None,reason:None,result:Value::Null};
    match ticket.receipt() {
        GitLocalReceipt::Pending=>{},GitLocalReceipt::RetainedUnknown|GitLocalReceipt::Settled {was_unknown:true,..}=>{
            value.stage=read::Phase::CleanupUnknown;value.outcome=Some(read::Outcome::CleanupUnknown);value.reason=Some("unknown".into());
        },
        GitLocalReceipt::Settled {outcome,was_unknown:false}=>{
            value.stage=read::Phase::Settled;match outcome {
                Ok(terminal)=>{value.outcome=Some(terminal.status);value.reason=terminal.reason;value.result=terminal.result;},
                Err(error)=>{let (reason,outcome)=reason(&error);value.reason=Some(reason.into());value.outcome=Some(outcome);},
            }
        }
    }value
}
/// No return value from this advisory probe grants work or finality. A busy
/// original publisher can only defer the relay's epoch comparison; actual
/// publisher/Host/GO/publication claims still use the unchanged strict gate.
fn agent_watch_epoch(control:&crate::saved_command_owner::AndroidRegistrationControl,publisher:Option<&Mutex<PublisherSlot>>)->Result<Option<u64>,BridgeError> {
    if control.is_unknown() {return Err(BridgeError::cleanup_unknown())}
    let Some(publisher)=publisher else {return control.epoch().map(Some)};
    let slot=match publisher.try_lock() {
        Ok(slot)=>slot,
        Err(std::sync::TryLockError::WouldBlock)=>return Ok(None),
        Err(std::sync::TryLockError::Poisoned(_))=>return Err(BridgeError::cleanup_unknown()),
    };
    if slot.finished||(slot.entered&&!slot.joined) {return Ok(None)}
    slot.value.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.git_local_epoch().map(Some)
}
fn agent_review_matches(review:Option<&crate::service_git_requests::NativeLink>,incoming:Option<&crate::service_git_requests::NativeLink>)->bool {
    match (review,incoming) {
        (None,None)=>true,
        (Some(a),Some(b))=>a.phase()==crate::service_git_requests::Phase::Prepare&&b.phase()==crate::service_git_requests::Phase::Apply&&a.same_request(b),
        _=>false,
    }
}
#[cfg(any(target_os="linux",target_os="macos"))]
pub(super) fn agent_running(state:&DocumentState)->bool {
    matches!(&state.git_local,Some(Entry::Original {gate,..}) if gate.0.agent.is_some())
}
#[cfg(any(target_os="linux",target_os="macos"))]
pub(super) fn agent_tick(document:&Arc<Inner>,state:&mut DocumentState) {
    if let Some(Entry::Original {ticket,gate})=&state.git_local {
        if let Some(agent)=gate.0.agent.as_ref().filter(|_|!ticket.settled()) {
            agent.entry().expire(Instant::now());
            if let Ok(Some((_,at)))=agent.entry().stop_at() {ticket.agent_stop_at(at);}
            else if gate.agent_watch_current_locked(document,state,ticket.operation_id()).is_err() {
                let at=Instant::now();agent.entry().cancel(crate::service_git_protocol::Reason::ContextChanged,at);
                let first=agent.entry().stop_at().ok().flatten().map_or(at,|(_,first)|first);
                ticket.agent_stop_at(first);
            }
        }
    }
    reconcile(document,state);
}
pub(super) fn reconcile(document:&Arc<Inner>,state:&mut DocumentState) {
    if state.git_local_review.as_ref().is_some_and(|r|Instant::now()>=r.expires
        ||!scope_current(document,state,&r.public.context,&r.root,state.revision)
        ||!document.android_registration_control.matches_epoch(r.epoch)||!fetch::review_current(state,r)||!push::review_current(state,r)||r.agent.as_ref().is_some_and(|a|{a.entry().expire(Instant::now());a.stopped()})) {state.git_local_review=None;}
    let Some(Entry::Original {ticket,gate})=&state.git_local else {return};
    if !ticket.settled() {return}
    let view=projection(state.git_local.as_ref().expect("same original"));
    let remote=gate.0.agent.as_ref().filter(|a|a.is_remote()).cloned();
    let mut prepared=if gate.0.phase==wire::Phase::Prepare {
        match ticket.receipt() {
            GitLocalReceipt::Settled {outcome:Ok(terminal),was_unknown:false} if terminal.status==read::Outcome::Ok=>{
                (|| {
                    gate.current_locked(document,state,ticket.operation_id()).ok()?;
                    let expires=gate.0.admitted.checked_add(REVIEW)?;
                    if Instant::now()>=expires {return None}
                    let review=terminal.review().ok()?;
                    if let Some(agent)=gate.0.agent.as_ref().filter(|a|!a.is_remote()) {
                        let summary=agent_git_index::agent_git_review(agent.scope(),&review,
                            format!("{}-review",ticket.operation_id()),gate.0.document_revision,gate.0.context.generation)?;
                        if !agent.ready(summary,expires).ok()? {return None}
                    }
                    Some(ReadyReview {public:wire::Prepared {review_id:format!("{}-review",ticket.operation_id()),
                        context:gate.context(),action:gate.0.action.public(),review,diff:terminal.result.get("diff").cloned()},
                        action:gate.0.action.clone(),root:gate.0.root.clone(),stamp:gate.0.stamp.clone(),epoch:gate.0.epoch,expires,agent:gate.0.agent.clone(),fetch:gate.0.fetch.clone(),push:gate.0.push.clone()})
                })()
            },_=>None,
        }
    }else{None};
    if prepared.is_none() {if let Some(agent)=&gate.0.agent {agent.no_review();}}
    if fetch::finish(state).is_err() || push::finish(state).is_err() {
        // Original IO may have returned, but contradictory/missing private
        // Connection retirement evidence cannot free admission or mint a
        // replacement review. Keep the original entry/hold for attention.
        if let Some(agent)=&remote {agent.entry().unknown();}
        state.unknown=true;state.github.retire(crate::github_connection_protocol::Reason::CleanupUnknown);return;
    }
    if let Some(agent)=remote {
        // Native settlement alone is not the Connection's actual return.
        // finish may return Ok after poisoning/retiring that same Connection.
        if !state.github.git_remote_finish_known() {
            agent.entry().unknown();state.unknown=true;return;
        }
        // The held-gate candidate was formed BEFORE finish. The hold is now
        // gone: rematch via the original prepared-current path, never call a
        // removed-hold gate or create a new review/expiry here.
        if prepared.as_ref().is_some_and(|r|Instant::now()>=r.expires
            ||!scope_current(document,state,&r.public.context,&r.root,agent.scope().document_revision)
            ||!document.android_registration_control.matches_epoch(r.epoch)
            ||!fetch::review_current(state,r)||!push::review_current(state,r)||agent.stopped()
            ||document.bridge.edits.saved_registration_guard(&document.session_identity).map_or(true,|e|!e.matches(&r.stamp))) {
            prepared=None;
        }
        let candidate=match prepared.as_ref() {
            Some(r)=>match agent_git_index::agent_git_remote_review(agent.scope(),&r.public.review,r.public.review_id.clone(),agent.scope().document_revision,r.public.context.generation) {
                Some(summary)=>Some((summary,r.expires)),
                None=>{agent.entry().unknown();state.unknown=true;return;}
            },None=>None,
        };
        let returned=agent_git_index::agent_git_remote_outcome(agent.scope(),&view)
            .map_err(|_|crate::service_protocol::Error::StateUnknown)
            .and_then(|outcome|agent.remote_connection_returned(candidate,outcome));
        match returned {
            Ok(true)=>{},Ok(false)=>prepared=None,
            Err(_)=>{agent.entry().unknown();state.unknown=true;return;}
        }
    }
    state.git_local_review=prepared;state.git_local=Some(Entry::Finished(view));
}
impl DocumentBinding {
    pub(super) fn git_local_new_gate(&self,state:&DocumentState)->Result<(),BridgeError> {
        self.git_local_new_gate_for(state,wire::Kind::Stage)
    }
    pub(super) fn git_local_new_gate_for(&self,state:&DocumentState,kind:wire::Kind)->Result<(),BridgeError> {
        if !state.lifetime.original_bound()||state.lost_observed {return Err(BridgeError::unavailable("The original application document is unavailable."))}
        self.passive_query_gate_locked(state,self.inner.bridge.as_ref())?;
        if pending(state)||!self.inner.bridge.supervisor.can_exit()||!self.inner.bridge.edits.can_exit()
            ||self.inner.bridge.edits.preflight_attention()||state.slot.as_ref().is_some_and(|s|s.phase!=Phase::Idle||!s.owner.resources_settled())
            ||state.github.native_work_pending()||(!matches!(kind,wire::Kind::Fetch|wire::Kind::Push|wire::Kind::PushNewBranch)&&state.github.registration().is_some()) {return Err(BridgeError::new("busy","Finish the original task before changing local Git state."))}
        if !self.inner.bridge.supervisor.git_local_profile_available()||kind==wire::Kind::Fetch&&!self.inner.bridge.supervisor.git_fetch_profile_available()||kind.is_push()&&!self.inner.bridge.supervisor.git_push_profile_available_for(kind) {return Err(BridgeError::unavailable("The fixed local Git writer is unavailable."))}Ok(())
    }
    fn git_local_snapshot(&self,state:&DocumentState)->wire::Status {wire::Status {schema_version:1,document_revision:state.revision,
        available:self.inner.bridge.supervisor.git_local_profile_available()&&state.lifetime.original_bound()&&!state.lost_observed,
        review:state.git_local_review.as_ref().map(|r|r.public.clone()),operation:state.git_local.as_ref().map(projection)}}
    pub(crate) fn git_local_status(&self)->wire::Status {let mut state=self.lock();reconcile(&self.inner,&mut state);self.git_local_snapshot(&state)}
    pub(crate) fn git_local_cancel(&self,id:&str)->Result<wire::Status,BridgeError> {
        let mut state=self.lock();match &state.git_local {
            Some(Entry::Original {ticket,..}) if ticket.operation_id()==id=>ticket.stop(),
            Some(Entry::Finished(v)) if v.operation_id==id=>{},_=>return Err(BridgeError::invalid()),
        }reconcile(&self.inner,&mut state);Ok(self.git_local_snapshot(&state))
    }
    pub(crate) fn git_local_discard(&self,id:&str)->Result<wire::Status,BridgeError> {
        let mut state=self.lock();reconcile(&self.inner,&mut state);
        if pending(&state)||state.git_local_review.as_ref().is_none_or(|r|r.public.review_id!=id) {return Err(BridgeError::invalid())}
        state.git_local_review=None;Ok(self.git_local_snapshot(&state))
    }
    pub(crate) fn git_local_prepare(&self,args:wire::Prepare)->Result<wire::StartResult,BridgeError> {
        self.git_local_prepare_original(args,None)
    }
    pub(super) fn git_local_prepare_original(&self,args:wire::Prepare,agent:Option<Arc<crate::service_git_requests::NativeLink>>)->Result<wire::StartResult,BridgeError> {
        let admitted=Instant::now();let mut state=self.lock();reconcile(&self.inner,&mut state);
        let request=wire::StartRequest {phase:wire::Phase::Prepare,project_id:args.project_id.clone(),expected_document_revision:args.expected_document_revision,
            action:Some(args.action.public()),review_id:None};
        let outcome=(|| {
            self.git_local_new_gate_for(&state,args.action.kind())?;
            if state.git_local_review.is_some() {return Err(BridgeError::new("busy","Use or close the current Git review first."))}
            if state.revision!=args.expected_document_revision {return Err(changed())}if !args.action.valid(){return Err(BridgeError::invalid())}
            let (generation,root)=self.inner.bridge.native_project(&args.project_id).map_err(|_|changed())?;
            let fetch=fetch::select(&state,&args.project_id,generation,&args.action,admitted)?;
            let push=push::select(&state,&args.project_id,generation,&args.action,admitted)?;
            if (fetch.is_some()||push.is_some())&&agent.as_ref().is_some_and(|a|!a.is_remote()){return Err(BridgeError::invalid())}
            let future=GitLocalAdmission::reservation_bytes(args.action.kind()).ok_or_else(BridgeError::invalid)?;
            lookup_memory::git_local_admission_bytes_for(&self.inner,&state,future,args.action.kind()).map_err(|_|BridgeError::new("busy","The current native tasks leave insufficient Git working storage."))?;
            let epoch=self.inner.android_registration_control.epoch()?;
            let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let stamp=Arc::new(edit.stamp()?);
            #[cfg(any(target_os="linux",target_os="macos"))]
            if let Some(agent)=&agent {self.agent_git_index_admission(&state,agent,crate::service_git_requests::Phase::Prepare,&root,generation,epoch,&edit,&args.action,fetch.as_ref(),push.as_ref())?;}
            let gate=GitLocalGate(Arc::new(Selection {document:Arc::downgrade(&self.inner),root,
                context:wire::Context {project_id:args.project_id.clone(),generation,revision:format!("document-{}",args.expected_document_revision)},
                document_revision:state.revision,action:args.action.clone(),phase:wire::Phase::Prepare,admitted,stamp,epoch,review:None,publisher:None,
                post:OnceLock::new(),ready:OnceLock::new(),app_data:None,agent,fetch,push}));
            let reserved=GitLocalAdmission::reserve(gate.clone(),args.action,wire::Phase::Prepare,admitted)?;
            let ticket=self.inner.bridge.supervisor.start_git_local(reserved)?;
            state.git_local=Some(Entry::Original {ticket,gate});fetch::retain(&mut state)?;push::retain(&mut state)?;drop(edit);Ok(())
        })();
        self.git_local_started(&state,request,outcome)
    }
    pub(crate) fn git_local_apply(&self,args:wire::Apply,app_data:&Path)->Result<wire::StartResult,BridgeError> {
        self.git_local_apply_original(args,app_data,None)
    }
    pub(super) fn git_local_apply_original(&self,args:wire::Apply,app_data:&Path,agent:Option<Arc<crate::service_git_requests::NativeLink>>)->Result<wire::StartResult,BridgeError> {
        let request=wire::StartRequest {phase:wire::Phase::Apply,project_id:args.project_id.clone(),expected_document_revision:args.expected_document_revision,
            action:None,review_id:Some(args.review_id.clone())};
        // Mandatory ControlSlot ordering: reserve before Doc. No epoch/Store
        // effects yet. Any normal pre-insertion refusal rejects OFF Doc.
        let publisher=match self.inner.android_registration_control.reserve(RegistrationPublisherKind::General,false) {
            Ok(value)=>value,Err(error)=>{let state=self.lock();return self.git_local_started(&state,request,Err(error));}
        };
        let admitted=publisher.at();
        let held=Arc::new(Mutex::new(PublisherSlot {value:Some(publisher),entered:false,joined:false,finished:false}));
        let mut inserted=false;
        let result={
            let mut state=self.lock();
            // Do NOT call the ordinary epoch() reconciliation after our own
            // publisher reservation: it properly refuses pending publishers.
            let outcome=(|| {
                let kind=state.git_local_review.as_ref().ok_or_else(changed)?.action.kind();
                self.git_local_new_gate_for(&state,kind)?;
                if state.revision!=args.expected_document_revision {return Err(changed())}
                let review=state.git_local_review.as_ref().ok_or_else(changed)?;
                if !agent_review_matches(review.agent.as_deref(),agent.as_deref()) {return Err(changed());}
                let publisher=held.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
                let epoch=publisher.value.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.git_local_epoch()?;
                if review.public.review_id!=args.review_id||review.public.context.project_id!=args.project_id
                    ||Instant::now()>=review.expires||epoch!=review.epoch
                    ||!scope_current(&self.inner,&state,&review.public.context,&review.root,args.expected_document_revision) {return Err(changed())}
                if !app_data.is_absolute()||app_data.as_os_str().len()>4096 {return Err(BridgeError::invalid())}
                let fetch=fetch::selected_review(&state,review,admitted)?;
                let push=push::selected_review(&state,review,admitted)?;
                if (fetch.is_some()||push.is_some())&&agent.as_ref().is_some_and(|a|!a.is_remote()){return Err(BridgeError::invalid())}
                let future=GitLocalAdmission::reservation_bytes(review.action.kind()).ok_or_else(BridgeError::invalid)?;
                lookup_memory::git_local_admission_bytes_for(&self.inner,&state,future,review.action.kind()).map_err(|_|BridgeError::new("busy","The current native tasks leave insufficient Git working storage."))?;
                let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
                if !edit.matches(&review.stamp) {return Err(changed())}
                #[cfg(any(target_os="linux",target_os="macos"))]
                if let Some(agent)=&agent {self.agent_git_index_admission(&state,agent,crate::service_git_requests::Phase::Apply,&review.root,review.public.context.generation,epoch,&edit,&review.action,fetch.as_ref(),push.as_ref())?;}
                let gate=GitLocalGate(Arc::new(Selection {document:Arc::downgrade(&self.inner),root:review.root.clone(),
                    context:wire::Context {project_id:args.project_id.clone(),generation:review.public.context.generation,
                        revision:format!("document-{}",args.expected_document_revision)},document_revision:state.revision,
                    action:review.action.clone(),phase:wire::Phase::Apply,admitted,stamp:review.stamp.clone(),epoch,review:Some(review.public.review.clone()),
                    publisher:Some(held.clone()),post:OnceLock::new(),ready:OnceLock::new(),app_data:Some(app_data.to_owned()),agent,fetch,push}));
                let reserved=GitLocalAdmission::reserve(gate.clone(),review.action.clone(),wire::Phase::Apply,admitted)?;
                let ticket=self.inner.bridge.supervisor.start_git_local(reserved)?;
                // Consume before the optional same-Connection hold. A hold
                // failure retains this actual owner as Unknown, never a new
                // admission refusal or an unspent Publisher/review.
                state.git_local=Some(Entry::Original {ticket,gate});state.git_local_review=None;inserted=true;
                invalidate_read_data(&mut state);fetch::retain(&mut state)?;push::retain(&mut state)?;drop(edit);drop(publisher);Ok(())
            })();
            self.git_local_started(&state,request,outcome)
        };
        if !inserted {
            let mut slot=held.lock().map_err(|_|BridgeError::cleanup_unknown())?;
            if slot.entered||slot.value.as_ref().is_none_or(|p|p.accepted()) {return Err(BridgeError::cleanup_unknown())}
            slot.finished=true;let publisher=slot.value.take().ok_or_else(BridgeError::cleanup_unknown)?;publisher.reject();
        }
        result
    }
    fn git_local_started(&self,state:&DocumentState,request:wire::StartRequest,outcome:Result<(),BridgeError>)->Result<wire::StartResult,BridgeError> {
        let (admission,reason)=match outcome {
            Ok(())=>(read::Admission::Started,None),Err(error) if error.code=="cleanup_unknown"=>return Err(error),
            Err(error)=>(read::Admission::Refused,Some(match error.code.as_str() {
                "git_stale_observation"=>read::StartRefusal::StaleObservation,"invalid_request"=>read::StartRefusal::InvalidInput,
                "busy"=>read::StartRefusal::Busy,_=>read::StartRefusal::Unavailable,
            })),
        };
        Ok(wire::StartResult {schema_version:1,admission,request,status:self.git_local_snapshot(state),reason})
    }
}

#[cfg(test)]
#[path="service_git_native_tests.rs"]
mod agent_tests;
