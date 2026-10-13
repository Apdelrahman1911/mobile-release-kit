//! One finite Setup state in the original GitHub ConnectionState.
//! Secret material is an opaque same-Arc loan; no independent owner or renewed deadline.
use std::time::Instant;
use crate::{asset_source::RegisteredRoot, edit_owner::SavedEditStamp, error::BridgeError,
    github_setup_protocol as wire, supervisor::{GitHubSetupReceipt, GitHubSetupTicket}};

pub(crate) fn refused(reason: wire::Reason) -> BridgeError {
    let message = match reason {
        wire::Reason::NotConnected => "Connect the registered project to GitHub before reviewing repository settings.",
        wire::Reason::ConsentExpired => "The review expired or was already used. Prepare a fresh review; do not retry an uncertain change.",
        wire::Reason::Busy => "The original operation must settle before another repository setting action.",
        wire::Reason::CleanupUnknown => "Original cleanup is unconfirmed. Keep the original session for retirement.",
        wire::Reason::Unqualified | wire::Reason::RuntimeUnavailable => "The fixed repository settings runtime is unavailable in this build.",
        wire::Reason::RateLimited => "The original GitHub rate-limit interval still applies.",
        wire::Reason::Expired => "The original session credential expired. Disconnect before authenticating again.",
        wire::Reason::TargetChanged => "The original project, edit context, account, repository or review changed.",
        wire::Reason::Cancelled => "The original repository setting action was cancelled; its remote effect may remain unknown.",
        wire::Reason::OrganizationRestricted => "The owning organization restricts this policy. No weaker policy or automatic retry was attempted.",
        wire::Reason::PolicyUnsupported => "The returned complete policy is not supported; no missing field is treated as a default.",
        wire::Reason::PolicyChanged => "Repository settings changed after the review. Prepare a new review before deciding again.",
        wire::Reason::Forbidden => "GitHub did not permit this operation. Preview requires Administration read; Apply requires Administration write.",
        _ => "The request does not match the current supported repository setting action.",
    };
    let name = serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_remote_setup_refused_{}", name.replace('-', "_")), message)
}
pub(crate) fn connection_reason(value: crate::github_connection_protocol::Reason) -> wire::Reason {
    use crate::github_connection_protocol::Reason as R;
    match value {
        R::None => wire::Reason::None, R::Unqualified => wire::Reason::Unqualified,
        R::RuntimeUnavailable => wire::Reason::RuntimeUnavailable, R::NotConnected => wire::Reason::NotConnected,
        R::Busy => wire::Reason::Busy, R::Expired => wire::Reason::Expired, R::RateLimited => wire::Reason::RateLimited,
        R::Cancelled => wire::Reason::Cancelled, R::CleanupUnknown => wire::Reason::CleanupUnknown,
        R::TargetChanged => wire::Reason::TargetChanged, R::Unauthorized => wire::Reason::Unauthorized,
        R::Forbidden => wire::Reason::Forbidden, R::NotFoundOrInaccessible => wire::Reason::NotFoundOrInaccessible,
        R::NetworkUnavailable => wire::Reason::NetworkUnavailable, R::TlsFailed => wire::Reason::TlsFailed,
        R::ResponseInvalid => wire::Reason::ResponseInvalid, R::ResponseLimit => wire::Reason::ResponseLimit,
        _ => wire::Reason::InvalidInput,
    }
}
pub(crate) fn outcome_reason(value: &BridgeError) -> wire::Reason { match value.code.as_str() {
    "cleanup_unknown" => wire::Reason::CleanupUnknown, "protocol_error" => wire::Reason::ResponseInvalid,
    "output_limit" | "stdout_limit" | "stderr_limit" => wire::Reason::ResponseLimit,
    "cancelled" | "shutting_down" => wire::Reason::Cancelled, "runtime_unavailable" => wire::Reason::RuntimeUnavailable,
    "github_sealing_failed" => wire::Reason::SealingFailed,
    "github_remote_setup_refused_resources_unavailable" => wire::Reason::ResourcesUnavailable,
    "github_remote_setup_refused_material_unavailable" => wire::Reason::MaterialUnavailable,
    "github_remote_setup_refused_material_changed" => wire::Reason::MaterialChanged,
    "github_remote_setup_refused_material_too_large" => wire::Reason::MaterialTooLarge,
    "github_remote_setup_refused_requirement_unsupported" => wire::Reason::RequirementUnsupported,
    "github_remote_setup_refused_configuration_changed" => wire::Reason::ConfigurationChanged,
    "github_remote_setup_refused_target_changed" => wire::Reason::TargetChanged,
    "github_remote_setup_refused_cancelled" => wire::Reason::Cancelled,
    "github_remote_setup_refused_expired" => wire::Reason::Expired,
    "github_remote_setup_refused_cleanup_unknown" => wire::Reason::CleanupUnknown,
    _ => wire::Reason::NetworkUnavailable,
} }

pub(crate) struct Active {
    pub(crate) ticket: GitHubSetupTicket, pub(crate) request: wire::Request,
    pub(crate) session_id: String, pub(crate) project_id: String, pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot, pub(crate) edit_stamp: SavedEditStamp,
    pub(crate) consent_id: String, pub(crate) consent_end: Option<Instant>,
}
// One closed retained authority. Variables carry the original field Arc, not
// a lookalike SecretSealed or another optional consent beside the real one.
pub(crate) enum ConsentMaterial {
    Secret(crate::supervisor::SecretSealed),
    Variable(std::sync::Arc<crate::asset_session::GitHubVariableMaterial>),
}
impl ConsentMaterial {
    fn retained_heap_bytes(&self)->Option<usize>{match self {
        Self::Secret(value)=>value.retained_heap_bytes(),
        // The same document census charges this Arc's unique material backing
        // and deduplicates its actual NativeContext/Payload with other loans.
        Self::Variable(_)=>Some(0),
    }}
    pub(crate) fn secret(&self)->Option<&crate::supervisor::SecretSealed>{match self{Self::Secret(v)=>Some(v),Self::Variable(_)=>None}}
    pub(crate) fn variable(&self)->Option<&std::sync::Arc<crate::asset_session::GitHubVariableMaterial>>{match self{Self::Variable(v)=>Some(v),Self::Secret(_)=>None}}
}
pub(crate) struct Consent {
    pub(crate) material: Option<ConsentMaterial>,
    pub(crate) id: String, pub(crate) prepared: wire::Prepared, pub(crate) end: Instant,
    pub(crate) session_id: String, pub(crate) project_id: String, pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot, pub(crate) edit_stamp: SavedEditStamp,
}
impl Consent {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.id.capacity()
        .checked_add(self.prepared.retained_heap_bytes()?)?.checked_add(self.session_id.capacity())?
        .checked_add(self.project_id.capacity())?.checked_add(self.root.path.capacity())?
        .checked_add(self.material.as_ref().map_or(Some(0),|v|v.retained_heap_bytes())?)}
}
pub(crate) struct State {
    pub(crate) view: wire::Status, pub(crate) active: Option<Active>, pub(crate) consent: Option<Consent>,
    pub(crate) exhausted: bool,
}
impl State {
    pub(crate) fn new() -> Self { Self { view: wire::Status { schema_version: 1, revision: 1,
        session_id: None, available: false, reason: wire::Reason::NotConnected,
        operation: None, consent: None, observed: None }, active: None, consent: None, exhausted: false } }
    pub(crate) fn snapshot(&self) -> wire::Status { self.view.clone() }
    pub(crate) fn native_work_pending(&self) -> bool { self.active.is_some() }
    pub(crate) fn settled(&self) -> bool { self.active.is_none() }
    pub(crate) fn receipt(&self) -> Option<GitHubSetupReceipt> { self.active.as_ref().map(|v| v.ticket.receipt()) }
    pub(crate) fn revoke_consent(&mut self) { self.consent = None; self.view.consent = None; }
    pub(crate) fn finish(&mut self, before: wire::Status) {
        if self.exhausted { self.view = before; return; }
        if self.view != before {
            if before.revision >= wire::LAST_REVISION - 1 {
                self.view.revision = wire::LAST_REVISION; self.exhausted = true; self.unknown();
            } else { self.view.revision = before.revision + 1; }
        }
    }
    pub(crate) fn observe_go(&mut self) {
        if self.active.as_ref().is_some_and(|v| v.request.kind == wire::Kind::Apply && v.ticket.go_claimed()) {
            if let Some(op) = &mut self.view.operation { op.effect = wire::Effect::Unknown; }
        }
    }
    pub(crate) fn unknown(&mut self) {
        self.revoke_consent(); self.view.available = false; self.view.reason = wire::Reason::CleanupUnknown;
        if let Some(active) = &self.active { active.ticket.stop(); }
        self.observe_go();
        if let Some(op) = &mut self.view.operation {
            // A separate later domain failure cannot rewrite this original's
            // already published terminal receipt. Current admission still closes.
            if op.phase != wire::Phase::Settled {
                op.phase = wire::Phase::CleanupUnknown; op.reason = wire::Reason::CleanupUnknown;
                op.write_claimed = None; op.write_acknowledged = None;
                if op.kind == wire::Kind::Apply && op.effect == wire::Effect::ReadbackConfirmed { op.effect = wire::Effect::Unknown; }
            }
        }
    }
    pub(crate) fn stop(&mut self) {
        self.revoke_consent();
        if let Some(active) = &self.active {
            active.ticket.stop();
            if let Some(op) = &mut self.view.operation {
                if op.phase != wire::Phase::CleanupUnknown { op.phase = wire::Phase::Stopping; op.reason = wire::Reason::Cancelled; }
            }
        }
        self.observe_go();
    }
    pub(crate) fn expire_consent(&mut self, now: Instant) {
        if self.consent.as_ref().is_some_and(|v| now >= v.end) {
            self.revoke_consent(); self.view.reason = wire::Reason::ConsentExpired;
        }
    }
    pub(crate) fn start(&mut self, active: Active, before: wire::Status) {
        // The actual snapshot is retained and capacity-checked before admission.
        self.revoke_consent(); self.view.observed = None;
        self.view.operation = Some(wire::Operation { id: active.ticket.operation_id().into(), kind: active.request.kind,
            phase: wire::Phase::Running, reason: wire::Reason::None, effect: wire::Effect::NotStarted,
            write_claimed: None, write_acknowledged: None });
        self.view.session_id = Some(active.session_id.clone()); self.view.available = false; self.view.reason = wire::Reason::Busy;
        self.active = Some(active); self.finish(before);
    }
    pub(crate) fn cancel(&mut self, id: &str) -> Result<(), BridgeError> {
        if !self.active.as_ref().is_some_and(|v| v.ticket.operation_id() == id) { return Err(refused(wire::Reason::InvalidInput)); }
        let before = self.snapshot(); self.stop(); self.finish(before); Ok(())
    }
    pub(crate) fn discard(&mut self, args: &wire::DiscardArgs) -> Result<(), BridgeError> {
        if self.active.is_some() { return Err(refused(wire::Reason::Busy)); }
        if args.expected_revision != self.view.revision || !self.consent.as_ref().is_some_and(|v|
            v.id == args.consent_id && v.session_id == args.session_id) { return Err(refused(wire::Reason::ConsentExpired)); }
        let before = self.snapshot(); self.revoke_consent(); self.finish(before); Ok(())
    }
    pub(crate) fn retained_heap_bytes_if_quiescent(&self) -> Option<usize> {
        if self.active.is_some() || self.exhausted || self.view.reason == wire::Reason::CleanupUnknown
            || self.view.operation.as_ref().is_some_and(|v| v.phase != wire::Phase::Settled || v.reason == wire::Reason::CleanupUnknown) {
            return None;
        }
        let mut bytes = self.view.retained_heap_bytes()?;
        if let Some(v) = &self.consent { bytes = bytes.checked_add(v.id.capacity())?
            .checked_add(v.prepared.retained_heap_bytes()?)?.checked_add(v.session_id.capacity())?
            .checked_add(v.project_id.capacity())?.checked_add(v.root.path.capacity())?
            .checked_add(v.material.as_ref().map_or(Some(0),|material|material.retained_heap_bytes())?)?; }
        Some(bytes)
    }
}

#[cfg(test)]
pub(crate) fn data_checks() {
    use wire::{Effect,Kind,Operation,Phase,Reason};
    let mut state=State::new();assert!(state.settled() && !state.native_work_pending());
    assert!(state.view.fits_wire() && state.retained_heap_bytes_if_quiescent().is_some());
    assert!(state.cancel("foreign-operation").is_err());
    let before=state.snapshot();state.view.available=true;state.view.reason=Reason::None;state.finish(before);
    assert_eq!(state.view.revision,2);
    state.view.operation=Some(Operation { id:"prior-apply".into(),kind:Kind::Apply,phase:Phase::Settled,
        reason:Reason::None,effect:Effect::ReadbackConfirmed,write_claimed:Some(true),write_acknowledged:Some(true) });
    let original=state.view.operation.clone();let before=state.snapshot();state.unknown();state.finish(before);
    assert_eq!(state.view.operation,original);assert!(!state.view.available && state.view.reason==Reason::CleanupUnknown);
    assert!(state.retained_heap_bytes_if_quiescent().is_none());
    let mut pending=State::new();pending.view.operation=Some(Operation {id:"current-apply".into(),kind:Kind::Apply,
        phase:Phase::Stopping,reason:Reason::Cancelled,effect:Effect::Unknown,write_claimed:None,write_acknowledged:None});
    pending.unknown();let op=pending.view.operation.as_ref().unwrap();
    assert_eq!((op.phase,op.effect,op.write_claimed,op.write_acknowledged),(Phase::CleanupUnknown,Effect::Unknown,None,None));
    let mut exhausted=State::new();exhausted.view.revision=wire::LAST_REVISION-1;
    let before=exhausted.snapshot();exhausted.view.available=true;exhausted.finish(before);
    assert_eq!(exhausted.view.revision,wire::LAST_REVISION);assert!(exhausted.exhausted);
    assert!(!exhausted.view.available && exhausted.view.reason==Reason::CleanupUnknown);
    let before=exhausted.snapshot();exhausted.view.reason=Reason::None;exhausted.finish(before.clone());assert_eq!(exhausted.snapshot(),before);
    for reason in [Reason::Busy,Reason::TargetChanged,Reason::ConsentExpired,Reason::CleanupUnknown] {
        let error=refused(reason);assert!(error.code.starts_with("github_remote_setup_refused_"));
        assert!(!error.message.is_empty());
    }
}

#[cfg(test)]
pub(crate) fn consent_data_checks(stamp: SavedEditStamp, expiry_stamp: SavedEditStamp) {
    // Explicit correlation DATA only, never passed to a runtime/GO or registered
    // as a project. The move-only stamp comes from the actual idle Edit registry.
    let mut state=State::new();
    let now=Instant::now();
    let target=wire::Target { project_binding:"a".repeat(64),repository:"owner/repository".into(),account_id:"1".into(),
        repository_id:"2".into(),selection:wire::Selection::ActionsEnabled { enabled:true } };
    let before=wire::Policy::Actions { enabled:false,allowed_actions:wire::AllowedActions::All,sha_pinning_required:true };
    let prepared=wire::Prepared::Repository(wire::RepositoryPrepared {after:before.changed(target.selection.clone()).unwrap(),target,before,observed_at:"2026-10-09T00:00:00Z".into(),
        confirmation:"Change actions_enabled for owner/repository? Review the exact before and after values. Enabling Actions can allow configured workflows to run; write tokens or review approvals grant additional privileges. GitHub does not provide an atomic compare-and-set here: another administrator can change settings after this review. This does not configure secrets, change local workflows, or qualify a release.".into()});
    assert!(prepared.valid());
    // The same actual expiry/one-use checks also retain the new non-Copy
    // environment variant. It is never given to a runtime or registered root.
    let mut expiry_target=prepared.target().clone();
    expiry_target.selection=wire::Selection::Environment(wire::EnvironmentSelection {mode:wire::EnvironmentMode::Configure,
        stage:wire::EnvironmentStage::Candidate,wait_timer_minutes:10,prevent_self_review:None,reviewer_login:None,branches:None});
    let old_policy=wire::EnvironmentPolicy {wait_timer_minutes:0,protected_branches:false,required_reviewers:None};
    let expiry_observed=wire::EnvironmentFacts {name:"mobile-candidate".into(),id:Some("3".into()),policy:Some(old_policy)};
    let expiry_prepared=wire::Prepared::Environment(wire::EnvironmentPrepared {target:expiry_target,before:expiry_observed.clone(),
        after:wire::EnvironmentPolicy {wait_timer_minutes:10,protected_branches:false,required_reviewers:None},reviewer:None,
        observed_at:"2026-10-09T00:00:00Z".into(),confirmation:wire::ENVIRONMENT_CONFIRMATION.into()});
    assert!(expiry_prepared.valid());
    state.consent=Some(Consent {material:None,id:"a".repeat(32),prepared,end:now+std::time::Duration::from_secs(10),
        session_id:"session-1".into(),project_id:"unregistered-data-only".into(),generation:1,
        root:RegisteredRoot {path:"/never-opened-correlation-data".into(),identity:crate::asset_source::ProjectIdentity::Windows {volume:0,file_id:[0;16]}},
        edit_stamp:stamp});
    for args in [wire::DiscardArgs {session_id:"other".into(),expected_revision:1,consent_id:"a".repeat(32)},
        wire::DiscardArgs {session_id:"session-1".into(),expected_revision:2,consent_id:"a".repeat(32)},
        wire::DiscardArgs {session_id:"session-1".into(),expected_revision:1,consent_id:"b".repeat(32)}] {
        assert!(state.discard(&args).is_err() && state.consent.is_some());
    }
    let args=wire::DiscardArgs {session_id:"session-1".into(),expected_revision:1,consent_id:"a".repeat(32)};
    state.discard(&args).unwrap();assert!(state.consent.is_none() && state.view.consent.is_none());
    assert!(state.discard(&args).is_err());
    let end=now+std::time::Duration::from_secs(10);
    state.view.consent=Some(wire::ConsentView {id:"b".repeat(32),expires_at:"2026-10-09T00:00:10Z".into(),prepared:expiry_prepared.clone()});
    state.consent=Some(Consent {material:None,id:"b".repeat(32),prepared:expiry_prepared,end,session_id:"session-1".into(),
        project_id:"unregistered-data-only".into(),generation:1,
        root:RegisteredRoot {path:"/never-opened-expiry-data".into(),identity:crate::asset_source::ProjectIdentity::Windows {volume:0,file_id:[0;16]}},
        edit_stamp:expiry_stamp});
    state.view.observed=Some(wire::Observation::Environment(expiry_observed));
    let actual_private=state.consent.as_ref().unwrap();
    let private_bytes=actual_private.id.capacity()+actual_private.prepared.retained_heap_bytes().unwrap()
        +actual_private.session_id.capacity()+actual_private.project_id.capacity()+actual_private.root.path.capacity();
    assert_eq!(state.retained_heap_bytes_if_quiescent(),Some(state.view.retained_heap_bytes().unwrap()+private_bytes));
    state.expire_consent(now);assert!(state.consent.as_ref().is_some_and(|v|v.end==end));
    state.expire_consent(end);assert!(state.consent.is_none() && state.view.consent.is_none());
    assert_eq!(state.view.reason,wire::Reason::ConsentExpired);
    assert!(state.discard(&wire::DiscardArgs {session_id:"session-1".into(),expected_revision:state.view.revision,consent_id:"b".repeat(32)}).is_err());
    state.expire_consent(end+std::time::Duration::from_secs(120));assert!(state.consent.is_none());
}
