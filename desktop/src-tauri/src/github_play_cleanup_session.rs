//! One explicit hosted known-edit cleanup on the SAME Connection and Supervisor.
//! No publishing permission, protected key loan, provider edit ID or run adoption.
use super::*;
use crate::{
    asset_source::RegisteredRoot,
    edit_owner::{SavedEditGuard, SavedEditStamp},
    github_play_cleanup_protocol as p,
    supervisor::{GitHubPlayCleanupReceipt, GitHubPlayCleanupTicket},
};
use serde_json::Value;
use std::sync::{Arc, Weak};

pub(crate) fn refused(r: p::Reason) -> BridgeError {
    let code = serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_play_cleanup_refused_{}",code.replace('-',"_")),match r {
        p::Reason::CleanupUnknown=>"Keep the original GitHub task; cleanup is unconfirmed. Do not repeat the dispatch.",
        p::Reason::ConsentExpired=>"The original review expired or was already used. Check previous attempts before a new review.",
        p::Reason::Busy=>"Finish the original task before starting another GitHub operation.",
        p::Reason::Unqualified=>"The installed hosted cleanup runtime is unavailable.",
        p::Reason::JournalFull=>"The 32 retained cleanup records are full. Preserve them; do not delete evidence or repeat a possibly sent dispatch.",
        _=>"Hosted Play cleanup does not match the current project, verified account or original review.",
    })
}

pub(crate) fn connection_reason(r: Reason) -> p::Reason {
    serde_json::to_value(r)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or(p::Reason::InvalidInput)
}
fn error_reason(e: &BridgeError) -> p::Reason {
    e.code
        .strip_prefix("github_play_cleanup_refused_")
        .and_then(|v| serde_json::from_value(Value::String(v.replace('_', "-"))).ok())
        .unwrap_or_else(|| connection_reason(outcome_error(e)))
}
struct Active {
    ticket: GitHubPlayCleanupTicket,
    request: p::Request,
    session_id: String,
    project_id: String,
    generation: u32,
    root: RegisteredRoot,
    stamp: SavedEditStamp,
    consent_id: String,
    consent_end: Option<Instant>,
    agent: Option<Arc<crate::service_play_cleanup_requests::NativeLink>>,
    review_identity: Option<Arc<()>>,
}
struct Consent {
    identity: Arc<()>,
    agent: Option<Arc<crate::service_play_cleanup_requests::NativeScope>>,
    id: String,
    prepared: p::Prepared,
    end: Instant,
    session_id: String,
    project_id: String,
    generation: u32,
    root: RegisteredRoot,
    stamp: SavedEditStamp,
}
pub(crate) struct AgentReview {
    pub(crate) purpose: p::Purpose,
    pub(crate) identity: Arc<()>,
    pub(crate) id: String,
    pub(crate) end: Instant,
    pub(crate) session_id: String,
    pub(crate) project_id: String,
    pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot,
    pub(crate) stamp: SavedEditStamp,
}
fn forward_agent(a: &Active) {
    let Some(link) = &a.agent else { return };
    match link.entry().first_stop() {
        Ok(Some((_, at))) => a.ticket.stop_at(at),
        Err(_) => {
            link.entry().unknown();
            a.ticket.stop();
        }
        Ok(None) => {}
    }
}
pub(super) struct State {
    view: p::Status,
    active: Option<Active>,
    consent: Option<Consent>,
    pub(super) exhausted: bool,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) service: Option<Weak<crate::application_service::ApplicationService>>,
}
impl State {
    pub(super) fn activity_review_conflict(&self) -> bool { self.consent.is_some() }
    pub(super) fn new() -> Self {
        Self {
            view: p::Status {
                schema_version: 1,
                agent_access: None,
                revision: 1,
                session_id: None,
                available: false,
                reason: p::Reason::NotConnected,
                operation: None,
                consent: None,
                pending: Vec::new(),
                observed: None,
                acknowledged: false,
            },
            active: None,
            consent: None,
            exhausted: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            service: None,
        }
    }
    pub(super) fn native_work_pending(&self) -> bool {
        self.active.is_some()
    }
    fn finish(&mut self, mut before: p::Status) {
        if self.exhausted {
            self.view = before;
            return;
        }
        // Countdown DATA is not a new review revision. All identity/enabled
        // changes still advance it; actual admission checks the original end.
        if let (Some(old), Some(current)) = (&mut before.agent_access, &self.view.agent_access) {
            old.remaining_ms = current.remaining_ms;
        }
        if before != self.view {
            if before.revision >= p::LAST_REVISION - 1 {
                self.view.revision = p::LAST_REVISION;
                self.exhausted = true;
                self.unknown();
            } else {
                self.view.revision = before.revision + 1;
            }
        }
    }
    pub(super) fn revoke_consent(&mut self) {
        if let Some(c) = &self.consent {
            if let Some(scope) = &c.agent {
                scope.revoke(
                    crate::service_play_cleanup_protocol::Reason::ContextChanged,
                    Instant::now(),
                );
            }
        }
        self.consent = None;
        self.view.consent = None;
        self.view.agent_access = None;
    }
    fn observe_go(&mut self) {
        if let Some(a) = self
            .active
            .as_ref()
            .filter(|a| a.request.kind == p::Kind::Dispatch && a.ticket.go_claimed())
        {
            if let Some(link) = &a.agent {
                if link.native_go(a.ticket.operation_id()).is_err() {
                    link.entry().unknown();
                }
            }
            if let Some(o) = &mut self.view.operation {
                if o.phase != p::Phase::CleanupUnknown {
                    o.effect = p::Effect::PotentiallyApplied;
                }
            }
        }
    }
    fn stop(&mut self) {
        self.revoke_consent();
        if let Some(a) = &self.active {
            if let Some(link) = &a.agent {
                link.entry().cancel(
                    crate::service_play_cleanup_protocol::Reason::UserCancelled,
                    Instant::now(),
                );
            }
            forward_agent(a);
            a.ticket.stop();
            if let Some(o) = &mut self.view.operation {
                if o.phase != p::Phase::CleanupUnknown {
                    o.phase = p::Phase::Stopping;
                    o.reason = p::Reason::Cancelled;
                }
            }
        }
        self.observe_go();
    }
    fn unknown(&mut self) {
        if let Some(a) = &self.active {
            a.ticket.agent_unknown();
        }
        self.stop();
        self.view.available = false;
        self.view.reason = p::Reason::CleanupUnknown;
        if let Some(o) = &mut self.view.operation {
            if o.phase != p::Phase::Settled {
                o.phase = p::Phase::CleanupUnknown;
                o.reason = p::Reason::CleanupUnknown;
            }
        }
    }
    pub(super) fn context_changed(&mut self) {
        let b = self.view.clone();
        self.stop();
        self.finish(b);
    }
    pub(super) fn retired(&mut self, r: Reason) {
        let b = self.view.clone();
        if r == Reason::CleanupUnknown {
            self.unknown();
        } else {
            self.stop();
        }
        self.finish(b);
    }
    pub(super) fn reset(&mut self) {
        let b = self.view.clone();
        self.revoke_consent();
        self.view.pending.clear();
        self.view.observed = None;
        self.view.acknowledged = false;
        self.view.operation = None;
        self.view.session_id = None;
        self.finish(b);
    }
    pub(super) fn heap(&self) -> Option<usize> {
        if self.active.is_some() || self.exhausted || self.view.reason == p::Reason::CleanupUnknown
        {
            return None;
        }
        let mut n = self.view.heap()?;
        if let Some(c) = &self.consent {
            n = n
                .checked_add(c.prepared.heap()?)?
                .checked_add(c.id.capacity())?
                .checked_add(c.session_id.capacity())?
                .checked_add(c.project_id.capacity())?
                .checked_add(c.root.path.capacity())?;
        }
        Some(n)
    }
}
impl ConnectionState {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn play_cleanup_service(
        &self,
    ) -> Option<Arc<crate::application_service::ApplicationService>> {
        self.play_cleanup.service.as_ref().and_then(Weak::upgrade)
    }
    pub(crate) fn play_cleanup_agent_review(
        &mut self,
        args: &p::StartArgs,
        g: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<AgentReview, BridgeError> {
        let retained = self
            .play_cleanup
            .consent
            .as_ref()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?
            .prepared
            .target
            .clone();
        let target = self.play_cleanup_context(
            &args.session_id,
            args.expected_revision,
            g,
            binding,
            retained.marker.clone(),
            retained.version_tag.clone(),
            None,
            now,
        )?;
        let c = self
            .play_cleanup
            .consent
            .as_ref()
            .filter(|c| {
                args.confirm && args.purpose == c.prepared.target.purpose()
                    && c.id == args.consent_id
                    && c.session_id == args.session_id
                    && c.generation == g
                    && &c.root == root
                    && edit.matches(&c.stamp)
                    && now < c.end
                    && c.agent.is_none()
                    && c.prepared.target == target
            })
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        Ok(AgentReview {
            purpose: c.prepared.target.purpose(),
            identity: c.identity.clone(),
            id: c.id.clone(),
            end: c.end,
            session_id: c.session_id.clone(),
            project_id: c.project_id.clone(),
            generation: c.generation,
            root: c.root.clone(),
            stamp: edit.stamp()?,
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn play_cleanup_agent_allow(
        &mut self,
        review: &AgentReview,
        scope: Arc<crate::service_play_cleanup_requests::NativeScope>,
        access: crate::service_play_cleanup_protocol::Access,
        service: &Arc<crate::application_service::ApplicationService>,
    ) -> Result<p::Status, BridgeError> {
        let before = self.play_cleanup.view.clone();
        let c = self
            .play_cleanup
            .consent
            .as_mut()
            .filter(|c| {
                Arc::ptr_eq(&c.identity, &review.identity)
                    && c.agent.is_none()
                    && c.id == scope.consent_id.as_str()
                    && scope.purpose == review.purpose && scope.purpose == c.prepared.target.purpose()
                    && scope.end <= c.end
            })
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        if !access.valid()
            || !access.enabled
            || access.consent_id != scope.consent_id
            || access.project_id != scope.project_id
            || access.purpose != scope.purpose
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        c.agent = Some(scope);
        self.play_cleanup.service = Some(Arc::downgrade(service));
        self.play_cleanup.view.agent_access = Some(access);
        self.play_cleanup
            .view
            .consent
            .as_mut()
            .ok_or_else(|| refused(p::Reason::CleanupUnknown))?
            .agent_allowed = true;
        self.play_cleanup.finish(before);
        Ok(self.play_cleanup.view.clone())
    }
    pub(crate) fn play_cleanup_agent_start_args(
        &mut self,
        link: &Arc<crate::service_play_cleanup_requests::NativeLink>,
    ) -> Result<p::StartArgs, BridgeError> {
        link.current(false)
            .map_err(|_| refused(p::Reason::ConsentExpired))?;
        let c = self
            .play_cleanup
            .consent
            .as_ref()
            .filter(|c| {
                c.agent
                    .as_ref()
                    .is_some_and(|s| Arc::ptr_eq(s, link.scope()))
                    && link
                        .scope()
                        .review
                        .upgrade()
                        .is_some_and(|r| Arc::ptr_eq(&r, &c.identity))
            })
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        Ok(p::StartArgs {
            session_id: c.session_id.clone(),
            expected_revision: self.play_cleanup.view.revision,
            consent_id: c.id.clone(),
            confirm: true,
            purpose: c.prepared.target.purpose(),
        })
    }
    pub(crate) fn play_cleanup_agent_close(&mut self, at: Instant) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(service) = self.play_cleanup_service() {
            service.play_cleanup_requests().close(at);
        }
        if let Some(c) = &self.play_cleanup.consent {
            if let Some(scope) = &c.agent {
                scope.revoke(crate::service_play_cleanup_protocol::Reason::Shutdown, at);
            }
        }
        if let Some(a) = &self.play_cleanup.active {
            if let Some(link) = &a.agent {
                link.entry()
                    .cancel(crate::service_play_cleanup_protocol::Reason::Shutdown, at);
                forward_agent(a);
            }
        }
    }
    pub(crate) fn play_cleanup_status(
        &mut self,
        qualified: bool,
        now: Instant,
        external: Reason,
    ) -> p::Status {
        let before = self.play_cleanup.view.clone();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self
            .play_cleanup
            .consent
            .as_ref()
            .and_then(|c| c.agent.as_ref())
            .is_some()
        {
            let service = self.play_cleanup.service.as_ref().and_then(Weak::upgrade);
            let live = self
                .play_cleanup
                .consent
                .as_ref()
                .and_then(|c| c.agent.as_ref())
                .is_some_and(|scope| {
                    service.as_ref().is_some_and(|s| {
                        s.native_history_current().is_ok()
                            && s.play_cleanup_requests().scope_live(scope).unwrap_or(false)
                    })
                });
            let access = service.and_then(|s| s.play_cleanup_requests().access().ok().flatten());
            if !live || access.is_none() {
                self.play_cleanup.revoke_consent();
            } else {
                // A queued CLI entry consumes Allow, not the private native
                // review. Keep that review until its same original claim starts.
                self.play_cleanup.view.agent_access = access;
            }
        }
        if self
            .play_cleanup
            .consent
            .as_ref()
            .is_some_and(|c| now >= c.end)
        {
            self.play_cleanup.revoke_consent();
        }
        self.play_cleanup.observe_go();
        let reason = if self.unknown || self.exhausted || self.play_cleanup.exhausted {
            p::Reason::CleanupUnknown
        } else if !p::configured() {
            p::Reason::PublisherUnconfigured
        } else if !qualified {
            p::Reason::Unqualified
        } else if external != Reason::None {
            connection_reason(external)
        } else if self.native_work_pending() {
            p::Reason::Busy
        } else if let Some(s) = &self.private {
            if let Some(r) = s.retirement {
                connection_reason(r)
            } else if now >= s.clock.end {
                p::Reason::Expired
            } else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
                p::Reason::RateLimited
            } else if s.token.is_none()
                || s.account_pin.is_none()
                || s.repository_pin.is_none()
                || self.status.repository.state != FactState::Observed
                || self.status.account.state != FactState::Observed
                || !self
                    .status
                    .session
                    .as_ref()
                    .is_some_and(|v| v.state == SessionState::Connected)
            {
                p::Reason::NotConnected
            } else if !crate::github_repository_create_protocol::coordinate(&s.repository) {
                p::Reason::InvalidInput
            } else {
                p::Reason::None
            }
        } else {
            p::Reason::NotConnected
        };
        self.play_cleanup.view.available = reason == p::Reason::None;
        self.play_cleanup.view.reason = reason;
        // The retained operation belongs to its original session even after an
        // explicit Disconnect has retired the private connection. A new native
        // connection resets both; an absent current session is not its receipt.
        if self.play_cleanup.active.is_none() && self.play_cleanup.view.operation.is_none() {
            self.play_cleanup.view.session_id = self.private.as_ref().map(|s| s.id.clone());
        }
        self.play_cleanup.finish(before);
        self.play_cleanup.view.clone()
    }
    /// Original active ticket retains its entire working debit through STOP
    /// and unknown cleanup; idle review DATA does not block allocations.
    pub(crate) fn play_cleanup_work_pending(&self) -> bool {
        self.play_cleanup.native_work_pending()
    }
    pub(crate) fn play_cleanup_registered_project(&self) -> Option<&str> {
        self.play_cleanup
            .active
            .as_ref()
            .map(|a| a.project_id.as_str())
            .or_else(|| {
                self.play_cleanup
                    .consent
                    .as_ref()
                    .map(|c| c.project_id.as_str())
            })
    }
    fn play_cleanup_binding(&self, g: u32, r: &RegisteredRoot, e: &SavedEditGuard<'_>) -> bool {
        if let Some(a) = &self.play_cleanup.active {
            a.generation == g && &a.root == r && e.matches(&a.stamp)
        } else if let Some(c) = &self.play_cleanup.consent {
            c.generation == g && &c.root == r && e.matches(&c.stamp)
        } else {
            true
        }
    }
    fn play_cleanup_context(
        &mut self,
        id: &str,
        revision: u32,
        generation: u32,
        binding: &str,
        marker: String,
        version_tag: Option<p::version_tag::Selection>,
        pending_purpose: Option<p::Purpose>,
        now: Instant,
    ) -> Result<p::Target, BridgeError> {
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if revision != self.play_cleanup.view.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        if !self.play_cleanup.view.available {
            return Err(refused(self.play_cleanup.view.reason));
        }
        let s = self
            .private
            .as_ref()
            .filter(|s| {
                s.id == id
                    && s.generation == generation
                    && s.retirement.is_none()
                    && s.token.is_some()
                    && now < s.clock.end
            })
            .ok_or_else(|| refused(p::Reason::NotConnected))?;
        let a = self
            .status
            .account
            .value
            .as_ref()
            .filter(|a| {
                self.status.account.state == FactState::Observed
                    && s.account_pin.as_ref() == Some(&a.id)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if !self
            .status
            .session
            .as_ref()
            .is_some_and(|v| v.state == SessionState::Connected)
        {
            return Err(refused(p::Reason::NotConnected));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(refused(p::Reason::RateLimited));
        }
        let repository = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|r| {
                self.status.repository.state == FactState::Observed
                    && s.repository_pin.as_ref() == Some(&r.id)
                    && r.full_name.eq_ignore_ascii_case(&s.repository)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let target = p::Target {
            scope: p::Scope {
                project_binding: binding.into(),
                repository: s.repository.clone(),
                account_id: a.id.clone(),
                repository_id: repository.id.clone(),
            },
            tooling_repository: crate::github_release_protocol::TOOLING_REPOSITORY.into(),
            tooling_sha: crate::github_release_protocol::TOOLING_SHA
                .ok_or_else(|| refused(p::Reason::PublisherUnconfigured))?
                .into(),
            marker,
            version_tag,
            pending_purpose,
        };
        if !target.publisher_bound() {
            return Err(refused(p::Reason::InvalidInput));
        }
        Ok(target)
    }
    fn play_cleanup_launch(
        &mut self,
        request: p::Request,
        root: RegisteredRoot,
        stamp: SavedEditStamp,
        consent_id: String,
        consent_end: Option<Instant>,
        review_identity: Option<Arc<()>>,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if !supervisor.play_cleanup_profile_available() {
            return Err(refused(p::Reason::Unqualified));
        }
        if !request.valid()
            || !self.play_cleanup.view.fits()
            || !crate::github_preflight_protocol::hex(&consent_id, 32)
            || (request.kind == p::Kind::Dispatch) != consent_end.is_some()
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if self.play_cleanup.view.revision >= p::LAST_REVISION - 8 {
            self.exhaust();
            return Err(refused(p::Reason::CleanupUnknown));
        }
        p::encode_initial("github-play-cleanup-18446744073709551615", &request)?;
        let s = self
            .private
            .as_ref()
            .filter(|s| s.retirement.is_none() && s.token.is_some() && now < s.clock.end)
            .ok_or_else(|| refused(p::Reason::Expired))?;
        let (session_id, project_id, generation) =
            (s.id.clone(), s.project_id.clone(), s.generation);
        let end = (now + Duration::from_secs(60))
            .min(s.clock.end)
            .min(consent_end.unwrap_or(s.clock.end));
        if end <= now {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let retained = self
            .play_cleanup
            .heap()
            .and_then(|n| n.checked_add(request.heap()?))
            .and_then(|n| n.checked_add(request.heap()?))
            .and_then(|n| {
                n.checked_add(
                    session_id.capacity()
                        + project_id.capacity()
                        + root.path.capacity()
                        + consent_id.capacity(),
                )
            })
            .and_then(|n| n.checked_add(2 * p::RESPONSE_LIMIT + p::GO_LIMIT + 65536));
        if !retained.is_some_and(|n| n <= p::RETAINED_LIMIT) {
            return Err(refused(p::Reason::ResourcesUnavailable));
        }
        let before = self.play_cleanup.view.clone();
        let agent = gate.agent().cloned();
        let ticket = supervisor
            .start_play_cleanup(request.clone(), gate, end)
            .map_err(|e| refused(error_reason(&e)))?;
        let b = self.preflight.snapshot();
        self.preflight.revoke_consent();
        self.preflight.finish(b);
        let b = self.release.snapshot();
        self.release.revoke_consent();
        self.release.finish(b);
        let b = self.setup.snapshot();
        self.setup.revoke_consent();
        self.setup.finish(b);
        self.publication.context_changed();
        self.repository_create.context_changed();
        self.activity.context_changed();
        self.pull_request.context_changed();
        self.actions_retry.context_changed();
        self.play_cleanup.revoke_consent();
        // Pending records are retained for explanation across a readback. They
        // never substitute for the private prepared consent or authorize POST.
        self.play_cleanup.view.observed = None;
        self.play_cleanup.view.acknowledged = false;
        self.play_cleanup.view.operation = Some(p::Operation {
            id: ticket.operation_id().into(),
            project_id: project_id.clone(),
            kind: request.kind,
            target: request.target.clone(),
            phase: p::Phase::Running,
            reason: p::Reason::None,
            effect: if request.kind == p::Kind::Dispatch {
                p::Effect::NotSent
            } else {
                p::Effect::None
            },
        });
        self.play_cleanup.active = Some(Active {
            ticket,
            request,
            session_id: session_id.clone(),
            project_id,
            generation,
            root,
            stamp,
            consent_id,
            consent_end,
            agent,
            review_identity,
        });
        self.play_cleanup.view.session_id = Some(session_id);
        self.play_cleanup.view.available = false;
        self.play_cleanup.view.reason = p::Reason::Busy;
        self.play_cleanup.finish(before);
        let b = self.status.clone();
        self.capability(now, Reason::None);
        self.finish(b);
        Ok(self.play_cleanup.view.clone())
    }
    pub(crate) fn play_cleanup_prepare(
        &mut self,
        a: p::PrepareArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        source: p::Source,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if a.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        // Candidate/attempt/platform and original A come only from the fixed
        // joined hosted-counter read, never Activity/history/renderer fields.
        let target = self.play_cleanup_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            nonce.clone(),
            a.version_tag.clone(),
            None,
            now,
        )?;
        self.play_cleanup_launch(
            p::Request {
                kind: p::Kind::Prepare,
                target,
                source: Some(source),
                home: None,
                prepared: None,
            },
            root,
            stamp,
            nonce,
            None,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn play_cleanup_pending(
        &mut self,
        a: p::PendingArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        home: String,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if a.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        let target = self.play_cleanup_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            nonce.clone(),
            a.version_tag.clone(),
            (a.purpose == p::Purpose::VersionTag).then_some(p::Purpose::VersionTag),
            now,
        )?;
        self.play_cleanup_launch(
            p::Request {
                kind: p::Kind::Pending,
                target,
                source: None,
                home: Some(home),
                prepared: None,
            },
            root,
            stamp,
            nonce,
            None,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn play_cleanup_start(
        &mut self,
        a: p::StartArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        source: p::Source,
        home: String,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let old = self
            .play_cleanup
            .consent
            .as_ref()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?
            .prepared
            .target
            .clone();
        let target = self.play_cleanup_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            old.marker.clone(),
            old.version_tag.clone(),
            None,
            now,
        )?;
        if !a.confirm || a.purpose != target.purpose()
            || !self.play_cleanup.consent.as_ref().is_some_and(|c| {
                c.id == a.consent_id
                    && c.session_id == a.session_id
                    && c.generation == g
                    && c.root == root
                    && edit.matches(&c.stamp)
                    && now < c.end
                    && c.prepared.target == target
                    && match (&c.agent, gate.agent()) {
                        (None, None) => true,
                        (Some(scope), Some(link)) => {
                            Arc::ptr_eq(scope, link.scope())
                                && scope
                                    .review
                                    .upgrade()
                                    .is_some_and(|r| Arc::ptr_eq(&r, &c.identity))
                                && link.current(false).is_ok()
                        }
                        _ => false,
                    }
            })
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.play_cleanup.view.clone();
        let c = self
            .play_cleanup
            .consent
            .take()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        self.play_cleanup.revoke_consent();
        self.play_cleanup.finish(before); // One use even if admission fails.
        self.play_cleanup_launch(
            p::Request {
                kind: p::Kind::Dispatch,
                target,
                source: Some(source),
                home: Some(home),
                prepared: Some(c.prepared),
            },
            root,
            c.stamp,
            c.id,
            Some(c.end),
            Some(c.identity.clone()),
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn play_cleanup_observe(
        &mut self,
        a: p::ObserveArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        home: String,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let prepared = self
            .play_cleanup
            .view
            .pending
            .iter()
            .find(|r| r.prepared.target.marker == a.marker)
            .map(|r| r.prepared.clone())
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let target = &prepared.target;
        let current = self.play_cleanup_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            target.marker.clone(),
            target.version_tag.clone(),
            None,
            now,
        )?;
        if !current.same_scope(target) {
            return Err(refused(p::Reason::TargetChanged));
        }
        self.play_cleanup_launch(
            p::Request {
                kind: p::Kind::Observe,
                target: target.clone(),
                source: None,
                home: Some(home),
                prepared: Some(prepared),
            },
            root,
            stamp,
            a.marker,
            None,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn play_cleanup_cancel(&mut self, id: &str) -> Result<p::Status, BridgeError> {
        if self.play_cleanup.active.is_none() {
            return if self
                .play_cleanup
                .view
                .operation
                .as_ref()
                .is_some_and(|o| o.id == id && o.phase == p::Phase::Settled)
            {
                Ok(self.play_cleanup.view.clone())
            } else {
                Err(refused(p::Reason::InvalidInput))
            };
        }
        if !self
            .play_cleanup
            .active
            .as_ref()
            .is_some_and(|a| a.ticket.operation_id() == id)
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.play_cleanup.context_changed();
        Ok(self.play_cleanup.view.clone())
    }
    pub(crate) fn play_cleanup_discard(
        &mut self,
        a: &crate::github_setup_protocol::DiscardArgs,
    ) -> Result<p::Status, BridgeError> {
        if self.play_cleanup.active.is_some() {
            return Err(refused(p::Reason::Busy));
        }
        if a.expected_revision != self.play_cleanup.view.revision
            || !self
                .play_cleanup
                .consent
                .as_ref()
                .is_some_and(|c| c.id == a.consent_id && c.session_id == a.session_id)
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.play_cleanup.view.clone();
        self.play_cleanup.revoke_consent();
        self.play_cleanup.finish(before);
        Ok(self.play_cleanup.view.clone())
    }
    pub(crate) fn play_cleanup_go(
        &self,
        id: &str,
        digest: &str,
        request: &p::Request,
        g: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let a = self
            .play_cleanup
            .active
            .as_ref()
            .filter(|a| {
                a.ticket.operation_id() == id
                    && &a.request == request
                    && a.generation == g
                    && &a.root == root
                    && edit.matches(&a.stamp)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if self.unknown || self.exhausted || self.play_cleanup.exhausted {
            return Err(refused(p::Reason::CleanupUnknown));
        }
        if self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || self.publication.native_work_pending()
            || self.repository_create.native_work_pending()
            || self.activity.native_work_pending()
            || self.pull_request.native_work_pending()
            || self.actions_retry.native_work_pending()
            || self.fetch.is_some()
            || self.push.is_some()
            || self.enrollment.is_some()
            || self.version_reserve_pending()
        {
            return Err(refused(p::Reason::Busy));
        }
        if !request.target.publisher_bound()
            || request
                .prepared
                .as_ref()
                .is_some_and(|p| !p.publisher_bound())
        {
            return Err(refused(p::Reason::PublisherUnconfigured));
        }
        if let Some(link) = &a.agent {
            link.current(true)
                .map_err(|_| refused(p::Reason::ConsentExpired))?;
        }
        if a.consent_end.is_some_and(|end| now >= end) {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let s = self
            .private
            .as_ref()
            .filter(|s| {
                s.id == a.session_id
                    && s.project_id == a.project_id
                    && s.generation == a.generation
                    && s.ticket.is_none()
                    && s.gh_hold.is_none()
                    && s.retirement.is_none()
                    && s.token.is_some()
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if now >= s.clock.end {
            return Err(refused(p::Reason::Expired));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(refused(p::Reason::RateLimited));
        }
        if s.account_pin.as_ref() != Some(&request.target.scope.account_id)
            || s.repository_pin.as_ref() != Some(&request.target.scope.repository_id)
            || !s
                .repository
                .eq_ignore_ascii_case(&request.target.scope.repository)
            || self.status.account.state != FactState::Observed
            || self.status.repository.state != FactState::Observed
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        let mut bytes = p::encode_go(
            id,
            digest,
            if request.kind == p::Kind::Pending {
                None
            } else {
                s.token.as_deref()
            },
            request,
        )?;
        if !claim() {
            use zeroize::Zeroize;
            bytes.zeroize();
            return Err(refused(p::Reason::Cancelled));
        }
        if let Some(link) = &a.agent {
            if link.native_go(id).is_err() {
                use zeroize::Zeroize;
                bytes.zeroize();
                link.entry().unknown();
                return Err(refused(p::Reason::CleanupUnknown));
            }
        }
        Ok(bytes)
    }
    pub(crate) fn reconcile_play_cleanup(
        &mut self,
        now: Instant,
        external: Reason,
        proof: Option<(u32, &RegisteredRoot, &SavedEditGuard<'_>)>,
    ) {
        let cb = self.status.clone();
        let before = self.play_cleanup.view.clone();
        self.play_cleanup.observe_go();
        if let Some(a) = &self.play_cleanup.active {
            forward_agent(a);
        }
        let current = proof.is_some_and(|(g, r, e)| self.play_cleanup_binding(g, r, e));
        if !current && self.play_cleanup_registered_project().is_some() {
            self.play_cleanup.stop();
        }
        match self
            .play_cleanup
            .active
            .as_ref()
            .map(|a| a.ticket.receipt())
        {
            Some(GitHubPlayCleanupReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(GitHubPlayCleanupReceipt::Settled {
                outcome,
                settled_at,
                was_unknown,
            }) => self.accept_play_cleanup(
                outcome,
                settled_at,
                was_unknown,
                now,
                current && external == Reason::None,
            ),
            _ => {}
        }
        if self.unknown {
            self.play_cleanup.unknown();
        } else if !current && self.play_cleanup_registered_project().is_some() {
            self.play_cleanup.view.reason = p::Reason::TargetChanged;
            self.play_cleanup.view.available = false;
        }
        self.play_cleanup.finish(before);
        self.capability(now, external);
        self.finish(cb);
    }
    fn accept_play_cleanup(
        &mut self,
        result: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
        now: Instant,
        current: bool,
    ) {
        // Neither a terminal-shaped reply nor later known joins erase original
        // Unknown. Preserve the very same ticket/request/GO buffers here.
        if was_unknown
            || self.unknown
            || result
                .as_ref()
                .is_err_and(|e| error_reason(e) == p::Reason::CleanupUnknown)
        {
            if let Some(a) = &self.play_cleanup.active {
                if let Some(link) = &a.agent {
                    link.entry().unknown();
                }
            }
            self.unknown_inner();
            return;
        }
        let Some(a) = self.play_cleanup.active.take() else {
            self.unknown_inner();
            return;
        };
        let agent_link = a.agent.clone();
        let agent_operation = a.ticket.operation_id().to_owned();
        let mut effect = if a.request.kind == p::Kind::Dispatch {
            if a.ticket.go_claimed() {
                p::Effect::PotentiallyApplied
            } else {
                p::Effect::NotSent
            }
        } else {
            p::Effect::None
        };
        let mut reason = result
            .as_ref()
            .map_or_else(error_reason, |r| r.result.reason);
        if !result.as_ref().map_or(true, |reply| {
            self.play_cleanup
                .view
                .heap()
                .and_then(|n| n.checked_add(reply.heap()?))
                .and_then(|n| n.checked_add(a.ticket.retained_heap()?))
                .and_then(|n| n.checked_add(a.request.heap()?))
                .and_then(|n| n.checked_add(2 * p::RESPONSE_LIMIT + 65536))
                .is_some_and(|n| n <= p::RETAINED_LIMIT)
        }) {
            reason = p::Reason::ResourcesUnavailable;
        }
        if let Ok(r) = &result {
            if !self.apply_control(&r.result.control, settled_at) {
                reason = p::Reason::ResponseInvalid;
            }
        }
        if self
            .private
            .as_ref()
            .is_some_and(|s| now >= s.clock.end && s.retirement.is_none())
        {
            self.retire_inner(Reason::Expired, false);
        }
        if self.unknown || reason == p::Reason::CleanupUnknown {
            self.play_cleanup.active = Some(a);
            self.unknown_inner();
            if let Some(o) = &mut self.play_cleanup.view.operation {
                o.phase = p::Phase::CleanupUnknown;
                o.reason = p::Reason::CleanupUnknown;
                o.effect = effect;
            }
            return;
        }
        if let Ok(reply) = &result {
            if let Some(c) = &reply.result.cleanup {
                if c.acknowledged {
                    self.play_cleanup.view.acknowledged = true;
                    effect = p::Effect::AcknowledgedUnconfirmed;
                }
            }
        }
        if let Some(r) = self.private.as_ref().and_then(|s| s.retirement) {
            reason = connection_reason(r);
        } else if !current {
            reason = p::Reason::TargetChanged;
        } else if self
            .play_cleanup
            .view
            .operation
            .as_ref()
            .is_some_and(|o| o.phase == p::Phase::Stopping)
        {
            reason = p::Reason::Cancelled;
        } else if let Ok(reply) = result {
            if reason == reply.result.reason {
                if let Some(c) = reply.result.cleanup {
                    effect = c.effect;
                    self.play_cleanup.view.observed = c.observed;
                    self.play_cleanup.view.acknowledged = c.acknowledged;
                }
                if let Some(rows) = reply.result.pending {
                    self.play_cleanup.view.pending = rows;
                }
                if let Some(prepared) = reply.result.prepared {
                    let ready = (|| {
                        if !prepared.publisher_bound() {
                            return None;
                        }
                        let s = self
                            .private
                            .as_ref()
                            .filter(|s| s.id == a.session_id && s.retirement.is_none())?;
                        let end = (settled_at + Duration::from_secs(120)).min(s.clock.end);
                        if now >= end {
                            return None;
                        }
                        let wall = s
                            .clock
                            .wall
                            .checked_add(end.duration_since(s.clock.admitted))?;
                        Some((end, display_utc(wall)?))
                    })();
                    if let Some((end, expires_at)) = ready {
                        self.play_cleanup.view.consent = Some(p::ConsentView {
                            id: a.consent_id.clone(),
                            expires_at,
                            prepared: prepared.clone(),
                            agent_allowed: false,
                        });
                        self.play_cleanup.consent = Some(Consent {
                            identity: Arc::new(()),
                            agent: None,
                            id: a.consent_id,
                            prepared,
                            end,
                            session_id: a.session_id,
                            project_id: a.project_id,
                            generation: a.generation,
                            root: a.root,
                            stamp: a.stamp,
                        });
                    } else {
                        reason = p::Reason::ConsentExpired;
                    }
                }
            }
        }
        if reason != p::Reason::None && effect == p::Effect::ObservedUnconfirmed {
            effect = p::Effect::Unresolved;
            self.play_cleanup.view.observed = None;
        }
        if let Some(o) = &mut self.play_cleanup.view.operation {
            o.phase = p::Phase::Settled;
            o.reason = reason;
            o.effect = effect;
        }
        if !self.play_cleanup.view.fits() {
            self.play_cleanup.view.pending.clear();
            self.play_cleanup.revoke_consent();
            reason = p::Reason::ResponseLimit;
            self.play_cleanup.view.observed = None;
            if let Some(o) = &mut self.play_cleanup.view.operation {
                o.reason = reason;
                if o.effect == p::Effect::ObservedUnconfirmed {
                    o.effect = p::Effect::Unresolved;
                }
            }
        }
        self.play_cleanup.view.reason = reason;
        if let Some(link) = agent_link {
            use crate::service_play_cleanup_protocol as wire;
            let effect = match effect {
                p::Effect::AcknowledgedUnconfirmed => wire::Effect::AcknowledgedUnconfirmed,
                p::Effect::PotentiallyApplied => wire::Effect::PotentiallyApplied,
                _ => wire::Effect::NotSent,
            };
            let refusal = if reason == p::Reason::None {
                None
            } else {
                Some(wire::Reason::NativeRefused)
            };
            if link.settled(&agent_operation, effect, refusal).is_err() {
                link.entry().unknown();
                self.unknown_inner();
                return;
            }
        }
        if let Some(r) = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized),
            p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid),
            p::Reason::Cancelled => Some(Reason::Cancelled),
            _ => None,
        } {
            self.retire_inner(r, false);
        }
        self.play_cleanup_finish_retirement();
    }
    fn play_cleanup_finish_retirement(&mut self) {
        // A settled Prepare/Dispatch is not a request to disconnect. The shared
        // completion routine consumes the token; call it only for the original
        // retirement path. Unknown remains handled by its separate branch.
        if self
            .private
            .as_ref()
            .is_some_and(|s| s.retirement.is_some())
        {
            self.complete_retirement();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn access_countdown_is_data_but_disable_or_replacement_advances_original_revision() {
        use crate::service_protocol::Id;
        let id = |c: &str| Id::parse(&c.repeat(32)).unwrap();
        let mut state = State::new();
        state.view.agent_access = Some(crate::service_play_cleanup_protocol::Access {
            purpose: p::Purpose::PlayCleanup,
            service_instance: id("a"),
            project_id: id("b"),
            consent_id: id("c"),
            enabled: true,
            remaining_ms: 10000,
        });
        let before = state.view.clone();
        state.view.agent_access.as_mut().unwrap().remaining_ms = 9000;
        state.finish(before);
        assert_eq!(state.view.revision, 1);
        let before = state.view.clone();
        state.view.agent_access.as_mut().unwrap().remaining_ms = 0;
        state.view.agent_access.as_mut().unwrap().enabled = false;
        state.finish(before);
        assert_eq!(state.view.revision, 2);
        let before = state.view.clone();
        state.view.agent_access.as_mut().unwrap().consent_id = id("d");
        state.finish(before);
        assert_eq!(state.view.revision, 3);
    }
    #[test]
    fn stale_or_unknown_data_without_original_consent_never_gains_agent_review() {
        let mut state = State::new();
        assert!(state.consent.is_none() && state.active.is_none());
        state.view.acknowledged = true;
        state.unknown();
        assert!(state.consent.is_none() && state.view.agent_access.is_none());
        assert_eq!(state.view.reason, p::Reason::CleanupUnknown);
        assert!(state.heap().is_none());
    }
}
