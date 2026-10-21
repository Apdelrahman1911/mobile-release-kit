//! Remote creation in the SAME authenticated connection and original Supervisor.
use super::*;
use std::sync::{Arc, Weak};
use crate::{
    asset_source::RegisteredRoot,
    edit_owner::{SavedEditGuard, SavedEditStamp},
    github_repository_create_protocol as p,
    supervisor::{RepositoryCreateReceipt, RepositoryCreateTicket},
};
use serde_json::Value;

pub(crate) fn refused(r: p::Reason) -> BridgeError {
    let code = serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_repository_create_refused_{}",code.replace('-',"_")),match r {
        p::Reason::CleanupUnknown=>"Keep the original GitHub task; cleanup is unconfirmed. Do not repeat creation.",
        p::Reason::ConsentExpired=>"The original review expired or was already used. Check previous attempts before a new review.",
        p::Reason::Busy=>"Finish the original task before starting another GitHub operation.",
        p::Reason::Unqualified=>"The installed repository-creation runtime is unavailable.",
        _=>"Repository creation does not match the current project, verified account or original review.",
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
        .strip_prefix("github_repository_create_refused_")
        .and_then(|v| serde_json::from_value(Value::String(v.replace('_', "-"))).ok())
        .unwrap_or_else(|| connection_reason(outcome_error(e)))
}
struct Active {
    agent: Option<Arc<crate::service_github_action_requests::Entry>>,
    ticket: RepositoryCreateTicket,
    request: p::Request,
    session_id: String,
    project_id: String,
    generation: u32,
    root: RegisteredRoot,
    stamp: SavedEditStamp,
    consent_id: String,
    consent_end: Option<Instant>,
}
struct Consent {
    identity: Arc<()>,
    agent: Option<Weak<crate::service_github_action_requests::NativeScope>>,
    id: String,
    prepared: p::Prepared,
    end: Instant,
    session_id: String,
    project_id: String,
    generation: u32,
    root: RegisteredRoot,
    stamp: SavedEditStamp,
}
pub(super) struct State {
    view: p::Status,
    active: Option<Active>,
    consent: Option<Consent>,
    pub(super) exhausted: bool,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            view: p::Status {
                schema_version: 1,
                revision: 1,
                session_id: None,
                available: false,
                reason: p::Reason::NotConnected,
                operation: None,
                consent: None,
                pending: Vec::new(),
                observed: None,
            },
            active: None,
            consent: None,
            exhausted: false,
        }
    }
    pub(super) fn native_work_pending(&self) -> bool {
        self.active.is_some()
    }
    fn finish(&mut self, before: p::Status) {
        if self.exhausted {
            return;
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
        action_delegation::revoke(&self.consent.as_ref().and_then(|c| c.agent.clone()));
        self.consent = None;
        self.view.consent = None;
    }
    fn observe_go(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.request.kind == p::Kind::Create && a.ticket.go_claimed())
        {
            if let Some(o) = &mut self.view.operation {
                o.effect = p::Effect::PotentiallyApplied;
            }
        }
    }
    fn stop(&mut self) {
        self.revoke_consent();
        if let Some(a) = &self.active {
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
        if let Some(a) = &self.active { action_delegation::unknown(&a.agent); }
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
    pub(crate) fn repository_create_status(
        &mut self,
        qualified: bool,
        now: Instant,
        external: Reason,
    ) -> p::Status {
        let before = self.repository_create.view.clone();
        if self
            .repository_create
            .consent
            .as_ref()
            .is_some_and(|c| now >= c.end)
        {
            self.repository_create.revoke_consent();
        }
        self.repository_create.observe_go();
        let reason = if self.unknown || self.exhausted || self.repository_create.exhausted {
            p::Reason::CleanupUnknown
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
                || self.status.account.state != FactState::Observed
                || !self
                    .status
                    .session
                    .as_ref()
                    .is_some_and(|v| v.state == SessionState::Connected)
            {
                p::Reason::NotConnected
            } else if !p::coordinate(&s.repository) {
                p::Reason::InvalidInput
            } else {
                p::Reason::None
            }
        } else {
            p::Reason::NotConnected
        };
        self.repository_create.view.available = reason == p::Reason::None;
        self.repository_create.view.reason = reason;
        // The retained operation belongs to its original session even after an
        // explicit Disconnect has retired the private connection. A new native
        // connection resets both; an absent current session is not its receipt.
        if self.repository_create.active.is_none()
            && self.repository_create.view.operation.is_none()
        {
            self.repository_create.view.session_id = self.private.as_ref().map(|s| s.id.clone());
        }
        self.repository_create.finish(before);
        self.repository_create.view.clone()
    }
    pub(crate) fn repository_create_registered_project(&self) -> Option<&str> {
        self.repository_create
            .active
            .as_ref()
            .map(|a| a.project_id.as_str())
            .or_else(|| {
                self.repository_create
                    .consent
                    .as_ref()
                    .map(|c| c.project_id.as_str())
            })
    }
    fn repository_create_binding(
        &self,
        g: u32,
        r: &RegisteredRoot,
        e: &SavedEditGuard<'_>,
    ) -> bool {
        if let Some(a) = &self.repository_create.active {
            a.generation == g && &a.root == r && e.matches(&a.stamp)
        } else if let Some(c) = &self.repository_create.consent {
            c.generation == g && &c.root == r && e.matches(&c.stamp)
        } else {
            true
        }
    }
    fn repository_create_context(
        &mut self,
        id: &str,
        revision: u32,
        generation: u32,
        binding: &str,
        kind: p::OwnerKind,
        visibility: p::Visibility,
        marker: String,
        now: Instant,
    ) -> Result<p::Target, BridgeError> {
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if revision != self.repository_create.view.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        if !self.repository_create.view.available {
            return Err(refused(self.repository_create.view.reason));
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
        // A genuine /user identity is enough to request this narrow operation.
        // Missing/inaccessible repository metadata is NOT proof of absence.
        let target = p::Target {
            project_binding: binding.into(),
            repository: s.repository.clone(),
            account_id: a.id.clone(),
            account_login: a.login.clone(),
            owner_kind: kind,
            visibility,
            marker,
        };
        if !target.valid() {
            return Err(refused(p::Reason::InvalidInput));
        }
        Ok(target)
    }
    fn repository_create_start(
        &mut self,
        request: p::Request,
        root: RegisteredRoot,
        stamp: SavedEditStamp,
        consent_id: String,
        consent_end: Option<Instant>,
        gate: crate::asset_session::RepositoryCreateGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if !supervisor.repository_create_profile_available() {
            return Err(refused(p::Reason::Unqualified));
        }
        if !request.valid()
            || !self.repository_create.view.fits()
            || !crate::github_preflight_protocol::hex(&consent_id, 32)
            || (request.kind == p::Kind::Create) != consent_end.is_some()
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if self.repository_create.view.revision >= p::LAST_REVISION - 8 {
            self.exhaust();
            return Err(refused(p::Reason::CleanupUnknown));
        }
        p::encode_initial("repository-create-18446744073709551615", &request)?;
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
            .repository_create
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
        let before = self.repository_create.view.clone();
        let agent = gate.agent().cloned();
        gate.agent_entering()?;
        let ticket = supervisor
            .start_repository_create(request.clone(), gate, end)
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
        self.pull_request.context_changed();
        self.actions_retry.context_changed();self.play_cleanup.context_changed();
        self.repository_create.revoke_consent();
        // Pending records are retained for explanation across a readback. They
        // never substitute for the private prepared consent or authorize POST.
        self.repository_create.view.observed = None;
        self.repository_create.view.operation = Some(p::Operation {
            id: ticket.operation_id().into(),
            project_id: project_id.clone(),
            kind: request.kind,
            target: request.target.clone(),
            phase: p::Phase::Running,
            reason: p::Reason::None,
            effect: if request.kind == p::Kind::Create {
                p::Effect::NotSent
            } else {
                p::Effect::None
            },
        });
        self.repository_create.active = Some(Active {
            agent,
            ticket,
            request,
            session_id: session_id.clone(),
            project_id,
            generation,
            root,
            stamp,
            consent_id,
            consent_end,
        });
        self.repository_create.view.session_id = Some(session_id);
        self.repository_create.view.available = false;
        self.repository_create.view.reason = p::Reason::Busy;
        self.repository_create.finish(before);
        let b = self.status.clone();
        self.capability(now, Reason::None);
        self.finish(b);
        Ok(self.repository_create.view.clone())
    }
    pub(crate) fn repository_create_prepare(
        &mut self,
        a: p::PrepareArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        gate: crate::asset_session::RepositoryCreateGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if a.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        let target = self.repository_create_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            a.owner_kind,
            a.visibility,
            nonce.clone(),
            now,
        )?;
        self.repository_create_start(
            p::Request {
                kind: p::Kind::Prepare,
                target,
                home: None,
                prepared: None,
            },
            root,
            stamp,
            nonce,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn repository_create_pending(
        &mut self,
        a: p::PendingArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        home: String,
        gate: crate::asset_session::RepositoryCreateGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if a.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        let kind = if self
            .private
            .as_ref()
            .zip(self.status.account.value.as_ref())
            .is_some_and(|(s, a)| {
                s.repository
                    .split('/')
                    .next()
                    .is_some_and(|o| o.eq_ignore_ascii_case(&a.login))
            }) {
            p::OwnerKind::User
        } else {
            p::OwnerKind::Organization
        };
        let target = self.repository_create_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            kind,
            p::Visibility::Private,
            nonce.clone(),
            now,
        )?;
        self.repository_create_start(
            p::Request {
                kind: p::Kind::Pending,
                target,
                home: Some(home),
                prepared: None,
            },
            root,
            stamp,
            nonce,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn repository_create_create(
        &mut self,
        a: p::CreateArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        home: String,
        gate: crate::asset_session::RepositoryCreateGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let old = self
            .repository_create
            .consent
            .as_ref()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?
            .prepared
            .target
            .clone();
        let target = self.repository_create_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            old.owner_kind,
            old.visibility,
            old.marker,
            now,
        )?;
        if !action_delegation::origin(&self.repository_create.consent.as_ref().and_then(|c| c.agent.clone()), gate.agent())
            || !a.confirm
            || !self.repository_create.consent.as_ref().is_some_and(|c| {
                c.id == a.consent_id
                    && c.session_id == a.session_id
                    && c.generation == g
                    && c.root == root
                    && edit.matches(&c.stamp)
                    && now < c.end
                    && c.prepared.target == target
            })
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.repository_create.view.clone();
        let c = self
            .repository_create
            .consent
            .take()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        self.repository_create.revoke_consent();
        self.repository_create.finish(before); // One use even if admission fails.
        self.repository_create_start(
            p::Request {
                kind: p::Kind::Create,
                target,
                home: Some(home),
                prepared: Some(c.prepared),
            },
            root,
            c.stamp,
            c.id,
            Some(c.end),
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn repository_create_reconcile(
        &mut self,
        a: p::ReconcileArgs,
        g: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        home: String,
        gate: crate::asset_session::RepositoryCreateGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let prepared = self
            .repository_create
            .view
            .pending
            .iter()
            .find(|r| r.prepared.target.marker == a.marker)
            .map(|r| r.prepared.clone())
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let target = &prepared.target;
        let current = self.repository_create_context(
            &a.session_id,
            a.expected_revision,
            g,
            binding,
            target.owner_kind,
            target.visibility,
            target.marker.clone(),
            now,
        )?;
        if !current.same_scope(target) {
            return Err(refused(p::Reason::TargetChanged));
        }
        self.repository_create_start(
            p::Request {
                kind: p::Kind::Reconcile,
                target: target.clone(),
                home: Some(home),
                prepared: Some(prepared),
            },
            root,
            stamp,
            a.marker,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn repository_create_cancel(&mut self, id: &str) -> Result<p::Status, BridgeError> {
        if !self
            .repository_create
            .active
            .as_ref()
            .is_some_and(|a| a.ticket.operation_id() == id)
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.repository_create.context_changed();
        self.pull_request.context_changed();
        self.actions_retry.context_changed();self.play_cleanup.context_changed();
        Ok(self.repository_create.view.clone())
    }
    pub(crate) fn repository_create_discard(
        &mut self,
        a: &crate::github_setup_protocol::DiscardArgs,
    ) -> Result<p::Status, BridgeError> {
        if self.repository_create.active.is_some() {
            return Err(refused(p::Reason::Busy));
        }
        if a.expected_revision != self.repository_create.view.revision
            || !self
                .repository_create
                .consent
                .as_ref()
                .is_some_and(|c| c.id == a.consent_id && c.session_id == a.session_id)
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.repository_create.view.clone();
        self.repository_create.revoke_consent();
        self.repository_create.finish(before);
        Ok(self.repository_create.view.clone())
    }
    pub(crate) fn repository_create_go(
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
            .repository_create
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
        if self.unknown || self.exhausted || self.repository_create.exhausted {
            return Err(refused(p::Reason::CleanupUnknown));
        }
        if self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || self.publication.native_work_pending()
            || (self.pull_request.native_work_pending() || (self.actions_retry.native_work_pending() || self.play_cleanup.native_work_pending())) || self.activity.native_work_pending()
            || self.enrollment.is_some()
            || self.version_reserve_pending()
        {
            return Err(refused(p::Reason::Busy));
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
        if s.account_pin.as_ref() != Some(&request.target.account_id)
            || !s
                .repository
                .eq_ignore_ascii_case(&request.target.repository)
            || !self.status.account.value.as_ref().is_some_and(|v| {
                self.status.account.state == FactState::Observed
                    && v.id == request.target.account_id
                    && v.login.eq_ignore_ascii_case(&request.target.account_login)
            })
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
        Ok(bytes)
    }
    pub(crate) fn reconcile_repository_create(
        &mut self,
        now: Instant,
        external: Reason,
        proof: Option<(u32, &RegisteredRoot, &SavedEditGuard<'_>)>,
    ) {
        let cb = self.status.clone();
        let before = self.repository_create.view.clone();
        self.repository_create.observe_go();
        let current = proof.is_some_and(|(g, r, e)| self.repository_create_binding(g, r, e));
        if !current && self.repository_create_registered_project().is_some() {
            self.repository_create.stop();
        }
        match self
            .repository_create
            .active
            .as_ref()
            .map(|a| a.ticket.receipt())
        {
            Some(RepositoryCreateReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(RepositoryCreateReceipt::Settled {
                outcome,
                settled_at,
                was_unknown,
            }) => self.accept_repository_create(
                outcome,
                settled_at,
                was_unknown,
                now,
                current && external == Reason::None,
            ),
            _ => {}
        }
        if self.unknown {
            self.repository_create.unknown();
        } else if !current && self.repository_create_registered_project().is_some() {
            self.repository_create.view.reason = p::Reason::TargetChanged;
            self.repository_create.view.available = false;
        }
        self.repository_create.finish(before);
        self.capability(now, external);
        self.finish(cb);
    }
    fn accept_repository_create(
        &mut self,
        result: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
        now: Instant,
        current: bool,
    ) {
        let Some(a) = self.repository_create.active.take() else {
            self.unknown_inner();
            return;
        };
        let agent = a.agent.clone();
        let agent_id = a.ticket.operation_id().to_owned();
        let mut effect = if a.request.kind == p::Kind::Create {
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
            self.repository_create
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
        if was_unknown || self.unknown || reason == p::Reason::CleanupUnknown {
            action_delegation::unknown(&agent);
            self.unknown_inner();
            if let Some(o) = &mut self.repository_create.view.operation {
                o.phase = p::Phase::CleanupUnknown;
                o.reason = p::Reason::CleanupUnknown;
                o.effect = effect;
            }
            self.complete_retirement();
            return;
        }
        if let Some(r) = self.private.as_ref().and_then(|s| s.retirement) {
            reason = connection_reason(r);
        } else if !current {
            reason = p::Reason::TargetChanged;
        } else if self
            .repository_create
            .view
            .operation
            .as_ref()
            .is_some_and(|o| o.phase == p::Phase::Stopping)
        {
            reason = p::Reason::Cancelled;
        } else if let Ok(reply) = result {
            if reason == reply.result.reason {
                if let Some(c) = reply.result.creation {
                    effect = c.effect;
                    self.repository_create.view.observed = c.observed;
                }
                if let Some(rows) = reply.result.pending {
                    self.repository_create.view.pending = rows;
                }
                if let Some(prepared) = reply.result.prepared {
                    let ready = (|| {
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
                        self.repository_create.view.consent = Some(p::ConsentView {
                            id: a.consent_id.clone(),
                            expires_at,
                            prepared: prepared.clone(),
                        });
                        self.repository_create.consent = Some(Consent {
                            identity: Arc::new(()), agent: None,
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
        if reason != p::Reason::None && effect == p::Effect::CreatedObserved {
            effect = p::Effect::PotentiallyApplied;
            self.repository_create.view.observed = None;
        }
        if let Some(o) = &mut self.repository_create.view.operation {
            o.phase = p::Phase::Settled;
            o.reason = reason;
            o.effect = effect;
        }
        if !self.repository_create.view.fits() {
            self.repository_create.view.pending.clear();
            self.repository_create.revoke_consent();
            reason = p::Reason::ResponseLimit;
        }
        self.repository_create.view.reason = reason;
        if let Some(r) = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized),
            p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid),
            p::Reason::Cancelled => Some(Reason::Cancelled),
            _ => None,
        } {
            self.retire_inner(r, false);
        }
        self.repository_create_finish_retirement();
        if let Some(o)=&self.repository_create.view.operation {
            if o.id==agent_id && o.phase==p::Phase::Settled { action_delegation::accepted(&agent,&agent_id,self.repository_create.view.reason,o.effect); } else { action_delegation::unknown(&agent); }
        } else { action_delegation::unknown(&agent); }
    }
    fn repository_create_finish_retirement(&mut self) {
        // A settled Prepare/Create is not a request to disconnect. The shared
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
    fn completed_repository_task_never_invents_retirement_and_keeps_original_status_binding() {
        // Existing inert ConnectionState fixture only. No ticket, receipt,
        // native grant, runtime, filesystem or credential acquisition.
        let now = Instant::now();
        let mut connection = super::super::tests::fixture(now);
        let original_status = connection.status.clone();
        connection.repository_create_finish_retirement();
        assert_eq!(connection.status, original_status);
        assert!(connection.private.as_ref().unwrap().token.is_some());

        connection.private.as_mut().unwrap().retirement = Some(Reason::Cancelled);
        connection.repository_create_finish_retirement();
        assert!(connection.private.as_ref().unwrap().token.is_none());
        assert_eq!(
            connection.status.session.as_ref().unwrap().state,
            SessionState::Failed
        );

        let mut connection = super::super::tests::fixture(now);
        let id = connection.private.as_ref().unwrap().id.clone();
        connection.repository_create.view.session_id = Some(id.clone());
        connection.repository_create.view.operation = Some(p::Operation {
            id: "inert-original".into(),
            project_id: "project-1".into(),
            kind: p::Kind::Prepare,
            target: p::Target {
                project_binding: "a".repeat(64),
                repository: "owner/app".into(),
                account_id: "11".into(),
                account_login: "owner".into(),
                owner_kind: p::OwnerKind::User,
                visibility: p::Visibility::Private,
                marker: "b".repeat(32),
            },
            phase: p::Phase::Settled,
            reason: p::Reason::Cancelled,
            effect: p::Effect::None,
        });
        connection.private = None;
        let retained = connection.repository_create_status(false, now, Reason::None);
        assert!(!retained.available);
        assert_eq!(retained.session_id, Some(id));
        assert!(retained.operation.is_some());
        connection.repository_create.reset();
        let reset = connection.repository_create_status(false, now, Reason::None);
        assert!(reset.session_id.is_none() && reset.operation.is_none());
    }
}

impl ConnectionState {
    pub(crate) fn repository_create_agent_review(&self, a: &action_delegation::Selection, g:u32, root:&RegisteredRoot, edit:&SavedEditGuard<'_>, now:Instant) -> Result<action_delegation::Review,BridgeError> {
        let c=self.repository_create.consent.as_ref().ok_or_else(||refused(p::Reason::ConsentExpired))?;
        if a.kind!=crate::service_github_action_protocol::Kind::RepositoryCreate || a.session_id!=c.session_id || a.consent_id!=c.id || a.expected_revision!=self.repository_create.view.revision || c.generation!=g || &c.root!=root || !edit.matches(&c.stamp) || now>=c.end || c.agent.is_some() || self.repository_create.active.is_some() || self.repository_create.exhausted {return Err(refused(p::Reason::ConsentExpired))}
        action_delegation::review(a.kind,&c.session_id,&c.id,a.expected_revision,&c.prepared,c.identity.clone(),edit.stamp()?,c.end)
    }
    pub(crate) fn repository_create_agent_allow(&mut self, review:&action_delegation::Review, scope:&Arc<crate::service_github_action_requests::NativeScope>)->Result<(),BridgeError>{
        let c=self.repository_create.consent.as_mut().ok_or_else(||refused(p::Reason::ConsentExpired))?;
        if !Arc::ptr_eq(&c.identity,&review.identity)||c.agent.is_some()||scope.review!=review.data{return Err(refused(p::Reason::ConsentExpired))}c.agent=Some(Arc::downgrade(scope));Ok(())
    }
    pub(crate) fn repository_create_agent_revoke(&mut self, scope:&Arc<crate::service_github_action_requests::NativeScope>){
        if self.repository_create.consent.as_ref().and_then(|c|c.agent.as_ref()).and_then(Weak::upgrade).is_some_and(|s|Arc::ptr_eq(&s,scope)){let before=self.repository_create.view.clone();self.repository_create.revoke_consent();self.repository_create.finish(before);}
    }
}
