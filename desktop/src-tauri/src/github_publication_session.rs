//! Publication state in the SAME authenticated connection, not a credential owner.
use super::*;
use crate::{
    asset_source::RegisteredRoot,
    edit_owner::{SavedEditGuard, SavedEditStamp},
    github_publication_protocol as p,
    supervisor::{GitHubPublicationReceipt, GitHubPublicationTicket},
};
use serde_json::Value;

pub(crate) fn refused(reason: p::Reason) -> BridgeError {
    let text = serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_setup_publication_refused_{}",text.replace('-',"_")),
        match reason {p::Reason::ConsentExpired=>"The original review expired or was already used; do not retry an uncertain publication.",
            p::Reason::CleanupUnknown=>"Keep the original operation for retirement; cleanup is unconfirmed.",
            p::Reason::PublisherUnconfigured|p::Reason::Unqualified=>"The installed setup publication runtime is unavailable.",
            p::Reason::Busy=>"Wait for the original GitHub operation to settle.",
            _=>"The setup publication does not match the original project, account, repository or saved review."})
}
pub(crate) fn connection_reason(reason: Reason) -> p::Reason {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or(p::Reason::InvalidInput)
}
fn error_reason(error: &BridgeError) -> p::Reason {
    if let Some(value) = error.code.strip_prefix("github_setup_publication_refused_") {
        return serde_json::from_value(Value::String(value.replace('_', "-")))
            .unwrap_or(p::Reason::InvalidInput);
    }
    connection_reason(outcome_error(error))
}
struct Active {
    ticket: GitHubPublicationTicket,
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
                pull: None,
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
        self.consent = None;
        self.view.consent = None;
    }
    fn observe_go(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|v| v.request.kind == p::Kind::Publish && v.ticket.go_claimed())
        {
            if let Some(op) = &mut self.view.operation {
                op.effect = p::Effect::PotentiallyApplied;
            }
        }
    }
    pub(super) fn stop(&mut self) {
        self.revoke_consent();
        if let Some(active) = &self.active {
            active.ticket.stop();
            if let Some(op) = &mut self.view.operation {
                if op.phase != p::Phase::CleanupUnknown {
                    op.phase = p::Phase::Stopping;
                    op.reason = p::Reason::Cancelled;
                }
            }
        }
        self.observe_go();
    }
    pub(super) fn unknown(&mut self) {
        self.stop();
        self.view.available = false;
        self.view.reason = p::Reason::CleanupUnknown;
        if let Some(op) = &mut self.view.operation {
            if op.phase != p::Phase::Settled {
                op.phase = p::Phase::CleanupUnknown;
                op.reason = p::Reason::CleanupUnknown;
            }
        }
    }
    pub(super) fn context_changed(&mut self) {
        let before = self.view.clone();
        self.stop();
        self.finish(before);
    }
    pub(super) fn retired(&mut self, reason: Reason) {
        let before = self.view.clone();
        if reason == Reason::CleanupUnknown {
            self.unknown()
        } else {
            self.stop()
        }
        self.finish(before);
    }
    pub(super) fn reset(&mut self) {
        let before = self.view.clone();
        self.revoke_consent();
        self.view.pending.clear();
        self.view.pull = None;
        self.view.operation = None;
        self.view.session_id = None;
        self.finish(before);
    }
    pub(super) fn heap(&self) -> Option<usize> {
        if self.active.is_some() || self.exhausted || self.view.reason == p::Reason::CleanupUnknown
        {
            return None;
        }
        let mut n = self.view.heap()?;
        if let Some(v) = &self.consent {
            n = n
                .checked_add(v.id.capacity())?
                .checked_add(v.prepared.heap()?)?
                .checked_add(v.session_id.capacity())?
                .checked_add(v.project_id.capacity())?
                .checked_add(v.root.path.capacity())?;
        }
        Some(n)
    }
}
impl ConnectionState {
    pub(crate) fn publication_status(
        &mut self,
        qualified: bool,
        now: Instant,
        external: Reason,
    ) -> p::Status {
        let before = self.publication.view.clone();
        if self
            .publication
            .consent
            .as_ref()
            .is_some_and(|v| now >= v.end)
        {
            self.publication.revoke_consent();
        }
        self.publication.observe_go();
        let reason = if self.unknown || self.exhausted || self.publication.exhausted {
            p::Reason::CleanupUnknown
        } else if !qualified {
            p::Reason::Unqualified
        } else if !p::configured() {
            p::Reason::PublisherUnconfigured
        } else if external != Reason::None {
            connection_reason(external)
        } else if self.native_work_pending() {
            p::Reason::Busy
        } else if let Some(private) = &self.private {
            if let Some(reason) = private.retirement {
                connection_reason(reason)
            } else if now >= private.clock.end {
                p::Reason::Expired
            } else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
                p::Reason::RateLimited
            } else if private.token.is_none()
                || private.account_pin.is_none()
                || private.repository_pin.is_none()
                || self.status.account.state != FactState::Observed
                || self.status.repository.state != FactState::Observed
                || !self
                    .status
                    .session
                    .as_ref()
                    .is_some_and(|v| v.state == SessionState::Connected)
            {
                p::Reason::NotConnected
            } else {
                p::Reason::None
            }
        } else {
            p::Reason::NotConnected
        };
        self.publication.view.available = reason == p::Reason::None;
        self.publication.view.reason = reason;
        if self.publication.active.is_none() {
            self.publication.view.session_id = self.private.as_ref().map(|v| v.id.clone());
        }
        self.publication.finish(before);
        self.publication.view.clone()
    }
    pub(crate) fn publication_registered_project(&self) -> Option<&str> {
        self.publication
            .active
            .as_ref()
            .map(|v| v.project_id.as_str())
            .or_else(|| {
                self.publication
                    .consent
                    .as_ref()
                    .map(|v| v.project_id.as_str())
            })
    }
    fn publication_binding(
        &self,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
    ) -> bool {
        if let Some(v) = &self.publication.active {
            v.generation == generation && &v.root == root && edit.matches(&v.stamp)
        } else if let Some(v) = &self.publication.consent {
            v.generation == generation && &v.root == root && edit.matches(&v.stamp)
        } else {
            true
        }
    }
    fn publication_context(
        &mut self,
        id: &str,
        revision: u32,
        generation: u32,
        binding: &str,
        base: String,
        marker: String,
        now: Instant,
    ) -> Result<p::Target, BridgeError> {
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if revision != self.publication.view.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        if !self.publication.view.available {
            return Err(refused(self.publication.view.reason));
        }
        let private = self
            .private
            .as_ref()
            .filter(|v| {
                v.id == id
                    && v.generation == generation
                    && v.retirement.is_none()
                    && v.token.is_some()
                    && now < v.clock.end
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let account = self
            .status
            .account
            .value
            .as_ref()
            .filter(|v| {
                self.status.account.state == FactState::Observed
                    && private.account_pin.as_ref() == Some(&v.id)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let repo = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|v| {
                self.status.repository.state == FactState::Observed
                    && private.repository_pin.as_ref() == Some(&v.id)
                    && v.full_name.eq_ignore_ascii_case(&private.repository)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(refused(p::Reason::RateLimited));
        }
        let target = p::Target {
            project_binding: binding.into(),
            repository: repo.full_name.clone(),
            account_id: account.id.clone(),
            repository_id: repo.id.clone(),
            base,
            tooling_repository: crate::github_preflight_protocol::TOOLING_REPOSITORY.into(),
            tooling_sha: crate::github_preflight_protocol::TOOLING_SHA
                .ok_or_else(|| refused(p::Reason::PublisherUnconfigured))?
                .into(),
            marker,
        };
        if !target.valid() {
            return Err(refused(p::Reason::InvalidInput));
        }
        Ok(target)
    }
    fn publication_start(
        &mut self,
        request: p::Request,
        root: RegisteredRoot,
        stamp: SavedEditStamp,
        consent_id: String,
        consent_end: Option<Instant>,
        gate: crate::asset_session::GitHubPublicationGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if !supervisor.github_publication_profile_available() {
            return Err(refused(p::Reason::Unqualified));
        }
        if !request.valid()
            || !self.publication.view.fits()
            || !crate::github_preflight_protocol::hex(&consent_id, 32)
            || (request.kind == p::Kind::Publish) != consent_end.is_some()
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if self.publication.view.revision >= p::LAST_REVISION - 8 {
            self.exhaust();
            return Err(refused(p::Reason::CleanupUnknown));
        }
        p::encode_initial("github-publication-18446744073709551615", &request)?;
        let private = self
            .private
            .as_ref()
            .filter(|v| v.retirement.is_none() && v.token.is_some() && now < v.clock.end)
            .ok_or_else(|| refused(p::Reason::Expired))?;
        let (session_id, project_id, generation) = (
            private.id.clone(),
            private.project_id.clone(),
            private.generation,
        );
        let end = (now + Duration::from_secs(60))
            .min(private.clock.end)
            .min(consent_end.unwrap_or(private.clock.end));
        if end <= now {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let retained = self
            .publication
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
        let before = self.publication.view.clone();
        let ticket = supervisor
            .start_github_publication(request.clone(), gate, end)
            .map_err(|v| refused(error_reason(&v)))?;
        let old = self.preflight.snapshot();
        self.preflight.revoke_consent();
        self.preflight.finish(old);
        let old = self.release.snapshot();
        self.release.revoke_consent();
        self.release.finish(old);
        let old = self.setup.snapshot();
        self.setup.revoke_consent();
        self.setup.finish(old);
        self.publication.revoke_consent();
        self.publication.view.pending.clear();
        self.publication.view.pull = None;
        self.publication.view.operation = Some(p::Operation {
            id: ticket.operation_id().into(),
            kind: request.kind,
            phase: p::Phase::Running,
            reason: p::Reason::None,
            effect: if request.kind == p::Kind::Publish {
                p::Effect::NotSent
            } else {
                p::Effect::None
            },
        });
        self.publication.active = Some(Active {
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
        self.publication.view.session_id = Some(session_id);
        self.publication.view.available = false;
        self.publication.view.reason = p::Reason::Busy;
        self.publication.finish(before);
        let before = self.status.clone();
        self.capability(now, Reason::None);
        self.finish(before);
        Ok(self.publication.view.clone())
    }
    pub(crate) fn publication_prepare(
        &mut self,
        args: p::PrepareArgs,
        generation: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        source: p::Source,
        gate: crate::asset_session::GitHubPublicationGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if args.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        let target = self.publication_context(
            &args.session_id,
            args.expected_revision,
            generation,
            binding,
            args.base,
            nonce.clone(),
            now,
        )?;
        self.publication_start(
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
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn publication_pending(
        &mut self,
        args: p::PendingArgs,
        generation: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        nonce: String,
        home: String,
        gate: crate::asset_session::GitHubPublicationGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        if args.expected_connection_revision != self.status.revision {
            return Err(refused(p::Reason::TargetChanged));
        }
        let base = self
            .status
            .repository
            .value
            .as_ref()
            .map(|v| v.default_branch.clone())
            .ok_or_else(|| refused(p::Reason::NotConnected))?;
        let target = self.publication_context(
            &args.session_id,
            args.expected_revision,
            generation,
            binding,
            base,
            nonce.clone(),
            now,
        )?;
        self.publication_start(
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
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn publication_publish(
        &mut self,
        args: p::PublishArgs,
        generation: u32,
        root: RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        source: p::Source,
        home: String,
        gate: crate::asset_session::GitHubPublicationGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let old = self
            .publication
            .consent
            .as_ref()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        let target = self.publication_context(
            &args.session_id,
            args.expected_revision,
            generation,
            binding,
            old.prepared.target.base.clone(),
            old.prepared.target.marker.clone(),
            now,
        )?;
        if !args.confirm
            || !self.publication.consent.as_ref().is_some_and(|v| {
                v.id == args.consent_id
                    && v.session_id == args.session_id
                    && v.generation == generation
                    && v.root == root
                    && edit.matches(&v.stamp)
                    && now < v.end
                    && v.prepared.target == target
            })
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.publication.view.clone();
        let consent = self
            .publication
            .consent
            .take()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        self.publication.revoke_consent();
        self.publication.finish(before); // Spend even if later admission fails.
        self.publication_start(
            p::Request {
                kind: p::Kind::Publish,
                target,
                source: Some(source),
                home: Some(home),
                prepared: Some(consent.prepared),
            },
            root,
            consent.stamp,
            consent.id,
            Some(consent.end),
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn publication_reconcile(
        &mut self,
        args: p::ReconcileArgs,
        generation: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        home: String,
        gate: crate::asset_session::GitHubPublicationGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        let target = self
            .publication
            .view
            .pending
            .iter()
            .find(|v| v.summary.target.marker == args.marker)
            .map(|v| v.summary.target.clone())
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let current = self.publication_context(
            &args.session_id,
            args.expected_revision,
            generation,
            binding,
            target.base.clone(),
            target.marker.clone(),
            now,
        )?;
        // Historical tooling pin is retained for read-only reconciliation. It
        // cannot mint a new write using the current build's different caller.
        if !current.same_scope(&target) {
            return Err(refused(p::Reason::TargetChanged));
        }
        self.publication_start(
            p::Request {
                kind: p::Kind::Reconcile,
                target,
                source: None,
                home: Some(home),
                prepared: None,
            },
            root,
            stamp,
            args.marker,
            None,
            gate,
            supervisor,
            now,
        )
    }
    pub(crate) fn publication_cancel(&mut self, id: &str) -> Result<p::Status, BridgeError> {
        if !self
            .publication
            .active
            .as_ref()
            .is_some_and(|v| v.ticket.operation_id() == id)
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.publication.context_changed();
        Ok(self.publication.view.clone())
    }
    pub(crate) fn publication_discard(
        &mut self,
        args: &crate::github_setup_protocol::DiscardArgs,
    ) -> Result<p::Status, BridgeError> {
        if self.publication.active.is_some() {
            return Err(refused(p::Reason::Busy));
        }
        if args.expected_revision != self.publication.view.revision
            || !self
                .publication
                .consent
                .as_ref()
                .is_some_and(|v| v.id == args.consent_id && v.session_id == args.session_id)
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let before = self.publication.view.clone();
        self.publication.revoke_consent();
        self.publication.finish(before);
        Ok(self.publication.view.clone())
    }
    pub(crate) fn publication_go(
        &self,
        id: &str,
        digest: &str,
        request: &p::Request,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let active = self
            .publication
            .active
            .as_ref()
            .filter(|v| {
                v.ticket.operation_id() == id
                    && &v.request == request
                    && v.generation == generation
                    && &v.root == root
                    && edit.matches(&v.stamp)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if self.unknown || self.exhausted || self.publication.exhausted {
            return Err(refused(p::Reason::CleanupUnknown));
        }
        if self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
        {
            return Err(refused(p::Reason::Busy));
        }
        if active.consent_end.is_some_and(|end| now >= end) {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let private = self
            .private
            .as_ref()
            .filter(|v| {
                v.id == active.session_id
                    && v.project_id == active.project_id
                    && v.generation == active.generation
                    && v.ticket.is_none()
                    && v.retirement.is_none()
                    && v.token.is_some()
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if now >= private.clock.end {
            return Err(refused(p::Reason::Expired));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(refused(p::Reason::RateLimited));
        }
        if private.account_pin.as_ref() != Some(&request.target.account_id)
            || private.repository_pin.as_ref() != Some(&request.target.repository_id)
            || !private
                .repository
                .eq_ignore_ascii_case(&request.target.repository)
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        let token = if request.kind == p::Kind::Pending {
            None
        } else {
            private.token.as_deref()
        };
        let mut bytes = p::encode_go(id, digest, token, request)?;
        if !claim() {
            use zeroize::Zeroize;
            bytes.zeroize();
            return Err(refused(p::Reason::Cancelled));
        }
        Ok(bytes)
    }
    pub(crate) fn reconcile_publication(
        &mut self,
        now: Instant,
        external: Reason,
        proof: Option<(u32, &RegisteredRoot, &SavedEditGuard<'_>)>,
    ) {
        let connection_before = self.status.clone();
        let before = self.publication.view.clone();
        self.publication.observe_go();
        let current = proof.is_some_and(|(generation, root, edit)| {
            self.publication_binding(generation, root, edit)
        });
        if !current && self.publication_registered_project().is_some() {
            self.publication.stop();
        }
        let receipt = self.publication.active.as_ref().map(|v| v.ticket.receipt());
        match receipt {
            Some(GitHubPublicationReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(GitHubPublicationReceipt::Settled {
                outcome,
                settled_at,
                was_unknown,
            }) => self.accept_publication(
                outcome,
                settled_at,
                was_unknown,
                now,
                current && external == Reason::None,
            ),
            _ => {}
        }
        if self.unknown {
            self.publication.unknown();
        } else if !current && self.publication_registered_project().is_some() {
            self.publication.view.reason = p::Reason::TargetChanged;
            self.publication.view.available = false;
        }
        self.publication.finish(before);
        self.capability(now, external);
        self.finish(connection_before);
    }
    fn accept_publication(
        &mut self,
        result: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
        now: Instant,
        current: bool,
    ) {
        let Some(active) = self.publication.active.take() else {
            self.unknown_inner();
            return;
        };
        let mut effect = if active.request.kind == p::Kind::Publish {
            if active.ticket.go_claimed() {
                p::Effect::PotentiallyApplied
            } else {
                p::Effect::NotSent
            }
        } else {
            p::Effect::None
        };
        let mut reason = result
            .as_ref()
            .map_or_else(error_reason, |v| v.result.reason);
        let fits = result.as_ref().map_or(true, |reply| {
            self.publication
                .view
                .heap()
                .and_then(|n| n.checked_add(reply.heap()?))
                .and_then(|n| n.checked_add(active.ticket.retained_heap()?))
                .and_then(|n| n.checked_add(active.request.heap()?))
                .and_then(|n| n.checked_add(2 * p::RESPONSE_LIMIT + 65536))
                .is_some_and(|n| n <= p::RETAINED_LIMIT)
        });
        if !fits {
            reason = p::Reason::ResourcesUnavailable
        }
        if let Ok(reply) = &result {
            if !self.apply_control(&reply.result.control, settled_at) {
                reason = p::Reason::ResponseInvalid
            }
        }
        if self
            .private
            .as_ref()
            .is_some_and(|v| now >= v.clock.end && v.retirement.is_none())
        {
            self.retire_inner(Reason::Expired, false);
        }
        if was_unknown || self.unknown || reason == p::Reason::CleanupUnknown {
            self.unknown_inner();
            if let Some(op) = &mut self.publication.view.operation {
                op.phase = p::Phase::CleanupUnknown;
                op.reason = p::Reason::CleanupUnknown;
                op.effect = effect;
            }
            self.complete_retirement();
            return;
        }
        if let Some(retirement) = self.private.as_ref().and_then(|v| v.retirement) {
            reason = connection_reason(retirement);
        } else if !current {
            reason = p::Reason::TargetChanged;
        } else if self
            .publication
            .view
            .operation
            .as_ref()
            .is_some_and(|v| v.phase == p::Phase::Stopping)
        {
            reason = p::Reason::Cancelled;
        } else if let Ok(reply) = result {
            if reason == reply.result.reason {
                if let Some(value) = reply.result.publication {
                    effect = value.effect;
                    self.publication.view.pull = value.pull;
                }
                if let Some(pending) = reply.result.pending {
                    self.publication.view.pending = pending;
                }
                if let Some(prepared) = reply.result.prepared {
                    let ready = (|| {
                        let private = self
                            .private
                            .as_ref()
                            .filter(|v| v.id == active.session_id && v.retirement.is_none())?;
                        let end = (settled_at + Duration::from_secs(120)).min(private.clock.end);
                        if now >= end {
                            return None;
                        }
                        let wall = private
                            .clock
                            .wall
                            .checked_add(end.duration_since(private.clock.admitted))?;
                        Some((end, display_utc(wall)?))
                    })();
                    if let Some((end, expires_at)) = ready {
                        self.publication.view.consent = Some(p::ConsentView {
                            id: active.consent_id.clone(),
                            expires_at,
                            prepared: prepared.clone(),
                        });
                        self.publication.consent = Some(Consent {
                            id: active.consent_id,
                            prepared,
                            end,
                            session_id: active.session_id,
                            project_id: active.project_id,
                            generation: active.generation,
                            root: active.root,
                            stamp: active.stamp,
                        });
                    } else {
                        reason = p::Reason::ConsentExpired;
                    }
                }
            }
        }
        if reason != p::Reason::None && effect == p::Effect::DraftPrObserved {
            effect = p::Effect::PotentiallyApplied;
            self.publication.view.pull = None;
        }
        if let Some(op) = &mut self.publication.view.operation {
            op.phase = p::Phase::Settled;
            op.reason = reason;
            op.effect = effect;
        }
        if !self.publication.view.fits() {
            self.publication.view.pending.clear();
            self.publication.revoke_consent();
            reason = p::Reason::ResponseLimit;
        }
        self.publication.view.reason = reason;
        let retire = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized),
            p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid),
            p::Reason::Cancelled => Some(Reason::Cancelled),
            _ => None,
        };
        if let Some(reason) = retire {
            self.retire_inner(reason, false);
        }
        // Finishing a publication request does not itself disconnect the
        // account. Only complete an already-requested original retirement.
        // CleanupUnknown retains its separate fail-closed path above.
        if self.private.as_ref().is_some_and(|v| v.retirement.is_some()) {
            self.complete_retirement();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_source::{DirectoryIdentity, ProjectIdentity},
        edit_owner::EditOwner,
        runtime::RuntimeConfig,
        supervisor::PublicationControlFixture,
    };
    use std::{path::PathBuf, sync::Arc};

    fn request(kind: p::Kind) -> p::Request {
        let target = p::Target {
            project_binding: "a".repeat(64),
            repository: "owner/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
            base: "release/setup".into(),
            tooling_repository: crate::github_preflight_protocol::TOOLING_REPOSITORY.into(),
            tooling_sha: "b".repeat(40),
            marker: "c".repeat(32),
        };
        let prepared = p::Prepared {
            protocol: p::PROTOCOL.into(),
            head: target.head(),
            target: target.clone(),
            base_commit: "d".repeat(40),
            base_tree: "e".repeat(40),
            desired_tree: "f".repeat(40),
            confirmation: p::CONFIRMATION.into(),
            files: p::PATHS
                .iter()
                .map(|path| p::ReviewFile {
                    path: (*path).into(),
                    before: None,
                    after: "inert saved DATA".into(),
                })
                .collect(),
        };
        p::Request {
            kind,
            target,
            source: matches!(kind, p::Kind::Prepare | p::Kind::Publish).then(|| p::Source {
                root: "/inert/project".into(),
                root_identity: crate::github_setup_protocol::SecretRootIdentity {
                    device: "1".into(),
                    inode: "2".into(),
                    mode: 0o40700,
                    uid: 123,
                    gid: 123,
                },
            }),
            home: (kind != p::Kind::Prepare).then(|| "/inert/home".into()),
            prepared: (kind == p::Kind::Publish).then_some(prepared),
        }
    }
    // Actual edit registration/stamp and same in-memory connection/Owner. Root
    // identity is predicate DATA only, never passed to a native file opener.
    fn fixture(
        kind: p::Kind,
        at: Instant,
    ) -> (
        ConnectionState,
        EditOwner,
        Arc<()>,
        RegisteredRoot,
        PublicationControlFixture,
    ) {
        let edit = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/never-opened-publication-edit",
        )));
        let doc = Arc::new(());
        edit.bind_saved_registration(
            &doc,
            Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()),
        );
        edit.initial_document("main").unwrap();
        let stamp = edit
            .saved_registration_guard(&doc)
            .unwrap()
            .stamp()
            .unwrap();
        let root = RegisteredRoot {
            path: PathBuf::from("/inert/project"),
            identity: ProjectIdentity::Posix(DirectoryIdentity::synthetic_evidence_identity()),
        };
        let req = request(kind);
        let (ticket, control) =
            GitHubPublicationTicket::control_fixture(req.clone(), at + Duration::from_secs(60));
        let mut state = super::super::tests::fixture(at);
        let private = state.private.as_mut().unwrap();
        private.account_pin = Some("11".into());
        private.repository_pin = Some("22".into());
        state.status.session.as_mut().unwrap().state = SessionState::Connected;
        state.status.operation.as_mut().unwrap().phase = Phase::Settled;
        state.publication.view.session_id = Some("github-session-1".into());
        state.publication.view.operation = Some(p::Operation {
            id: ticket.operation_id().into(),
            kind,
            phase: p::Phase::Running,
            reason: p::Reason::None,
            effect: if kind == p::Kind::Publish {
                p::Effect::NotSent
            } else {
                p::Effect::None
            },
        });
        state.publication.active = Some(Active {
            ticket,
            request: req,
            session_id: "github-session-1".into(),
            project_id: "project-1".into(),
            generation: 2,
            root: root.clone(),
            stamp,
            consent_id: "c".repeat(32),
            consent_end: (kind == p::Kind::Publish).then_some(at + Duration::from_secs(30)),
        });
        (state, edit, doc, root, control)
    }
    fn go(
        state: &ConnectionState,
        edit: &EditOwner,
        doc: &Arc<()>,
        root: &RegisteredRoot,
        control: &PublicationControlFixture,
        now: Instant,
    ) -> Result<Vec<u8>, BridgeError> {
        let a = state.publication.active.as_ref().unwrap();
        let raw = p::encode_initial(a.ticket.operation_id(), &a.request).unwrap();
        let digest = p::digest(&raw);
        let guard = edit.saved_registration_guard(doc)?;
        state.publication_go(
            a.ticket.operation_id(),
            &digest,
            &a.request,
            2,
            root,
            &guard,
            now,
            || control.claim(),
        )
    }
    #[test]
    fn settled_publication_request_only_retires_an_explicitly_retiring_connection() {
        for retirement in [None, Some(Reason::Cancelled), Some(Reason::Expired)] {
            let at = Instant::now();
            let (mut state, _edit, _doc, _root, control) = fixture(p::Kind::Prepare, at);
            let end = state.private.as_ref().unwrap().clock.end;
            state.private.as_mut().unwrap().retirement = retirement;

            // Supplied settled error DATA exercises the actual state handler,
            // not native completion, a provider call or an acquired credential.
            state.accept_publication(
                Err(refused(p::Reason::NetworkUnavailable)),
                at,
                false,
                at,
                true,
            );

            let private = state.private.as_ref().unwrap();
            assert_eq!(private.clock.end, end);
            assert_eq!(private.token.is_some(), retirement.is_none());
            assert_eq!(
                state.status.session.as_ref().unwrap().state,
                match retirement {
                    None => SessionState::Connected,
                    Some(Reason::Expired) => SessionState::Expired,
                    _ => SessionState::Failed,
                }
            );
            assert!(state.publication.active.is_none());
            assert_eq!(
                state.publication.view.operation.as_ref().unwrap().phase,
                p::Phase::Settled
            );
            assert!(control.retained());
        }
    }
    #[test]
    fn final_go_uses_original_edit_root_request_and_one_use_owner_claim() {
        let at = Instant::now();
        let (state, edit, doc, root, control) = fixture(p::Kind::Publish, at);
        let mut wrong = root.clone();
        wrong.path = PathBuf::from("/inert/other");
        assert!(go(&state, &edit, &doc, &wrong, &control, at).is_err());
        assert!(!state
            .publication
            .active
            .as_ref()
            .unwrap()
            .ticket
            .go_claimed());
        let original = go(&state, &edit, &doc, &root, &control, at).unwrap();
        let value: Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(value["go"]["token"], "INERT_NOT_A_CREDENTIAL");
        assert!(go(&state, &edit, &doc, &root, &control, at).is_err());
        assert!(control.retained());
        // Actual edit document loss, not a fabricated public revision, vetoes GO.
        let (state, edit, doc, root, control) = fixture(p::Kind::Prepare, at);
        edit.document_lost("main");
        assert!(go(&state, &edit, &doc, &root, &control, at).is_err());
        assert!(!state
            .publication
            .active
            .as_ref()
            .unwrap()
            .ticket
            .go_claimed());
    }
    #[test]
    fn credential_consent_expiry_and_cooldown_cannot_claim_or_reset_original_clock() {
        for case in 0..3 {
            let at = Instant::now();
            let (mut state, edit, doc, root, control) = fixture(p::Kind::Publish, at);
            let original = state.private.as_ref().unwrap().clock.end;
            let now = match case {
                0 => at + Duration::from_secs(30),
                1 => {
                    state.private.as_mut().unwrap().clock.end = at;
                    at
                }
                _ => {
                    state.cooldown = Some(at + Duration::from_secs(5));
                    at
                }
            };
            assert!(go(&state, &edit, &doc, &root, &control, now).is_err());
            assert!(!state
                .publication
                .active
                .as_ref()
                .unwrap()
                .ticket
                .go_claimed());
            assert!(state.private.as_ref().unwrap().clock.end <= original);
            assert!(control.retained());
        }
        let at = Instant::now();
        let (state, edit, doc, root, control) = fixture(p::Kind::Pending, at);
        let raw = go(&state, &edit, &doc, &root, &control, at).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert!(value["go"]["token"].is_null());
    }
    #[test]
    fn cancellation_preserves_original_ticket_and_pre_or_post_go_effect() {
        for sent in [false, true] {
            let at = Instant::now();
            let (mut state, edit, doc, root, control) = fixture(p::Kind::Publish, at);
            if sent {
                go(&state, &edit, &doc, &root, &control, at).unwrap();
            }
            assert!(state.publication_cancel("different-original").is_err());
            let id = state
                .publication
                .active
                .as_ref()
                .unwrap()
                .ticket
                .operation_id()
                .to_string();
            state.publication_cancel(&id).unwrap();
            assert_eq!(
                state.publication.view.operation.as_ref().unwrap().phase,
                p::Phase::Stopping
            );
            assert_eq!(
                state.publication.view.operation.as_ref().unwrap().effect,
                if sent {
                    p::Effect::PotentiallyApplied
                } else {
                    p::Effect::NotSent
                }
            );
            assert!(state.publication.active.is_some() && control.retained());
            assert!(go(&state, &edit, &doc, &root, &control, at).is_err());
            // Supplied final error DATA tests projection only, not OS finality.
            state.accept_publication(
                Err(BridgeError::new("cancelled", "inert")),
                at,
                false,
                at,
                true,
            );
            assert_eq!(
                state.publication.view.operation.as_ref().unwrap().effect,
                if sent {
                    p::Effect::PotentiallyApplied
                } else {
                    p::Effect::NotSent
                }
            );
            assert!(state.publication.active.is_none());
            assert!(control.retained());
        }
    }
    #[test]
    fn unknown_cleanup_keeps_original_until_receipt_and_late_data_never_upgrades() {
        let at = Instant::now();
        let (mut state, edit, doc, root, control) = fixture(p::Kind::Publish, at);
        go(&state, &edit, &doc, &root, &control, at).unwrap();
        control.unknown();
        let guard = edit.saved_registration_guard(&doc).unwrap();
        state.reconcile_publication(at, Reason::None, Some((2, &root, &guard)));
        assert!(state.unknown && state.publication.active.is_some() && control.retained());
        assert_eq!(
            state.publication.view.operation.as_ref().unwrap().phase,
            p::Phase::CleanupUnknown
        );
        state.accept_publication(Err(BridgeError::timeout()), at, true, at, true);
        assert!(state.unknown && state.publication.active.is_none() && control.retained());
        assert_eq!(
            state.publication.view.operation.as_ref().unwrap().phase,
            p::Phase::CleanupUnknown
        );
        assert!(state.publication.view.consent.is_none() && state.publication.view.pull.is_none());
    }
    #[test]
    fn actual_consent_status_expiry_and_context_change_retire_private_prepared() {
        for expired in [false, true] {
            let at = Instant::now();
            let (mut state, edit, doc, root, _) = fixture(p::Kind::Publish, at);
            let active = state.publication.active.take().unwrap();
            let prepared = active.request.prepared.unwrap();
            let stamp = edit
                .saved_registration_guard(&doc)
                .unwrap()
                .stamp()
                .unwrap();
            state.publication.consent = Some(Consent {
                id: "c".repeat(32),
                prepared: prepared.clone(),
                end: at + Duration::from_secs(1),
                session_id: "github-session-1".into(),
                project_id: "project-1".into(),
                generation: 2,
                root,
                stamp,
            });
            state.publication.view.consent = Some(p::ConsentView {
                id: "c".repeat(32),
                expires_at: "2026-09-17T12:00:01Z".into(),
                prepared,
            });
            if expired {
                state.publication_status(false, at + Duration::from_secs(1), Reason::None);
            } else {
                state.setup_context_changed();
            }
            assert!(
                state.publication.consent.is_none() && state.publication.view.consent.is_none()
            );
        }
    }
}
