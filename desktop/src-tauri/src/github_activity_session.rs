//! One bounded read inside the SAME ConnectionState, Setup supervisor and clock.
use super::*;
use crate::{
    asset_source::RegisteredRoot,
    edit_owner::{SavedEditGuard, SavedEditStamp},
    github_activity_protocol as p,
    supervisor::{GitHubActivityReceipt, GitHubActivityTicket},
};
pub(crate) fn refused(r: p::Reason) -> BridgeError {
    let name = serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_activity_refused_{}",name.replace('-',"_")),match r{
        p::Reason::CleanupUnknown=>"The original activity read has unconfirmed cleanup. Keep its status and do not reconnect to dismiss it.",
        p::Reason::TargetChanged=>"The selected project or verified GitHub account/repository changed. Check current status before reading again.",
        p::Reason::Busy=>"Finish the original task before reading GitHub activity. Status and Stop remain available.",
        _=>"This GitHub activity read is unavailable for the current original connection.",})
}

#[cfg(test)]
mod activity_control_tests {
    use super::*;
    #[test]
    fn activity_stop_can_return_only_exact_retained_terminal_data() {
        // Source-control fixture only: no native receipt, worker or join is
        // manufactured by this test; it exercises the no-op terminal branch.
        let mut state = ConnectionState::new();
        state.activity.view.operation = Some(p::Operation {
            id: "activity-a".into(),
            project_id: "project-a".into(),
            target: p::Target {
                project_binding: "f".repeat(64),
                repository: "example/application".into(),
                account_id: "7".into(),
                repository_id: "9".into(),
            },
            selection: p::Selection::Overview { branch: None },
            phase: p::Phase::Settled,
            reason: p::Reason::Cancelled,
        });
        let original = state.activity.view.clone();
        assert_eq!(
            state.github_activity_cancel("activity-a").unwrap(),
            original
        );
        assert!(state.github_activity_cancel("activity-b").is_err());
        state.activity.view.operation.as_mut().unwrap().phase = p::Phase::CleanupUnknown;
        assert!(state.github_activity_cancel("activity-a").is_err());
        assert_eq!(
            state.activity.view.operation.as_ref().unwrap().phase,
            p::Phase::CleanupUnknown
        );
    }
}
pub(crate) fn connection_reason(r: Reason) -> p::Reason {
    match r {
        Reason::Stale => p::Reason::TargetChanged,
        Reason::PublisherUnconfigured => p::Reason::Unqualified,
        _ => serde_json::to_value(r)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(p::Reason::InvalidInput),
    }
}
fn error_reason(e: &BridgeError) -> p::Reason {
    e.code
        .strip_prefix("github_activity_refused_")
        .and_then(|v| serde_json::from_value(serde_json::Value::String(v.replace('_', "-"))).ok())
        .unwrap_or_else(|| connection_reason(outcome_error(e)))
}
struct Active {
    ticket: GitHubActivityTicket,
    request: p::Request,
    session_id: String,
    project_id: String,
    generation: u32,
    root: RegisteredRoot,
    stamp: SavedEditStamp,
}
pub(super) struct State {
    view: p::Status,
    active: Option<Active>,
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
                result: None,
            },
            active: None,
            exhausted: false,
        }
    }
    pub(super) fn native_work_pending(&self) -> bool {
        self.active.is_some()
    }
    fn finish(&mut self, b: p::Status) {
        if self.exhausted {
            self.view = b;
            return;
        }
        if self.view != b {
            if b.revision >= p::LAST_REVISION - 1 {
                self.view.revision = p::LAST_REVISION;
                self.exhausted = true;
                self.unknown();
            } else {
                self.view.revision = b.revision + 1;
            }
        }
    }
    fn stop(&mut self) {
        if let Some(a) = &self.active {
            a.ticket.stop();
            if let Some(o) = &mut self.view.operation {
                if o.phase != p::Phase::CleanupUnknown {
                    o.phase = p::Phase::Stopping;
                    o.reason = p::Reason::Cancelled;
                }
            }
        }
    }
    fn unknown(&mut self) {
        self.stop();
        self.view.available = false;
        self.view.reason = p::Reason::CleanupUnknown;
        self.view.result = None;
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
        self.view.result = None;
        self.finish(b);
    }
    pub(super) fn retired(&mut self, r: Reason) {
        let b = self.view.clone();
        if r == Reason::CleanupUnknown {
            self.unknown();
        } else {
            self.stop();
            self.view.result = None;
        }
        self.finish(b);
    }
    pub(super) fn reset(&mut self) {
        let b = self.view.clone();
        self.view.result = None;
        self.view.operation = None;
        self.view.session_id = None;
        self.finish(b);
    }
    pub(super) fn heap(&self) -> Option<usize> {
        if self.active.is_some() || self.exhausted || self.view.reason == p::Reason::CleanupUnknown
        {
            return None;
        }
        self.view.heap()
    }
}
impl ConnectionState {
    pub(crate) fn github_activity_status(
        &mut self,
        qualified: bool,
        now: Instant,
        external: Reason,
    ) -> p::Status {
        let b = self.activity.view.clone();
        let reason = if self.unknown || self.exhausted || self.activity.exhausted {
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
                || s.repository_pin.is_none()
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
        self.activity.view.available = reason == p::Reason::None;
        self.activity.view.reason = reason;
        if self.activity.active.is_none() && self.activity.view.operation.is_none() {
            self.activity.view.session_id = self.private.as_ref().map(|s| s.id.clone());
        }
        self.activity.finish(b);
        self.activity.view.clone()
    }
    pub(crate) fn github_activity_registered_project(&self) -> Option<&str> {
        self.activity.active.as_ref().map(|a| a.project_id.as_str())
    }
    pub(crate) fn github_activity_read(
        &mut self,
        args: p::ReadArgs,
        generation: u32,
        root: RegisteredRoot,
        binding: &str,
        stamp: SavedEditStamp,
        gate: crate::asset_session::GitHubActivityGoGate,
        supervisor: &Supervisor,
        now: Instant,
    ) -> Result<p::Status, BridgeError> {
        self.room()
            .map_err(|_| refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending() {
            return Err(refused(p::Reason::Busy));
        }
        if !self.activity.view.available {
            return Err(refused(self.activity.view.reason));
        }
        if args.expected_revision != self.activity.view.revision
            || args.expected_connection_revision != self.status.revision
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        if self.activity.view.revision >= p::LAST_REVISION - 8 {
            self.exhaust();
            return Err(refused(p::Reason::CleanupUnknown));
        }
        let s = self
            .private
            .as_ref()
            .filter(|s| {
                s.id == args.session_id
                    && s.project_id == args.project_id
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
        let r = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|r| {
                self.status.repository.state == FactState::Observed
                    && s.repository_pin.as_ref() == Some(&r.id)
                    && s.repository.eq_ignore_ascii_case(&r.full_name)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let request = p::Request {
            target: p::Target {
                project_binding: binding.into(),
                repository: s.repository.clone(),
                account_id: a.id.clone(),
                repository_id: r.id.clone(),
            },
            selection: args.selection,
        };
        if !request.valid() || !self.activity.view.fits() {
            return Err(refused(p::Reason::InvalidInput));
        }
        p::encode_initial("github-activity-18446744073709551615", &request)?;
        let end = (now + Duration::from_secs(60)).min(s.clock.end);
        let (session_id, project_id) = (s.id.clone(), s.project_id.clone());
        let retained = self
            .activity
            .heap()
            .and_then(|n| n.checked_add(request.heap()?))
            .and_then(|n| n.checked_add(request.heap()?))
            .and_then(|n| {
                n.checked_add(
                    session_id.capacity()
                        + project_id.capacity()
                        + root.path.capacity()
                        + 2 * p::RESPONSE_LIMIT
                        + p::GO_LIMIT
                        + 65536,
                )
            });
        if !retained.is_some_and(|n| n <= p::RETAINED_LIMIT) {
            return Err(refused(p::Reason::ResourcesUnavailable));
        }
        let b = self.activity.view.clone();
        let ticket = supervisor
            .start_github_activity(request.clone(), gate, end)
            .map_err(|e| refused(error_reason(&e)))?;
        // An explicit new read invalidates old write reviews, but never starts
        // a dispatch, publication, creation or another provider action.
        let b0 = self.preflight.snapshot();
        self.preflight.revoke_consent();
        self.preflight.finish(b0);
        let b0 = self.release.snapshot();
        self.release.revoke_consent();
        self.release.finish(b0);
        let b0 = self.setup.snapshot();
        self.setup.revoke_consent();
        self.setup.finish(b0);
        self.publication.context_changed();
        self.repository_create.context_changed();
        self.pull_request.context_changed();
        self.activity.view.result = None;
        self.activity.view.operation = Some(p::Operation {
            id: ticket.operation_id().into(),
            project_id: project_id.clone(),
            target: request.target.clone(),
            selection: request.selection.clone(),
            phase: p::Phase::Running,
            reason: p::Reason::None,
        });
        self.activity.active = Some(Active {
            ticket,
            request,
            session_id: session_id.clone(),
            project_id,
            generation,
            root,
            stamp,
        });
        self.activity.view.session_id = Some(session_id);
        self.activity.view.available = false;
        self.activity.view.reason = p::Reason::Busy;
        self.activity.finish(b);
        let b = self.status.clone();
        self.capability(now, Reason::None);
        self.finish(b);
        Ok(self.activity.view.clone())
    }
    pub(crate) fn github_activity_cancel(&mut self, id: &str) -> Result<p::Status, BridgeError> {
        // A terminal receipt can win the race with this exact original Stop.
        // Return that retained fact, not an invented second operation or error
        // that would make a genuinely joined read look unconfirmed in the UI.
        if self.activity.active.is_none()
            && self
                .activity
                .view
                .operation
                .as_ref()
                .is_some_and(|o| o.id == id && o.phase == p::Phase::Settled)
        {
            return Ok(self.activity.view.clone());
        }
        if !self
            .activity
            .active
            .as_ref()
            .is_some_and(|a| a.ticket.operation_id() == id)
        {
            return Err(refused(p::Reason::InvalidInput));
        }
        let b = self.activity.view.clone();
        self.activity.stop();
        self.activity.finish(b);
        Ok(self.activity.view.clone())
    }
    pub(crate) fn github_activity_go(
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
            .activity
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
        if self.unknown || self.exhausted || self.activity.exhausted {
            return Err(refused(p::Reason::CleanupUnknown));
        }
        if self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || self.publication.native_work_pending()
            || self.pull_request.native_work_pending() || self.repository_create.native_work_pending()
            || self.enrollment.is_some()
        {
            return Err(refused(p::Reason::Busy));
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
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if now >= s.clock.end {
            return Err(refused(p::Reason::Expired));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|e| now < e) {
            return Err(refused(p::Reason::RateLimited));
        }
        if s.account_pin.as_ref() != Some(&request.target.account_id)
            || s.repository_pin.as_ref() != Some(&request.target.repository_id)
            || !s
                .repository
                .eq_ignore_ascii_case(&request.target.repository)
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        let mut bytes = p::encode_go(
            id,
            digest,
            s.token
                .as_deref()
                .ok_or_else(|| refused(p::Reason::NotConnected))?,
            request,
        )?;
        if !claim() {
            use zeroize::Zeroize;
            bytes.zeroize();
            return Err(refused(p::Reason::Cancelled));
        }
        Ok(bytes)
    }
    pub(crate) fn reconcile_github_activity(
        &mut self,
        now: Instant,
        external: Reason,
        proof: Option<(u32, &RegisteredRoot, &SavedEditGuard<'_>)>,
    ) {
        let cb = self.status.clone();
        let b = self.activity.view.clone();
        let current = self.activity.active.as_ref().is_some_and(|a| {
            proof.is_some_and(|(g, r, e)| a.generation == g && &a.root == r && e.matches(&a.stamp))
        });
        if !current {
            self.activity.stop();
        }
        match self.activity.active.as_ref().map(|a| a.ticket.receipt()) {
            Some(GitHubActivityReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(GitHubActivityReceipt::Settled {
                outcome,
                settled_at,
                was_unknown,
            }) => self.accept_github_activity(
                outcome,
                settled_at,
                was_unknown,
                now,
                current && external == Reason::None,
            ),
            _ => {}
        }
        if self.unknown {
            self.activity.unknown();
        }
        self.activity.finish(b);
        self.capability(now, external);
        self.finish(cb);
    }
    fn accept_github_activity(
        &mut self,
        result: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
        now: Instant,
        current: bool,
    ) {
        if was_unknown || self.unknown {
            self.unknown_inner();
            return;
        }
        let Some(a) = self.activity.active.take() else {
            self.unknown_inner();
            return;
        };
        let mut reason = result
            .as_ref()
            .map_or_else(error_reason, |r| r.result.reason);
        if !result.as_ref().map_or(true, |r| {
            self.activity
                .view
                .heap()
                .and_then(|n| n.checked_add(r.heap()?))
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
            } else if matches!(
                r.result.control.reason,
                Reason::Unauthorized | Reason::TargetChanged | Reason::ResponseInvalid
            ) {
                reason = connection_reason(r.result.control.reason);
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
            self.activity.active = Some(a);
            self.unknown_inner();
            return;
        }
        if let Some(r) = self.private.as_ref().and_then(|s| s.retirement) {
            reason = connection_reason(r);
        } else if !current {
            reason = p::Reason::TargetChanged;
        } else if self
            .activity
            .view
            .operation
            .as_ref()
            .is_some_and(|o| o.phase == p::Phase::Stopping)
        {
            reason = p::Reason::Cancelled;
        }
        if reason == p::Reason::None {
            if let Ok(r) = result {
                if let Some(data) = r.result.data {
                    self.activity.view.result = Some(p::Observation {
                        target: r.result.target,
                        selection: r.result.selection,
                        observed_at: r.result.observed_at,
                        data,
                    });
                }
            }
        }
        if let Some(o) = &mut self.activity.view.operation {
            o.phase = p::Phase::Settled;
            o.reason = reason;
        }
        if !self.activity.view.fits() {
            self.activity.view.result = None;
            reason = p::Reason::ResponseLimit;
            if let Some(o) = &mut self.activity.view.operation {
                o.reason = reason;
            }
        }
        self.activity.view.reason = reason;
        if let Some(retire) = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized),
            p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid),
            p::Reason::Expired => Some(Reason::Expired),
            _ => None,
        } {
            self.retire_inner(retire, false);
        }
        // Normal read completion MUST NOT retire the credential session.
        if self
            .private
            .as_ref()
            .is_some_and(|s| s.retirement.is_some())
        {
            self.complete_retirement();
        }
    }
}
