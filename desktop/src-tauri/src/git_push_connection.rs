//! Push borrows the ORIGINAL selected ConnectionState. No token getter,
//! second authentication owner, caller URL, serialized credential or new clock.
//! A hold can stop only its actual GitLocal owner and survives until that exact
//! owner's joined receipt; equality of these pins alone authorizes nothing.
use super::*;
use crate::{
    asset_session::GitLocalGate,
    git_local_protocol::{self as local, push_worker::Target},
    git_push_protocol as push,
    github_connection_protocol::Permission,
    supervisor::{GitLocalPushHold, GitLocalReceipt},
};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Pins {
    session: String,
    project: String,
    generation: u32,
    credential_end: Instant,
    target: Target,
    action: push::Action,
}
impl Pins {
    pub(crate) fn target(&self, review: Option<&push::Review>) -> Result<Target, BridgeError> {
        if review.is_some_and(|r| !r.matches(&self.action) || !self.target.matches_review(r)) {
            return Err(refused(Reason::TargetChanged));
        }
        Ok(self.target.clone())
    }

    pub(crate) fn heap(&self) -> Option<usize> {
        let mut bytes = 0usize;
        for text in [
            &self.session,
            &self.project,
            &self.target.repository,
            &self.target.login,
            &self.target.account_id,
            &self.target.repository_id,
            &self.action.expected_revision,
            &self.action.expected_reference_revision,
            &self.action.remote,
            &self.action.local_ref,
            &self.action.remote_ref,
            &self.action.old_oid,
            &self.action.new_oid,
            &self.action.connection_session_id,
        ] {
            bytes = bytes.checked_add(text.capacity())?;
        }
        Some(bytes)
    }
}
pub(super) struct Hold {
    pins: Pins,
    original: Arc<GitLocalPushHold>,
}
impl Hold {
    pub(super) fn stop(&self, unknown: bool) {
        self.original.stop(unknown);
    }
}
impl ConnectionState {
    fn push_pin_current(
        &self,
        pins: &Pins,
        now: Instant,
        work_end: Instant,
    ) -> Result<(), BridgeError> {
        if self.unknown || self.exhausted {
            return Err(refused(Reason::CleanupUnknown));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(refused(Reason::RateLimited));
        }
        let p = self
            .private
            .as_ref()
            .filter(|p| {
                p.id == pins.session
                    && p.project_id == pins.project
                    && p.generation == pins.generation
                    && p.repository.eq_ignore_ascii_case(&pins.target.repository)
                    && p.retirement.is_none()
                    && p.ticket.is_none()
                    && p.gh_hold.is_none()
                    && p.token.is_some()
                    && now < p.clock.end
                    && work_end < p.clock.end
                    && p.clock.end <= pins.credential_end
            })
            .ok_or_else(|| refused(Reason::TargetChanged))?;
        if p.account_pin.as_deref() != Some(pins.target.account_id.as_str())
            || p.repository_pin.as_deref() != Some(pins.target.repository_id.as_str())
            || self.status.account.state != FactState::Observed
            || self.status.repository.state != FactState::Observed
            || !self
                .status
                .account
                .value
                .as_ref()
                .is_some_and(|a| a.id == pins.target.account_id && a.login == pins.target.login)
            || !self.status.repository.value.as_ref().is_some_and(|r| {
                r.id == pins.target.repository_id
                    && r.full_name == pins.target.repository
                    && !r.archived
                    && r.permissions.pull == Permission::ReportedAllowed
                    && r.permissions.push == Permission::ReportedAllowed
            })
            || !self.status.session.as_ref().is_some_and(|s| {
                s.id == pins.session
                    && s.project_id == pins.project
                    && s.state == SessionState::Connected
            })
        {
            return Err(refused(Reason::TargetChanged));
        }
        Ok(())
    }
    /// Called under the real Doc BEFORE original admission. The exact public
    /// revision is a comparison at admission, not an epoch reset on later status.
    pub(crate) fn select_git_push(
        &self,
        project: &str,
        generation: u32,
        action: &push::Action,
        now: Instant,
        work_end: Instant,
    ) -> Result<Pins, BridgeError> {
        if !action.valid() || self.status.revision != action.expected_connection_revision {
            return Err(refused(Reason::TargetChanged));
        }
        if self.status.revision >= u32::MAX - 4
            || self.preflight.exhausted
            || self.release.exhausted
            || self.setup.exhausted
            || self.history.exhausted
            || self.publication.exhausted
            || self.repository_create.exhausted
            || self.activity.exhausted
            || self.pull_request.exhausted
            || self.actions_retry.exhausted
        {
            return Err(refused(Reason::CleanupUnknown));
        }
        if self.native_work_pending() {
            return Err(refused(Reason::Busy));
        }
        let p = self
            .private
            .as_ref()
            .filter(|p| {
                p.id == action.connection_session_id
                    && p.project_id == project
                    && p.generation == generation
            })
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let account = self
            .status
            .account
            .value
            .as_ref()
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let repository = self
            .status
            .repository
            .value
            .as_ref()
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let pins = Pins {
            session: p.id.clone(),
            project: project.into(),
            generation,
            credential_end: p.clock.end,
            target: Target {
                repository: repository.full_name.clone(),
                login: account.login.clone(),
                account_id: account.id.clone(),
                repository_id: repository.id.clone(),
            },
            action: action.clone(),
        };
        if !pins.target.valid() {
            return Err(refused(Reason::InvalidInput));
        }
        self.push_pin_current(&pins, now, work_end)?;
        Ok(pins)
    }
    pub(crate) fn git_push_review_current(
        &self,
        pins: &Pins,
        action: &push::Action,
        review: &push::Review,
        now: Instant,
        work_end: Instant,
    ) -> Result<(), BridgeError> {
        if self.native_work_pending()
            || !review.matches(action)
            || action != &pins.action
            || action.connection_session_id != pins.session
            || !pins.target.matches_review(review)
        {
            return Err(refused(Reason::TargetChanged));
        }
        self.push_pin_current(pins, now, work_end)
    }
    pub(crate) fn git_push_prepared_current(
        &self,
        pins: &Pins,
        review: &push::Review,
        now: Instant,
    ) -> bool {
        // Historical currentness keeps DATA only; it cannot grant another45s.
        !self.native_work_pending()
            && review.matches(&pins.action)
            && pins.target.matches_review(review)
            && self.push_pin_current(pins, now, now).is_ok()
    }
    /// The caller has already retained the admitted ticket under the SAME Doc.
    /// Failure must retain that ticket/Unknown, not report a new-work rejection.
    pub(crate) fn retain_git_push(
        &mut self,
        pins: Pins,
        original: Arc<GitLocalPushHold>,
        gate: &GitLocalGate,
        id: &str,
    ) -> Result<(), BridgeError> {
        if self.push.is_some() || self.fetch.is_some() || !original.matches(gate, id) {
            return Err(BridgeError::cleanup_unknown());
        }
        self.push = Some(Hold { pins, original });
        let before = self.preflight.snapshot();
        self.preflight.revoke_consent();
        self.preflight.finish(before);
        let before = self.release.snapshot();
        self.release.revoke_consent();
        self.release.finish(before);
        let before = self.setup.snapshot();
        self.setup.revoke_consent();
        self.setup.finish(before);
        self.publication.revoke_consent();
        self.repository_create.context_changed();
        self.pull_request.context_changed();
        self.actions_retry.context_changed();
        Ok(())
    }
    pub(crate) fn git_push_current(
        &self,
        pins: &Pins,
        gate: &GitLocalGate,
        id: &str,
        now: Instant,
    ) -> Result<(), BridgeError> {
        let hold = self
            .push
            .as_ref()
            .filter(|h| h.pins == *pins && h.original.matches(gate, id))
            .ok_or_else(|| refused(Reason::TargetChanged))?;
        if self
            .private
            .as_ref()
            .is_some_and(|s| s.ticket.is_some() || s.gh_hold.is_some())
            || self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || self.publication.native_work_pending()
            || self.repository_create.native_work_pending()
            || self.activity.native_work_pending()
            || self.pull_request.native_work_pending()
            || self.actions_retry.native_work_pending()
            || self.enrollment.is_some()
            || self.version_reserve_pending()
            || self.fetch.is_some()
        {
            return Err(refused(Reason::TargetChanged));
        }
        self.push_pin_current(pins, now, hold.original.work_end())
    }
    pub(crate) fn git_push_go(
        &self,
        pins: &Pins,
        gate: &GitLocalGate,
        id: &str,
        request: &local::Request,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        self.git_push_current(pins, gate, id, now)?;
        let target = pins.target(
            request
                .binding
                .as_ref()
                .and_then(|b| b.review.push_details()),
        )?;
        if request.id != id
            || request.push_target.as_ref() != Some(&target)
            || !matches!(&request.action,local::Action::Push(a) if a==&pins.action)
        {
            return Err(refused(Reason::TargetChanged));
        }
        let token = self
            .private
            .as_ref()
            .and_then(|p| p.token.as_deref())
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let go = request.push_go(token)?;
        if !claim() {
            return Err(refused(Reason::Cancelled));
        }
        Ok(go)
    }
    /// Uses only the actual same-ticket mailbox, not a public status or helper
    /// frame. Unknown retains this hold/token and cannot admit another Push.
    pub(crate) fn finish_git_push(
        &mut self,
        gate: &GitLocalGate,
        id: &str,
    ) -> Result<(), BridgeError> {
        let hold = self
            .push
            .as_ref()
            .filter(|h| h.original.matches(gate, id))
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let receipt = hold.original.receipt();
        match receipt {
            GitLocalReceipt::Settled {
                was_unknown: false, ..
            } => {}
            _ => return Err(BridgeError::cleanup_unknown()),
        }
        let (settled_at, control) = hold
            .original
            .joined_control()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        // The session cannot be replaced while this original hold is pending.
        // Retirement/STOP is allowed here, but must still refer to these exact
        // original pins; a historical public Connected status cannot supply it.
        if !control.valid()
            || !self.private.as_ref().is_some_and(|p| {
                p.id == hold.pins.session
                    && p.project_id == hold.pins.project
                    && p.generation == hold.pins.generation
                    && p.account_pin.as_deref() == Some(hold.pins.target.account_id.as_str())
                    && p.repository_pin.as_deref() == Some(hold.pins.target.repository_id.as_str())
            })
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let before = self.status.clone();
        let mut reason = control.reason;
        if !self.apply_control(&control, settled_at) {
            reason = Reason::ResponseInvalid;
        }
        self.push = None;
        if self.unknown {
            self.unknown_inner();
        } else if self
            .private
            .as_ref()
            .is_some_and(|p| p.retirement.is_some())
        {
            self.complete_retirement();
        } else if self
            .private
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.clock.end)
        {
            self.retire_inner(Reason::Expired, false);
        } else {
            // Keep the original connection rule: an HTTP deadline by itself
            // does not prove expiration of the selected credential.
            if reason == Reason::Expired {
                reason = Reason::NetworkUnavailable;
            }
            if retires(reason) {
                self.retire_inner(reason, false);
            } else if reason != Reason::None {
                self.fact_retirement(reason);
            }
        }
        self.finish(before);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_push_protocol::tests as data;
    use crate::github_connection_protocol::{Permission, Permissions, Visibility};

    // Real ConnectionState comparison methods, only DATA. No original GitLocal
    // ticket, source, credential, join or native command is created here.
    fn connected(at: Instant) -> ConnectionState {
        let mut s = super::super::tests::fixture(at);
        let p = s.private.as_mut().unwrap();
        p.id = "connection-1".into();
        p.repository = "owner/repository".into();
        p.account_pin = Some("12".into());
        p.repository_pin = Some("34".into());
        s.status.revision = 3;
        let session = s.status.session.as_mut().unwrap();
        session.id = "connection-1".into();
        session.target_repository = "owner/repository".into();
        session.state = SessionState::Connected;
        s.status.account = Fact {
            state: FactState::Observed,
            value: Some(Account {
                id: "12".into(),
                login: "owner".into(),
            }),
            observed_at: Some("2026-09-17T12:00:01Z".into()),
            reason: Reason::None,
        };
        s.status.repository = Fact {
            state: FactState::Observed,
            value: Some(Repository {
                id: "34".into(),
                full_name: "owner/repository".into(),
                default_branch: "main".into(),
                visibility: Visibility::Private,
                archived: false,
                permissions: Permissions {
                    pull: Permission::ReportedAllowed,
                    push: Permission::ReportedAllowed,
                    admin: Permission::Unknown,
                },
            }),
            observed_at: Some("2026-09-17T12:00:01Z".into()),
            reason: Reason::None,
        };
        s
    }

    #[test]
    fn local_git_read_session_rechecks_actual_idle_registration_facts_and_expiry() {
        let at = Instant::now();
        let mut s = connected(at);
        // Only an actually settled Connection status can coexist with a NEW
        // local read. This fixture supplies DATA, no ticket or native join.
        assert!(s.local_git_read_session("project-1", 2, at).is_none());
        s.status.operation.as_mut().unwrap().phase = Phase::Settled;
        let original = s.local_git_read_session("project-1", 2, at).unwrap();
        assert!(s.local_git_read_session("other-project", 2, at).is_none());
        assert!(s.local_git_read_session("project-1", 3, at).is_none());
        s.status.revision += 1; // Ordinary status churn is not a new session.
        assert!(s.local_git_read_session("project-1", 2, at) == Some(original));
        assert!(s
            .local_git_read_session("project-1", 2, s.private.as_ref().unwrap().clock.end)
            .is_none());
        let changes: [fn(&mut ConnectionState); 9] = [
            |s: &mut ConnectionState| s.status.account.value.as_mut().unwrap().id = "99".into(),
            |s: &mut ConnectionState| s.status.repository.value.as_mut().unwrap().id = "99".into(),
            |s: &mut ConnectionState| {
                s.status.repository.value.as_mut().unwrap().full_name = "other/repository".into()
            },
            |s: &mut ConnectionState| s.status.account.state = FactState::Stale,
            |s: &mut ConnectionState| {
                s.status.session.as_mut().unwrap().state = SessionState::Disconnecting
            },
            |s: &mut ConnectionState| {
                s.private.as_mut().unwrap().retirement = Some(Reason::Cancelled)
            },
            |s: &mut ConnectionState| s.private.as_mut().unwrap().token = None,
            |s: &mut ConnectionState| s.unknown(),
            |s: &mut ConnectionState| s.exhaust(),
        ];
        for change in changes {
            let mut changed = connected(at);
            changed.status.operation.as_mut().unwrap().phase = Phase::Settled;
            change(&mut changed);
            assert!(changed.local_git_read_session("project-1", 2, at).is_none());
        }
    }

    #[test]
    fn local_git_read_session_distinguishes_original_disconnect_and_connection_aba() {
        let at = Instant::now();
        let empty = ConnectionState::new()
            .local_git_read_session("project-1", 2, at)
            .unwrap();
        let mut s = connected(at);
        s.status.operation.as_mut().unwrap().phase = Phase::Settled;
        let connected = s.local_git_read_session("project-1", 2, at).unwrap();
        assert!(connected != empty);
        // Existing retirement method drains this DATA-only idle session. No
        // live ticket/owner/credential is supplied or invented by this test.
        s.retire_inner(Reason::Cancelled, true);
        let disconnected = s.local_git_read_session("project-1", 2, at).unwrap();
        assert!(disconnected != connected);
        s.next_session += 1; // The actual successful connect admission advances this epoch.
        assert!(s.local_git_read_session("project-1", 2, at) != Some(disconnected));
        s.unknown();
        assert!(s.local_git_read_session("project-1", 2, at).is_none());
    }

    #[test]
    fn push_requires_reported_write_permission_and_same_account_session_and_revision() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let mut s = connected(at);
        let a = data::action();
        let pins = s.select_git_push("project-1", 2, &a, at, end).unwrap();
        assert!(pins.target(Some(&data::review())).is_ok());
        assert!(s.push.is_none() && !s.native_work_pending());
        for permission in [Permission::Unknown, Permission::ReportedDenied] {
            s.status.repository.value.as_mut().unwrap().permissions.push = permission;
            assert!(s.select_git_push("project-1", 2, &a, at, end).is_err());
        }
        s.status.repository.value.as_mut().unwrap().permissions.push = Permission::ReportedAllowed;
        for (project, generation) in [("foreign", 2), ("project-1", 3)] {
            assert!(s.select_git_push(project, generation, &a, at, end).is_err());
        }
        let mut changed = a.clone();
        changed.expected_connection_revision += 1;
        assert!(s
            .select_git_push("project-1", 2, &changed, at, end)
            .is_err());
        s.private.as_mut().unwrap().account_pin = Some("99".into());
        assert!(s.select_git_push("project-1", 2, &a, at, end).is_err());
    }

    #[test]
    fn prepared_push_binds_all_selected_refs_oids_and_account_not_just_target_name() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let s = connected(at);
        let a = data::action();
        let pins = s.select_git_push("project-1", 2, &a, at, end).unwrap();
        let r = data::review();
        assert!(s.git_push_review_current(&pins, &a, &r, at, end).is_ok());
        assert!(s.git_push_prepared_current(&pins, &r, at));
        let mut wrong = a.clone();
        wrong.remote_ref = "refs/heads/other".into();
        let mut changed = r.clone();
        changed.upstream_ref = wrong.remote_ref.clone();
        assert!(changed.matches(&wrong));
        assert!(s
            .git_push_review_current(&pins, &wrong, &changed, at, end)
            .is_err());
        assert!(!s.git_push_prepared_current(&pins, &changed, at));
        assert!(pins.target(Some(&changed)).is_err());
        let mut changed = r;
        changed.account_id = "99".into();
        assert!(pins.target(Some(&changed)).is_err());
    }

    #[test]
    fn known_control_cooldown_and_original_expiry_never_renew_push_permission() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let mut s = connected(at);
        let pins = s
            .select_git_push("project-1", 2, &data::action(), at, end)
            .unwrap();
        let original = s.private.as_ref().unwrap().clock.end;
        s.status.revision += 1;
        assert!(s.push_pin_current(&pins, at, end).is_ok());
        assert_eq!(s.private.as_ref().unwrap().clock.end, original);
        s.cooldown = Some(end);
        assert!(s.push_pin_current(&pins, at, end).is_err());
        s.cooldown = None;
        s.cooldown_blocked = true;
        assert!(s.push_pin_current(&pins, at, end).is_err());
        s.cooldown_blocked = false;
        s.unknown = true;
        assert!(s.push_pin_current(&pins, at, end).is_err());
        s.unknown = false;
        s.private.as_mut().unwrap().clock.end = end;
        assert!(s.push_pin_current(&pins, at, end).is_err());
        assert!(s.push_pin_current(&pins, at, at).is_ok());
        s.private.as_mut().unwrap().clock.end = original + Duration::from_secs(1);
        assert!(s.push_pin_current(&pins, at, end).is_err());
    }
}
