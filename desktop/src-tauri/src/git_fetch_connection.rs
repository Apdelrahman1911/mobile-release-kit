//! Fetch borrows the ORIGINAL selected ConnectionState. No token getter,
//! second authentication owner, caller URL, serialized credential or new clock.
//! A hold can stop only its actual GitLocal owner and survives until that exact
//! owner's joined receipt; equality of these pins alone authorizes nothing.
use super::*;
use crate::{
    asset_session::GitLocalGate,
    git_fetch_protocol as fetch,
    git_local_protocol::{self as local, fetch_worker::Target},
    supervisor::{GitLocalFetchHold, GitLocalReceipt},
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
}
impl Pins {
    pub(crate) fn target(&self, review: Option<&fetch::Review>) -> Result<Target, BridgeError> {
        let mut target = self.target.clone();
        if let Some(review) = review {
            if !target.matches_review(review) {
                return Err(refused(Reason::TargetChanged));
            }
            target.oid = Some(review.candidate_ref_oid.clone());
        }
        Ok(target)
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
            &self.target.reference,
        ] {
            bytes = bytes.checked_add(text.capacity())?;
        }
        bytes.checked_add(self.target.oid.as_ref().map_or(0, String::capacity))
    }
}
pub(super) struct Hold {
    pins: Pins,
    original: Arc<GitLocalFetchHold>,
}
impl Hold {
    pub(super) fn stop(&self, unknown: bool) {
        self.original.stop(unknown);
    }
}
impl ConnectionState {
    fn fetch_pin_current(
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
    pub(crate) fn select_git_fetch(
        &self,
        project: &str,
        generation: u32,
        action: &fetch::Action,
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
                reference: action.reference.clone(),
                oid: None,
            },
        };
        if !pins.target.valid() {
            return Err(refused(Reason::InvalidInput));
        }
        self.fetch_pin_current(&pins, now, work_end)?;
        Ok(pins)
    }
    /// Delegation liveness only. No new operation budget or token is issued;
    /// native Prepare/Apply/GO still run their full original gates.
    pub(crate) fn git_fetch_delegation_current(&self,pins:&Pins,action:&fetch::Action,now:Instant)->bool {
        !self.native_work_pending() && action.valid() && action.connection_session_id==pins.session
            && action.reference==pins.target.reference && self.fetch_pin_current(pins,now,now).is_ok()
    }
    pub(crate) fn git_fetch_review_current(
        &self,
        pins: &Pins,
        action: &fetch::Action,
        review: &fetch::Review,
        now: Instant,
        work_end: Instant,
    ) -> Result<(), BridgeError> {
        if self.native_work_pending()
            || !review.matches(action)
            || review.up_to_date()
            || action.connection_session_id != pins.session
            || !pins.target.matches_review(review)
        {
            return Err(refused(Reason::TargetChanged));
        }
        self.fetch_pin_current(pins, now, work_end)
    }
    pub(crate) fn git_fetch_prepared_current(
        &self,
        pins: &Pins,
        review: &fetch::Review,
        now: Instant,
    ) -> bool {
        // Equal-tip reviews intentionally stay Close-only; no new HTTP/GO or
        // minimum next-operation budget is implied by keeping this DATA.
        !self.native_work_pending()
            && pins.target.matches_review(review)
            && self.fetch_pin_current(pins, now, now).is_ok()
    }
    /// The caller has already retained the admitted ticket under the SAME Doc.
    /// Failure must retain that ticket/Unknown, not report a new-work rejection.
    pub(crate) fn retain_git_fetch(
        &mut self,
        pins: Pins,
        original: Arc<GitLocalFetchHold>,
        gate: &GitLocalGate,
        id: &str,
    ) -> Result<(), BridgeError> {
        if self.fetch.is_some() || self.push.is_some() || !original.matches(gate, id) {
            return Err(BridgeError::cleanup_unknown());
        }
        self.fetch = Some(Hold { pins, original });
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
    pub(crate) fn git_fetch_current(
        &self,
        pins: &Pins,
        gate: &GitLocalGate,
        id: &str,
        now: Instant,
    ) -> Result<(), BridgeError> {
        let hold = self
            .fetch
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
            || self.push.is_some()
        {
            return Err(refused(Reason::TargetChanged));
        }
        self.fetch_pin_current(pins, now, hold.original.work_end())
    }
    pub(crate) fn git_fetch_go(
        &self,
        pins: &Pins,
        gate: &GitLocalGate,
        id: &str,
        request: &local::Request,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        self.git_fetch_current(pins, gate, id, now)?;
        let target = pins.target(
            request
                .binding
                .as_ref()
                .and_then(|b| b.review.fetch_details()),
        )?;
        if request.id != id || request.fetch_target.as_ref() != Some(&target) {
            return Err(refused(Reason::TargetChanged));
        }
        let token = self
            .private
            .as_ref()
            .and_then(|p| p.token.as_deref())
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let go = request.fetch_go(token)?;
        if !claim() {
            return Err(refused(Reason::Cancelled));
        }
        Ok(go)
    }
    /// Uses only the actual same-ticket mailbox, not a public status or helper
    /// frame. Unknown retains this hold/token and cannot admit another Fetch.
    pub(crate) fn finish_git_fetch(
        &mut self,
        gate: &GitLocalGate,
        id: &str,
    ) -> Result<(), BridgeError> {
        let hold = self
            .fetch
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
        self.fetch = None;
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
    use crate::git_fetch_protocol::tests as data;
    use crate::github_connection_protocol::{Permission, Permissions, Visibility};

    // Comparison DATA only: no ticket, source/profile, consent or HTTP native
    // owner is fabricated, and selecting these pins cannot produce GO.
    fn connected(at: Instant) -> ConnectionState {
        let mut s = super::super::tests::fixture(at);
        let p = s.private.as_mut().unwrap();
        p.account_pin = Some("11".into());
        p.repository_pin = Some("22".into());
        s.status.revision = 4;
        s.status.session.as_mut().unwrap().state = SessionState::Connected;
        s.status.account = Fact {
            state: FactState::Observed,
            value: Some(Account {
                id: "11".into(),
                login: "owner".into(),
            }),
            observed_at: Some("2026-09-17T12:00:01Z".into()),
            reason: Reason::None,
        };
        s.status.repository = Fact {
            state: FactState::Observed,
            value: Some(Repository {
                id: "22".into(),
                full_name: "owner/app".into(),
                default_branch: "main".into(),
                visibility: Visibility::Private,
                archived: false,
                permissions: Permissions {
                    pull: Permission::ReportedAllowed,
                    push: Permission::Unknown,
                    admin: Permission::Unknown,
                },
            }),
            observed_at: Some("2026-09-17T12:00:01Z".into()),
            reason: Reason::None,
        };
        s
    }
    #[test]
    fn selected_connection_requires_exact_account_repository_generation_and_revision() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let mut s = connected(at);
        let a = data::action();
        let p = s.select_git_fetch("project-1", 2, &a, at, end).unwrap();
        assert!(p.target(Some(&data::review())).unwrap().oid == Some("4".repeat(40)));
        assert!(s.fetch.is_none() && !s.native_work_pending());
        for (project, generation) in [("other", 2), ("project-1", 3)] {
            assert!(s
                .select_git_fetch(project, generation, &a, at, end)
                .is_err());
        }
        let mut bad = a.clone();
        bad.expected_connection_revision += 1;
        assert!(s.select_git_fetch("project-1", 2, &bad, at, end).is_err());
        s.private.as_mut().unwrap().account_pin = Some("99".into());
        assert!(s.select_git_fetch("project-1", 2, &a, at, end).is_err());
        s.private.as_mut().unwrap().account_pin = Some("11".into());
        s.status.repository.value.as_mut().unwrap().id = "99".into();
        assert!(s.select_git_fetch("project-1", 2, &a, at, end).is_err());
    }
    #[test]
    fn original_pin_postcheck_does_not_reset_credential_clock_or_accept_status_as_auth() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let mut s = connected(at);
        let p = s
            .select_git_fetch("project-1", 2, &data::action(), at, end)
            .unwrap();
        let original = s.private.as_ref().unwrap().clock.end;
        s.status.revision += 1;
        assert!(s.fetch_pin_current(&p, at, end).is_ok());
        assert_eq!(s.private.as_ref().unwrap().clock.end, original);
        s.status.account.state = FactState::Stale;
        assert!(s.fetch_pin_current(&p, at, end).is_err());
        s.status.account.state = FactState::Observed;
        s.private.as_mut().unwrap().repository_pin = Some("99".into());
        assert!(s.fetch_pin_current(&p, at, end).is_err());
    }
    #[test]
    fn cooldown_unknown_and_shortened_original_expiry_refuse_later_work() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let mut s = connected(at);
        let p = s
            .select_git_fetch("project-1", 2, &data::action(), at, end)
            .unwrap();
        s.cooldown = Some(end);
        assert!(s.fetch_pin_current(&p, at, end).is_err());
        s.cooldown = None;
        s.cooldown_blocked = true;
        assert!(s.fetch_pin_current(&p, at, end).is_err());
        s.cooldown_blocked = false;
        s.unknown = true;
        assert!(s.fetch_pin_current(&p, at, end).is_err());
        s.unknown = false;
        s.private.as_mut().unwrap().clock.end = end;
        assert!(s.fetch_pin_current(&p, at, end).is_err());
        assert!(s.fetch_pin_current(&p, at, at).is_ok()); // Retaining DATA does not grant another45s.
        s.private.as_mut().unwrap().clock.end = p.credential_end + Duration::from_secs(1);
        assert!(s.fetch_pin_current(&p, at, end).is_err()); // No extending the selected original.
    }
    #[test]
    fn equal_tip_review_remains_close_only_and_foreign_review_never_matches() {
        let at = Instant::now();
        let end = at + Duration::from_secs(45);
        let s = connected(at);
        let a = data::action();
        let p = s.select_git_fetch("project-1", 2, &a, at, end).unwrap();
        let mut r = data::review();
        r.expected_target = Some(r.candidate_ref_oid.clone());
        assert!(s.git_fetch_prepared_current(&p, &r, at));
        assert!(s.git_fetch_review_current(&p, &a, &r, at, end).is_err());
        r.account_id = "99".into();
        assert!(!s.git_fetch_prepared_current(&p, &r, at));
        assert!(p.target(Some(&r)).is_err());
    }
    #[test]
    fn remote_delegation_current_uses_original_pins_and_never_renews_expiry() {
        let at=Instant::now();let mut s=connected(at);let a=data::action();
        let p=s.select_git_fetch("project-1",2,&a,at,at+Duration::from_secs(45)).unwrap();
        assert!(s.git_fetch_delegation_current(&p,&a,at));
        let end=s.private.as_ref().unwrap().clock.end;
        s.status.revision+=1;assert!(s.git_fetch_delegation_current(&p,&a,at));
        assert_eq!(s.private.as_ref().unwrap().clock.end,end);
        s.status.account.state=FactState::Stale;assert!(!s.git_fetch_delegation_current(&p,&a,at));
        s.status.account.state=FactState::Observed;
        s.unknown=true;assert!(!s.git_remote_finish_known());assert!(!s.git_fetch_delegation_current(&p,&a,at));
        s.unknown=false;s.private.as_mut().unwrap().clock.end=at;
        assert!(!s.git_fetch_delegation_current(&p,&a,at));
        // finish-known alone is NOT credential liveness or actual return.
        assert!(s.git_remote_finish_known());
    }

}
