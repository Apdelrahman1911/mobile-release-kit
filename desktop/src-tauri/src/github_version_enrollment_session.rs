//! A finite hold inside the ORIGINAL authenticated connection. No token getter,
//! new account selection, Setup consent, authority registration or process owner.
use super::*;
use crate::{
    supervisor::{VersionEnrollmentControl, VersionEnrollmentJoined},
    version_enrollment_protocol as p,
};
use std::sync::Arc;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Pins {
    pub(crate) session_id: String,
    pub(crate) project_id: String,
    pub(crate) generation: u32,
    pub(crate) target: p::Target,
    pub(crate) credential_end: Instant,
}
pub(super) struct Hold {
    pins: Pins,
    control: Arc<VersionEnrollmentControl>,
}
impl Hold {
    pub(super) fn stop(&self, unknown: bool) {
        if unknown {
            self.control.unknown();
        } else {
            self.control.stop();
        }
    }
}
pub(crate) fn connection_reason(reason: Reason) -> p::Reason {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or(p::Reason::InvalidInput)
}
impl ConnectionState {
    pub(super) fn enrollment_pins(
        &self,
        project_id: &str,
        generation: u32,
        binding: &str,
        now: Instant,
    ) -> Result<Pins, BridgeError> {
        if self.unknown || self.exhausted {
            return Err(p::refused(p::Reason::CleanupUnknown));
        }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) {
            return Err(p::refused(p::Reason::RateLimited));
        }
        let private = self
            .private
            .as_ref()
            .filter(|v| {
                v.project_id == project_id
                    && v.generation == generation
                    && v.retirement.is_none()
                    && v.token.is_some()
                    && v.ticket.is_none()
                    && v.gh_hold.is_none()
                    && now < v.clock.end
            })
            .ok_or_else(|| p::refused(p::Reason::NotConnected))?;
        let account = self
            .status
            .account
            .value
            .as_ref()
            .filter(|v| {
                self.status.account.state == FactState::Observed
                    && private.account_pin.as_ref() == Some(&v.id)
            })
            .ok_or_else(|| p::refused(p::Reason::TargetChanged))?;
        let repository = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|v| {
                self.status.repository.state == FactState::Observed
                    && private.repository_pin.as_ref() == Some(&v.id)
                    && v.full_name.eq_ignore_ascii_case(&private.repository)
                    && !v.archived
            })
            .ok_or_else(|| p::refused(p::Reason::TargetChanged))?;
        if !self
            .status
            .session
            .as_ref()
            .is_some_and(|v| v.state == SessionState::Connected)
        {
            return Err(p::refused(p::Reason::NotConnected));
        }
        let target = p::Target {
            project_binding: binding.into(),
            repository: repository.full_name.clone(),
            account_id: account.id.clone(),
            repository_id: repository.id.clone(),
        };
        if !target.valid() {
            return Err(p::refused(p::Reason::InvalidInput));
        }
        Ok(Pins {
            session_id: private.id.clone(),
            project_id: project_id.into(),
            generation,
            target,
            credential_end: private.clock.end,
        })
    }
    pub(crate) fn begin_version_enrollment(
        &mut self,
        project_id: &str,
        generation: u32,
        binding: &str,
        control: Arc<VersionEnrollmentControl>,
        reviewed: Option<&Pins>,
        now: Instant,
    ) -> Result<Pins, BridgeError> {
        self.room()
            .map_err(|_| p::refused(p::Reason::CleanupUnknown))?;
        if self.native_work_pending()
            || self.enrollment.is_some()
            || !control.current()
            || !control.never_admitted()
        {
            return Err(p::refused(p::Reason::Busy));
        }
        let pins = self.enrollment_pins(project_id, generation, binding, now)?;
        if reviewed.is_some_and(|old| old != &pins) {
            return Err(p::refused(p::Reason::ReviewChanged));
        }
        self.enrollment = Some(Hold {
            pins: pins.clone(),
            control,
        });
        // Other staged remote approvals cannot survive this new original intent.
        let before = self.preflight.snapshot();
        self.preflight.revoke_consent();
        self.preflight.finish(before);
        let before = self.release.snapshot();
        self.release.revoke_consent();
        self.release.finish(before);
        let before = self.setup.snapshot();
        self.setup.revoke_consent();
        self.setup.finish(before);
        self.publication.revoke_consent();self.repository_create.context_changed();
        self.pull_request.context_changed();self.play_cleanup.context_changed();
        Ok(pins)
    }
    pub(crate) fn version_enrollment_current(
        &self,
        pins: &Pins,
        control: &Arc<VersionEnrollmentControl>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        if !control.current()
            || self.version_reserve_pending()
            || !self
                .enrollment
                .as_ref()
                .is_some_and(|h| h.pins == *pins && Arc::ptr_eq(&h.control, control))
            || self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || (self.publication.native_work_pending() || (self.pull_request.native_work_pending() || self.play_cleanup.native_work_pending()) || self.activity.native_work_pending() || self.repository_create.native_work_pending())
        {
            return Err(p::refused(p::Reason::TargetChanged));
        }
        if self.enrollment_pins(
            &pins.project_id,
            pins.generation,
            &pins.target.project_binding,
            now,
        )? != *pins
        {
            return Err(p::refused(p::Reason::TargetChanged));
        }
        Ok(())
    }
    pub(crate) fn version_enrollment_go(
        &self,
        pins: &Pins,
        control: &Arc<VersionEnrollmentControl>,
        id: &str,
        digest: &str,
        request: &p::Request,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        self.version_enrollment_current(pins, control, now)?;
        if request.target != pins.target {
            return Err(p::refused(p::Reason::TargetChanged));
        }
        let token = self
            .private
            .as_ref()
            .and_then(|v| v.token.as_deref())
            .ok_or_else(|| p::refused(p::Reason::NotConnected))?;
        let bytes = p::encode_go(id, digest, token)?;
        if !claim() {
            return Err(p::refused(p::Reason::Cancelled));
        }
        Ok(bytes)
    }
    pub(crate) fn observe_version_enrollment_control(
        &mut self,
        pins: &Pins,
        control: &Arc<VersionEnrollmentControl>,
        joined: &VersionEnrollmentJoined,
    ) -> Result<(), BridgeError> {
        if !self
            .enrollment
            .as_ref()
            .is_some_and(|h| h.pins == *pins && Arc::ptr_eq(&h.control, control))
            || !joined.matches(control, joined.request())
        {
            return Err(p::refused(p::Reason::CleanupUnknown));
        }
        if let Ok(reply) = joined.outcome() {
            if !self.apply_control(&reply.result.control, joined.settled_at()) {
                self.retire_inner(Reason::ResponseInvalid, false);
                return Err(p::refused(p::Reason::ResponseInvalid));
            }
            let reason = reply.result.control.reason;
            if retires(reason) {
                self.retire_inner(reason, false);
            }
        }
        Ok(())
    }
    pub(crate) fn finish_version_enrollment(
        &mut self,
        control: &Arc<VersionEnrollmentControl>,
    ) -> Result<(), BridgeError> {
        if control.pending()
            || !self
                .enrollment
                .as_ref()
                .is_some_and(|h| Arc::ptr_eq(&h.control, control))
        {
            return Err(p::refused(p::Reason::CleanupUnknown));
        }
        self.enrollment = None;
        if self
            .private
            .as_ref()
            .is_some_and(|v| v.retirement.is_some())
        {
            self.complete_retirement();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_selected_connection_hold_refuses_aba_and_retirement_keeps_original_until_returned() {
        // Existing fixture supplies only in-memory connection DATA, not native
        // authentication, a worker or storage/EOF/finality evidence.
        let now = Instant::now();
        let mut state = super::super::tests::fixture(now);
        state.private.as_mut().unwrap().account_pin = Some("11".into());
        state.private.as_mut().unwrap().repository_pin = Some("22".into());
        state.status.session.as_mut().unwrap().state = SessionState::Connected;
        state.status.operation.as_mut().unwrap().phase = Phase::Settled;
        state.status.account = Fact {
            state: FactState::Observed,
            value: Some(Account {
                id: "11".into(),
                login: "owner".into(),
            }),
            observed_at: None,
            reason: Reason::None,
        };
        state.status.repository = Fact {
            state: FactState::Observed,
            value: Some(Repository {
                id: "22".into(),
                full_name: "owner/app".into(),
                default_branch: "main".into(),
                visibility: wire::Visibility::Private,
                archived: false,
                permissions: wire::Permissions {
                    pull: wire::Permission::Unknown,
                    push: wire::Permission::Unknown,
                    admin: wire::Permission::Unknown,
                },
            }),
            observed_at: None,
            reason: Reason::None,
        };
        let (id, generation) = state
            .registration()
            .map(|(id, g)| (id.to_owned(), g))
            .unwrap();
        let control = Arc::new(VersionEnrollmentControl::new());
        let pins = state
            .begin_version_enrollment(&id, generation, &"a".repeat(64), control.clone(), None, now)
            .unwrap();
        assert!(state.native_work_pending());
        state
            .version_enrollment_current(&pins, &control, now)
            .unwrap();
        let mut other = pins.clone();
        other.session_id.push('x');
        assert!(state
            .version_enrollment_current(&other, &control, now)
            .is_err());
        state.retire(Reason::Cancelled);
        assert!(state.private.as_ref().unwrap().token.is_some());
        assert!(control.pending());
        assert!(state
            .version_enrollment_current(&pins, &control, now)
            .is_err());
        control.returned(now + std::time::Duration::from_secs(60)).unwrap();
        state.finish_version_enrollment(&control).unwrap();
        assert!(state.private.as_ref().unwrap().token.is_none());
    }
}
