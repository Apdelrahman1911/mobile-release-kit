//! A dedicated reservation hold on the ORIGINAL selected-account connection.
//! Enrollment pins are reused comparison checks, not its consent or receipt.
pub(crate) use super::enrollment::Pins;
use super::*;
use crate::{
    supervisor::{VersionReserveControl, VersionReserveJoined},
    version_allocation_state_native::dialogue,
};
use std::sync::Arc;
use zeroize::Zeroizing;
pub(super) struct Hold {
    pins: Pins,
    control: Arc<VersionReserveControl>,
}
impl Hold {
    pub(super) fn stop(&self, unknown: bool) {
        if unknown {
            self.control.unknown()
        } else {
            self.control.stop()
        }
    }
}
impl ConnectionState {
    pub(crate) fn begin_version_reserve(
        &mut self,
        project: &str,
        generation: u32,
        binding: &str,
        control: Arc<VersionReserveControl>,
        now: Instant,
    ) -> Result<Pins, BridgeError> {
        self.room().map_err(|_| BridgeError::cleanup_unknown())?;
        if self.native_work_pending()
            || self.reserve.is_some()
            || !control.current()
            || !control.never_admitted()
        {
            return Err(refused(Reason::Busy));
        }
        let pins = self.enrollment_pins(project, generation, binding, now)?;
        if pins.credential_end <= control.work_end() {
            return Err(refused(Reason::Expired));
        }
        self.reserve = Some(Hold {
            pins: pins.clone(),
            control,
        });
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
        Ok(pins)
    }
    pub(crate) fn version_reserve_current(
        &self,
        pins: &Pins,
        control: &Arc<VersionReserveControl>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        if !control.current()
            || !self
                .reserve
                .as_ref()
                .is_some_and(|h| h.pins == *pins && Arc::ptr_eq(&h.control, control))
            || self.enrollment.is_some()
            || self.preflight.native_work_pending()
            || self.release.native_work_pending()
            || self.setup.native_work_pending()
            || self.history.native_work_pending()
            || self.publication.native_work_pending()
            || self.repository_create.native_work_pending()
            || self.activity.native_work_pending()
            || self.pull_request.native_work_pending()
            || self.enrollment_pins(
                &pins.project_id,
                pins.generation,
                &pins.target.project_binding,
                now,
            )? != *pins
        {
            return Err(refused(Reason::TargetChanged));
        }
        Ok(())
    }
    pub(crate) fn version_reserve_go(
        &self,
        pins: &Pins,
        control: &Arc<VersionReserveControl>,
        request: &dialogue::Request,
        now: Instant,
        claim: impl FnOnce() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        self.version_reserve_current(pins, control, now)?;
        if !request.matches_repository(&pins.target.repository, &pins.target.repository_id) {
            return Err(refused(Reason::TargetChanged));
        }
        let token = self
            .private
            .as_ref()
            .and_then(|s| s.token.as_deref())
            .ok_or_else(|| refused(Reason::NotConnected))?;
        let go = request.go(token)?;
        if !claim() {
            return Err(refused(Reason::Cancelled));
        }
        Ok(go)
    }
    pub(crate) fn observe_version_reserve_control(
        &mut self,
        pins: &Pins,
        control: &Arc<VersionReserveControl>,
        joined: &VersionReserveJoined,
    ) -> Result<(), BridgeError> {
        if !self
            .reserve
            .as_ref()
            .is_some_and(|h| h.pins == *pins && Arc::ptr_eq(&h.control, control))
            || !joined.same_control(control)
        {
            return Err(BridgeError::cleanup_unknown());
        }
        // Failure before worker FIN has no HTTP control to adopt. The original
        // joined outcome remains separately visible and is never forged to OK.
        if let Ok(finished) = joined.finished() {
            if !self.apply_control(&finished.control, joined.settled_at()?) {
                self.retire_inner(Reason::ResponseInvalid, false);
                return Err(refused(Reason::ResponseInvalid));
            }
            if retires(finished.control.reason) {
                self.retire_inner(finished.control.reason, false);
            }
        }
        Ok(())
    }
    pub(crate) fn reserved_version_edit_current(
        &self,
        pins: &Pins,
        now: Instant,
    ) -> Result<(), BridgeError> {
        if self.reserve.is_some()
            || self.native_work_pending()
            || self.enrollment_pins(
                &pins.project_id,
                pins.generation,
                &pins.target.project_binding,
                now,
            )? != *pins
        {
            return Err(refused(Reason::TargetChanged));
        }
        Ok(())
    }
    pub(crate) fn finish_version_reserve(
        &mut self,
        control: &Arc<VersionReserveControl>,
    ) -> Result<(), BridgeError> {
        if control.pending()
            || !self
                .reserve
                .as_ref()
                .is_some_and(|h| Arc::ptr_eq(&h.control, control))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.reserve = None;
        if self
            .private
            .as_ref()
            .is_some_and(|p| p.retirement.is_some())
        {
            self.complete_retirement();
        }
        Ok(())
    }
}
