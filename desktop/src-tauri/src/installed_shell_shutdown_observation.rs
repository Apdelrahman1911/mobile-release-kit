//! Read-only test token for the initial, genuinely owned app-info query.
//! It observes the existing J scheduling seam; it cannot select a runtime,
//! create a query, cancel an operation or authorize native cleanup.
use super::*;

pub(crate) struct HeldAppInfo {
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    endpoint: Instant,
    attempted: bool,
}

fn need(condition: bool) -> Result<(), BridgeError> {
    if condition { Ok(()) } else { Err(BridgeError::cleanup_unknown()) }
}

impl Supervisor {
    pub(crate) fn arm_initial_app_info_shutdown(&self) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        let mut case = lock(&self.inner.native_test.case);
        need(owners.is_empty() && self.inner.next.load(Ordering::SeqCst) == 1
            && !self.stopping() && !self.disabled() && self.passive_method_available("capabilities")
            && *case == installed_native_fixture::Case::None)?;
        *case = installed_native_fixture::Case::Shutdown;
        Ok(())
    }

    pub(crate) fn retain_held_app_info(&self) -> Result<Option<HeldAppInfo>, BridgeError> {
        if !self.inner.native_test.held.load(Ordering::SeqCst) { return Ok(None); }
        let key = lock(&self.inner.native_test.shell_owner).ok_or_else(BridgeError::cleanup_unknown)?;
        let owners = lock(&self.inner.owners);
        need(owners.len() == 1 && !self.stopping() && !self.disabled())?;
        let owner = owners.get(&key).ok_or_else(BridgeError::cleanup_unknown)?;
        let state = lock(&owner.state);
        need(matches!(owner.profile, Profile::Passive(Method::Capabilities))
            && !state.terminal && !state.unknown && state.error.is_none() && Instant::now() < state.endpoint)?;
        need(!self.inner.native_test.shell_token_issued.swap(true, Ordering::SeqCst))?;
        // The driver holds resources while the original child reader is held.
        // Retain the actual registry Arc only; do not acquire that resource lock.
        Ok(Some(HeldAppInfo { inner: self.inner.clone(), owner: owner.clone(), endpoint: state.endpoint, attempted: false }))
    }
}

impl HeldAppInfo {
    pub(crate) async fn observe_retired(&mut self, original_observation_end: Instant) -> Result<(), BridgeError> {
        need(!self.attempted)?;
        self.attempted = true;
        // Neither this observation nor a delayed GUI response renews the owner.
        let end = original_observation_end.min(self.endpoint.checked_add(CLEANUP_TIME).ok_or_else(BridgeError::cleanup_unknown)?);
        if Instant::now() >= end { return Err(BridgeError::timeout()); }
        let mut original = self.owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let handle = original.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        let returned = tokio::select! {
            result = handle => result,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(BridgeError::timeout()),
        };
        // Pending or consumed-failed originals stay in their existing slot and
        // this token cannot consume them again. Only a genuine Ok is removed.
        returned.map_err(|_| BridgeError::cleanup_unknown())?;
        original.take();
        drop(original);

        let resources = self.owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        need(resources.inspection_return == Some(ManagementJoin::Returned)
            && resources.acquisition_return == Some(ManagementJoin::Returned)
            && resources.inspection.is_none() && resources.inspection_error.is_none()
            && resources.acquisition.is_none() && resources.acquisition_error.is_none()
            && resources.child.is_none() && resources.waited.is_some() && resources.kill_attempted
            && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
            && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
            && resources.write_end.is_some() && resources.out_end.is_none() && resources.err_end.is_none()
            && resources.native_started && resources.native_settlement.is_none()
            && matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && resources.native_observation.is_none() && resources.native_observation_return == Some(ManagementJoin::Returned)
            && resources.native_snapshots.len() == 1 && resources.native_snapshots[0].environment_clear())?;
        {
            let slots = lock(resources.passive.as_ref().ok_or_else(BridgeError::cleanup_unknown)?);
            need(slots.settled() && slots.claimed_observation().is_some() && !slots.no_child_effect())?;
            let observation = slots.fixture_observation().ok_or_else(BridgeError::cleanup_unknown)?;
            need(observation.phase() == "settled" && observation.records() > 0
                && observation.positive_closes() == observation.records()
                && observation.live_originals() == 0 && observation.pending_acquisitions() == 0 && observation.uncertain_closes() == 0)?;
        }
        {
            let state = lock(&self.owner.state);
            need(state.endpoint == self.endpoint && state.terminal && !state.unknown && state.reply.is_none()
                && state.error.as_ref().is_some_and(|error| error.code == "shutting_down")
                && state.driver_end.is_none() // The genuine return was consumed by retirement, not reconstructed here.
                && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
                && matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))))?;
        }
        need(self.owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
            && self.owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none())
            && lock(&self.owner.permit).is_none() && lock(&self.inner.owners).is_empty()
            && self.inner.stopping.load(Ordering::SeqCst) && !self.inner.disabled.load(Ordering::SeqCst)
            && self.inner.permits.available_permits() == ACTIVE_LIMIT)?;
        if Instant::now() >= end { return Err(BridgeError::timeout()); }
        installed_native_fixture::report(&resources.native_snapshots);
        Ok(())
    }
}
