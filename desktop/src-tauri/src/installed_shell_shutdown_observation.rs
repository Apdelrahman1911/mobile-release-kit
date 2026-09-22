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
    #[cfg(all(debug_assertions, feature = "custom-protocol"))]
    pub(crate) fn admit_installed_session_once(&self, identity: &Arc<()>) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        need(owners.is_empty() && self.inner.next.load(Ordering::SeqCst) == 1 && !self.stopping() && !self.disabled())?;
        self.inner.runtime.admit_installed_session_once(identity)
    }
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

// Same R1 caller/owner, with a scoped scheduling observation only. Task-local
// scope does not spawn a task: it follows this actual assessor future when it
// is polled, so a concurrent AssessCredentials request cannot steal the arm.
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
mod session {
    use super::*;
    use std::{future::Future, sync::Weak};
    use crate::asset_session::OriginalWork;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum SessionQueryHold { Observe, Loss, Deadline }
    struct Original {
        asset: Weak<OriginalWork>, owner: Arc<Owner>, endpoint: Instant,
        hold: SessionQueryHold, selected: bool, held: bool, asset_released: bool, attempted: bool,
    }
    #[derive(Default)]
    pub(in crate::supervisor) struct SessionQueryBook {
        armed: Option<(Weak<OriginalWork>, SessionQueryHold)>, originals: Vec<Original>,
        failed: bool, taken: bool,
    }
    tokio::task_local! { static ORIGINAL_ASSET_QUERY: Weak<OriginalWork>; }
    pub(crate) struct InstalledSessionQueries {
        originals: Vec<Original>, inner: Arc<Inner>, valid: bool, retired: bool, report_attempted: bool,
    }

    impl Supervisor {
        pub(crate) fn arm_installed_session_query(&self, asset: &Arc<OriginalWork>, hold: SessionQueryHold) -> Result<(), BridgeError> {
            let mut book = lock(&self.inner.native_test.session);
            need(self.passive_method_available("credentials.assess") && !self.stopping() && !self.disabled()
                && !book.failed && !book.taken && book.armed.is_none() && book.originals.len() < 16
                && book.originals.iter().all(|row| row.asset.as_ptr() != Arc::as_ptr(asset))
                && *lock(&self.inner.native_test.case) == installed_native_fixture::Case::None)?;
            book.originals.try_reserve(1).map_err(|_| BridgeError::cleanup_unknown())?;
            book.armed = Some((Arc::downgrade(asset), hold)); Ok(())
        }
        pub(crate) async fn observe_installed_session_query<F: Future>(&self, asset: &Arc<OriginalWork>, assessor: F) -> F::Output {
            let armed = {
                let book = lock(&self.inner.native_test.session);
                !book.failed && !book.taken && book.armed.as_ref().is_some_and(|(original,_)|
                    original.as_ptr() == Arc::as_ptr(asset))
            };
            // Unrelated/direct assessments in the same test compilation do not
            // participate. Only this already-armed asset's actual future scopes
            // registration; no method-global selector can capture another R1.
            if armed { ORIGINAL_ASSET_QUERY.scope(Arc::downgrade(asset), assessor).await }
            else { assessor.await }
        }
        pub(crate) fn installed_session_query_held(&self, asset_id: u32) -> bool {
            let book = lock(&self.inner.native_test.session);
            !book.failed && book.originals.iter().any(|row| row.held && !row.asset_released
                && row.asset.upgrade().is_some_and(|asset| asset.id == asset_id && !asset.stopped())
                && Instant::now() < row.endpoint && !lock(&row.owner.state).terminal)
        }
        pub(crate) fn take_installed_session_queries(&self) -> Result<InstalledSessionQueries, BridgeError> {
            let mut book = lock(&self.inner.native_test.session);
            need(!book.taken)?; book.taken = true;
            Ok(InstalledSessionQueries { originals: std::mem::take(&mut book.originals), inner: self.inner.clone(),
                valid: !book.failed && book.armed.is_none(), retired: false, report_attempted: false })
        }
    }
    pub(in crate::supervisor) fn register_session_query(inner: &Arc<Inner>, owner: &Arc<Owner>) {
        let Ok(asset) = ORIGINAL_ASSET_QUERY.try_with(Weak::clone) else { return; };
        let mut book = lock(&inner.native_test.session);
        let valid = matches!(owner.profile, Profile::Passive(Method::AssessCredentials))
            && book.armed.as_ref().is_some_and(|(expected, _)| Weak::ptr_eq(expected, &asset) && asset.strong_count() > 0)
            && !book.failed && !book.taken && book.originals.len() < 16;
        if !valid { book.failed = true; owner.fail(BridgeError::protocol()); return; }
        let (_, hold) = book.armed.take().expect("matched original arm");
        book.originals.push(Original { asset, owner: owner.clone(), endpoint: owner.endpoint(), hold,
            selected: false, held: false, asset_released: false, attempted: false });
    }
    pub(in crate::supervisor) fn session_child_case(hooks: &installed_native_fixture::Hooks, owner: &Arc<Owner>) -> Option<installed_native_fixture::Case> {
        let mut book = lock(&hooks.session);
        let row = book.originals.iter_mut().find(|row| Arc::ptr_eq(&row.owner, owner))?;
        if row.selected { book.failed = true; return None; }
        row.selected = true;
        Some(match row.hold { SessionQueryHold::Observe => installed_native_fixture::Case::SessionObserve,
            SessionQueryHold::Loss => installed_native_fixture::Case::SessionLoss,
            SessionQueryHold::Deadline => installed_native_fixture::Case::SessionDeadline })
    }
    pub(in crate::supervisor) fn hold_session_query(inner: &Inner, key: u64, end: Instant, stop: &watch::Receiver<bool>,
        case: installed_native_fixture::Case) -> Result<(), ()> {
        let (asset, loss, delay) = {
            let mut book = lock(&inner.native_test.session);
            let row = book.originals.iter_mut().find(|row| row.owner.key == key).ok_or(())?;
            if !row.selected || row.held || row.endpoint != end || row.asset.strong_count() == 0 { return Err(()); }
            let loss = row.hold == SessionQueryHold::Loss;
            let expected = match row.hold { SessionQueryHold::Observe => installed_native_fixture::Case::SessionObserve,
                SessionQueryHold::Loss => installed_native_fixture::Case::SessionLoss,
                SessionQueryHold::Deadline => installed_native_fixture::Case::SessionDeadline };
            if case != expected { return Err(()); }
            row.held = true; (row.asset.clone(), loss, row.hold != SessionQueryHold::Observe)
        };
        while delay && Instant::now() < end && !*stop.borrow() && stop.has_changed().is_ok() {
            // Real asset STOP releases only the loss hold. Deadline uses the
            // unchanged query endpoint/STOP; neither waits for publication.
            if loss {
                let original = asset.upgrade().ok_or(())?;
                if original.stopped() {
                    let mut book = lock(&inner.native_test.session);
                    let row = book.originals.iter_mut().find(|row| row.owner.key == key).ok_or(())?;
                    row.asset_released = true; break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
    impl InstalledSessionQueries {
        pub(crate) fn count(&self) -> usize { self.originals.len() }
        pub(crate) async fn observe_retired(&mut self, observation_end: Instant) -> bool {
            if !self.valid || self.retired || Instant::now() >= observation_end || self.originals.is_empty() { return false; }
            for row in &mut self.originals {
                if row.attempted || !row.selected || !row.held { return false; }
                row.attempted = true;
                // Await only the SAME original management tail AFTER retirement.
                // A successful query's work clock may already be past at final
                // app Exit; that cannot undo its recorded on-time settlement.
                // This uses the existing observation bound, never grants more
                // query/cleanup time, and retains a pending/failed original.
                if !lock(&row.owner.state).terminal { return false; }
                let Ok(mut original) = row.owner.observer.try_lock() else { return false; };
                let Some(handle) = original.as_mut() else { return false; };
                let returned = tokio::select! {
                    result = handle => result,
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(observation_end)) => return false,
                };
                if returned.is_err() { return false; }
                original.take(); drop(original);
                let Ok(resources) = row.owner.resources.try_lock() else { return false; };
                let state = lock(&row.owner.state);
                if state.endpoint != row.endpoint || !state.terminal || state.unknown || state.reply.is_some()
                    || state.driver_end.is_some() || state.driver_join != ManagementJoin::Returned || state.watchdog_join != ManagementJoin::Returned
                    || !matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned)))
                    || (if row.hold == SessionQueryHold::Deadline {
                        state.error.as_ref().map(|e| e.code.as_str()) != Some("query_timeout")
                            || state.cleanup_endpoint != Some(row.endpoint + CLEANUP_TIME)
                    } else { state.error.is_some() || state.cleanup_endpoint.is_some() })
                    || row.hold == SessionQueryHold::Loss && !row.asset_released { return false; }
                drop(state);
                if resources.inspection_return != Some(ManagementJoin::Returned) || resources.acquisition_return != Some(ManagementJoin::Returned)
                    || resources.inspection.is_some() || resources.inspection_error.is_some() || resources.acquisition.is_some() || resources.acquisition_error.is_some()
                    || resources.child.is_some() || resources.waited.is_none() || resources.writer.is_some() || resources.stdout.is_some() || resources.stderr.is_some()
                    || resources.failed_writer.is_some() || resources.failed_stdout.is_some() || resources.failed_stderr.is_some()
                    || resources.write_end.is_none() || resources.out_end.is_some() || resources.err_end.is_some()
                    || !resources.native_started || resources.native_settlement.is_some()
                    || !matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
                    || resources.native_observation.is_some() || resources.native_observation_return != Some(ManagementJoin::Returned)
                    || resources.native_snapshots.len() != 1 || !resources.native_snapshots[0].environment_clear() { return false; }
                if row.hold == SessionQueryHold::Deadline {
                    if !resources.kill_attempted { return false; }
                } else if resources.kill_attempted || !resources.waited.as_ref().is_some_and(|status| status.success())
                    || !resources.write_end.is_some_and(|end| end.complete) { return false; }
                let Some(slots) = resources.passive.as_ref() else { return false; };
                let slots = lock(slots);
                let Some(observation) = slots.fixture_observation() else { return false; };
                if !slots.settled() || slots.claimed_observation().is_none() || slots.no_child_effect()
                    || observation.phase() != "settled" || observation.records() == 0
                    || observation.positive_closes() != observation.records() || observation.live_originals() != 0
                    || observation.pending_acquisitions() != 0 || observation.uncertain_closes() != 0 { return false; }
                if !row.owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
                    || !row.owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none()) || lock(&row.owner.permit).is_some() { return false; }
            }
            if self.inner.disabled.load(Ordering::SeqCst) || !self.inner.stopping.load(Ordering::SeqCst)
                || !lock(&self.inner.owners).is_empty() || self.inner.permits.available_permits() != ACTIVE_LIMIT
                || Instant::now() >= observation_end { return false; }
            // Keep the actual checked maps in their original resource books.
            // finish must complete the whole Exit conjunction before main may
            // emit CONTRACTS, these maps, the session receipt and success.
            self.retired = true;
            true
        }
        pub(crate) fn report_retired(&mut self) -> bool {
            if !self.valid || !self.retired || self.report_attempted { return false; }
            self.report_attempted = true;
            // Reporting is one-use DATA observation, not retirement or a new
            // query/cleanup owner. A partial write/lock failure cannot produce
            // a session receipt or success, nor authorize replay.
            for row in &self.originals {
                let Ok(resources) = row.owner.resources.try_lock() else { return false; };
                installed_native_fixture::report(&resources.native_snapshots);
            }
            true
        }
    }
}
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
pub(crate) use session::{InstalledSessionQueries, SessionQueryHold};
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
pub(super) use session::{SessionQueryBook, register_session_query, session_child_case, hold_session_query};
