//! One explicit read-only check under the existing original document/slot.
//! It owns no project, vault lease, process, alternate installation or daemon.
use super::*;
use crate::installation::{self as wire, CheckPhase, CheckReason, CheckSettlement, CheckStatus, Matching};

pub(super) const WORK_TIME: Duration = Duration::from_secs(30);
pub(super) const CONTROL_RESERVE: usize = 16 * 1024 * 1024;
// Conservative channel/notification/task-control heap charge, not payload credit
// or an RSS promise. The native/JSON/index capacities have their own checked row.
const SIGNAL_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy)]
struct Failure { reason: CheckReason, at: Instant }
#[derive(Default)]
struct FailureLatch { first: Option<Failure>, unknown: bool, reported: Option<(Instant, bool)> }
impl FailureLatch {
    fn record(&mut self, reason: CheckReason, at: Instant) {
        if self.first.is_none_or(|old| at < old.at) { self.first = Some(Failure { reason, at }); }
        self.unknown |= reason == CheckReason::CleanupUnknown;
    }
}

pub(super) struct Work {
    pub(super) end: Instant,
    failure: Mutex<FailureLatch>, poisoned: AtomicBool,
    stop: watch::Sender<bool>, stopped: watch::Receiver<bool>,
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    native: Mutex<crate::installed_runtime::InstallationSlots>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        feature = "macos-installed-observation", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    observation: Mutex<Option<Arc<ReadObservation>>>,
}
impl Work {
    pub(super) fn new(end: Instant) -> Self {
        let (stop, stopped) = watch::channel(false);
        Self { end, failure: Mutex::new(FailureLatch::default()), poisoned: AtomicBool::new(false), stop, stopped,
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            native: Mutex::new(crate::installed_runtime::InstallationSlots::new()),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
                feature = "macos-installed-observation", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
                target_os = "macos", target_arch = "aarch64"))]
            observation: Mutex::new(None),
        }
    }
    fn fact(&self) -> Option<(Failure, bool)> {
        match self.failure.try_lock() {
            Ok(latch) => {
                let unknown = latch.unknown || self.poisoned.load(Ordering::SeqCst);
                latch.first.or_else(|| unknown.then_some(Failure { reason: CheckReason::CleanupUnknown, at: self.end }))
                    .map(|first| (first, unknown))
            },
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.poisoned.store(true, Ordering::SeqCst);
                Some((Failure { reason: CheckReason::CleanupUnknown, at: self.end }, true))
            },
        }
    }
    fn take_pending(&self) -> Option<(Failure, bool)> {
        let mut latch = self.failure.try_lock().ok()?;
        let first = latch.first?;
        let unknown = latch.unknown || self.poisoned.load(Ordering::SeqCst);
        if latch.reported == Some((first.at, unknown)) { return None; }
        latch.reported = Some((first.at, unknown));
        Some((first, unknown))
    }
    pub(super) fn settled(&self) -> bool {
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        { self.native.try_lock().is_ok_and(|slots| slots.settled()) }
        #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        { true } // No native adapter exists or can enter on this profile.
    }
    fn observed_settled(&self) -> bool {
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        { self.native.try_lock().is_ok_and(|slots| slots.observed_settled()) }
        #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        { false }
    }
    pub(super) fn retained_bytes_if_settled(&self) -> Option<usize> {
        if !self.settled() || self.poisoned.load(Ordering::SeqCst)
            || self.failure.try_lock().ok()?.unknown { return None; }
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        let native = self.native.try_lock().ok()?.control_bytes()?;
        #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let native = 0;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
            feature = "macos-installed-observation", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64"))]
        let observation = {
            let held = self.observation.try_lock().ok()?;
            held.as_ref().map_or(Some(0), |control| control.retained_bytes_if_quiet())?
        };
        #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
            feature = "macos-installed-observation", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64")))]
        let observation = 0;
        SIGNAL_BYTES.checked_add(native)?.checked_add(observation)
    }
}

// No Document or native Book mutex is taken before the returned error's
// timestamp is recorded. This latch is small and independent of native custody;
// STOP never waits on a blocking inspection or drops its original future.
pub(super) fn failure(owner: &OriginalWork, reason: CheckReason, at: Instant) {
    let Some(work) = &owner.installation else { return; };
    match work.failure.lock() {
        Ok(mut latch) => latch.record(reason, at),
        Err(_) => { work.poisoned.store(true, Ordering::SeqCst); },
    }
    let end = at.min(work.end) + CLEANUP;
    match owner.cleanup_end.lock() {
        Ok(mut original) => *original = Some(original.map_or(end, |old| old.min(end))),
        Err(_) => { work.poisoned.store(true, Ordering::SeqCst); },
    }
    work.stop.send_replace(true);
    owner.signal_stop();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    feature = "macos-installed-observation", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
    if let Ok(held) = work.observation.try_lock() {
        if held.as_ref().is_some_and(|control| !control.stop()) { work.poisoned.store(true, Ordering::SeqCst); }
    }
}
pub(super) fn stop_at(owner: &OriginalWork, reason: Reason, at: Instant) -> Instant {
    failure(owner, from_reason(reason), at);
    owner.installation.as_ref().and_then(Work::fact).map_or(at, |(first, _)| first.at.min(at))
}
pub(super) fn from_reason(reason: Reason) -> CheckReason { match reason {
    Reason::None => CheckReason::None,
    Reason::UserCancelled => CheckReason::Cancelled,
    Reason::Deadline | Reason::ReviewExpired => CheckReason::Deadline,
    Reason::CleanupUnknown => CheckReason::CleanupUnknown,
    Reason::DocumentLost | Reason::Shutdown => CheckReason::DocumentUnavailable,
    Reason::Capacity | Reason::MaterialLimit | Reason::ParserLimit => CheckReason::Bounds,
    Reason::Busy => CheckReason::Busy,
    Reason::Unqualified | Reason::UnsupportedPlatform | Reason::Closed => CheckReason::UnavailableProfile,
    _ => CheckReason::Native,
} }
fn asset_reason(reason: CheckReason) -> Reason { match reason {
    CheckReason::None => Reason::None,
    CheckReason::Cancelled => Reason::UserCancelled,
    CheckReason::Deadline => Reason::Deadline,
    CheckReason::CleanupUnknown => Reason::CleanupUnknown,
    CheckReason::DocumentUnavailable => Reason::DocumentLost,
    CheckReason::Bounds => Reason::Capacity,
    CheckReason::Busy => Reason::Busy,
    CheckReason::UnavailableProfile => Reason::Unqualified,
    _ => Reason::SourceRefused,
} }

pub(super) fn pending(state: &DocumentState) -> bool {
    state.slot.as_ref().is_some_and(|slot| slot.operation.installation()
        && (slot.phase != Phase::Idle || !slot.owner.resources_settled()))
}
pub(super) fn observe_failure(state: &mut DocumentState) -> bool {
    let Some(slot) = state.slot.as_mut().filter(|slot| slot.operation.installation()) else { return false; };
    let Some((first, unknown)) = slot.owner.installation.as_ref().and_then(Work::take_pending) else {
        if slot.owner.installation.as_ref().is_some_and(|work| work.poisoned.load(Ordering::SeqCst))
            && !state.unknown {
            slot.stop(Reason::CleanupUnknown, Instant::now()); slot.phase = Phase::Unknown;
            slot.settlement = Settlement::Unknown; state.unknown = true; return true;
        }
        return false;
    };
    let before = (slot.cleanup_end, slot.phase, slot.reason, slot.settlement, state.unknown);
    // Feed the actual earlier instant back through the original Slot transition.
    // Its own reason may stay first-observed; installation projection uses the
    // chronological first native reason retained by this original latch.
    slot.stop(asset_reason(first.reason), first.at);
    slot.installation_result = None;
    if unknown {
        slot.phase = Phase::Unknown; slot.settlement = Settlement::Unknown; state.unknown = true;
    }
    before != (slot.cleanup_end, slot.phase, slot.reason, slot.settlement, state.unknown)
}
fn normal_joins(owner: &OriginalWork) -> bool {
    owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
        && owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
}
fn matching_ready(owner: &OriginalWork) -> bool {
    owner.resources_settled() && normal_joins(owner) && !owner.interrupted()
        && owner.installation.as_ref().is_some_and(|work| work.observed_settled()
            && !work.poisoned.load(Ordering::SeqCst)
            && work.failure.try_lock().is_ok_and(|latch| latch.first.is_none() && !latch.unknown))
}

#[derive(Clone, Copy)]
pub(super) struct Registry {
    last: Option<CheckStatus>, view: CheckStatus, revoked: bool,
}
impl Registry {
    pub(super) fn new() -> Self {
        Self { last: None, view: CheckStatus::initial(0, false, false), revoked: false }
    }
}
fn invalid_document(state: &DocumentState) -> bool {
    state.unknown || state.exhausted || state.stopping || state.lost_observed || !state.lifetime.original_bound()
}
fn slot_view(state: &DocumentState, slot: &Slot) -> CheckStatus {
    let fact = slot.owner.installation.as_ref().and_then(Work::fact);
    let unknown = state.unknown || state.exhausted || slot.phase == Phase::Unknown
        || fact.is_some_and(|(_, unknown)| unknown);
    let settled = slot.owner.resources_settled();
    let reason = fact.map_or_else(|| from_reason(slot.reason), |(first, _)| first.reason);
    let stopping = slot.cleanup_end.is_some() || slot.owner.stopped();
    let matching = !unknown && !stopping && slot.phase == Phase::Idle && slot.settlement == Settlement::Known;
    CheckStatus { schema_version: 1, status_revision: 0, available: false, can_start: false,
        operation_id: Some(slot.owner.id),
        phase: if unknown { CheckPhase::Unknown } else if matching && slot.installation_result.is_some() { CheckPhase::Observed }
            else if stopping && settled && slot.phase == Phase::Idle { CheckPhase::Refused }
            else if stopping { CheckPhase::Stopping } else { CheckPhase::Checking },
        reason: if unknown && reason == CheckReason::None { CheckReason::CleanupUnknown } else { reason },
        settlement: if unknown { if settled { CheckSettlement::LateKnown } else { CheckSettlement::Unknown } }
            else if settled && slot.phase == Phase::Idle { CheckSettlement::Known } else { CheckSettlement::Pending },
        assessment: if matching { slot.installation_result } else { None },
    }
}
pub(super) fn remember(state: &mut DocumentState) {
    if state.unknown || state.exhausted || state.stopping || state.lost_observed
        || !state.lifetime.original_bound() && (state.installation.last.is_some()
            || state.slot.as_ref().is_some_and(|slot| slot.operation.installation())) {
        state.installation.revoked = true;
        if let Some(last) = &mut state.installation.last {
            last.invalidate(if state.unknown || state.exhausted { CheckReason::CleanupUnknown } else { CheckReason::DocumentUnavailable });
        }
    }
    if let Some(slot) = state.slot.as_ref().filter(|slot| slot.operation.installation()) {
        let mut row = slot_view(state, slot);
        if state.installation.revoked { row.invalidate(if state.unknown || state.exhausted { CheckReason::CleanupUnknown } else { CheckReason::DocumentUnavailable }); }
        if matches!(row.settlement, CheckSettlement::Known | CheckSettlement::LateKnown) {
            state.installation.last = Some(row);
        }
    }
}
fn status_data(state: &mut DocumentState, available: bool, can_start: bool) -> CheckStatus {
    remember(state);
    let mut row = state.slot.as_ref().filter(|slot| slot.operation.installation())
        .map(|slot| slot_view(state, slot)).or(state.installation.last)
        .unwrap_or_else(|| CheckStatus::initial(0, available, can_start));
    row.available = available; row.can_start = available && can_start && !state.installation.revoked;
    if state.installation.revoked {
        row.invalidate(if state.unknown || state.exhausted { CheckReason::CleanupUnknown } else { CheckReason::DocumentUnavailable });
    }
    // Availability may change in another original owner without a Document
    // event. Compare the complete bounded projection before issuing its own
    // monotonically increasing revision; never emit two tuples at one revision.
    row.status_revision = state.installation.view.status_revision;
    if row != state.installation.view {
        if let Some(next) = status_successor(row.status_revision) { row.status_revision = next; }
        else {
            state.installation.revoked = true;
            row = state.installation.view;
            row.status_revision = u32::MAX; row.invalidate(CheckReason::CleanupUnknown);
        }
        state.installation.view = row;
    }
    row
}
pub(super) fn publish(state: &mut DocumentState, slot: &mut Slot, matching: Matching) {
    if !slot.operation.installation() || slot.context.is_some() || slot.cleanup_end.is_some()
        || !matching_ready(&slot.owner) || invalid_document(state) || state.installation.revoked {
        slot.stop(Reason::CleanupUnknown, Instant::now()); state.unknown = true; return;
    }
    slot.installation_result = Some(matching); slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
    state.installation.last = Some(slot_view(state, slot));
}
fn error(reason: Reason) -> BridgeError { match reason {
    Reason::Busy => wire::inspection_busy(),
    Reason::Capacity | Reason::MaterialLimit | Reason::ParserLimit => BridgeError::new("installation_check_bounds",
        "Not all retained session or Android source state can be safely accounted for. Finish active work and retire the relevant selections through their own controls, then try again. This check does not clear them."),
    Reason::CleanupUnknown => BridgeError::cleanup_unknown(),
    Reason::DocumentLost | Reason::Shutdown => BridgeError::new("installation_document_unavailable",
        "The original application document is closing or unavailable."),
    _ => wire::inspection_unavailable(),
} }

// External fixture histories are not part of the DocumentState census.
// Only a positively empty nonblocking observation admits; neither contention
// nor poison becomes a zero-byte holding or permission to clear that history.
#[cfg(test)]
fn fixture_history_absent<T>(history: &Mutex<Option<T>>) -> Result<(), Reason> {
    match history.try_lock() {
        Ok(held) if held.is_none() => Ok(()),
        Ok(_) | Err(std::sync::TryLockError::WouldBlock) => Err(Reason::Busy),
        Err(std::sync::TryLockError::Poisoned(error)) => {
            drop(error);
            Err(Reason::CleanupUnknown)
        }
    }
}
impl DocumentBinding {
    fn installation_fixture_memory_gate(&self) -> Result<(), Reason> {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        fixture_history_absent(&self.inner.installed_session)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        fixture_history_absent(&self.inner.installed_macos_session)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if self.inner.fixture.is_some() { return Err(Reason::Busy); }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if self.inner.github_fixture.is_some() { return Err(Reason::Busy); }
        Ok(())
    }
    fn installation_check_available(&self) -> bool {
        wire::inspect_profile_available(self.inner.bridge.installed_project_selection_available())
    }
    fn installation_check_gate(&self, state: &DocumentState) -> Result<(), BridgeError> {
        if !self.installation_check_available() { return Err(wire::inspection_unavailable()); }
        if state.installation.revoked { return Err(BridgeError::cleanup_unknown()); }
        self.common_gate(state, false).map_err(|failure| error(failure.reason))?;
        idle(state).map_err(|failure| error(failure.reason))?;
        self.installation_fixture_memory_gate().map_err(error)?;
        // Android source selections can retain original asset owners outside
        // DocumentState after Slot retirement. Uncounted holdings REFUSE before
        // operation ID/control allocation; no clearing or recursive census.
        if !self.inner.bridge.android_build.installation_source_custody_empty() {
            return Err(error(Reason::Capacity));
        }
        if let Some(reason) = self.live_session_owner_reason() { return Err(error(reason)); }
        if !self.inner.bridge.supervisor.can_exit() || !self.inner.bridge.edits.can_exit()
            || state.github.native_work_pending() { return Err(wire::inspection_busy()); }
        Ok(())
    }
    pub(crate) fn installation_status(&self) -> Result<CheckStatus, BridgeError> {
        // Do not start an unrelated native/cleanup owner just to show this card.
        let original = self.lock().slot.as_ref().filter(|slot| slot.operation.installation()).map(|slot| slot.owner.id);
        if let Some(id) = original { self.reconcile_installation(id); }
        let mut state = self.lock();
        let available = self.installation_check_available();
        let can_start = self.installation_check_gate(&state).is_ok();
        Ok(status_data(&mut state, available, can_start))
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn inspect_installation(&self) -> Result<CheckStatus, BridgeError> {
        self.start_installation(|_| Ok(()))
    }
    #[cfg(feature = "desktop-shell")]
    fn start_installation(&self, before_go: impl FnOnce(&OriginalWork) -> Result<(), BridgeError>) -> Result<CheckStatus, BridgeError> {
        self.reconcile();
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.installation_check_gate(&state)?;
        installation_memory::admitted(&state, CONTROL_RESERVE).map_err(error)?;
        let id = self.next_operation(&mut state).map_err(|failure| error(failure.reason))?;
        // One sampled constructor endpoint, before dispatch. No result/picker
        // callback can renew it, and no native allocation runs in construction.
        let owner = OriginalWork::new_installation(id, Arc::downgrade(&self.inner));
        before_go(&owner)?;
        let slot = Slot::new(owner, Operation::InspectInstallation, None, None, None);
        let start = self.install(&mut state, slot, Job::Installation).map_err(|failure| error(failure.reason))?;
        let status = status_data(&mut state, true, false);
        drop(state); let _ = start.send(()); Ok(status)
    }
    pub(crate) fn cancel_installation(&self, id: u32) -> Result<CheckStatus, BridgeError> {
        let at = Instant::now(); // Before waiting for the real document gate.
        let mut state = self.lock();
        let matching = state.slot.as_ref().is_some_and(|slot| slot.operation.installation() && slot.owner.id == id);
        if matching {
            let slot = state.slot.as_mut().ok_or_else(BridgeError::invalid)?;
            if slot.phase != Phase::Idle || !slot.owner.resources_settled() {
                let reason = if slot.owner.endpoint().is_some_and(|end| at >= end) { Reason::Deadline } else { Reason::UserCancelled };
                slot.stop(reason, at); self.bump(&mut state);
            }
        } else if !state.installation.last.is_some_and(|row| row.operation_id == Some(id)
            && matches!(row.settlement, CheckSettlement::Known | CheckSettlement::LateKnown)) {
            return Err(BridgeError::new("installation_check_stale", "This check is no longer the current installation operation."));
        }
        // A terminal old id is an inert status request, never cancellation of
        // whichever unrelated project/credential owner now occupies the slot.
        drop(state); self.installation_status()
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn cleanup_expired(owner: &OriginalWork, native: Option<(crate::installed_runtime::AdmissionFailure, Instant)>) -> bool {
    if let Some((reason, at)) = native {
        failure(owner, crate::installed_runtime::installation_native_problem(reason), at);
    }
    let expired = owner.cleanup_end.lock().map_or(true, |end| end.is_none_or(|end| Instant::now() >= end));
    if expired { failure(owner, CheckReason::CleanupUnknown, Instant::now()); }
    expired
}
pub(super) fn execute(owner: &Arc<OriginalWork>) -> Result<Matching, CheckReason> {
    let Some(work) = &owner.installation else { return Err(CheckReason::CleanupUnknown); };
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        // Only execute_child calls this, after exact handle registration/GO.
        // Poison retains the Book in its original cell; never recover it to
        // launch a replacement reader or infer that dropping settled anything.
        let mut native = match work.native.lock() {
            Ok(native) => native,
            Err(_) => { failure(owner, CheckReason::CleanupUnknown, Instant::now()); return Err(CheckReason::CleanupUnknown); },
        };
        native.run(work.end, &work.stopped,
            &mut |reason, at| failure(owner, reason, at),
            &mut |first| cleanup_expired(owner, first),
            &mut |files, bytes| read_returned(owner, files, bytes))
    }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    { let _ = work; failure(owner, CheckReason::UnavailableProfile, Instant::now()); Err(CheckReason::UnavailableProfile) }
}
fn read_returned(_owner: &OriginalWork, _files: u32, _bytes: u64) {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        feature = "macos-installed-observation", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    if let Some(work) = &_owner.installation {
        let control = match work.observation.lock() {
            Ok(row) => row.clone(),
            Err(error) => {
                let at = Instant::now(); drop(error);
                failure(_owner, CheckReason::CleanupUnknown, at); return;
            },
        };
        if let Some(control) = control { control.read_returned(_owner, _files, _bytes); }
    }
}
#[cfg(feature = "desktop-shell")]
pub(super) async fn run(owner: &Arc<OriginalWork>) -> Staged {
    let result = child(owner, ChildJob::Installation).await;
    let at = Instant::now(); // The actual original join/error return, before stage locks.
    match result {
        Ok(ChildEnd::Installation(Ok(matching))) => Staged::Installation(matching),
        Ok(ChildEnd::Installation(Err(reason))) => {
            failure(owner, reason, at); Staged::Refused(asset_reason(reason))
        },
        Ok(ChildEnd::Refused(reason)) | Err(reason) => {
            failure(owner, from_reason(reason), at); Staged::Refused(reason)
        },
        _ => { failure(owner, CheckReason::CleanupUnknown, at); Staged::Refused(Reason::CleanupUnknown) },
    }
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    feature = "macos-installed-observation", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ReadObservation {
    pause: bool, first: AtomicBool, files: std::sync::atomic::AtomicU32, bytes: std::sync::atomic::AtomicU64,
    released: Mutex<bool>, changed: std::sync::Condvar,
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    feature = "macos-installed-observation", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
impl ReadObservation {
    fn new(pause: bool) -> Self {
        Self { pause, first: AtomicBool::new(false), files: std::sync::atomic::AtomicU32::new(0),
            bytes: std::sync::atomic::AtomicU64::new(0), released: Mutex::new(false), changed: std::sync::Condvar::new() }
    }
    fn retained_bytes_if_quiet(&self) -> Option<usize> {
        // The original Work owns this one Arc allocation; observer aliases do
        // not allocate another body. Inline Option/Mutex control belongs to the
        // enclosing OriginalWork census. Neither poison nor contention is zero.
        let _held = self.released.try_lock().ok()?;
        let (arc, _) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<Self>()).ok()?;
        // Separate conservative bounded synchronization backing/control row,
        // not a claim about whole-process RSS or general allocator overhead.
        const OBSERVATION_SYNC_CONTROL_BYTES: usize = 4 * 1024;
        arc.pad_to_align().size().checked_add(OBSERVATION_SYNC_CONTROL_BYTES)
    }
    // This is (verified_files, verified_bytes), not an operation identity.
    // The same start-returned CheckStatus carries the original operation_id.
    pub(crate) fn first_read(&self) -> Option<(u32, u64)> {
        self.first.load(Ordering::Acquire).then(|| (self.files.load(Ordering::Relaxed), self.bytes.load(Ordering::Relaxed)))
    }
    fn stop(&self) -> bool {
        let Ok(mut released) = self.released.lock() else { return false; };
        *released = true; self.changed.notify_all(); true
    }
    fn read_returned(&self, owner: &OriginalWork, files: u32, bytes: u64) {
        if self.first.load(Ordering::Acquire) { return; }
        self.files.store(files, Ordering::Relaxed); self.bytes.store(bytes, Ordering::Relaxed);
        self.first.store(true, Ordering::Release);
        if !self.pause { return; }
        let Some(work) = &owner.installation else { return; };
        let mut released = match self.released.lock() {
            Ok(released) => released,
            Err(error) => { let at = Instant::now(); drop(error); failure(owner, CheckReason::CleanupUnknown, at); return; },
        };
        while !*released && !owner.interrupted() {
            // This is the original entered child's test-only pause at a REAL
            // returned read. The immutable admitted work end is its sole bound;
            // STOP releases the same condition, with no replacement timer/owner.
            let remaining = work.end.saturating_duration_since(Instant::now());
            if remaining.is_zero() { break; }
            match self.changed.wait_timeout(released, remaining) {
                Ok((next, _)) => released = next,
                Err(error) => { let at = Instant::now(); drop(error); failure(owner, CheckReason::CleanupUnknown, at); return; },
            }
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    feature = "macos-installed-observation", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OriginalFacts {
    pub(crate) normal_coordinator_joined: bool, pub(crate) normal_child_joined: bool,
    pub(crate) native_settled: bool, pub(crate) storage_disposed: bool,
    pub(crate) resources_settled: bool, pub(crate) stopped: bool,
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    feature = "macos-installed-observation", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
impl DocumentBinding {
    pub(crate) fn inspect_installation_observed(&self, pause_after_first_read: bool)
        -> Result<(CheckStatus, Arc<ReadObservation>), BridgeError> {
        let control = Arc::new(ReadObservation::new(pause_after_first_read));
        let result = self.start_installation(|owner| {
            let work = owner.installation.as_ref().ok_or_else(BridgeError::invalid)?;
            let mut held = work.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if held.is_some() { return Err(BridgeError::invalid()); }
            *held = Some(control.clone()); Ok(())
        })?;
        Ok((result, control))
    }
    pub(crate) fn installation_observer_facts(&self, id: u32) -> Option<OriginalFacts> {
        let state = self.lock();
        let slot = state.slot.as_ref().filter(|slot| slot.operation.installation() && slot.owner.id == id)?;
        let owner = &slot.owner; let work = owner.installation.as_ref()?;
        let (native_settled, storage_disposed) = work.native.try_lock().ok()?.settlement_facts();
        Some(OriginalFacts {
            normal_coordinator_joined: owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()),
            normal_child_joined: owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()),
            native_settled, storage_disposed, resources_settled: owner.resources_settled(), stopped: owner.stopped(),
        })
    }
}

#[cfg(test)]
pub(super) fn assert_owner_contracts() {
    // Inert bookkeeping predicates only: no native allocations, FD operations,
    // real join receipts, app window, project, process, vault or Store is made.
    // Plain DATA-only Option holdings model the pre-census check. No real
    // fixture, registered project, original join, native object or worker exists.
    let external = Mutex::new(None::<()>);
    assert!(fixture_history_absent(&external).is_ok());
    *external.lock().unwrap() = Some(());
    assert_eq!(fixture_history_absent(&external), Err(Reason::Busy));
    *external.lock().unwrap() = None;
    let held = external.lock().unwrap();
    assert_eq!(fixture_history_absent(&external), Err(Reason::Busy));
    drop(held);
    assert!(fixture_history_absent(&external).is_ok());

    let owner = OriginalWork::new_installation(1, Weak::new());
    let end = owner.endpoint().unwrap();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        feature = "macos-installed-observation", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    {
        // Ordinary absent/present/contended DATA: no read boundary, native
        // object or join proof is manufactured for these allocation checks.
        let work = owner.installation.as_ref().unwrap();
        let without_observation = work.retained_bytes_if_settled().unwrap();
        let observation = Arc::new(ReadObservation::new(false));
        let observation_bytes = observation.retained_bytes_if_quiet().unwrap();
        assert!(observation_bytes > std::mem::size_of::<ReadObservation>());
        *work.observation.lock().unwrap() = Some(observation.clone());
        assert_eq!(work.retained_bytes_if_settled(), without_observation.checked_add(observation_bytes));
        {
            let _held = work.observation.lock().unwrap();
            assert!(work.retained_bytes_if_settled().is_none());
        }
        {
            let _held = observation.released.lock().unwrap();
            assert!(work.retained_bytes_if_settled().is_none());
        }
        assert_eq!(work.retained_bytes_if_settled(), without_observation.checked_add(observation_bytes));
    }
    assert_eq!(owner.cleanup_end.lock().unwrap().as_ref(), Some(&(end + CLEANUP)));
    let mut slot = Slot::new(owner.clone(), Operation::InspectInstallation, None, None, None);
    assert!(slot.cleanup_end.is_none());
    owner.set_endpoint(None); owner.set_endpoint(Some(end + Duration::from_secs(200)));
    assert_eq!(owner.endpoint(), Some(end));
    // Inert past timestamps avoid confusing injected order with the live
    // Instant sampled by Slot::stop's existing STOP notification.
    let early = end - WORK_TIME - Duration::from_secs(1);
    failure(&owner, CheckReason::PayloadMismatch, early);
    assert_eq!(*owner.cleanup_end.lock().unwrap(), Some(early + CLEANUP));
    failure(&owner, CheckReason::Native, early + Duration::from_millis(10));
    assert_eq!(owner.installation.as_ref().unwrap().fact().unwrap().0.reason, CheckReason::PayloadMismatch);
    slot.stop(Reason::UserCancelled, early + Duration::from_millis(20));
    assert_eq!(slot.cleanup_end, Some(early + CLEANUP));
    assert_eq!(owner.endpoint(), Some(end));
    assert!(owner.stopped() && slot.installation_result.is_none());

    let mut state = super::tests::empty_state();
    state.session = false;
    state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
    state.slot = Some(slot);
    assert!(pending(&state));
    assert!(common_document_gate(&state, false, || Ok(())).is_err());
    assert!(passive_document_gate(&state).is_err());
    assert!(credential_lock_gate(&state).is_err());
    assert!(!credential_discard_operation(Operation::InspectInstallation));
    let _ = observe_failure(&mut state);
    assert!(owner.installation.as_ref().unwrap().take_pending().is_none());
    assert!(!observe_failure(&mut state)); // Consumed facts cannot restart retirement.

    // Closed DATA receipts are a model here, never advertised as native joins.
    owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
    owner.child.try_lock().unwrap().receipt = JoinReceipt::Failed;
    assert!(!normal_joins(&owner));
    owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
    assert!(normal_joins(&owner));
    assert!(!matching_ready(&owner)); // STOP/not-entered still forbid matching.
    let slot = state.slot.as_mut().unwrap();
    slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
    let terminal = status_data(&mut state, true, true);
    assert_eq!(terminal.phase, CheckPhase::Refused);
    assert_eq!(terminal.reason, CheckReason::PayloadMismatch);
    assert_eq!(terminal.settlement, CheckSettlement::Known);
    assert!(terminal.assessment.is_none());
    assert!(!pending(&state));
    assert!(retire_context_authority(&mut state, early).is_none());
    assert!(state.slot.as_ref().unwrap().phase == Phase::Idle);
    state.slot = None;
    let retained = status_data(&mut state, true, true);
    assert_eq!(retained.operation_id, Some(1));
    assert_eq!(retained.phase, CheckPhase::Refused);
    let busy = status_data(&mut state, true, false);
    assert!(busy.status_revision > retained.status_revision);
    let next = status_data(&mut state, true, true);
    assert!(next.status_revision > busy.status_revision);
    state.lost_observed = true;
    let invalid = status_data(&mut state, true, true);
    assert_eq!(invalid.phase, CheckPhase::Unknown);
    assert!(!invalid.can_start && invalid.assessment.is_none());
    state.lost_observed = false;
    assert!(!status_data(&mut state, true, true).can_start); // Sticky authority loss.

    // A first status while the initial window is not yet bound is not a
    // fabricated loss of a previously admitted installation original.
    let mut initial = super::tests::empty_state();
    let _ = status_data(&mut initial, true, false);
    assert!(!initial.installation.revoked);
    let owner = OriginalWork::new_installation(2, Weak::new());
    let end = owner.endpoint().unwrap();
    failure(&owner, CheckReason::Native, end - Duration::from_secs(1));
    failure(&owner, CheckReason::CleanupUnknown, end);
    let (first, unknown) = owner.installation.as_ref().unwrap().fact().unwrap();
    assert_eq!(first.reason, CheckReason::Native); assert!(unknown);
    assert_eq!(*owner.cleanup_end.lock().unwrap(), Some(end + Duration::from_secs(1)));
}
