//! One-shot acquisition entry and dormant shared-core installer guard.
//!
//! This entry belongs ONLY in the dedicated isolated bridge process. It installs
//! a process-lifetime abort-only panic hook; never call it from a shared test
//! runner or the desktop process. The existing feature exclusions prohibit
//! desktop-shell/development/publisher/observation combinations.
//!
//! The original caller remains the native worker. The only spawned worker is
//! one watchdog owning clock/control DATA; no native book or native frame moves
//! to it. Abort means failure/Unknown of this dedicated process, never original
//! native settlement, child settlement, deletion authority or installer success.
//! Protected bootstrap/image binding, real prerequisite and activation remain
//! unwired. The direct publication core borrows this same original guard, but
//! no full sequencer, bridge binary or NSIS entry is enabled.
#![forbid(unsafe_code)]

use std::sync::{
    atomic::{AtomicU32, AtomicU8, Ordering},
    Mutex, OnceLock,
};
use std::thread::{self, JoinHandle, Thread, ThreadId};
use std::time::{Duration, Instant};
use crate::windows_input_acquisition::{self as acquisition, AcquisitionError};
use crate::windows_installer_controller_data::{
    clock_phase, may_begin, may_succeed, watch_decision, ClockPhase, WatchDecision,
    ARMED, GO, HARD_AFTER, RETIRE, STOP, STOP_AFTER,
};
pub use crate::windows_installer_controller_data::{ControllerFailures, ControllerFault};
use mrk_windows_installed_native::CloseOutcome;
use crate::runtime_publication_windows::{PublicationError, RuntimePrepared};
#[cfg(feature = "windows-installer-selection")]
pub use crate::windows_installer_selection::{SelectionError, SelectionOutcome};

type PriorPanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

// Explicit production stack request; never depend on ambient RUST_MIN_STACK.
const WATCHDOG_STACK_BYTES: usize = 2 * 1024 * 1024;

static OWNER: OnceLock<OriginalController> = OnceLock::new();

struct OriginalController {
    control: Control,
    caller: ThreadId,
    // Actual direct core return, not a copied publisher exit or activation receipt.
    publication_returned: OnceLock<Result<RuntimePrepared, PublicationError>>,
    #[cfg(feature = "windows-installer-selection")]
    activation_returned: OnceLock<Result<(), mrk_windows_installed_native::Error>>,
    #[cfg(feature = "windows-installer-selection")]
    selection_returned: OnceLock<Result<SelectionOutcome, SelectionError>>,
    #[cfg(feature = "windows-installer-selection")]
    selection_only: bool,
    // Only the original caller accesses this lock; the watchdog never does.
    // The actual handle is retained here before GO and consumed once by join.
    watchdog: Mutex<Option<JoinHandle<WatchdogExit>>>,
    original_joined: OnceLock<()>,
    returned: OnceLock<Result<(), AcquisitionError>>,
    final_result: OnceLock<Result<(), AcquisitionControllerReport>>,
    #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
    fixture_returned: OnceLock<Result<retained_fixture::CaseProof, &'static str>>,
    // A replaced arbitrary hook is never invoked, restored or dropped here.
    prior_hook: OnceLock<PriorPanicHook>,
}
impl OriginalController {
    fn new(started: Instant) -> Self {
        Self { control: Control::new(started), caller: thread::current().id(),
            publication_returned: OnceLock::new(), watchdog: Mutex::new(None),
            #[cfg(feature = "windows-installer-selection")]
            activation_returned: OnceLock::new(),
            #[cfg(feature = "windows-installer-selection")]
            selection_returned: OnceLock::new(),
            #[cfg(feature = "windows-installer-selection")]
            selection_only: false,
            original_joined: OnceLock::new(), returned: OnceLock::new(),
            final_result: OnceLock::new(), prior_hook: OnceLock::new(),
            #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
            fixture_returned: OnceLock::new(),
        }
    }
}

/// A loan of the registered controller and its ACTUAL retained JoinHandle.
/// Only this module can construct it, from the caller-held custody lock after
/// the real armed acknowledgement. It is not acquisition/prerequisite success.
pub(crate) struct ActiveInstallerGuard<'a> {
    owner: &'static OriginalController,
    original: &'a JoinHandle<WatchdogExit>,
}
impl<'a> ActiveInstallerGuard<'a> {
    fn borrow_actual(owner: &'static OriginalController,
        custody: &'a std::sync::MutexGuard<'_, Option<JoinHandle<WatchdogExit>>>) -> Result<Self, ControllerFault> {
        let original = custody.as_ref().ok_or_else(|| {
            owner.control.fail(ControllerFault::Barrier);
            ControllerFault::Barrier
        })?;
        let guard = Self { owner, original };
        guard.check()?;
        Ok(guard)
    }
    // Never re-lock watchdog: the caller already owns that MutexGuard. This
    // reads only controller DATA and the retained handle's nonblocking state.
    // STOP is allowed here so this SAME check can protect required settlement.
    fn active_elapsed(&self) -> Result<Duration, ControllerFault> {
        if self.owner.caller != thread::current().id()
            || !OWNER.get().is_some_and(|registered| std::ptr::eq(registered, self.owner))
            || self.owner.prior_hook.get().is_none()
            || self.owner.original_joined.get().is_some()
            || self.owner.final_result.get().is_some() {
            self.owner.control.fail(ControllerFault::ControllerState);
            return Err(ControllerFault::ControllerState);
        }
        let elapsed = self.owner.control.sample();
        if self.original.is_finished()
            || self.owner.control.state() & (GO | ARMED | RETIRE) != (GO | ARMED) {
            self.owner.control.fail(ControllerFault::Barrier);
            return Err(ControllerFault::Barrier);
        }
        Ok(elapsed)
    }
    pub(crate) fn check(&self) -> Result<(), ControllerFault> {
        let elapsed = self.active_elapsed()?;
        let failures = self.owner.control.failures();
        if !may_begin(self.owner.control.state(), elapsed) || !failures.is_empty() {
            let fault = failures.first.unwrap_or(ControllerFault::Barrier);
            self.owner.control.fail(fault);
            return Err(fault);
        }
        Ok(())
    }
    /// Consumes already-returned Result DATA, never an operation callback.
    /// A returned failure wins before a later STOP/clock/caller observation.
    pub(crate) fn after_return<T, E>(&self, returned: Result<T, E>, refusal: E) -> Result<T, E> {
        match returned {
            Err(first) => Err(first),
            Ok(value) => {
                self.check().map_err(|_| refusal)?;
                Ok(value)
            },
        }
    }
    pub(crate) fn settlement_boundary(&self) {
        // Cooperative STOP is deliberately not a reason to skip once cleanup.
        // Lost original custody, unlike STOP, cannot become detached cleanup.
        if self.active_elapsed().is_err() {
            self.owner.control.abort(ControllerFault::NativeFinalityUnknown);
        }
    }
    /// Reads the actual retained acquisition return while this SAME caller still
    /// holds the original guard. No copied success argument can supply this gate.
    pub(crate) fn require_acquired_inputs(&self) -> Result<(), ControllerFault> {
        if !matches!(self.owner.returned.get(), Some(Ok(()))) {
            self.owner.control.fail(ControllerFault::ControllerState);
            return Err(ControllerFault::ControllerState);
        }
        self.check()
    }
    pub(crate) fn retain_publication_return(&self, returned: Result<RuntimePrepared, PublicationError>) -> Result<RuntimePrepared, PublicationError> {
        if self.owner.publication_returned.set(returned).is_err() {
            self.owner.control.abort(ControllerFault::ControllerState);
        }
        let returned = self.owner.publication_returned.get()
            .unwrap_or_else(|| self.owner.control.abort(ControllerFault::ControllerState));
        // Actual first core DATA has been retained before any later controller
        // failure. Unknown keeps the native OWNER/storage and ends this process.
        if returned.is_err() { self.owner.control.fail(ControllerFault::PublicationFailed); }
        let settled = match returned {
            Ok(_) | Err(PublicationError::Invocation | PublicationError::Profile
                | PublicationError::InstallerGuard | PublicationError::OccupiedTargetSettled) => true,
            Err(PublicationError::Failed { originals_unknown, .. }) => !*originals_unknown,
            Err(PublicationError::AlreadyStarted | PublicationError::OwnerUnavailable) => false,
        };
        if !settled { self.owner.control.abort(ControllerFault::NativeFinalityUnknown); }
        match *returned {
            Err(first) => Err(first),
            Ok(prepared) => self.check().map(|()| prepared).map_err(|_| PublicationError::InstallerGuard),
        }
    }
    #[cfg(feature = "windows-installer-selection")]
    pub(crate) fn require_publication_return(&self) -> Result<(), ControllerFault> {
        if !matches!(self.owner.publication_returned.get(), Some(Ok(_))) {
            self.owner.control.fail(ControllerFault::ControllerState);
            return Err(ControllerFault::ControllerState);
        }
        self.require_acquired_inputs()
    }
    #[cfg(feature = "windows-installer-selection")]
    pub(crate) fn retain_activation_return(&self, returned: Result<(), mrk_windows_installed_native::Error>)
        -> Result<(), mrk_windows_installed_native::Error> {
        if self.owner.activation_returned.set(returned).is_err() {
            self.owner.control.abort(ControllerFault::ControllerState);
        }
        let returned = self.owner.activation_returned.get()
            .unwrap_or_else(|| self.owner.control.abort(ControllerFault::ControllerState));
        if returned.is_err() { self.owner.control.fail(ControllerFault::ActivationFailed); }
        // Query the actual original after the named construction loan ended.
        // No copied settled bit supplies native finality.
        if !acquisition::retained_activation_settled_for(returned) {
            self.owner.control.abort(ControllerFault::NativeFinalityUnknown);
        }
        self.after_return(*returned, mrk_windows_installed_native::Error::State)
    }
    #[cfg(feature = "windows-installer-selection")]
    pub(crate) fn retain_selection_return(&self, returned: Result<SelectionOutcome, SelectionError>)
        -> Result<SelectionOutcome, SelectionError> {
        if self.owner.selection_returned.set(returned).is_err() {
            self.owner.control.abort(ControllerFault::ControllerState);
        }
        let returned = self.owner.selection_returned.get()
            .unwrap_or_else(|| self.owner.control.abort(ControllerFault::ControllerState));
        if returned.is_err() { self.owner.control.fail(ControllerFault::SelectionFailed); }
        if !crate::windows_installer_selection::original_settled_for(returned) {
            self.owner.control.abort(ControllerFault::NativeFinalityUnknown);
        }
        self.after_return(returned.clone(), SelectionError::InstallerGuard)
    }

}

impl mrk_windows_installed_native::InstallerBoundary for ActiveInstallerGuard<'_> {
    fn producing_boundary(&self) -> Result<(), mrk_windows_installed_native::Error> {
        self.check().map_err(|_| mrk_windows_installed_native::Error::State)
    }
    fn settlement_boundary(&self) { ActiveInstallerGuard::settlement_boundary(self); }
    #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
    fn selection_fixture_return_boundary(&self,
        point: mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixturePoint) {
        selection_fixture::observe_return(self, point);
    }
}

struct Control {
    started: Instant,
    state: AtomicU8,
    first_fault: AtomicU8,
    faults: AtomicU32,
}
impl Control {
    fn new(started: Instant) -> Self {
        Self { started, state: AtomicU8::new(0), first_fault: AtomicU8::new(0),
            faults: AtomicU32::new(0) }
    }
    fn state(&self) -> u8 { self.state.load(Ordering::SeqCst) }
    fn failures(&self) -> ControllerFailures {
        ControllerFailures::observed(self.first_fault.load(Ordering::SeqCst),
            self.faults.load(Ordering::SeqCst))
    }
    fn fail(&self, fault: ControllerFault) {
        let _ = self.first_fault.compare_exchange(0, fault.code(), Ordering::SeqCst, Ordering::SeqCst);
        self.faults.fetch_or(fault.bit(), Ordering::SeqCst);
        self.state.fetch_or(STOP, Ordering::SeqCst);
        // This existing operation is only one atomic store, never a native lock.
        acquisition::request_stop();
    }
    fn abort(&self, fault: ControllerFault) -> ! {
        self.fail(fault);
        // No logging, formatting, filesystem output, PID lookup or cleanup.
        std::process::abort()
    }
    fn elapsed(&self) -> Duration {
        Instant::now().checked_duration_since(self.started)
            .unwrap_or_else(|| self.abort(ControllerFault::Clock))
    }
    fn observe_requested_stop(&self) {
        if acquisition::stop_is_requested() && self.state() & STOP == 0 {
            self.fail(ControllerFault::StopRequested);
        }
    }
    fn sample(&self) -> Duration {
        let elapsed = self.elapsed();
        match clock_phase(elapsed) {
            ClockPhase::Expired => self.abort(ControllerFault::HardDeadline),
            ClockPhase::Settlement => self.fail(ControllerFault::SettlementDeadline),
            ClockPhase::Work => (),
        }
        self.observe_requested_stop();
        elapsed
    }
}

/// The acquisition's actual returned error is always primary. Additional
/// controller faults are preserved independently, including their first cause.
#[derive(Debug)]
pub struct AcquisitionControllerReport {
    pub returned_acquisition_error: Option<&'static AcquisitionError>,
    pub controller_failures: ControllerFailures,
    pub acquisition_return_observed: bool,
    pub original_watchdog_joined: bool,
    #[cfg(feature = "windows-installer-selection")]
    pub returned_activation_error: Option<mrk_windows_installed_native::Error>,
    #[cfg(feature = "windows-installer-selection")]
    pub returned_selection_error: Option<&'static SelectionError>,
    #[cfg(feature = "windows-installer-selection")]
    pub selection_return_observed: bool,
}
#[derive(Debug)]
pub enum PrimaryFailure {
    Acquisition(&'static AcquisitionError),
    Controller(ControllerFault),
    #[cfg(feature = "windows-installer-selection")]
    Activation(mrk_windows_installed_native::Error),
    #[cfg(feature = "windows-installer-selection")]
    Selection(&'static SelectionError),
}
impl AcquisitionControllerReport {
    pub fn primary_failure(&self) -> Option<PrimaryFailure> {
        if let Some(error) = self.returned_acquisition_error { return Some(PrimaryFailure::Acquisition(error)); }
        #[cfg(feature = "windows-installer-selection")]
        {
            if let Some(error) = self.returned_activation_error { return Some(PrimaryFailure::Activation(error)); }
            if let Some(error) = self.returned_selection_error { return Some(PrimaryFailure::Selection(error)); }
        }
        self.controller_failures.first.map(PrimaryFailure::Controller)
    }
}
#[derive(Debug)]
pub enum ControllerError {
    AlreadyStarted,
    Failed(&'static AcquisitionControllerReport),
}

/// Monotonic, nonblocking in-process request only. It is NOT an authenticated
/// external NSIS cancellation transport and does not imply native settlement.
pub fn request_stop() {
    acquisition::request_stop();
    if let Some(owner) = OWNER.get() { owner.control.fail(ControllerFault::StopRequested); }
}

fn install_abort_hook(owner: &'static OriginalController) {
    if thread::panicking() { owner.control.abort(ControllerFault::ControllerState); }
    // take_hook returns the ACTUAL previous Box. Retain before installing our
    // no-output hook and before any watchdog or native work can begin.
    match owner.prior_hook.set(std::panic::take_hook()) {
        Ok(()) => (),
        Err(_original_box) => owner.control.abort(ControllerFault::ControllerState),
    }
    std::panic::set_hook(Box::new(|_| std::process::abort()));
}

struct WatchdogExit { armed: bool, elapsed: Duration }

fn watchdog(control: &Control, caller: Thread) -> WatchdogExit {
    // The production abort-only hook is already installed before this starts.
    // This function neither locks the owner nor accesses original native data.
    loop {
        control.observe_requested_stop();
        let elapsed = control.elapsed();
        match watch_decision(control.state(), elapsed) {
            WatchDecision::Abort => control.abort(ControllerFault::HardDeadline),
            WatchDecision::Stop => control.fail(ControllerFault::SettlementDeadline),
            WatchDecision::Retire => {
                let returned = WatchdogExit { armed: control.state() & ARMED != 0, elapsed };
                caller.unpark();
                return returned; // retirement is NOT acquisition success
            },
            WatchDecision::Arm => {
                control.state.fetch_or(ARMED, Ordering::SeqCst);
                caller.unpark(); // actual watchdog acknowledgement, not native finality
            },
            WatchDecision::Wait => {
                let endpoint = if elapsed < STOP_AFTER { STOP_AFTER } else { HARD_AFTER };
                thread::park_timeout(endpoint.saturating_sub(elapsed));
            },
        }
    }
}

fn await_armed(owner: &OriginalController, original: &JoinHandle<WatchdogExit>) -> bool {
    loop {
        let elapsed = owner.control.sample();
        let state = owner.control.state();
        // A finished original cannot protect native work, even with stale ready
        // flags. Check actual handle state before granting any positive admission.
        if original.is_finished() || state & STOP != 0 {
            owner.control.fail(ControllerFault::Barrier);
            return false;
        }
        if may_begin(state, elapsed) { return true; }
        // The real watchdog unparks this original caller at its acknowledgement.
        thread::park_timeout(STOP_AFTER.saturating_sub(elapsed).min(Duration::from_secs(1)));
    }
}

fn returned_is_settled(returned: &Result<(), AcquisitionError>) -> bool {
    match returned {
        // The actual driver supplies BOTH original finality observations for Ok.
        Ok(()) => true,
        // These constructors/decoders have no original native effects.
        Err(AcquisitionError::Profile(_) | AcquisitionError::NativeConstruction(_)) => true,
        Err(AcquisitionError::Failed(report)) => report.settlement == CloseOutcome::Settled,
        // An existing/poisoned native owner is not ours to replace or guess clear.
        Err(AcquisitionError::AlreadyStarted | AcquisitionError::OwnerUnavailable) => false,
    }
}

fn retire_and_join(owner: &OriginalController, original: &mut Option<JoinHandle<WatchdogExit>>) {
    // Caller reaches here only after actual known finality, or before any native
    // invocation. RETIRE requests watchdog shutdown, never successful acquisition.
    owner.control.state.fetch_or(RETIRE, Ordering::SeqCst);
    original.as_ref().unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState))
        .thread().unpark();
    loop {
        let elapsed = owner.control.sample();
        if original.as_ref().unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState))
            .is_finished() { break; }
        // Once native work has actually settled, the original caller drives the
        // SAME absolute deadline through watchdog shutdown. No detached join.
        thread::park_timeout(HARD_AFTER.saturating_sub(elapsed).min(Duration::from_millis(10)));
    }
    let handle = original.take().unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState));
    let returned = match handle.join() {
        Ok(returned) => returned,
        Err(_original_panic) => owner.control.abort(ControllerFault::WatchdogJoin),
    };
    if owner.original_joined.set(()).is_err() {
        owner.control.abort(ControllerFault::ControllerState);
    }
    // is_finished/notification was not evidence of join; only the return above is.
    if returned.elapsed >= HARD_AFTER || (owner.returned.get().is_some() && !returned.armed) {
        owner.control.fail(ControllerFault::WatchdogProtocol);
    }
}

fn finish(owner: &'static OriginalController) -> Result<(), ControllerError> {
    let elapsed = owner.control.sample(); // actual post-join aggregate observation
    let acquisition_ok = matches!(owner.returned.get(), Some(Ok(())));
    #[cfg(feature = "windows-installer-selection")]
    let acquisition_ok = {
        let selection_ok = owner.selection_returned.get().is_some_and(|returned|
            returned.is_ok() && crate::windows_installer_selection::original_settled_for(returned));
        let activation_ok = owner.activation_returned.get().is_none_or(|returned|
            returned.is_ok() && acquisition::retained_activation_settled_for(returned));
        // Acquisition-only remains acquisition-only. A selection request cannot
        // use that return, missing selection, copied report or unjoined watchdog.
        if owner.selection_only { selection_ok && owner.returned.get().is_none() }
        else { acquisition_ok && activation_ok && (owner.selection_returned.get().is_none() || selection_ok) }
    };
    let original_joined = owner.original_joined.get().is_some();
    let returned_error = match owner.returned.get() { Some(Err(error)) => Some(error), _ => None };
    let successful = may_succeed(owner.control.state(), elapsed, acquisition_ok,
        original_joined, owner.control.failures());
    if !successful && returned_error.is_none() && owner.control.failures().is_empty() {
        owner.control.fail(ControllerFault::ControllerState);
    }
    let result = if successful { Ok(()) } else {
        Err(AcquisitionControllerReport { returned_acquisition_error: returned_error,
            controller_failures: owner.control.failures(),
            acquisition_return_observed: owner.returned.get().is_some(),
            original_watchdog_joined: original_joined,
            #[cfg(feature = "windows-installer-selection")]
            returned_activation_error: owner.activation_returned.get().and_then(|r| r.as_ref().err()).copied(),
            #[cfg(feature = "windows-installer-selection")]
            returned_selection_error: owner.selection_returned.get().and_then(|r| r.as_ref().err()),
            #[cfg(feature = "windows-installer-selection")]
            selection_return_observed: owner.selection_returned.get().is_some(),
        })
    };
    if owner.final_result.set(result).is_err() {
        owner.control.abort(ControllerFault::ControllerState);
    }
    match owner.final_result.get() {
        Some(Ok(())) => Ok(()),
        Some(Err(report)) => Err(ControllerError::Failed(report)),
        None => owner.control.abort(ControllerFault::ControllerState),
    }
}

/// Fixed production acquisition arm, ONLY for a dedicated isolated bridge.
/// No callback, executable, budget, expected hashes, destination or runtime
/// profile can be passed. The source candidate must still pass real native
/// admission. Ok means only original retained input acquisition plus joined
/// watchdog; it is NOT publication, activation or installer qualification.
pub fn run_embedded_acquisition_once(source_candidate: &str) -> Result<(), ControllerError> {
    run_fixed_acquisition_once(source_candidate, FixedAcquisitionArm::Embedded)
}
#[derive(Clone, Copy)]
enum FixedAcquisitionArm {
    Embedded,
    #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
    Fixture(mrk_windows_installed_native::installer_fixture_data::InstallerFixtureCase),
    #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
    SelectionFixture(mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixtureCase),
}
fn run_fixed_acquisition_once(source_candidate: &str, arm: FixedAcquisitionArm) -> Result<(), ControllerError> {
    run_fixed_work_once(FixedControllerWork::Acquisition { source_candidate, arm })
}
/// Closed typed arms; no callback, command, destination or budget can be supplied.
enum FixedControllerWork<'a> {
    Acquisition { source_candidate: &'a str, arm: FixedAcquisitionArm },
    #[cfg(feature = "windows-installer-selection")]
    Preview { mode: mrk_windows_installed_native::SelectionMode, recovery: Option<String> },
    #[cfg(feature = "windows-installer-selection")]
    Maintenance { confirmed: mrk_windows_installed_native::SelectionPreview, recovery: Option<String> },
    #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
    SelectionFixture(mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixtureCase),
}
fn run_fixed_work_once(work: FixedControllerWork<'_>) -> Result<(), ControllerError> {
    let started = Instant::now(); // starts once BEFORE owner/hook/thread preparation
    let controller = OriginalController::new(started);
    #[cfg(feature = "windows-installer-selection")]
    let controller = {
        let mut controller = controller;
        controller.selection_only = !matches!(&work, FixedControllerWork::Acquisition { .. });
        controller
    };
    if OWNER.set(controller).is_err() {
        if let Some(owner) = OWNER.get() { owner.control.fail(ControllerFault::Duplicate); }
        return Err(ControllerError::AlreadyStarted);
    }
    let owner = OWNER.get().unwrap_or_else(|| std::process::abort());
    install_abort_hook(owner); // never run this production entry in a shared harness
    let mut original = owner.watchdog.lock()
        .unwrap_or_else(|_| owner.control.abort(ControllerFault::ControllerState));
    let elapsed = owner.control.sample();
    if clock_phase(elapsed) != ClockPhase::Work || owner.control.state() & STOP != 0 {
        return finish(owner); // no watchdog and no native work were started
    }
    let caller = thread::current();
    let control = &owner.control; // closure captures only clock/control, not the owner
    match thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
        .spawn(move || watchdog(control, caller)) {
        // Retain the ACTUAL returned handle immediately. No formatting/allocation
        // or other fallible operation intervenes before its original custody.
        Ok(handle) => *original = Some(handle),
        Err(_) => {
            owner.control.fail(ControllerFault::SpawnUnavailable);
            return finish(owner);
        },
    }
    owner.control.state.fetch_or(GO, Ordering::SeqCst); // only AFTER retention
    let handle = original.as_ref().unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState));
    handle.thread().unpark();
    if await_armed(owner, handle) {
        // The loan is made only from this registered owner's actual locked
        // original slot after acknowledgement, and stays through native return.
        if let Ok(guard) = ActiveInstallerGuard::borrow_actual(owner, &original) {
            // Original calling thread stays the worker; selection does not
            // transfer a NativeBook or manufacture an acquisition return.
            match work {
                FixedControllerWork::Acquisition { source_candidate, arm } => {
                    let returned = match arm {
                        FixedAcquisitionArm::Embedded => acquisition::acquire_embedded_inputs_once(source_candidate),
                        #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
                        FixedAcquisitionArm::Fixture(case) => retained_fixture::acquire(case, source_candidate),
                        #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
                        FixedAcquisitionArm::SelectionFixture(case) => selection_fixture::acquire(case, source_candidate),
                    };
                    // Store the actual native/policy result BEFORE reading a later STOP,
                    // clock, controller or join failure. None can replace this first result.
                    if owner.returned.set(returned).is_err() {
                        owner.control.abort(ControllerFault::ControllerState);
                    }
                    let returned = owner.returned.get().unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState));
                    if !returned_is_settled(returned) {
                        owner.control.abort(ControllerFault::NativeFinalityUnknown);
                    }
                    #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
                    if let FixedAcquisitionArm::Fixture(case) = arm {
                        let fixture_result = retained_fixture::after_acquisition(case, &guard);
                        if owner.fixture_returned.set(fixture_result).is_err() {
                            owner.control.abort(ControllerFault::ControllerState);
                        }
                        if owner.fixture_returned.get().is_some_and(|r| r.is_err()) {
                            owner.control.fail(ControllerFault::ControllerState);
                        }
                    }
                    #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
                    if let FixedAcquisitionArm::SelectionFixture(case) = arm {
                        selection_fixture::after_acquisition(case, &guard);
                    }
                },
                #[cfg(feature = "windows-installer-selection")]
                FixedControllerWork::Preview { mode, recovery } => {
                    let _ = crate::windows_installer_selection::preview_with_original_guard(&guard, mode, recovery);
                },
                #[cfg(feature = "windows-installer-selection")]
                FixedControllerWork::Maintenance { confirmed, recovery } => {
                    let _ = crate::windows_installer_selection::maintain_with_original_guard(&guard, confirmed, recovery);
                },
                #[cfg(all(test, feature = "windows-installer-selection-fixture"))]
                FixedControllerWork::SelectionFixture(case) => selection_fixture::perform(case, &guard),
            }
            let _ = guard.check(); // actual returned error/finality was selected first
        }
    }
    retire_and_join(owner, &mut original);
    finish(owner)
}


#[cfg(feature = "windows-installer-selection")]
pub(crate) fn preview_launch_entries_once(mode: mrk_windows_installed_native::SelectionMode,
    recovery: Option<String>) -> Result<mrk_windows_installed_native::SelectionPreview, ControllerError> {
    // Separate dedicated read-only invocation. Return only AFTER original
    // settlement, retirement, actual watchdog join and final gate.
    run_fixed_work_once(FixedControllerWork::Preview { mode, recovery })?;
    let owner = OWNER.get().unwrap_or_else(|| std::process::abort());
    match owner.selection_returned.get() {
        Some(Ok(SelectionOutcome::Preview(preview))) => Ok(preview.clone()),
        _ => owner.control.abort(ControllerFault::ControllerState),
    }
}
#[cfg(feature = "windows-installer-selection")]
pub(crate) fn maintain_launch_entries_once(confirmed: mrk_windows_installed_native::SelectionPreview,
    recovery: Option<String>) -> Result<mrk_windows_installed_native::SelectionReport, ControllerError> {
    // Private typed maintenance only. InstallActivated is refused here; that
    // mode requires the not-yet-enabled full installer original loan sequence.
    run_fixed_work_once(FixedControllerWork::Maintenance { confirmed, recovery })?;
    let owner = OWNER.get().unwrap_or_else(|| std::process::abort());
    match owner.selection_returned.get() {
        Some(Ok(SelectionOutcome::Applied(report))) => Ok(report.clone()),
        _ => owner.control.abort(ControllerFault::ControllerState),
    }
}

#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
mod retained_fixture;
#[cfg(all(test, feature = "windows-installer-selection-fixture"))]
mod selection_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_input_acquisition::PolicyError;
    use std::sync::Arc;

    // Every case here is an explicit, separate owned disposable Windows child.
    // Never combine these cases in a shared libtest process: process-lifetime
    // owners/STOP/hook cannot be reset. Production acquisition needs the real
    // protected native fixture separately; these tests do not fabricate one.
    #[test]
    #[ignore = "Root-owned disposable Windows child only; no shared runner"]
    fn owned_child_short_watchdog_acknowledges_then_original_join_returns() {
        let control = Arc::new(Control::new(Instant::now()));
        let worker_control = Arc::clone(&control);
        let caller = thread::current();
        let original = thread::spawn(move || watchdog(&worker_control, caller));
        // No assertion/unwind while the original worker can still be running.
        control.state.fetch_or(GO, Ordering::SeqCst);
        original.thread().unpark();
        while control.state() & ARMED == 0 && control.elapsed() < Duration::from_secs(5)
            && !original.is_finished() {
            thread::park_timeout(Duration::from_millis(10));
        }
        let acknowledged = control.state() & ARMED != 0;
        control.state.fetch_or(RETIRE, Ordering::SeqCst);
        original.thread().unpark();
        while !original.is_finished() {
            control.sample();
            thread::park_timeout(Duration::from_millis(10));
        }
        let returned = original.join();
        assert!(acknowledged);
        let returned = returned.unwrap();
        assert!(returned.armed);
        assert!(returned.elapsed < STOP_AFTER);
        assert!(control.failures().is_empty());
    }

    #[test]
    #[ignore = "Root-owned disposable Windows child only; absorbing global STOP"]
    fn owned_child_finished_guard_refuses_stale_ready_data_before_native() {
        let owner = OriginalController::new(Instant::now());
        let mut original = owner.watchdog.lock().unwrap();
        // Real returned handle with intentionally early completion. This closure
        // supplies return DATA, not native work or a real watchdog acknowledgement.
        match thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
            .spawn(|| WatchdogExit { armed: true, elapsed: Duration::ZERO }) {
            Ok(handle) => *original = Some(handle),
            Err(_) => panic!("fixed short guard thread unavailable"),
        }
        let handle = original.as_ref().unwrap();
        while !handle.is_finished() {
            if owner.control.elapsed() >= Duration::from_secs(5) {
                owner.control.abort(ControllerFault::Barrier);
            }
            thread::park_timeout(Duration::from_millis(10));
        }
        // Stale ready DATA must not overrule the actual original's completion.
        owner.control.state.fetch_or(GO | ARMED, Ordering::SeqCst);
        let admitted = await_armed(&owner, handle);
        retire_and_join(&owner, &mut original);
        // No assertion or unwind while the actual thread could remain running.
        assert!(!admitted);
        assert!(owner.control.failures().contains(ControllerFault::Barrier));
        assert!(owner.original_joined.get().is_some());
        assert!(owner.returned.get().is_none());
    }

    #[test]
    #[ignore = "Root-owned disposable Windows child only; one-shot global owner"]
    fn owned_child_duplicate_never_replaces_owner_clock_or_original_handle() {
        let started = Instant::now();
        assert!(OWNER.set(OriginalController::new(started)).is_ok());
        let original = OWNER.get().unwrap() as *const OriginalController;
        assert!(matches!(run_embedded_acquisition_once("unused"), Err(ControllerError::AlreadyStarted)));
        let retained = OWNER.get().unwrap();
        assert_eq!(retained as *const OriginalController, original);
        assert_eq!(retained.control.started, started);
        assert!(retained.watchdog.lock().unwrap().is_none());
        assert!(retained.prior_hook.get().is_none());
        assert!(retained.returned.get().is_none());
        assert!(retained.control.failures().contains(ControllerFault::Duplicate));
        assert!(!may_begin(retained.control.state(), Duration::ZERO));
    }

    #[test]
    #[ignore = "Root-owned disposable Windows child only; absorbing global STOP"]
    fn owned_child_injected_error_data_stays_primary_in_real_reporting_path() {
        // Injected Profile-error DATA exercises real retained-result/reporting
        // code. No native acquisition, native failure or actual join is claimed.
        let owner = Box::leak(Box::new(OriginalController::new(Instant::now())));
        assert!(owner.returned.set(Err(AcquisitionError::Profile(PolicyError::Binding))).is_ok());
        owner.control.fail(ControllerFault::StopRequested);
        owner.control.fail(ControllerFault::WatchdogJoin);
        let report = match finish(owner) {
            Err(ControllerError::Failed(report)) => report,
            _ => panic!("a failed original result cannot succeed"),
        };
        assert!(matches!(report.primary_failure(), Some(PrimaryFailure::Acquisition(AcquisitionError::Profile(PolicyError::Binding)))));
        assert!(report.controller_failures.contains(ControllerFault::StopRequested));
        assert!(report.controller_failures.contains(ControllerFault::WatchdogJoin));
        assert_eq!(report.controller_failures.first, Some(ControllerFault::StopRequested));
        assert!(!report.original_watchdog_joined);
    }

    #[test]
    #[ignore = "Root-owned disposable Windows child only; production hook and absorbing STOP"]
    fn owned_child_unarmed_original_cannot_issue_publication_guard() {
        assert!(OWNER.set(OriginalController::new(Instant::now())).is_ok());
        let owner = OWNER.get().unwrap();
        install_abort_hook(owner);
        let mut original = owner.watchdog.lock()
            .unwrap_or_else(|_| owner.control.abort(ControllerFault::ControllerState));
        let control = &owner.control;
        let caller = thread::current();
        match thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
            .spawn(move || watchdog(control, caller)) {
            Ok(handle) => *original = Some(handle),
            Err(_) => owner.control.abort(ControllerFault::SpawnUnavailable),
        }
        // An actual held thread is insufficient: no GO or actual ARMED was
        // published. No native operation or Publication owner is invoked.
        let refused = ActiveInstallerGuard::borrow_actual(owner, &original).is_err();
        retire_and_join(owner, &mut original);
        assert!(refused);
        assert!(owner.original_joined.get().is_some());
        assert!(owner.publication_returned.get().is_none());
        assert!(owner.control.failures().contains(ControllerFault::Barrier));
    }

    #[test]
    #[ignore = "Root-owned disposable Windows child only; production hook and absorbing STOP"]
    fn owned_child_active_guard_rejects_other_caller_and_preserves_returned_error_data() {
        let started = Instant::now();
        assert!(OWNER.set(OriginalController::new(started)).is_ok());
        let owner = OWNER.get().unwrap();
        install_abort_hook(owner);
        let mut original = owner.watchdog.lock()
            .unwrap_or_else(|_| owner.control.abort(ControllerFault::ControllerState));
        let control = &owner.control;
        let caller = thread::current();
        match thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
            .spawn(move || watchdog(control, caller)) {
            Ok(handle) => *original = Some(handle),
            Err(_) => owner.control.abort(ControllerFault::SpawnUnavailable),
        }
        owner.control.state.fetch_or(GO, Ordering::SeqCst);
        let handle = original.as_ref()
            .unwrap_or_else(|| owner.control.abort(ControllerFault::ControllerState));
        handle.thread().unpark();
        if !await_armed(owner, handle) { owner.control.abort(ControllerFault::Barrier); }
        let (acquisition_missing, other, first, positive, native_boundary) = {
            let guard = ActiveInstallerGuard::borrow_actual(owner, &original)
                .unwrap_or_else(|_| owner.control.abort(ControllerFault::Barrier));
            let acquisition_missing = guard.require_acquired_inputs();
            let other = thread::scope(|scope| {
                // A bounded second caller only checks controller DATA. It is
                // actually joined before this scope exits; no native transfer.
                let worker = thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
                    .spawn_scoped(scope, || guard.check())
                    .unwrap_or_else(|_| owner.control.abort(ControllerFault::SpawnUnavailable));
                worker.join().unwrap_or_else(|_| owner.control.abort(ControllerFault::WatchdogJoin))
            });
            // Injected policy-error DATA into the real production result gate,
            // NOT an actual native publication/failure/finality receipt.
            let first = guard.after_return(Err::<RuntimePrepared, _>(PublicationError::Profile), PublicationError::InstallerGuard);
            let positive = guard.after_return(Ok(()), PublicationError::InstallerGuard);
            let first = guard.retain_publication_return(first);
            // STOP must not prevent the actual settlement-custody check.
            mrk_windows_installed_native::InstallerBoundary::settlement_boundary(&guard);
            let native_boundary = mrk_windows_installed_native::InstallerBoundary::producing_boundary(&guard);
            (acquisition_missing, other, first, positive, native_boundary)
        };
        retire_and_join(owner, &mut original);
        // Every task-owned thread is actually joined before assertions.
        assert_eq!(acquisition_missing, Err(ControllerFault::ControllerState));
        assert!(owner.returned.get().is_none()); // a real armed guard is not acquisition success
        assert_eq!(native_boundary, Err(mrk_windows_installed_native::Error::State));
        assert_eq!(other, Err(ControllerFault::ControllerState));
        assert_eq!(first, Err(PublicationError::Profile));
        assert_eq!(positive, Err(PublicationError::InstallerGuard));
        assert_eq!(owner.publication_returned.get(), Some(&Err(PublicationError::Profile)));
        assert_eq!(owner.control.started, started);
        assert!(owner.original_joined.get().is_some());
        assert!(owner.control.failures().contains(ControllerFault::PublicationFailed));
        assert_eq!(owner.control.failures().first, Some(ControllerFault::ControllerState));
    }

    #[test]
    #[ignore = "Expected fatal exit; ONLY an owned disposable Windows child with original process wait"]
    fn owned_child_hard_expiry_uses_actual_current_process_failure_boundary() {
        // Test-local aged start does not add a production clock/budget override.
        let started = Instant::now().checked_sub(HARD_AFTER).unwrap();
        let control = Control::new(started);
        let _ = watchdog(&control, thread::current());
        // Unexpected return gives a normal successful test exit, which the
        // original outer child owner must reject. Do not substitute panic.
    }

    #[test]
    #[ignore = "Expected fatal exit; ONLY an owned disposable Windows child with original process wait"]
    fn owned_child_production_panic_hook_cannot_unwind_or_detach() {
        assert!(OWNER.set(OriginalController::new(Instant::now())).is_ok());
        install_abort_hook(OWNER.get().unwrap());
        panic!("fixed owned-child unwind injection");
    }
}
