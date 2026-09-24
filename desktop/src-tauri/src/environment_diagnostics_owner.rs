//! Original-resource owner for fixed, explicitly started build-tool diagnostics.
//! C/A/W command ownership stays in the core. This is NOT a Supervisor profile,
//! a generic runner, an account/signing owner, or a runtime qualification grant.
use std::{future::{pending, Future}, path::PathBuf, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context as TaskContext, Poll, Wake, Waker}, time::{Duration, Instant}};
use serde_json::Value;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStdin, ChildStdout, ChildStderr},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch}, task::JoinHandle};
#[cfg(any(all(unix, debug_assertions, feature = "development-runtime"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
use {std::process::Stdio, tokio::process::Command};
use crate::{environment_diagnostics_protocol::{self as wire, Availability, Capability, Context, Finality, Frame,
    Outcome, Phase, Profile, Projection, Reason, Start, Status}, error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}};
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
use crate::installed_runtime::{CloseOutcome, EnvironmentDiagnosticsRuntimeSlots};

// Separate native/document and interpreter/core/neutral-cwd qualifications.
// Host name, development-runtime, metadata inspection and a renderer checkbox
// confer neither. No environment-variable or other-owner fixture bypass exists.
const NATIVE_QUALIFIED: bool = false;
const RUNTIME_QUALIFIED: bool = false;
const WORK: Duration = Duration::from_secs(6);
const FINALITY: Duration = Duration::from_secs(10);

#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
#[path = "environment_diagnostics_hosted_tests.rs"]
pub(crate) mod hosted_tests;
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) use hosted_tests::{RegistrationPermit as EnvironmentRegistrationPermit, RuntimeSelection as EnvironmentRuntimeSelection};

#[derive(Clone, Copy)]
struct Clocks { admitted: Instant, work: Instant, finality: Instant }
impl Clocks {
    fn new(admitted: Instant) -> Self { Self { admitted, work: admitted + WORK, finality: admitted + FINALITY } }
}
#[derive(Clone)]
pub(crate) struct EnvironmentDiagnosticsOwner { inner: Arc<Inner> }
struct Inner {
    runtime: RuntimeConfig, registry: Mutex<Registry>, changes: watch::Sender<u32>, changed: Notify,
    poisoned: AtomicBool,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Mutex<Option<std::sync::Weak<hosted_tests::Permit>>>,
}
struct Registry {
    revision: u32, exhausted: bool, disabled: bool, stopping: bool, document_lost: bool,
    capability: Availability, active: Option<Active>, last: Option<Projection>,
}
struct Active {
    owner: Arc<Session>, projection: Projection, first_stop: Option<Instant>, work_expired: bool,
    accepted: bool, terminal: bool, unknown: bool, final_join_seen: bool,
}
struct Session {
    id: String, generation: String, context: Context, profile: Profile, clocks: Clocks,
    registration: u32, project: PathBuf, draft: Mutex<Option<Value>>, request: AsyncMutex<Option<Vec<u8>>>,
    stop: watch::Sender<bool>, pipes: watch::Sender<Pipes>, frames: mpsc::Sender<Frame>, wake: Notify,
    output_bytes: AtomicUsize, resource_unknown: AtomicBool,
    driver_done: AtomicBool, driver_joined: AtomicBool, driver_failed: AtomicBool,
    watchdog_joined: AtomicBool, watchdog_failed: AtomicBool, manager_failed: AtomicBool,
    startup: Mutex<Startup>, resources: AsyncMutex<Resources>,
    input: Arc<AsyncMutex<Pipe<ChildStdin>>>, output: Arc<AsyncMutex<Pipe<ChildStdout>>>, error: Arc<AsyncMutex<Pipe<ChildStderr>>>,
    driver: AsyncMutex<Option<JoinHandle<()>>>, watchdog: Mutex<Option<JoinHandle<bool>>>,
    manager: AsyncMutex<Option<JoinHandle<()>>>, observer: AsyncMutex<Option<JoinHandle<bool>>>,
    driver_return: Mutex<Option<Result<(), tokio::task::JoinError>>>,
    manager_return: Mutex<Option<Result<(), tokio::task::JoinError>>>,
    observer_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>,
    watchdog_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Option<Arc<hosted_tests::Permit>>,
}
#[derive(Default)]
struct Startup { attempted: bool, returned: bool, failed: bool, child: Option<Child> }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pipes { Pending, Available, Absent }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Close { New, Attempted, Settled, Unknown }
struct Pipe<T> { io: Option<T>, close: Close }
impl<T> Default for Pipe<T> { fn default() -> Self { Self { io: None, close: Close::New } } }
#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>, inspection_joined: bool, inspection_failed: bool,
    inspection_started: bool, inspection_error: Option<tokio::task::JoinError>,
    acquisition: Option<JoinHandle<()>>, acquisition_joined: bool, acquisition_failed: bool,
    acquisition_started: bool, acquisition_error: Option<tokio::task::JoinError>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed: Option<Arc<Mutex<EnvironmentDiagnosticsRuntimeSlots>>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    installed_started: bool, installed_joined: bool, installed_failed: bool,
    child: Option<Child>, waited: Option<ExitStatus>, wait_failed: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    write_failed: bool, out_failed: bool, err_failed: bool, frames: Option<mpsc::Receiver<Frame>>,
}
struct WriteEnd { sent: bool, closed: bool, failed: bool }
struct ReadEnd { frames: usize, eof: bool, closed: bool, failed: bool }

fn original_session(r: &Registry, owner: &Session) -> bool {
    r.active.as_ref().is_some_and(|a| std::ptr::eq(Arc::as_ptr(&a.owner), owner)
        && a.owner.id == owner.id && a.owner.generation == owner.generation && a.owner.context == owner.context
        && a.owner.registration == owner.registration && a.owner.project == owner.project)
}
// A Ready return is distinct from permission to retire. STOP and ordinary
// settled cancellation/shutdown are allowed; Unknown and H are absorbing.
fn final_clock_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    original_session(r, owner) && !r.disabled && !r.exhausted && !inner.poisoned.load(Ordering::SeqCst)
        && !owner.resource_unknown.load(Ordering::SeqCst) && now < owner.clocks.finality
        && r.active.as_ref().is_some_and(|a| !a.unknown)
}

/// Ticket contains only native identity, an executor and the original T. It is
/// prepared before the real document lock; no IO/child/request task is started.
pub(crate) struct Ticket { owner: Arc<Inner>, id: String, generation: String, clocks: Clocks, executor: tokio::runtime::Handle }
pub(crate) struct Admitted { status: Status, release: oneshot::Sender<()> }
impl Admitted {
    /// Called after DocumentBinding unlocks. A lost sender stops this original
    /// driver; it never hands lifecycle custody to the invoke future.
    pub(crate) fn release(self) -> Status { let _ = self.release.send(()); self.status }
}
fn nonce() -> Result<String, BridgeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes { value.push(HEX[usize::from(byte >> 4)] as char); value.push(HEX[usize::from(byte & 15)] as char); }
    Ok(value)
}
fn unavailable() -> BridgeError { BridgeError::new("environment_diagnostics_unavailable", "Build-tool diagnostics are not qualified for this host, runtime and original document.") }
fn busy() -> BridgeError { BridgeError::new("environment_diagnostics_busy", "Finish or cancel the original native operation before checking build tools.") }
fn invalid_owner() -> BridgeError { BridgeError::new("environment_diagnostics_owner", "This request does not identify the original build-tool diagnostics run.") }
fn refused(reason: Availability) -> BridgeError {
    match reason {
        Availability::CleanupUnknown => BridgeError::cleanup_unknown(), Availability::Shutdown => BridgeError::shutdown(),
        Availability::Busy => busy(), Availability::DocumentLost => invalid_owner(), _ => unavailable(),
    }
}

impl EnvironmentDiagnosticsOwner {
    pub(crate) fn new(runtime: RuntimeConfig) -> Self {
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner { runtime, registry: Mutex::new(Registry { revision: 0, exhausted: false,
            disabled: false, stopping: false, document_lost: false, capability: Availability::RuntimeUnqualified,
            active: None, last: None }), changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: Mutex::new(None),
        }) }
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub(crate) fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) }
    pub(crate) fn can_exit(&self) -> bool { self.reconcile(); !self.inner.poisoned.load(Ordering::SeqCst) && self.inner.lock().active.is_none() }
    pub(crate) fn busy(&self) -> bool { !self.can_exit() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> {
        if self.disabled() { Err(BridgeError::cleanup_unknown()) }
        else if self.stopping() { Err(BridgeError::shutdown()) }
        else if self.busy() { Err(busy()) } else { Ok(()) }
    }
    pub(crate) fn ticket(&self) -> Result<Ticket, BridgeError> {
        let clocks = Clocks::new(Instant::now()); // Before entropy, runtime inspection, acquisition or await.
        let executor = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
        if !self.inner.qualified() || Profile::current().is_none() { return Err(unavailable()); }
        Ok(Ticket { owner: self.inner.clone(), id: nonce()?, generation: nonce()?, clocks, executor })
    }
    /// Only DocumentBinding calls this under its actual admission mutex after
    /// reciprocal native checks and the in-memory original registry lookup.
    pub(crate) fn admit(&self, ticket: Ticket, input: Start, registration: u32, project: PathBuf) -> Result<Admitted, BridgeError> {
        self.reconcile();
        if !Arc::ptr_eq(&ticket.owner, &self.inner) { return Err(invalid_owner()); }
        let profile = Profile::current().ok_or_else(unavailable)?;
        let mut r = self.inner.lock();
        let reason = self.inner.availability(&r, Availability::Available);
        if reason != Availability::Available { return Err(refused(reason)); }
        if r.last.as_ref().is_some_and(|last| last.run_id == ticket.id || last.owner_generation == ticket.generation) { return Err(unavailable()); }
        if Instant::now() >= ticket.clocks.work { return Err(BridgeError::timeout()); }
        let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
        let (frames, receiver) = mpsc::channel(2);
        let context = input.context();
        let projection = Projection { run_id: ticket.id.clone(), owner_generation: ticket.generation.clone(), context: context.clone(),
            phase: Phase::Starting, outcome: None, finality: Finality::Pending, reason: Reason::None, result: None };
        let owner = Arc::new(Session { id: ticket.id, generation: ticket.generation, context, profile, clocks: ticket.clocks,
            registration, project, draft: Mutex::new(Some(input.draft)), request: AsyncMutex::new(None), stop, pipes, frames, wake: Notify::new(),
            output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false), driver_done: AtomicBool::new(false),
            driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false), watchdog_joined: AtomicBool::new(false),
            watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false), startup: Mutex::new(Startup::default()),
            resources: AsyncMutex::new(Resources { frames: Some(receiver),
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                installed: self.inner.installed_selected().then(|| Arc::new(Mutex::new(EnvironmentDiagnosticsRuntimeSlots::new()))),
                ..Resources::default() }),
            input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
            driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: self.inner.fixture.lock().ok().and_then(|p| p.as_ref().and_then(std::sync::Weak::upgrade)),
        });
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture { permit.bind(&owner)?; }
        let (release, enter) = oneshot::channel();
        // Acquire every new roster slot before publishing or starting a task.
        let mut book = owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut driver = owner.driver.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut manager = owner.manager.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut observer = owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        r.active = Some(Active { owner: owner.clone(), projection, first_stop: None, work_expired: false,
            accepted: false, terminal: false, unknown: false, final_join_seen: false });
        // Guards are constructed BEFORE spawn: even an unpolled task loss is
        // retained Unknown, not a successful no-op or permission to replace it.
        *watchdog_slot = Some(ticket.executor.spawn(watchdog(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.writer = Some(ticket.executor.spawn(write_request(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.stdout = Some(ticket.executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.output.clone(), false, Guard::new(&self.inner, &owner))));
        book.stderr = Some(ticket.executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.error.clone(), true, Guard::new(&self.inner, &owner))));
        *driver = Some(ticket.executor.spawn(drive(self.inner.clone(), owner.clone(), enter, Guard::new(&self.inner, &owner))));
        *manager = Some(ticket.executor.spawn(manage(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        *observer = Some(ticket.executor.spawn(observe_final(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        self.inner.bump(&mut r);
        let status = self.inner.snapshot_locked(&mut r, Availability::Available)?;
        drop(observer); drop(manager); drop(watchdog_slot); drop(driver); drop(book);
        drop(r);
        // Register the real final-handle completion waker before original GO.
        // This polls only a JoinHandle, never the task body or a native child.
        self.reconcile();
        Ok(Admitted { status, release })
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> {
        self.reconcile(); self.inner.snapshot_locked(&mut self.inner.lock(), gate)
    }
    pub(crate) fn cancel(&self, run: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        self.reconcile(); let mut r = self.inner.lock();
        if let Some(a) = r.active.as_ref().filter(|a| a.owner.id == run && a.owner.generation == generation) {
            let owner = a.owner.clone(); self.inner.stop_locked(&mut r, &owner, Reason::Cancelled, Instant::now());
        } else if !r.last.as_ref().is_some_and(|last| last.run_id == run && last.owner_generation == generation) { return Err(invalid_owner()); }
        self.inner.snapshot_locked(&mut r, gate)
    }
    pub(crate) fn document_lost(&self) {
        let mut r = self.inner.lock(); r.document_lost = true;
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::DocumentLost, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) fn context_changed(&self) {
        let mut r = self.inner.lock();
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::ContextChanged, Instant::now()); }
    }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool {
        let r = self.inner.lock(); r.active.as_ref().is_none_or(|a| a.owner.registration == registration)
    }
    pub(crate) fn request_shutdown(&self) {
        let mut r = self.inner.lock(); r.stopping = true;
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::Shutdown, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> {
        self.request_shutdown();
        loop {
            if self.can_exit() { return Ok(()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            // DATA observation only; cannot restart, abandon or move T/W/H.
            tokio::select! { _ = self.inner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
        }
    }
    fn reconcile(&self) {
        let owner = { self.inner.lock().active.as_ref().map(|a| a.owner.clone()) };
        let Some(owner) = owner else { return; };
        let mut r = self.inner.lock();
        self.inner.advance_locked(&mut r, &owner, Instant::now());
        let Some(active) = r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner)) else { return; };
        if active.final_join_seen { return; }
        let mut watchdog_slot = match owner.watchdog.try_lock() {
            Ok(slot) => slot,
            Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(_)) => { self.inner.unknown_locked(&mut r, &owner); return; }
        };
        let Some(handle) = watchdog_slot.as_mut() else { self.inner.unknown_locked(&mut r, &owner); return; };
        // Pending installs the ORIGINAL completion waker. is_finished plus a
        // pre-return notification would lose the last Ready wake and require
        // caller polling; the original handle itself now wakes native observers.
        let waker = Waker::from(Arc::new(FinalWake(Arc::downgrade(&self.inner))));
        let mut context = TaskContext::from_waker(&waker);
        let Poll::Ready(result) = Pin::new(handle).poll(&mut context) else { return; };
        if let Some(a) = r.active.as_mut() { a.final_join_seen = true; }
        let positive = matches!(&result, Ok(true));
        let joined = result.is_ok();
        let recorded = record_join(&owner.watchdog_return, result);
        owner.watchdog_joined.store(joined && recorded, Ordering::SeqCst);
        owner.watchdog_failed.store(!joined || !recorded, Ordering::SeqCst);
        if positive && recorded {
                let now = Instant::now(); self.inner.advance_locked(&mut r, &owner, now);
                if !final_clock_clear(&self.inner, &r, &owner, now) {
                    // Preserve the original Ready value AND handle. This latch
                    // prevents all subsequent status calls from re-polling it.
                    owner.resource_unknown.store(true, Ordering::SeqCst);
                    self.inner.unknown_locked(&mut r, &owner); return;
                }
                watchdog_slot.take();
                // The actual last join, not a terminal's timestamp, retires.
                if let Some(mut active) = r.active.take() {
                    if !Arc::ptr_eq(&active.owner, &owner) { r.active = Some(active); return; }
                    active.projection.phase = Phase::Settled; active.projection.finality = Finality::Settled;
                    if active.projection.outcome.is_none() { set_failure_outcome(&mut active.projection); }
                    r.last = Some(active.projection); self.inner.bump(&mut r);
                }
        } else {
                // Keep the actual failed handle and never poll it a second time.
                owner.resource_unknown.store(true, Ordering::SeqCst);
                self.inner.unknown_locked(&mut r, &owner);
        }
    }
}
struct NoWake;
impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
struct FinalWake(std::sync::Weak<Inner>);
impl Wake for FinalWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(inner) = self.0.upgrade() {
            // No registry/handle lock and no invented public revision. The
            // existing native subscriber consumes Ready and bumps on retirement.
            inner.changes.send_modify(|_| {});
            inner.changed.notify_one();
        }
    }
}
fn record_join<T>(slot: &Mutex<Option<Result<T, tokio::task::JoinError>>>, result: Result<T, tokio::task::JoinError>) -> bool {
    match slot.lock() {
        Ok(mut slot) if slot.is_none() => { *slot = Some(result); true },
        _ => false, // Never replace an original result, even after poison.
    }
}
fn set_failure_outcome(p: &mut Projection) {
    p.outcome = Some(match p.reason {
        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown => Outcome::Cancelled,
        Reason::TimedOut => Outcome::TimedOut,
        Reason::RuntimeUnavailable if p.result.is_none() => Outcome::Unavailable,
        _ if p.result.as_ref().is_some_and(|r| r.completed_rows() > 0) => Outcome::Partial,
        _ => Outcome::Failed,
    });
}
impl Inner {
    fn installed_selected(&self) -> bool {
        NATIVE_QUALIFIED && RUNTIME_QUALIFIED && self.runtime.environment_diagnostics_installed_profile_available()
    }
    fn qualified(&self) -> bool {
        if self.installed_selected() { return true; }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if self.fixture.lock().ok().and_then(|p| p.as_ref().and_then(std::sync::Weak::upgrade)).is_some_and(|p| p.permits(self)) { return true; }
        false
    }
    fn lock(&self) -> MutexGuard<'_, Registry> {
        match self.registry.lock() {
            Ok(r) => r,
            Err(error) => { self.poisoned.store(true, Ordering::SeqCst); error.into_inner() },
        }
    }
    fn bump(&self, r: &mut Registry) {
        if r.exhausted { return; }
        match r.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            Some(next) => r.revision = next,
            None => { r.exhausted = true; r.disabled = true; if let Some(a) = &r.active { a.owner.stop.send_replace(true); a.owner.wake.notify_waiters(); } },
        }
        self.changes.send_replace(r.revision); self.changed.notify_waiters();
    }
    fn availability(&self, r: &Registry, gate: Availability) -> Availability {
        if r.disabled || r.exhausted || self.poisoned.load(Ordering::SeqCst) || gate == Availability::CleanupUnknown { Availability::CleanupUnknown }
        else if r.stopping || gate == Availability::Shutdown { Availability::Shutdown }
        else if r.document_lost || gate == Availability::DocumentLost { Availability::DocumentLost }
        else if r.active.is_some() || gate == Availability::Busy { Availability::Busy }
        else if Profile::current().is_none() { Availability::UnsupportedPlatform }
        else if !self.qualified() { Availability::RuntimeUnqualified }
        else { gate }
    }
    fn snapshot_locked(&self, r: &mut Registry, gate: Availability) -> Result<Status, BridgeError> {
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.advance_locked(r, &owner, Instant::now()); }
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(BridgeError::cleanup_unknown()); }
        let reason = self.availability(r, gate);
        if reason != r.capability { r.capability = reason; self.bump(r); }
        if r.exhausted { return Err(BridgeError::cleanup_unknown()); }
        let status = Status { schema_version: 1, status_revision: r.revision, capability: Capability { available: reason == Availability::Available, reason },
            active: r.active.as_ref().map(|a| a.projection.clone()), last_terminal: r.last.clone() };
        crate::edit_protocol::bounded(&status, wire::STATUS_LIMIT)?; Ok(status)
    }
    fn stop_locked(&self, r: &mut Registry, owner: &Session, reason: Reason, at: Instant) {
        let Some(active) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        // Earliest actual native observation, capped by the immutable W. Never
        // infer a hidden child failure time or append another cleanup budget.
        let at = at.min(owner.clocks.work).max(owner.clocks.admitted);
        let mut changed = false;
        if active.first_stop.is_none() { active.first_stop = Some(at); changed = true; }
        if active.projection.reason == Reason::None && reason != Reason::None { active.projection.reason = reason; changed = true; }
        if !active.unknown && active.projection.phase != Phase::Stopping { active.projection.phase = Phase::Stopping; changed = true; }
        if active.projection.reason != Reason::None { set_failure_outcome(&mut active.projection); }
        // endpoint() may revisit a retained Unknown indefinitely. Re-broadcasting
        // the same STOP there would wake its own just-created wait future and
        // turn watchdog/original-join waiting into a hot loop. Only a new latch
        // or actual projection transition needs another notification.
        let first_signal = owner.stop.send_if_modified(|stopped| {
            if *stopped { false } else { *stopped = true; true }
        });
        if changed || first_signal { owner.wake.notify_waiters(); }
        if changed { self.bump(r); }
    }
    fn unknown_locked(&self, r: &mut Registry, owner: &Session) {
        self.stop_locked(r, owner, Reason::CleanupUnknown, Instant::now());
        if let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) {
            if !a.unknown {
                a.unknown = true; a.projection.phase = Phase::RetainedUnknown; a.projection.finality = Finality::Unknown;
                set_failure_outcome(&mut a.projection); r.disabled = true; self.bump(r);
            }
        }
    }
    fn advance_locked(&self, r: &mut Registry, owner: &Session, now: Instant) {
        let Some(a) = r.active.as_ref().filter(|a| a.owner.id == owner.id) else { return; };
        let work_due = now >= owner.clocks.work && !a.work_expired;
        let finality_due = now >= owner.clocks.finality && !a.unknown;
        if work_due {
            if let Some(a) = r.active.as_mut() { a.work_expired = true; }
            self.stop_locked(r, owner, Reason::TimedOut, owner.clocks.work);
        }
        if finality_due || self.poisoned.load(Ordering::SeqCst) || owner.resource_unknown.load(Ordering::SeqCst) { self.unknown_locked(r, owner); }
    }
    fn stop(&self, owner: &Session, reason: Reason) {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now());
        self.stop_locked(&mut r, owner, reason, Instant::now());
    }
    fn unknown(&self, owner: &Session) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.unknown_locked(&mut r, owner); }
    fn endpoint(&self, owner: &Session) -> Option<Instant> {
        let mut r = self.lock(); let now = Instant::now(); self.advance_locked(&mut r, owner, now);
        let a = r.active.as_ref().filter(|a| a.owner.id == owner.id)?;
        if !a.work_expired { Some(owner.clocks.work) } else if !a.unknown { Some(owner.clocks.finality) } else { None }
    }
    fn accept(&self, owner: &Session, frame: Frame) {
        self.accept_at(owner, frame, Instant::now());
    }
    fn accept_at(&self, owner: &Session, frame: Frame, now: Instant) {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, now);
        let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        match frame {
            Frame::Accepted if !a.accepted && !a.terminal => {
                a.accepted = true;
                if a.first_stop.is_none() && !a.unknown { a.projection.phase = Phase::Checking; }
                self.bump(&mut r);
            }
            Frame::Terminal(terminal) if a.accepted && !a.terminal => {
                a.terminal = true;
                let settled = terminal.lifetime.settled();
                let reason = match terminal.outcome { Outcome::Cancelled => Reason::Cancelled, Outcome::TimedOut => Reason::TimedOut,
                    Outcome::Partial | Outcome::Failed => Reason::CommandFailed, _ => Reason::None };
                if a.projection.reason == Reason::None { a.projection.outcome = Some(terminal.outcome); }
                a.projection.result = Some(terminal); self.bump(&mut r);
                // The core closed its input and cleanup/handlers before this
                // frame. Native closes its sole writer now but still requires
                // all actual waits/EOF/closes/task joins. No terminal-success race.
                if reason == Reason::None {
                    // Normal terminal retirement closes the already-finished
                    // core input, but is NOT a fabricated first-failure time.
                    if let Some(a) = r.active.as_mut() { if !a.unknown { a.projection.phase = Phase::Stopping; } }
                    owner.stop.send_replace(true); owner.wake.notify_waiters(); self.bump(&mut r);
                } else { self.stop_locked(&mut r, owner, reason, now); }
                if !settled { owner.resource_unknown.store(true, Ordering::SeqCst); self.unknown_locked(&mut r, owner); }
            }
            _ => {
                owner.resource_unknown.store(true, Ordering::SeqCst);
                self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner);
            }
        }
        owner.wake.notify_waiters();
    }
}

struct Guard { inner: Arc<Inner>, owner: Arc<Session>, complete: bool }
impl Guard { fn new(inner: &Arc<Inner>, owner: &Arc<Session>) -> Self { Self { inner: inner.clone(), owner: owner.clone(), complete: false } } }
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.complete { self.owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown(&self.owner); }
    }
}
trait OriginalClose { fn original_close(self) -> Result<(), ()>; }
macro_rules! close_pipe {
    ($type:ty) => { impl OriginalClose for $type {
        fn original_close(self) -> Result<(), ()> {
            #[cfg(unix)] { let owned = self.into_owned_fd().map_err(|_| ())?; nix::unistd::close(owned).map_err(|_| ()) }
            #[cfg(not(unix))] { let _ = self; Err(()) }
        }
    } };
}
close_pipe!(ChildStdin); close_pipe!(ChildStdout); close_pipe!(ChildStderr);
fn close_original<T: OriginalClose>(pipe: &mut Pipe<T>) -> bool {
    if pipe.close == Close::Settled { return true; }
    if pipe.close != Close::New { return false; }
    pipe.close = Close::Attempted;
    match pipe.io.take().map(OriginalClose::original_close) {
        Some(Ok(())) => { pipe.close = Close::Settled; true },
        _ => { pipe.close = Close::Unknown; false },
    }
}
async fn pipe_state(owner: &Session) -> Option<bool> {
    let mut state = owner.pipes.subscribe();
    loop {
        let value = *state.borrow_and_update();
        match value { Pipes::Available => return Some(true), Pipes::Absent => return Some(false), Pipes::Pending => {} }
        if state.changed().await.is_err() { return None; }
    }
}
async fn write_request(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> WriteEnd {
    match pipe_state(&owner).await {
        Some(true) => {}, other => { guard.complete = other.is_some(); return WriteEnd { sent: false, closed: false, failed: other.is_none() }; }
    }
    let mut input = owner.input.lock().await;
    let mut request = owner.request.lock().await;
    let mut stop = owner.stop.subscribe();
    let mut sent = false; let mut failed = false;
    if !*stop.borrow() {
        match (input.io.as_mut(), request.as_ref()) {
            (Some(writer), Some(bytes)) if bytes.len() <= wire::REQUEST_LIMIT => {
                let result = tokio::select! { biased;
                    _ = stop.changed() => None,
                    result = writer.write_all(bytes) => Some(result),
                };
                match result { Some(Ok(())) => sent = true, Some(Err(_)) => failed = true, None => {} }
            }
            _ => failed = true,
        }
    }
    request.take(); drop(request); // Retire only this original bounded input.
    if failed { inner.stop(&owner, Reason::ProtocolError); }
    if sent && !failed {
        // Hold this sole writer after the one complete request. Closing it is
        // STOP, not ordinary request framing or a renderer acknowledgment.
        while !*stop.borrow_and_update() { if stop.changed().await.is_err() { failed = true; break; } }
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if let Some(permit) = &owner.fixture { permit.boundary(&owner, hosted_tests::Boundary::WriterClose).await; }
    let closed = close_original(&mut input);
    if !closed { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
    guard.complete = true; WriteEnd { sent, closed, failed }
}
async fn read_output<T: AsyncRead + Unpin + OriginalClose>(inner: Arc<Inner>, owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>, stderr: bool, mut guard: Guard) -> ReadEnd {
    match pipe_state(&owner).await {
        Some(true) => {}, other => { guard.complete = other.is_some(); return ReadEnd { frames: 0, eof: false, closed: false, failed: other.is_none() }; }
    }
    let mut pipe = slot.lock().await; let mut buffer = [0u8; 4096]; let mut bytes = Vec::new();
    let mut frames = 0usize; let mut failed = false; let mut eof = false; let mut discard = false;
    loop {
        let Some(reader) = pipe.io.as_mut() else { failed = true; break; };
        match reader.read(&mut buffer).await {
            Ok(0) => { eof = true; if !bytes.is_empty() { failed = true; } break; },
            Ok(n) => {
                // One aggregate allowance including both transport streams and
                // framing. Continue draining after refusal without retaining raw text.
                let previous = owner.output_bytes.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
                    |value| Some(value.saturating_add(n))).unwrap_or(usize::MAX);
                if previous.saturating_add(n) > wire::RESPONSE_LIMIT || stderr { failed = true; discard = true; bytes.clear(); }
                if discard { inner.stop(&owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); continue; }
                for byte in &buffer[..n] {
                    if discard { break; }
                    bytes.push(*byte);
                    if *byte == b'\n' {
                        frames += 1;
                        let frame = if frames <= 2 { wire::decode(&bytes, &owner.id, &owner.generation, &owner.context, owner.profile.host()) }
                            else { Err(BridgeError::protocol()) };
                        let delivered = match frame { Ok(frame) => {
                            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
                            if matches!(&frame, Frame::Terminal(_)) { if let Some(permit) = &owner.fixture {
                                permit.boundary(&owner, hosted_tests::Boundary::TerminalHandoff).await;
                            } }
                            owner.frames.try_send(frame).is_ok()
                        }, Err(_) => false };
                        if !delivered { failed = true; discard = true; inner.stop(&owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
                        bytes.clear();
                    }
                }
            }
            Err(_) => { failed = true; break; },
        }
    }
    let closed = close_original(&mut pipe);
    if failed || !closed || !eof { owner.resource_unknown.store(true, Ordering::SeqCst); inner.stop(&owner, Reason::ProtocolError); inner.unknown(&owner); }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if !stderr { if let Some(permit) = &owner.fixture { permit.boundary(&owner, hosted_tests::Boundary::ReaderReturn).await; } }
    guard.complete = true; ReadEnd { frames, eof, closed, failed }
}
async fn clock_wait(end: Option<Instant>) {
    match end { Some(end) => tokio::time::sleep_until(tokio::time::Instant::from_std(end)).await, None => pending::<()>().await }
}
async fn watchdog(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> bool {
    // Acyclic: watchdog -> final observer -> manager -> driver/original book.
    // Direct Ready waiting keeps both W/H and the original JoinHandle waker
    // alive even while the final observer itself is held before return.
    let mut observer = owner.observer.lock().await;
    let observed = if observer.is_none() { false } else {
        let result = join_with_clock(&mut observer, &inner, &owner).await;
        let positive = matches!(&result, Ok(true));
        let recorded = record_join(&owner.observer_return, result);
        positive && recorded
    };
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, &owner, now);
    let positive = observed && final_clock_clear(&inner, &r, &owner, now);
    if positive { observer.take(); }
    else { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown_locked(&mut r, &owner); }
    // No await/effect between this last veto and the return. Reconcile still
    // owes its independent veto at the actual watchdog Ready observation.
    guard.complete = true; positive
}
async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match slot { Some(task) => task.await, None => pending().await }
}
async fn join_with_clock<T>(slot: &mut Option<JoinHandle<T>>, inner: &Inner, owner: &Session) -> Result<T, tokio::task::JoinError> {
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        tokio::select! { result = join_slot(slot) => return result, _ = wake => {}, _ = clock_wait(end) => {} }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn installed_worker_lost(book: &Resources) {
    // Only after the actual original Ready JoinError; a deadline is not return.
    if let Some(native) = &book.installed {
        match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
    }
}
fn original_worker_returned(started: bool, joined: bool, failed: bool, handle: bool, error: bool) -> bool {
    if !started { !joined && !failed && !handle && !error }
    else if failed { !joined && handle && error }
    else { joined && !handle && !error }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn installed_consumers_returned(book: &Resources, startup: &Startup, no_child_effect: bool) -> bool {
    if !original_worker_returned(book.inspection_started, book.inspection_joined, book.inspection_failed,
            book.inspection.is_some(), book.inspection_error.is_some())
        || !original_worker_returned(book.acquisition_started, book.acquisition_joined, book.acquisition_failed,
            book.acquisition.is_some(), book.acquisition_error.is_some()) { return false; }
    let io_returned = book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
        && !book.write_failed && !book.out_failed && !book.err_failed
        && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some();
    if !io_returned || startup.child.is_some() { return false; }
    if !startup.attempted {
        return no_child_effect && !startup.returned && !startup.failed && book.child.is_none() && book.waited.is_none() && !book.wait_failed;
    }
    startup.returned && !startup.failed && book.inspection_joined && !book.inspection_failed
        && book.acquisition_joined && !book.acquisition_failed && book.child.is_some() && !book.wait_failed
        && book.waited.as_ref().is_some_and(ExitStatus::success)
        && book.write_end.as_ref().is_some_and(|e| e.sent && e.closed && !e.failed)
        && book.out_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.frames == 2)
        && book.err_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.frames == 0)
}
// C/A/W use this same runtime. Even direct engine0/EOF/joins cannot release a
// claimed ledger without this same original's accepted, validated core lifetime.
fn installed_closure_ready(r: &Registry, owner: &Session, claimed: bool, direct_returned: bool) -> bool {
    direct_returned && original_session(r, owner) && (!claimed || r.active.as_ref().is_some_and(|a|
        a.accepted && a.terminal && a.projection.result.as_ref().is_some_and(|t| t.lifetime.settled())))
}
fn installed_final(book: &Resources, inner: &Inner) -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        if !inner.installed_selected() {
            return book.installed.is_none() && !book.installed_started && !book.installed_joined && !book.installed_failed
                && book.installed_settlement.is_none() && book.installed_return.is_none();
        }
        book.installed_started && book.installed_joined && !book.installed_failed && book.installed_settlement.is_none()
            && matches!(book.installed_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { !inner.installed_selected() && !book.installed_started && !book.installed_joined && !book.installed_failed }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn installed_claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    inner.installed_selected() && final_clock_clear(inner, r, owner, now)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current() == Some(owner.profile)
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn transfer_installed(book: &Resources, inner: &Inner, owner: &Session) -> Result<(), BridgeError> {
    if !book.inspection_started || !book.inspection_joined || book.inspection_failed || book.inspection.is_some()
        || book.inspection_error.is_some() || book.acquisition_started || book.acquisition_joined || book.acquisition_failed
        || book.acquisition.is_some() || book.acquisition_error.is_some() { return Err(BridgeError::cleanup_unknown()); }
    let native = book.installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !installed_claim_clear(inner, &r, owner, now) { return Err(unavailable()); }
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn acquire_installed(inner: &Inner, owner: &Session, native: &Arc<Mutex<EnvironmentDiagnosticsRuntimeSlots>>) {
    if !inner.installed_selected() { inner.stop(owner, Reason::RuntimeUnavailable); return; }
    let mut slots = match native.lock() { Ok(slots) => slots, Err(_) => { inner.unknown(owner); return; } };
    let capability = match slots.capability() { Ok(capability) => capability, Err(_) => { inner.unknown(owner); return; } };
    let stop = owner.stop.subscribe();
    let selected = match capability.prepare_once(owner.clocks.work, &stop) {
        Ok(selected) => selected, Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
    };
    let mut command = Command::new(&selected.python);
    command.args(["-I", "-S", "-B"]).arg(&selected.bootstrap).arg(&selected.core)
        .current_dir(&selected.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    let mut startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !installed_claim_clear(inner, &r, owner, now) { return; }
    if startup.attempted || startup.returned || startup.failed || startup.child.is_some() || capability.claim_once().is_err() {
        owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown_locked(&mut r, owner); return;
    }
    startup.attempted = true;
    drop(r);
    match command.spawn() { // Sole effect, immediately after the serialized one-use claim.
        Ok(child) => { startup.child = Some(child); startup.returned = true; },
        Err(_) => { startup.failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner); },
    }
}
async fn settle_installed(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { let _ = (book, inner, owner); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        let Some(native) = book.installed.clone() else {
            if inner.installed_selected() { inner.unknown(owner); }
            return;
        };
        if !book.installed_started {
            let returned = (|| {
                let slots = match native.try_lock() {
                    Ok(slots) => slots, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let startup = match owner.startup.try_lock() {
                    Ok(startup) => startup, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let r = inner.lock();
                installed_closure_ready(&r, owner, startup.attempted,
                    installed_consumers_returned(book, &startup, slots.no_child_effect()))
            })();
            if !inner.installed_selected() || !returned { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
            let (release, enter) = oneshot::channel();
            book.installed_started = true;
            book.installed_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                match native.lock() {
                    Ok(mut slots) => slots.settle_originals(),
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots.settle_originals() },
                }
            }));
            let _ = release.send(()); // The same original closer is registered before its first close.
        }
        if !book.installed_joined && !book.installed_failed {
            if book.installed_settlement.is_none() { inner.unknown(owner); return; }
            let result = join_with_clock(&mut book.installed_settlement, inner, owner).await;
            let joined = result.is_ok();
            if book.installed_return.is_some() { book.installed_failed = true; }
            else { book.installed_return = Some(result); book.installed_joined = joined; book.installed_failed = !joined; }
            if joined { book.installed_settlement.take(); } else { installed_worker_lost(book); }
        }
        if !installed_final(book, inner) { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}
fn spawn_original(inner: &Inner, owner: &Session, runtime: VerifiedRuntime) {
    // This gate remains distinct from source inspection. No packaged fallback,
    // environment-selected neutral cwd or other owner's permit is accepted.
    if !inner.qualified() || Profile::current() != Some(owner.profile) {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    #[cfg(not(all(unix, debug_assertions, feature = "development-runtime")))]
    { let _ = runtime; inner.stop(owner, Reason::RuntimeUnavailable); }
    #[cfg(all(unix, debug_assertions, feature = "development-runtime"))]
    {
        inner.endpoint(owner);
        if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
        let mut bootstrap = runtime.bootstrap.clone(); let mut control: Option<PathBuf> = None;
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture {
            match permit.prepare_spawn(owner, &runtime) {
                Ok(Some((shim, input))) => { bootstrap = shim; control = Some(input); }, Ok(None) => {},
                Err(_) => { owner.resource_unknown.store(true, Ordering::SeqCst); inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner); return; }
            }
        }
        let mut command = Command::new(&runtime.python);
        command.args(["-I", "-S", "-B"]).arg(&bootstrap).arg(&runtime.core);
        if let Some(control) = control { command.arg(control); }
        command.current_dir(&runtime.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
        let mut startup = match owner.startup.lock() {
            Ok(startup) => startup, Err(error) => { drop(error.into_inner()); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
        };
        inner.endpoint(owner);
        if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
        startup.attempted = true; // Before the sole original acquisition effect.
        match command.spawn() {
            Ok(child) => { startup.child = Some(child); startup.returned = true; },
            Err(_) => {
                startup.failed = true; // std/Tokio do not report failed-acquisition pipe closes.
                owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
                inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner);
            }
        }
    }
}
async fn start_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    let mut book = owner.resources.lock().await;
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
    let runtime = inner.runtime.clone(); let end = owner.clocks.work;
    let stop = owner.stop.subscribe();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let installed = book.installed.clone();
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    let inspection_owner = owner.clone();
    let (inspect_start, inspect_enter) = oneshot::channel();
    book.inspection_started = true;
    book.inspection = Some(tokio::task::spawn_blocking(move || {
        inspect_enter.blocking_recv().map_err(|_| unavailable())?;
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let result = if let Some(native) = installed {
            match native.lock() {
                Ok(mut slots) => runtime.resolve_environment_diagnostics_installed(&mut slots, end, &stop),
                Err(_) => Err(BridgeError::cleanup_unknown()),
            }
        } else { runtime.resolve_environment_diagnostics(end) };
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let result = { let _ = stop; runtime.resolve_environment_diagnostics(end) };
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &inspection_owner.fixture { permit.inspection_return(&inspection_owner); }
        result
    }));
    let _ = inspect_start.send(()); // Original handle recorded BEFORE inspection effects.
    let runtime = match join_with_clock(&mut book.inspection, inner, owner).await {
        Ok(result) => { book.inspection_joined = true; book.inspection.take(); match result {
            Ok(runtime) => runtime, Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
        } },
        Err(error) => {
            book.inspection_failed = true; book.inspection_error = Some(error);
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            installed_worker_lost(&book);
            owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return;
        },
    };
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
    let bytes = {
        let mut draft = match owner.draft.lock() {
            Ok(draft) => draft, Err(_) => { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
        };
        let Some(draft_value) = draft.as_ref() else { inner.stop(owner, Reason::ProtocolError); return; };
        let bytes = wire::request(&owner.id, &owner.generation, &owner.context, draft_value, owner.profile, &owner.project, &runtime.cwd);
        draft.take(); bytes
    };
    match bytes { Ok(bytes) => *owner.request.lock().await = Some(bytes), Err(_) => { inner.stop(owner, Reason::ProtocolError); return; } }
    let acquisition_owner = owner.clone(); let acquisition_inner = inner.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let installed = book.installed.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if installed.is_some() && transfer_installed(&book, inner, owner).is_err() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let (acquire_start, acquire_enter) = oneshot::channel();
    book.acquisition_started = true;
    book.acquisition = Some(tokio::task::spawn_blocking(move || {
        if acquire_enter.blocking_recv().is_ok() {
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if let Some(native) = installed {
                drop(runtime); // Selection DATA is never launch authority.
                acquire_installed(&acquisition_inner, &acquisition_owner, &native); return;
            }
            spawn_original(&acquisition_inner, &acquisition_owner, runtime);
        }
        else { acquisition_inner.stop(&acquisition_owner, Reason::Cancelled); }
    }));
    let _ = acquire_start.send(()); // The original blocking acquisition cannot precede custody.
}
async fn drive(inner: Arc<Inner>, owner: Arc<Session>, enter: oneshot::Receiver<()>, mut guard: Guard) {
    if enter.await.is_err() { inner.stop(&owner, Reason::Cancelled); }
    else {
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture { permit.boundary(&owner, hosted_tests::Boundary::Startup).await; }
        start_original(&inner, &owner).await;
    }
    continue_original(&inner, &owner).await;
    guard.complete = true;
}
async fn wait_child(child: &mut Option<Child>) -> std::io::Result<ExitStatus> { match child { Some(child) => child.wait().await, None => pending().await } }
async fn next_frame(frames: &mut Option<mpsc::Receiver<Frame>>) -> Option<Frame> { match frames { Some(frames) => frames.recv().await, None => pending().await } }
fn drain(book: &mut Resources, inner: &Inner, owner: &Session) {
    if let Some(frames) = book.frames.as_mut() { while let Ok(frame) = frames.try_recv() { deliver_frame(inner, owner, frame); } }
}
fn deliver_frame(inner: &Inner, owner: &Session, frame: Frame) {
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    let accepted = matches!(&frame, Frame::Accepted);
    inner.accept(owner, frame);
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if accepted { if let Some(permit) = &owner.fixture { permit.driver_boundary(owner); } }
}
fn require_terminal(inner: &Inner, owner: &Session) {
    if !inner.lock().active.as_ref().is_some_and(|a| a.owner.id == owner.id && a.accepted && a.terminal) {
        inner.stop(owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
    }
}
enum Event { Wait(std::io::Result<ExitStatus>), Write(Result<WriteEnd, tokio::task::JoinError>),
    Out(Result<ReadEnd, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Frame(Option<Frame>), Wake }
fn observe_child_status(inner: &Inner, owner: &Session, status: &ExitStatus) {
    if !status.success() {
        // A terminal precedes the core's final stdio closes. Nonzero cannot
        // certify those later original child-side transport returns.
        inner.stop(owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
    }
}
async fn continue_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    // Sole driver, or its already-registered surviving manager AFTER a lost
    // driver. Only original book cleanup: no new inspection/acquisition/IO task.
    let mut book = owner.resources.lock().await;
    if book.inspection.is_some() && !book.inspection_joined && !book.inspection_failed {
        match join_with_clock(&mut book.inspection, inner, owner).await {
            Ok(_) => { book.inspection_joined = true; book.inspection.take(); }, // Late runtime DATA never launches.
            Err(error) => {
                book.inspection_failed = true; book.inspection_error = Some(error);
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                installed_worker_lost(&book);
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
            },
        }
    }
    if book.acquisition.is_some() && !book.acquisition_joined && !book.acquisition_failed {
        match join_with_clock(&mut book.acquisition, inner, owner).await {
            Ok(()) => { book.acquisition_joined = true; book.acquisition.take(); },
            Err(error) => {
                book.acquisition_failed = true; book.acquisition_error = Some(error);
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                installed_worker_lost(&book);
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
            },
        }
    }
    let expected = {
        let mut startup = match owner.startup.lock() {
            Ok(startup) => startup, Err(error) => { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); error.into_inner() }
        };
        if book.child.is_none() { book.child = startup.child.take(); }
        else if startup.child.is_some() { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
        startup.returned || book.child.is_some()
    };
    let pipes = *owner.pipes.borrow();
    if pipes == Pipes::Pending {
        if let Some(child) = book.child.as_mut() {
            let mut input = owner.input.lock().await; let mut output = owner.output.lock().await; let mut error = owner.error.lock().await;
            if input.io.is_none() && input.close == Close::New { input.io = child.stdin.take(); }
            if output.io.is_none() && output.close == Close::New { output.io = child.stdout.take(); }
            if error.io.is_none() && error.close == Close::New { error.io = child.stderr.take(); }
            if input.io.is_none() || output.io.is_none() || error.io.is_none() || child.stdin.is_some() || child.stdout.is_some() || child.stderr.is_some() {
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
            }
            owner.pipes.send_replace(Pipes::Available);
        } else { owner.pipes.send_replace(Pipes::Absent); }
    }
    if book.write_failed { let mut pipe = owner.input.lock().await; let _ = close_original(&mut pipe); }
    if book.out_failed { let mut pipe = owner.output.lock().await; let _ = close_original(&mut pipe); }
    if book.err_failed { let mut pipe = owner.error.lock().await; let _ = close_original(&mut pipe); }
    let mut frames_open = book.frames.is_some();
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        let wait_pending = book.child.is_some() && book.waited.is_none() && !book.wait_failed;
        let write_pending = book.writer.is_some() && !book.write_failed;
        let out_pending = book.stdout.is_some() && !book.out_failed;
        let err_pending = book.stderr.is_some() && !book.err_failed;
        if !wait_pending && !write_pending && !out_pending && !err_pending { drain(&mut book, inner, owner); break; }
        let event = {
            let Resources { child, writer, stdout, stderr, frames, .. } = &mut *book;
            tokio::select! {
                result = wait_child(child), if wait_pending => Event::Wait(result),
                result = join_slot(writer), if write_pending => Event::Write(result),
                result = join_slot(stdout), if out_pending => Event::Out(result),
                result = join_slot(stderr), if err_pending => Event::Err(result),
                frame = next_frame(frames), if frames_open => Event::Frame(frame),
                _ = wake => Event::Wake, _ = clock_wait(end) => Event::Wake,
            }
        };
        match event {
            Event::Wait(Ok(status)) => {
                observe_child_status(inner, owner, &status);
                book.waited = Some(status);
            }
            Event::Wait(Err(_)) => { book.wait_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
            Event::Write(Ok(end)) => { book.writer.take(); book.write_end = Some(end); },
            Event::Out(Ok(end)) => { book.stdout.take(); book.out_end = Some(end); drain(&mut book, inner, owner); if expected { require_terminal(inner, owner); } },
            Event::Err(Ok(end)) => { book.stderr.take(); book.err_end = Some(end); },
            Event::Write(Err(_)) => { book.write_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.input.lock().await; let _ = close_original(&mut p); },
            Event::Out(Err(_)) => { book.out_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.output.lock().await; let _ = close_original(&mut p); },
            Event::Err(Err(_)) => { book.err_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.error.lock().await; let _ = close_original(&mut p); },
            Event::Frame(Some(frame)) => deliver_frame(inner, owner, frame), Event::Frame(None) => frames_open = false, Event::Wake => {},
        }
    }
    if expected { require_terminal(inner, owner); }
    settle_installed(&mut book, inner, owner).await;
    // No broad signal or PID discovery. EOF is cooperative STOP; an unreturned
    // original child stays retained at H, even if its terminal was once positive.
}
type Continuation = Pin<Box<dyn Future<Output = ()> + Send>>;
async fn continuation(slot: &mut Option<Continuation>) { match slot { Some(future) => future.await, None => pending().await } }
enum Monitor { Driver(Result<(), tokio::task::JoinError>), Continued, Wake }
async fn monitor_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    let mut driver = owner.driver.lock().await;
    let mut continuing: Option<Continuation> = None;
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        let driver_known = owner.driver_joined.load(Ordering::SeqCst) || owner.driver_failed.load(Ordering::SeqCst);
        if driver.is_none() && !driver_known { owner.driver_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); continue; }
        if owner.driver_failed.load(Ordering::SeqCst) && !owner.driver_done.load(Ordering::SeqCst) && continuing.is_none() {
            let inner = inner.clone(); let owner = owner.clone();
            continuing = Some(Box::pin(async move { continue_original(&inner, &owner).await }));
        }
        if driver_known && owner.driver_done.load(Ordering::SeqCst) && continuing.is_none() { break; }
        let is_continuing = continuing.is_some();
        let event = tokio::select! {
            result = join_slot(&mut driver), if !driver_known => Monitor::Driver(result),
            _ = continuation(&mut continuing), if is_continuing => Monitor::Continued,
            _ = wake => Monitor::Wake, _ = clock_wait(end) => Monitor::Wake,
        };
        match event {
            Monitor::Driver(result) => {
                let joined = result.is_ok(); let recorded = record_join(&owner.driver_return, result);
                if joined { owner.driver_done.store(true, Ordering::SeqCst); }
                if joined && recorded { driver.take(); owner.driver_joined.store(true, Ordering::SeqCst); }
                else { owner.driver_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
                owner.wake.notify_waiters();
            },
            Monitor::Continued => { continuing.take(); owner.driver_done.store(true, Ordering::SeqCst); owner.wake.notify_waiters(); }, Monitor::Wake => {},
        }
    }
}
async fn manage(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) { monitor_original(&inner, &owner).await; guard.complete = true; }
async fn observe_final(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> bool {
    let manager_joined = {
        let mut manager = owner.manager.lock().await;
        if manager.is_none() { false } else {
            let result = join_with_clock(&mut manager, &inner, &owner).await;
            let joined = result.is_ok(); let recorded = record_join(&owner.manager_return, result);
            if joined && recorded { manager.take(); }
            joined && recorded
        }
    };
    if !manager_joined {
        owner.manager_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner);
        // Exceptional original-only custody. Never a new acquisition/reader,
        // repair of the lost receipt or successful result after manager loss.
        monitor_original(&inner, &owner).await;
    }
    let settled = {
        let book = owner.resources.lock().await;
        let startup = match owner.startup.lock() { Ok(s) => s, Err(e) => { owner.resource_unknown.store(true, Ordering::SeqCst); e.into_inner() } };
        let startup_settled = book.inspection.is_none() && book.acquisition.is_none() && !book.inspection_failed && !book.acquisition_failed
            && !startup.failed && (!startup.attempted || startup.returned && book.acquisition_joined);
        let io_joined = book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none() && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some();
        let io = if startup.returned {
            book.waited.is_some() && !book.wait_failed
                && book.write_end.as_ref().is_some_and(|r| r.closed)
                && book.out_end.as_ref().is_some_and(|r| r.closed && r.eof)
                && book.err_end.as_ref().is_some_and(|r| r.closed && r.eof)
        } else { book.child.is_none() && startup.child.is_none() };
        let protocol = if startup.returned {
            let r = inner.lock();
            r.active.as_ref().is_some_and(|a| a.owner.id == owner.id && a.accepted && a.terminal
                && a.projection.result.as_ref().is_some_and(|t| t.lifetime.settled()))
                && book.out_end.as_ref().is_some_and(|r| r.frames == 2 && !r.failed)
                && book.err_end.as_ref().is_some_and(|r| r.frames == 0 && !r.failed)
                && book.write_end.as_ref().is_some_and(|r| r.sent && !r.failed)
        } else { true };
        manager_joined && startup_settled && io_joined && io && protocol && installed_final(&book, &inner)
            && owner.driver_joined.load(Ordering::SeqCst)
            && !owner.resource_unknown.load(Ordering::SeqCst)
    };
    if !settled { inner.unknown(&owner); }
    // Final observer owns no unjoined child/IO/acquisition at this point. Its
    // ORIGINAL handle remains with the watchdog until its actual Ready join.
    { let mut r = inner.lock(); inner.bump(&mut r); }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if let Some(permit) = &owner.fixture { permit.boundary(&owner, hosted_tests::Boundary::ObserverReturn).await; }
    guard.complete = true; settled
}

#[cfg(test)]
mod tests {
    // State/clock DATA and actual finite in-memory task joins only. No runtime
    // inspection, files, native processes, tool permission or close evidence.
    use super::*;
    fn projection() -> Projection { Projection { run_id: "a".repeat(32), owner_generation: "b".repeat(32),
        context: Context { project_id: "project-1".into(), draft_revision: 0, baseline_generation: 0,
            platform: wire::Platform::Android, operation: wire::Operation::Build }, phase: Phase::Starting,
        outcome: None, finality: Finality::Pending, reason: Reason::None, result: None } }
    pub(super) fn inert_active() -> (EnvironmentDiagnosticsOwner, Arc<Session>) {
        inert_active_at(Instant::now())
    }
    fn inert_active_at(admitted: Instant) -> (EnvironmentDiagnosticsOwner, Arc<Session>) {
        let owner = EnvironmentDiagnosticsOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened")));
        let projection = projection(); let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
        let (frames, receiver) = mpsc::channel(2);
        let session = Arc::new(Session { id: projection.run_id.clone(), generation: projection.owner_generation.clone(), context: projection.context.clone(),
            profile: Profile::LinuxX64, clocks: Clocks::new(admitted), registration: 1, project: PathBuf::from("/unopened-project"),
            draft: Mutex::new(None), request: AsyncMutex::new(None), stop, pipes, frames, wake: Notify::new(), output_bytes: AtomicUsize::new(0),
            resource_unknown: AtomicBool::new(false), driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
            watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false), startup: Mutex::new(Startup::default()),
            resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }), input: Arc::new(AsyncMutex::new(Pipe::default())),
            output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())), driver: AsyncMutex::new(None),
            watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: None,
        });
        owner.inner.lock().active = Some(Active { owner: session.clone(), projection, first_stop: None, work_expired: false,
            accepted: false, terminal: false, unknown: false, final_join_seen: false });
        (owner, session)
    }
    fn decoded_terminal(session: &Session, value: Value) -> Frame {
        let mut bytes = serde_json::to_vec(&serde_json::json!({"protocol":wire::PROTOCOL,"runId":session.id,
            "ownerGeneration":session.generation,"seq":1,"kind":"terminal","result":value})).unwrap();
        bytes.push(b'\n');
        wire::decode(&bytes, &session.id, &session.generation, &session.context, session.profile.host()).unwrap()
    }
    #[test]
    fn final_retirement_requires_original_identity_and_h_but_not_an_unset_stop() {
        let (owner, session) = inert_active(); let now = session.clocks.admitted;
        let (_, foreign) = inert_active();
        {
            let mut r = owner.inner.lock();
            assert!(final_clock_clear(&owner.inner, &r, &session, session.clocks.finality - Duration::from_nanos(1)));
            assert!(!final_clock_clear(&owner.inner, &r, &session, session.clocks.finality));
            assert!(!final_clock_clear(&owner.inner, &r, &foreign, now)); // Same IDs, different original Arc.
            owner.inner.stop_locked(&mut r, &session, Reason::Cancelled, now);
            r.stopping = true; r.document_lost = true;
            assert!(*session.stop.borrow() && final_clock_clear(&owner.inner, &r, &session, now));
        }
        owner.inner.unknown(&session);
        assert_eq!(owner.inner.endpoint(&session), Some(session.clocks.work)); // Early Unknown still has an endpoint.
        assert!(!final_clock_clear(&owner.inner, &owner.inner.lock(), &session, now));
        assert_eq!(session.clocks.finality, now + FINALITY);
    }
    #[tokio::test]
    async fn positive_observer_ready_after_h_or_early_unknown_retains_original_returns() {
        for expired in [false, true] {
            let admitted = if expired { Instant::now() - FINALITY } else { Instant::now() };
            let (application, owner) = inert_active_at(admitted);
            if !expired { application.inner.unknown(&owner); }
            // Arbitrary true memory DATA attacks the join envelope; it is NOT a
            // positive native-finality receipt or qualification of this owner.
            *owner.observer.lock().await = Some(tokio::spawn(async { true }));
            let (sent, ready) = oneshot::channel();
            let inner = application.inner.clone(); let original = owner.clone();
            let guard = Guard::new(&inner, &original);
            *owner.watchdog.lock().unwrap() = Some(tokio::spawn(async move {
                let value = watchdog(inner, original, guard).await;
                sent.send(()).unwrap(); value
            }));
            ready.await.unwrap(); // Current-thread task has returned; the original handle is not yet polled here.
            assert!(owner.watchdog.lock().unwrap().as_ref().unwrap().is_finished());
            application.reconcile(); application.reconcile();
            assert!(matches!(&*owner.observer_return.lock().unwrap(), Some(Ok(true))));
            assert!(matches!(&*owner.watchdog_return.lock().unwrap(), Some(Ok(false))));
            assert!(owner.observer.lock().await.is_some() && owner.watchdog.lock().unwrap().is_some());
            let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
            assert!(Arc::ptr_eq(&active.owner, &owner) && active.unknown && active.final_join_seen && r.disabled && r.last.is_none());
            drop(r); assert!(!application.can_exit() && owner.resource_unknown.load(Ordering::SeqCst));
        }
    }
    #[tokio::test]
    async fn positive_watchdog_ready_first_reconciled_after_h_cannot_retire_or_be_repolled() {
        let (application, owner) = inert_active_at(Instant::now() - FINALITY);
        let (sent, ready) = oneshot::channel();
        *owner.watchdog.lock().unwrap() = Some(tokio::spawn(async move { sent.send(()).unwrap(); true }));
        ready.await.unwrap();
        application.reconcile(); application.reconcile();
        assert!(matches!(&*owner.watchdog_return.lock().unwrap(), Some(Ok(true))));
        assert!(owner.watchdog.lock().unwrap().is_some() && owner.watchdog_joined.load(Ordering::SeqCst));
        assert!(!owner.watchdog_failed.load(Ordering::SeqCst)); // Ready true was not rewritten as a JoinError.
        let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
        assert!(Arc::ptr_eq(&active.owner, &owner) && active.unknown && active.final_join_seen && r.last.is_none());
        assert_eq!(owner.clocks.finality, owner.clocks.admitted + FINALITY);
        drop(r); assert!(!application.can_exit());
    }
    #[test]
    fn installed_closer_requires_same_original_settled_core_not_engine_exit_data() {
        for mode in ["missing", "unsettled", "negative", "cancelled"] {
            let (application, owner) = inert_active(); let now = owner.clocks.admitted;
            {
                let r = application.inner.lock();
                assert!(!installed_closure_ready(&r, &owner, true, true));
                assert!(installed_closure_ready(&r, &owner, false, true)); // Known preclaim branch needs no terminal.
                assert!(!installed_closure_ready(&r, &owner, false, false));
            }
            application.inner.accept_at(&owner, Frame::Accepted, now);
            if mode != "missing" {
                let mut value = wire::tests::terminal(&owner.context);
                match mode {
                    "unsettled" => { value["outcome"] = serde_json::json!("partial");
                        value["lifetime"]["toolDescriptorsClosed"] = serde_json::json!(false); },
                    "negative" => { value["checks"][0]["reason"] = serde_json::json!("nonzero-exit");
                        value["checks"][0]["returnCode"] = serde_json::json!(1);
                        value["checks"][0]["version"] = Value::Null;
                        value["checks"][0]["assessment"] = serde_json::json!("not-assessed"); },
                    "cancelled" => { value["outcome"] = serde_json::json!("cancelled");
                        value["lifetime"]["stopObserved"] = serde_json::json!("cancelled"); },
                    _ => unreachable!(),
                }
                application.inner.accept_at(&owner, decoded_terminal(&owner, value), now);
            }
            let (_, foreign) = inert_active(); let r = application.inner.lock();
            // direct_returned=true is engine/IO-return DATA only: the actual
            // production closer decision still requires original C/A/W proof.
            assert_eq!(installed_closure_ready(&r, &owner, true, true), matches!(mode, "negative" | "cancelled"));
            assert!(!installed_closure_ready(&r, &owner, true, false));
            assert!(!installed_closure_ready(&r, &foreign, true, true));
            if mode == "unsettled" { assert!(r.active.as_ref().unwrap().unknown); }
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[tokio::test]
    async fn preclaim_borrowers_need_actual_ready_and_opaque_spawn_failure_never_means_no_child() {
        let (application, owner) = inert_active();
        {
            let mut book = owner.resources.lock().await;
            book.inspection_started = true; book.acquisition_started = true;
            book.inspection = Some(tokio::spawn(pending::<Result<VerifiedRuntime, BridgeError>>()));
            book.acquisition = Some(tokio::spawn(pending::<()>()));
            // Ordinary absent-pipe DATA: no file or native pipe is invented.
            book.write_end = Some(WriteEnd { sent: false, closed: false, failed: false });
            book.out_end = Some(ReadEnd { frames: 0, eof: false, closed: false, failed: false });
            book.err_end = Some(ReadEnd { frames: 0, eof: false, closed: false, failed: false });
            assert!(!installed_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
            book.inspection_failed = true; book.acquisition_failed = true;
            assert!(!installed_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
            book.inspection_failed = false; book.acquisition_failed = false;
            book.inspection.as_ref().unwrap().abort(); book.acquisition.as_ref().unwrap().abort();
        }
        continue_original(&application.inner, &owner).await;
        continue_original(&application.inner, &owner).await; // Must not repoll failed Ready handles.
        let mut book = owner.resources.lock().await;
        assert!(book.inspection_error.as_ref().is_some_and(|e| e.is_cancelled())
            && book.acquisition_error.as_ref().is_some_and(|e| e.is_cancelled()));
        assert!(installed_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
        assert!(!installed_consumers_returned(&book, &owner.startup.lock().unwrap(), false));
        let mut startup = owner.startup.lock().unwrap(); startup.attempted = true; startup.failed = true;
        assert!(!installed_consumers_returned(&book, &startup, true));
        // Unselected dev/headless path remains separate; a stray installed slot
        // can never satisfy native finality without its original settlement.
        assert!(installed_final(&book, &application.inner));
        book.installed = Some(Arc::new(Mutex::new(EnvironmentDiagnosticsRuntimeSlots::new())));
        assert!(!installed_final(&book, &application.inner) && !book.installed_started);
    }
    #[test]
    fn startup_and_hidden_failure_never_renew_finality_clock() {
        let t = Instant::now(); let clock = Clocks::new(t);
        assert_eq!(clock.work.duration_since(t), WORK); assert_eq!(clock.finality.duration_since(t), FINALITY);
        for failure in [t, t + Duration::from_secs(2), clock.work, clock.finality] {
            assert!(clock.finality <= failure + FINALITY);
        }
        // Late startup return cannot receive another six seconds; a lost
        // terminal cannot append a fresh ten-second cleanup reservation.
        let late = t + Duration::from_secs(9);
        assert!(late >= clock.work); assert_eq!(clock.finality.saturating_duration_since(late), Duration::from_secs(1));
        assert!(clock.finality >= clock.work);
    }
    #[test]
    fn native_failure_overlay_does_not_publish_complete_or_clear_unknown() {
        for (reason, outcome) in [(Reason::Cancelled, Outcome::Cancelled), (Reason::TimedOut, Outcome::TimedOut),
            (Reason::CommandFailed, Outcome::Failed), (Reason::CleanupUnknown, Outcome::Failed),
            (Reason::ContextChanged, Outcome::Cancelled), (Reason::RuntimeUnavailable, Outcome::Unavailable)] {
            let mut p = projection(); p.reason = reason; p.outcome = Some(Outcome::Complete); p.finality = Finality::Unknown;
            p.phase = Phase::RetainedUnknown; set_failure_outcome(&mut p);
            assert_eq!(p.outcome, Some(outcome)); assert_eq!(p.finality, Finality::Unknown); assert_eq!(p.phase, Phase::RetainedUnknown);
        }
    }
    #[test]
    fn unqualified_constructor_starts_no_worker_and_never_uses_other_owner_permission() {
        let owner = EnvironmentDiagnosticsOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened")));
        let status = owner.status(Availability::Available).unwrap();
        assert!(!status.capability.available); assert!(status.active.is_none()); assert!(status.last_terminal.is_none()); assert!(owner.can_exit());
        assert!(owner.ticket().is_err()); // No Tokio runtime or qualification.
        owner.document_lost();
        assert_eq!(owner.status(Availability::Available).unwrap().capability.reason, Availability::DocumentLost);
    }
    #[test]
    fn blocked_startup_and_lost_terminal_reach_same_original_h_and_retain_slot() {
        for accepted in [false, true] {
            let (owner, session) = inert_active(); let t = session.clocks.admitted;
            if accepted { owner.inner.accept_at(&session, Frame::Accepted, t); }
            let mut r = owner.inner.lock();
            owner.inner.advance_locked(&mut r, &session, session.clocks.work);
            assert_eq!(r.active.as_ref().unwrap().projection.reason, Reason::TimedOut);
            owner.inner.advance_locked(&mut r, &session, session.clocks.finality);
            let active = r.active.as_ref().unwrap();
            assert!(active.unknown && r.disabled && *session.stop.borrow());
            assert_eq!(active.projection.finality, Finality::Unknown); assert_eq!(active.first_stop, Some(session.clocks.work));
            assert_eq!(session.clocks.finality.duration_since(t), FINALITY); assert!(r.last.is_none());
        }
    }
    #[test]
    fn repeated_unknown_endpoints_do_not_notify_their_own_waiters() {
        let (owner, session) = inert_active();
        let mut stop = session.stop.subscribe();
        let waker = Waker::from(Arc::new(NoWake)); let mut context = TaskContext::from_waker(&waker);
        let mut first_wake = Box::pin(session.wake.notified());
        assert!(matches!(first_wake.as_mut().poll(&mut context), Poll::Pending));
        session.resource_unknown.store(true, Ordering::SeqCst);
        // Inert clock observation makes both endpoints due without any timer,
        // runtime or native resource; subsequent endpoint reads must just wait.
        owner.inner.advance_locked(&mut owner.inner.lock(), &session, session.clocks.finality);
        assert!(matches!(first_wake.as_mut().poll(&mut context), Poll::Ready(())));
        assert!(stop.has_changed().unwrap()); assert!(*stop.borrow_and_update());
        let before = { let r = owner.inner.lock(); (r.revision, r.active.as_ref().unwrap().first_stop) };
        for _ in 0..8 {
            let mut wake = Box::pin(session.wake.notified()); // Same order as the original join/watchdog loops.
            assert!(matches!(wake.as_mut().poll(&mut context), Poll::Pending));
            assert!(owner.inner.endpoint(&session).is_none());
            assert!(matches!(wake.as_mut().poll(&mut context), Poll::Pending));
            assert!(!stop.has_changed().unwrap());
            let r = owner.inner.lock(); let active = r.active.as_ref().unwrap();
            assert_eq!((r.revision, active.first_stop), before);
            assert!(active.unknown && r.disabled && r.last.is_none());
            assert_eq!(active.projection.finality, Finality::Unknown);
        }
        assert_eq!(session.clocks.finality, session.clocks.admitted + FINALITY);
    }
    #[test]
    fn terminal_at_or_after_w_or_h_never_wins_success_in_either_delivery_order() {
        for due in [WORK, FINALITY] {
            for clock_first in [false, true] {
                let (owner, session) = inert_active(); let now = session.clocks.admitted + due;
                owner.inner.accept_at(&session, Frame::Accepted, session.clocks.admitted);
                if clock_first { owner.inner.advance_locked(&mut owner.inner.lock(), &session, now); }
                owner.inner.accept_at(&session, wire::tests::terminal_frame(&session.context), now);
                owner.inner.advance_locked(&mut owner.inner.lock(), &session, now);
                let r = owner.inner.lock(); let active = r.active.as_ref().unwrap();
                assert_eq!(active.projection.reason, Reason::TimedOut); assert_eq!(active.projection.outcome, Some(Outcome::TimedOut));
                assert!(active.projection.result.is_some()); assert!(active.work_expired);
                assert_eq!(active.unknown, due == FINALITY); assert!(r.last.is_none());
            }
        }
    }
    #[test]
    fn first_cancel_is_sticky_and_normal_terminal_does_not_invent_a_failure_time() {
        let (owner, session) = inert_active(); let t = session.clocks.admitted;
        owner.inner.accept_at(&session, Frame::Accepted, t);
        owner.inner.accept_at(&session, wire::tests::terminal_frame(&session.context), t + Duration::from_secs(1));
        { let r = owner.inner.lock(); let active = r.active.as_ref().unwrap(); assert!(active.first_stop.is_none());
            assert_eq!(active.projection.finality, Finality::Pending); assert_eq!(active.projection.reason, Reason::None); }
        // A provisional complete result still cannot clear a subsequent native
        // STOP before all original joins. No fresh cleanup window is created.
        let mut r = owner.inner.lock();
        owner.inner.stop_locked(&mut r, &session, Reason::Cancelled, t + Duration::from_secs(2));
        owner.inner.advance_locked(&mut r, &session, session.clocks.finality);
        owner.inner.stop_locked(&mut r, &session, Reason::CommandFailed, t + Duration::from_secs(11));
        let active = r.active.as_ref().unwrap(); assert_eq!(active.first_stop, Some(t + Duration::from_secs(2)));
        assert_eq!(active.projection.reason, Reason::Cancelled); assert_eq!(active.projection.outcome, Some(Outcome::Cancelled));
        assert!(active.unknown && r.disabled); assert_eq!(session.clocks.finality, t + FINALITY);
    }
}
