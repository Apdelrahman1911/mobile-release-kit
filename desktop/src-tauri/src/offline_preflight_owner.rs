//! One original saved Android offline-preflight owner, not a generic runner.
//! The ordinary core retains C/A/W custody; native retains every original
//! startup, child, pipe, decoder, wait, driver, manager and final-join record.
use std::{future::{pending, Future}, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context as TaskContext, Poll, Wake, Waker}, time::{Duration, Instant}};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStdin, ChildStdout, ChildStderr},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch}, task::JoinHandle};
#[cfg(all(unix, debug_assertions, feature = "development-runtime"))]
use {std::process::Stdio, tokio::process::Command};
use crate::{asset_source::RegisteredRoot, offline_preflight_protocol::{self as wire, Availability, Context, Frame,
    Outcome, Phase, Prepare, Profile, Reason, Start, Status, Terminal}, error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}};

// No other owner's fixture permit, environment switch, host name or successful
// DATA parsing qualifies this operation. Windows has no supported profile.
const NATIVE_QUALIFIED: bool = false;
const RUNTIME_QUALIFIED: bool = false;
const INTENT: Duration = Duration::from_secs(300);
const WORK: Duration = Duration::from_secs(1800);
const HARD: Duration = Duration::from_secs(1810);
const SETTLEMENT: Duration = Duration::from_secs(10);
#[derive(Clone, Copy)]
struct Clocks { admitted: Instant, work: Instant, finality: Instant }
impl Clocks {
    fn new(admitted: Instant) -> Self { Self { admitted, work: admitted + WORK, finality: admitted + HARD } }
    fn settlement(self, first_stop: Option<Instant>) -> Instant {
        first_stop.map_or(self.finality, |first| self.finality.min(first + SETTLEMENT))
    }
}
#[derive(Clone)]
pub(crate) struct OfflinePreflightOwner { inner: Arc<Inner> }
struct Inner {
    runtime: RuntimeConfig, registry: Mutex<Registry>, changes: watch::Sender<u32>, changed: Notify, poisoned: AtomicBool,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Mutex<Option<std::sync::Weak<tests::hosted::Permit>>>,
}
struct Registry {
    revision: u32, exhausted: bool, disabled: bool, stopping: bool, document_lost: bool,
    capability: Availability, prepared: Option<Prepared>, active: Option<Active>, last: Option<wire::Projection>,
}
struct Prepared { projection: wire::Projection, expires: Instant, registration: u32, project: RegisteredRoot }
struct Active {
    owner: Arc<Session>, projection: RunProjection, first_stop: Option<Instant>, work_expired: bool,
    accepted: bool, terminal: bool, unknown: bool, final_join_seen: bool,
}
struct RunProjection {
    operation_id: String, owner_generation: String, context: Context, phase: Phase,
    outcome: Option<Outcome>, reason: Reason, result: Option<Terminal>,
}
impl RunProjection {
    fn public(&self) -> wire::Projection {
        let terminal = self.phase == Phase::Terminal;
        let unknown = self.phase == Phase::Unknown;
        wire::Projection { operation_id: self.operation_id.clone(), owner_generation: self.owner_generation.clone(), context: self.context.clone(),
            phase: self.phase, intent_usable: false,
            outcome: if unknown { Some(Outcome::Unknown) } else if terminal { self.outcome } else { None },
            reason: if unknown { Reason::CleanupUnknown } else { self.reason },
            result: if terminal && self.outcome == Some(Outcome::Complete) { self.result.as_ref().and_then(|t| t.result.clone()) } else { None } }
    }
}
struct Session {
    id: String, generation: String, context: Context, profile: Profile, clocks: Clocks,
    registration: u32, project: RegisteredRoot, request: AsyncMutex<Option<Vec<u8>>>,
    stop: watch::Sender<bool>, pipes: watch::Sender<Pipes>, frames: mpsc::Sender<Frame>, wake: Notify,
    output_bytes: AtomicUsize, resource_unknown: AtomicBool,
    driver_done: AtomicBool, driver_joined: AtomicBool, driver_failed: AtomicBool,
    watchdog_joined: AtomicBool, watchdog_failed: AtomicBool, manager_failed: AtomicBool,
    startup: Mutex<Startup>, resources: AsyncMutex<Resources>,
    input: Arc<AsyncMutex<Pipe<ChildStdin>>>, output: Arc<AsyncMutex<Pipe<ChildStdout>>>, error: Arc<AsyncMutex<Pipe<ChildStderr>>>,
    driver: AsyncMutex<Option<JoinHandle<()>>>, watchdog: Mutex<Option<JoinHandle<bool>>>,
    manager: AsyncMutex<Option<JoinHandle<()>>>, observer: AsyncMutex<Option<JoinHandle<bool>>>,
    driver_return: Mutex<Option<Result<(), tokio::task::JoinError>>>, manager_return: Mutex<Option<Result<(), tokio::task::JoinError>>>,
    observer_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>, watchdog_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Option<Arc<tests::hosted::Permit>>,
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
    acquisition: Option<JoinHandle<()>>, acquisition_joined: bool, acquisition_failed: bool,
    child: Option<Child>, waited: Option<ExitStatus>, wait_failed: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    write_failed: bool, out_failed: bool, err_failed: bool, frames: Option<mpsc::Receiver<Frame>>,
}
struct WriteEnd { sent: bool, closed: bool, failed: bool }
struct ReadEnd { frames: usize, eof: bool, closed: bool, failed: bool }
pub(crate) struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
impl Admitted {
    /// Only after DocumentBinding unlocks. Dropping GO instead sends this
    /// original driver STOP; the invoke future never receives resource custody.
    pub(crate) fn release(self) -> Status { if let Some(release) = self.release { let _ = release.send(()); } self.status }
}
fn nonce() -> Result<String, BridgeError> {
    let mut bytes = [0u8; 16]; getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes { value.push(HEX[usize::from(byte >> 4)] as char); value.push(HEX[usize::from(byte & 15)] as char); } Ok(value)
}
pub(crate) fn unavailable() -> BridgeError { BridgeError::new("offline_preflight_unavailable", "Saved offline checks are unavailable for this original document, host and runtime.") }
fn busy() -> BridgeError { BridgeError::new("offline_preflight_busy", "Finish or cancel the original operation before reviewing saved offline checks.") }
fn invalid_owner() -> BridgeError { BridgeError::new("offline_preflight_owner", "This request does not identify an unused original saved offline-check intent.") }
fn prepare_refusal(reason: Availability) -> BridgeError {
    // These fixed Prepare errors are guaranteed BEFORE new intent allocation.
    if reason == Availability::Busy { busy() } else { unavailable() }
}
fn refusal_reason(reason: Availability) -> Reason { match reason {
    Availability::CleanupUnknown => Reason::CleanupUnknown, Availability::Shutdown => Reason::Shutdown,
    Availability::DocumentLost => Reason::DocumentLost, Availability::Busy => Reason::StaleIntent,
    _ => Reason::RuntimeUnavailable,
} }
fn retire(mut projection: wire::Projection, reason: Reason) -> wire::Projection {
    projection.intent_usable = false; projection.reason = reason; projection.result = None;
    projection.phase = if reason == Reason::CleanupUnknown { Phase::Unknown } else { Phase::Terminal };
    projection.outcome = Some(match reason { Reason::CleanupUnknown => Outcome::Unknown,
        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown => Outcome::Cancelled,
        Reason::TimedOut => Outcome::TimedOut, _ => Outcome::Refused });
    projection
}

impl OfflinePreflightOwner {
    pub(crate) fn new(runtime: RuntimeConfig) -> Self {
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner { runtime, registry: Mutex::new(Registry { revision: 0, exhausted: false,
            disabled: false, stopping: false, document_lost: false, capability: Availability::RuntimeUnqualified,
            prepared: None, active: None, last: None }), changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: Mutex::new(None),
        }) }
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub(crate) fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) }
    pub(crate) fn can_exit(&self) -> bool { self.reconcile(); let r = self.inner.lock();
        !self.inner.poisoned.load(Ordering::SeqCst) && r.active.is_none() && r.prepared.is_none() }
    pub(crate) fn busy(&self) -> bool { !self.can_exit() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> {
        if self.disabled() { Err(BridgeError::cleanup_unknown()) } else if self.stopping() { Err(BridgeError::shutdown()) }
        else if self.busy() { Err(busy()) } else { Ok(()) }
    }
    pub(crate) fn prepared_project(&self, operation: &str, generation: &str) -> Result<String, BridgeError> {
        self.inner.lock().prepared.as_ref().filter(|p| p.projection.operation_id == operation && p.projection.owner_generation == generation)
            .map(|p| p.projection.context.project_id.clone()).ok_or_else(invalid_owner)
    }
    /// DATA only under the actual DocumentBinding mutex and native registration
    /// lookup. No filesystem/tool/runtime inspection, child or cleanup task.
    pub(crate) fn prepare(&self, input: Prepare, registration: u32, project: RegisteredRoot, gate: Availability) -> Result<Status, BridgeError> {
        let prepared_at = Instant::now(); // Before this intent's entropy; never renewed by polling.
        self.reconcile(); let mut r = self.inner.lock();
        let reason = self.inner.availability(&r, gate);
        if reason != Availability::Available { return Err(prepare_refusal(reason)); }
        let id = nonce()?; let generation = nonce()?;
        if r.last.as_ref().is_some_and(|last| last.operation_id == id || last.owner_generation == generation) { return Err(unavailable()); }
        let projection = wire::Projection { operation_id: id, owner_generation: generation, context: input.context(),
            phase: Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: Reason::None, result: None };
        r.prepared = Some(Prepared { projection, expires: prepared_at + INTENT, registration, project });
        self.inner.bump(&mut r);
        // After commit, only typed status or unknown/lost reply, never the three
        // fixed preallocation refusal codes used by the renderer controller.
        self.inner.snapshot_locked(&mut r, gate)
    }
    /// T is captured synchronously at DocumentBinding Start entry, before any
    /// await/entropy/runtime/acquisition. Consume matching consent FIRST.
    pub(crate) fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        let clocks = Clocks::new(admitted_at);
        let mut r = self.inner.lock();
        if !r.prepared.as_ref().is_some_and(|p| p.projection.operation_id == input.operation_id && p.projection.owner_generation == input.owner_generation) {
            return Err(invalid_owner()); // Foreign/replayed Start never stops another owner.
        }
        let prepared = r.prepared.take().ok_or_else(invalid_owner)?; // One use, before executor/runtime/effects.
        let mut refused = if Instant::now() >= prepared.expires { Some(Reason::IntentExpired) }
            else if registered.as_ref().is_none_or(|(generation, project)| *generation != prepared.registration || project != &prepared.project) { Some(Reason::StaleIntent) }
            else { None };
        let availability = self.inner.availability(&r, gate);
        if matches!(availability, Availability::CleanupUnknown | Availability::Shutdown | Availability::DocumentLost)
            || refused.is_none() && availability != Availability::Available { refused = Some(refusal_reason(availability)); }
        if refused.is_none() && Instant::now() >= clocks.work { refused = Some(Reason::TimedOut); }
        let executor = tokio::runtime::Handle::try_current().ok();
        let profile = Profile::current();
        if refused.is_none() && (executor.is_none() || profile.is_none()) { refused = Some(Reason::RuntimeUnavailable); }
        if let Some(reason) = refused {
            if reason == Reason::CleanupUnknown { r.disabled = true; }
            r.last = Some(retire(prepared.projection, reason)); self.inner.bump(&mut r);
            return Ok(Admitted { status: self.inner.snapshot_locked(&mut r, gate)?, release: None });
        }
        // A consumed intent already has a safe refusal tombstone if an internal
        // allocation/slot error prevents admission. It is never armed again.
        r.last = Some(retire(prepared.projection.clone(), Reason::StaleIntent));
        self.inner.bump(&mut r);
        let executor = executor.ok_or_else(unavailable)?;
        let profile = profile.ok_or_else(unavailable)?;
        let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
        let (frames, receiver) = mpsc::channel(2);
        let context = prepared.projection.context;
        let projection = RunProjection { operation_id: input.operation_id.clone(), owner_generation: input.owner_generation.clone(),
            context: context.clone(), phase: Phase::Starting, outcome: None, reason: Reason::None, result: None };
        let owner = Arc::new(Session { id: input.operation_id, generation: input.owner_generation, context, profile, clocks,
            registration: prepared.registration, project: prepared.project, request: AsyncMutex::new(None), stop, pipes, frames, wake: Notify::new(),
            output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false), driver_done: AtomicBool::new(false),
            driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false), watchdog_joined: AtomicBool::new(false),
            watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false), startup: Mutex::new(Startup::default()),
            resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
            input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
            driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: self.inner.fixture.lock().ok().and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade)),
        });
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture { permit.bind(&owner)?; }
        let (release, enter) = oneshot::channel();
        // Every new roster slot precedes publication/spawn. No hosted-fixture
        // alternate bootstrap, other-owner permission or caller-owned runner.
        let mut book = owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut driver = owner.driver.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut manager = owner.manager.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut observer = owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        r.active = Some(Active { owner: owner.clone(), projection, first_stop: None, work_expired: false,
            accepted: false, terminal: false, unknown: false, final_join_seen: false });
        *watchdog_slot = Some(executor.spawn(watchdog(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.writer = Some(executor.spawn(write_request(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.stdout = Some(executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.output.clone(), false, Guard::new(&self.inner, &owner))));
        book.stderr = Some(executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.error.clone(), true, Guard::new(&self.inner, &owner))));
        *driver = Some(executor.spawn(drive(self.inner.clone(), owner.clone(), enter, Guard::new(&self.inner, &owner))));
        *manager = Some(executor.spawn(manage(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        *observer = Some(executor.spawn(observe_final(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        self.inner.bump(&mut r);
        let status = self.inner.snapshot_locked(&mut r, gate)?;
        drop(observer); drop(manager); drop(watchdog_slot); drop(driver); drop(book); drop(r);
        self.reconcile(); // Original final-handle completion waker, before GO.
        Ok(Admitted { status, release: Some(release) })
    }
    pub(crate) fn status(&self, gate: Availability) -> Result<Status, BridgeError> {
        self.reconcile(); self.inner.snapshot_locked(&mut self.inner.lock(), gate)
    }
    pub(crate) fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        let mut r = self.inner.lock();
        // Match before clock reconciliation: foreign DATA changes no owner.
        if r.prepared.as_ref().is_some_and(|p| p.projection.operation_id == operation && p.projection.owner_generation == generation) {
            self.inner.retire_prepared(&mut r, Reason::Cancelled);
        } else if let Some(a) = r.active.as_ref().filter(|a| a.owner.id == operation && a.owner.generation == generation) {
            let owner = a.owner.clone(); self.inner.stop_locked(&mut r, &owner, Reason::Cancelled, Instant::now());
        } else if !r.last.as_ref().is_some_and(|last| last.operation_id == operation && last.owner_generation == generation) { return Err(invalid_owner()); }
        drop(r); self.status(gate)
    }
    pub(crate) fn document_lost(&self) {
        let mut r = self.inner.lock(); if r.document_lost { return; } r.document_lost = true;
        self.inner.retire_prepared(&mut r, Reason::DocumentLost);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::DocumentLost, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) fn context_changed(&self) {
        let mut r = self.inner.lock(); self.inner.retire_prepared(&mut r, Reason::ContextChanged);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::ContextChanged, Instant::now()); }
    }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool {
        let r = self.inner.lock(); r.active.as_ref().is_none_or(|a| a.owner.registration == registration)
            && r.prepared.as_ref().is_none_or(|p| p.registration == registration)
    }
    pub(crate) fn request_shutdown(&self) {
        let mut r = self.inner.lock(); r.stopping = true; self.inner.retire_prepared(&mut r, Reason::Shutdown);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::Shutdown, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> {
        self.request_shutdown();
        loop {
            if self.can_exit() { return Ok(()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            tokio::select! { _ = self.inner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
        }
    }
    fn reconcile(&self) {
        let owner = { let mut r = self.inner.lock(); self.inner.expire_prepared(&mut r, Instant::now()); r.active.as_ref().map(|a| a.owner.clone()) };
        let Some(owner) = owner else { return; };
        let mut r = self.inner.lock(); self.inner.advance_locked(&mut r, &owner, Instant::now());
        let Some(active) = r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner)) else { return; };
        if active.final_join_seen { return; }
        let mut watchdog_slot = match owner.watchdog.try_lock() {
            Ok(slot) => slot, Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(_)) => { self.inner.unknown_locked(&mut r, &owner); return; }
        };
        let Some(handle) = watchdog_slot.as_mut() else { self.inner.unknown_locked(&mut r, &owner); return; };
        let waker = Waker::from(Arc::new(FinalWake(Arc::downgrade(&self.inner))));
        let mut context = TaskContext::from_waker(&waker);
        let Poll::Ready(result) = Pin::new(handle).poll(&mut context) else { return; };
        if let Some(a) = r.active.as_mut() { a.final_join_seen = true; }
        let positive = matches!(&result, Ok(true)); let joined = result.is_ok();
        let recorded = record_join(&owner.watchdog_return, result);
        owner.watchdog_joined.store(joined && recorded, Ordering::SeqCst);
        owner.watchdog_failed.store(!joined || !recorded, Ordering::SeqCst);
        if positive && recorded {
            watchdog_slot.take(); self.inner.advance_locked(&mut r, &owner, Instant::now());
            if let Some(mut active) = r.active.take() {
                if !Arc::ptr_eq(&active.owner, &owner) { r.active = Some(active); return; }
                active.projection.phase = if active.unknown { Phase::Unknown } else { Phase::Terminal };
                if active.projection.outcome.is_none() { set_failure_outcome(&mut active.projection); }
                r.last = Some(active.projection.public()); self.inner.bump(&mut r);
            }
        } else {
            // Retain the original failed handle and its result; never re-poll it.
            owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown_locked(&mut r, &owner);
        }
    }
}
struct FinalWake(std::sync::Weak<Inner>);
impl Wake for FinalWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { if let Some(inner) = self.0.upgrade() { inner.changes.send_modify(|_| {}); inner.changed.notify_one(); } }
}
fn record_join<T>(slot: &Mutex<Option<Result<T, tokio::task::JoinError>>>, result: Result<T, tokio::task::JoinError>) -> bool {
    match slot.lock() { Ok(mut slot) if slot.is_none() => { *slot = Some(result); true }, _ => false }
}
fn set_failure_outcome(p: &mut RunProjection) {
    if p.reason == Reason::None { p.reason = Reason::CommandIncomplete; }
    p.outcome = Some(match p.reason {
        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown => Outcome::Cancelled,
        Reason::TimedOut => Outcome::TimedOut, Reason::RuntimeUnavailable => Outcome::Refused, Reason::CleanupUnknown => Outcome::Unknown,
        _ => p.result.as_ref().filter(|t| t.reason == p.reason && t.outcome != Outcome::Complete).map_or(Outcome::Failed, |t| t.outcome),
    });
}
impl Inner {
    fn qualified(&self) -> bool {
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if self.fixture.lock().ok().and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade))
            .is_some_and(|permit| permit.permits(self)) { return true; }
        NATIVE_QUALIFIED && RUNTIME_QUALIFIED
    }
    fn lock(&self) -> MutexGuard<'_, Registry> {
        match self.registry.lock() { Ok(r) => r, Err(error) => { self.poisoned.store(true, Ordering::SeqCst); error.into_inner() } }
    }
    fn bump(&self, r: &mut Registry) {
        if r.exhausted { return; }
        match r.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            Some(next) => r.revision = next,
            None => { r.exhausted = true; r.disabled = true;
                if let Some(prepared) = r.prepared.take() { r.last = Some(retire(prepared.projection, Reason::CleanupUnknown)); }
                if let Some(a) = &r.active { a.owner.stop.send_replace(true); a.owner.wake.notify_waiters(); }
            },
        }
        self.changes.send_replace(r.revision); self.changed.notify_waiters();
    }
    fn retire_prepared(&self, r: &mut Registry, reason: Reason) {
        if let Some(prepared) = r.prepared.take() {
            if reason == Reason::CleanupUnknown { r.disabled = true; }
            r.last = Some(retire(prepared.projection, reason)); self.bump(r);
        }
    }
    fn expire_prepared(&self, r: &mut Registry, now: Instant) {
        if r.prepared.as_ref().is_some_and(|p| now >= p.expires) { self.retire_prepared(r, Reason::IntentExpired); }
    }
    fn availability(&self, r: &Registry, gate: Availability) -> Availability {
        if r.disabled || r.exhausted || self.poisoned.load(Ordering::SeqCst) || gate == Availability::CleanupUnknown { Availability::CleanupUnknown }
        else if r.stopping || gate == Availability::Shutdown { Availability::Shutdown }
        // No original can have started on an unsupported backend. Its missing
        // editing/crash hook must not falsely lock unrelated passive services.
        // Actual retained owners and Unknown still take their original gates.
        else if r.active.is_none() && r.prepared.is_none()
            && (Profile::current().is_none() || gate == Availability::UnsupportedPlatform) { Availability::UnsupportedPlatform }
        else if r.document_lost || gate == Availability::DocumentLost { Availability::DocumentLost }
        else if r.active.is_some() || r.prepared.is_some() || gate == Availability::Busy { Availability::Busy }
        else if !self.qualified() { Availability::RuntimeUnqualified } else { gate }
    }
    fn snapshot_locked(&self, r: &mut Registry, gate: Availability) -> Result<Status, BridgeError> {
        self.expire_prepared(r, Instant::now());
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.advance_locked(r, &owner, Instant::now()); }
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(BridgeError::cleanup_unknown()); }
        let reason = self.availability(r, gate);
        if reason != r.capability { r.capability = reason; self.bump(r); }
        if r.exhausted { return Err(BridgeError::cleanup_unknown()); }
        let operation = r.active.as_ref().map(|a| a.projection.public())
            .or_else(|| r.prepared.as_ref().map(|p| p.projection.clone())).or_else(|| r.last.clone());
        let status = Status { schema_version: 1, status_revision: r.revision, availability: reason, operation };
        crate::edit_protocol::bounded(&status, wire::STATUS_LIMIT)?; Ok(status)
    }
    fn stop_locked(&self, r: &mut Registry, owner: &Session, reason: Reason, at: Instant) {
        let Some(active) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        let at = at.min(owner.clocks.work).max(owner.clocks.admitted); let mut changed = false;
        if active.first_stop.is_none() { active.first_stop = Some(at); changed = true; }
        if active.projection.reason == Reason::None && reason != Reason::None { active.projection.reason = reason; changed = true; }
        if !active.unknown && active.projection.phase != Phase::Stopping { active.projection.phase = Phase::Stopping; changed = true; }
        if active.projection.reason != Reason::None { set_failure_outcome(&mut active.projection); }
        let first_signal = owner.stop.send_if_modified(|stopped| { if *stopped { false } else { *stopped = true; true } });
        if changed || first_signal { owner.wake.notify_waiters(); } if changed { self.bump(r); }
    }
    fn unknown_locked(&self, r: &mut Registry, owner: &Session) {
        self.stop_locked(r, owner, Reason::CleanupUnknown, Instant::now());
        if let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) {
            if !a.unknown { a.unknown = true; a.projection.phase = Phase::Unknown; r.disabled = true; self.bump(r); }
        }
    }
    fn advance_locked(&self, r: &mut Registry, owner: &Session, now: Instant) {
        let Some(a) = r.active.as_ref().filter(|a| a.owner.id == owner.id) else { return; };
        if now >= owner.clocks.work && !a.work_expired {
            if let Some(a) = r.active.as_mut() { a.work_expired = true; }
            self.stop_locked(r, owner, Reason::TimedOut, owner.clocks.work);
        }
        let finality_due = r.active.as_ref().is_some_and(|a| !a.unknown && now >= owner.clocks.settlement(a.first_stop));
        if finality_due || self.poisoned.load(Ordering::SeqCst) || owner.resource_unknown.load(Ordering::SeqCst) { self.unknown_locked(r, owner); }
    }
    fn stop(&self, owner: &Session, reason: Reason) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.stop_locked(&mut r, owner, reason, Instant::now()); }
    fn unknown(&self, owner: &Session) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.unknown_locked(&mut r, owner); }
    fn endpoint(&self, owner: &Session) -> Option<Instant> {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now());
        let a = r.active.as_ref().filter(|a| a.owner.id == owner.id)?;
        if a.unknown { None } else if a.first_stop.is_some() { Some(owner.clocks.settlement(a.first_stop)) } else { Some(owner.clocks.work) }
    }
    fn accept(&self, owner: &Session, frame: Frame) { self.accept_at(owner, frame, Instant::now()); }
    fn accept_at(&self, owner: &Session, frame: Frame, now: Instant) {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, now);
        let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        match frame {
            Frame::Accepted if !a.accepted && !a.terminal => {
                a.accepted = true; if a.first_stop.is_none() && !a.unknown { a.projection.phase = Phase::Running; } self.bump(&mut r);
            }
            Frame::Terminal(terminal) if a.accepted && !a.terminal => {
                a.terminal = true; let settled = terminal.lifetime.settled() && terminal.outcome != Outcome::Unknown; let reason = terminal.reason;
                if a.projection.reason == Reason::None { a.projection.outcome = Some(terminal.outcome); }
                a.projection.result = Some(terminal); self.bump(&mut r);
                if reason == Reason::None {
                    // Complete policy FAIL/MISSING/nonzero rows are NOT F. This
                    // closes the already-finished core input, still provisional.
                    if let Some(a) = r.active.as_mut() { if !a.unknown { a.projection.phase = Phase::Stopping; } }
                    owner.stop.send_replace(true); owner.wake.notify_waiters(); self.bump(&mut r);
                } else { self.stop_locked(&mut r, owner, reason, now); }
                if !settled { owner.resource_unknown.store(true, Ordering::SeqCst); self.unknown_locked(&mut r, owner); }
            }
            _ => { owner.resource_unknown.store(true, Ordering::SeqCst); self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner); }
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
                        let frame = if frames <= 2 { wire::decode(&bytes, &owner.id, &owner.generation, &owner.context) }
                            else { Err(BridgeError::protocol()) };
                        let delivered = match frame { Ok(frame) => {
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
    guard.complete = true; ReadEnd { frames, eof, closed, failed }
}
async fn clock_wait(end: Option<Instant>) {
    match end { Some(end) => tokio::time::sleep_until(tokio::time::Instant::from_std(end)).await, None => pending::<()>().await }
}
async fn watchdog(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> bool {
    // Acyclic: watchdog -> final observer -> manager -> driver/original book.
    // Direct Ready waiting keeps both W/H and the original JoinHandle waker
    // alive even while the final observer itself is held before return.
    let positive = {
        let mut observer = owner.observer.lock().await;
        if observer.is_none() { false } else {
            let result = join_with_clock(&mut observer, &inner, &owner).await;
            let positive = matches!(&result, Ok(true));
            let recorded = record_join(&owner.observer_return, result);
            if positive && recorded { observer.take(); }
            positive && recorded
        }
    };
    if !positive { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
    inner.endpoint(&owner); // Last synchronous clock veto, no new await/effect.
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
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture {
            // The independent offline permit can only check the fixed actual
            // resolver tuple. It cannot supply another bootstrap/argv/cwd.
            if permit.prepare_spawn(owner, &runtime).is_err() {
                inner.stop(owner, Reason::RuntimeUnavailable); return;
            }
        }
        let mut command = Command::new(&runtime.python);
        command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core);
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
    let (inspect_start, inspect_enter) = oneshot::channel();
    book.inspection = Some(tokio::task::spawn_blocking(move || {
        inspect_enter.blocking_recv().map_err(|_| unavailable())?;
        let result = runtime.resolve_offline_preflight(end);
        result
    }));
    let _ = inspect_start.send(()); // Original handle recorded BEFORE inspection effects.
    let runtime = match join_with_clock(&mut book.inspection, inner, owner).await {
        Ok(result) => { book.inspection_joined = true; book.inspection.take(); match result {
            Ok(runtime) => runtime, Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
        } },
        Err(_) => { book.inspection_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; },
    };
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
    let bytes = wire::request(&owner.id, &owner.generation, &owner.context, owner.profile, &owner.project, &runtime.cwd);
    match bytes { Ok(bytes) => *owner.request.lock().await = Some(bytes), Err(_) => { inner.stop(owner, Reason::ProtocolError); return; } }
    let acquisition_owner = owner.clone(); let acquisition_inner = inner.clone();
    let (acquire_start, acquire_enter) = oneshot::channel();
    book.acquisition = Some(tokio::task::spawn_blocking(move || {
        if acquire_enter.blocking_recv().is_ok() { spawn_original(&acquisition_inner, &acquisition_owner, runtime); }
        else { acquisition_inner.stop(&acquisition_owner, Reason::Cancelled); }
    }));
    let _ = acquire_start.send(()); // The original blocking acquisition cannot precede custody.
}
async fn drive(inner: Arc<Inner>, owner: Arc<Session>, enter: oneshot::Receiver<()>, mut guard: Guard) {
    if enter.await.is_err() { inner.stop(&owner, Reason::Cancelled); }
    else {
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
    inner.accept(owner, frame);
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
            Err(_) => { book.inspection_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
        }
    }
    if book.acquisition.is_some() && !book.acquisition_joined && !book.acquisition_failed {
        match join_with_clock(&mut book.acquisition, inner, owner).await {
            Ok(()) => { book.acquisition_joined = true; book.acquisition.take(); },
            Err(_) => { book.acquisition_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
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
        manager_joined && startup_settled && io_joined && io && protocol && owner.driver_joined.load(Ordering::SeqCst)
            && !owner.resource_unknown.load(Ordering::SeqCst)
    };
    if !settled { inner.unknown(&owner); }
    // Final observer owns no unjoined child/IO/acquisition at this point. Its
    // ORIGINAL handle remains with the watchdog until its actual Ready join.
    { let mut r = inner.lock(); inner.bump(&mut r); }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if let Some(permit) = &owner.fixture { permit.observer_return(&owner, settled).await; }
    guard.complete = true; settled
}

#[cfg(test)]
#[path = "offline_preflight_owner_tests.rs"]
mod tests;
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) use tests::hosted::RegistrationPermit as OfflineRegistrationPermit;
