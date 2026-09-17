//! One retained finite native owner, separate from disposable passive queries.
//!
//! Source qualification is NOT enablement. Both this admission gate and the
//! packaged spawn gate remain closed. No Windows edit backend is admitted.
use std::{collections::BTreeSet, future::{Future, pending}, path::PathBuf, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use serde_json::json;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::{Mutex as AsyncMutex, Notify, mpsc, watch}, task::JoinHandle};
#[cfg(all(unix, feature = "development-runtime", debug_assertions))]
use {std::process::Stdio, tokio::process::Command};
use crate::{edit_protocol::{self as wire, Capability, Checkout, ChildFrame, ConfigEditStatus, CoreReason,
    EditAvailability, EditProjection, Effect, Journal, NativeEditReason as Reason, NativeFinality, Phase,
    PrepareConfigEdit, Prepared, ResourceState}, error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}};

const NATIVE_EDIT_QUALIFIED: bool = false;
const ACTIVE: Duration = Duration::from_secs(30);
const REVIEW: Duration = Duration::from_secs(15 * 60);
const SOFT_STOP: Duration = Duration::from_secs(8);
const FINALIZATION: Duration = Duration::from_secs(10);

// Value-only clock decisions shared by the real lock-held admission/expiry
// paths and inert boundary tests. No alternate clock source or owner exists.
fn claim_phase(review_end: Instant, now: Instant) -> Option<Instant> {
    (now < review_end).then(|| now + ACTIVE)
}
fn phase_deadline(review_end: Instant, phase_end: Option<Instant>, applying: bool) -> Option<Instant> {
    if applying { phase_end } else { Some(phase_end.map_or(review_end, |end| end.min(review_end))) }
}
fn expired_phase(review_end: Instant, phase_end: Option<Instant>, applying: bool, now: Instant) -> Option<(Instant, Reason)> {
    let end = phase_deadline(review_end, phase_end, applying)?;
    (now >= end).then_some((end, if !applying && end == review_end { Reason::ReviewExpired } else { Reason::ActiveTimeout }))
}

#[derive(Clone)]
pub struct EditOwner { inner: Arc<Inner> }
struct Inner {
    runtime: RuntimeConfig, registry: Mutex<Registry>, changes: watch::Sender<u32>, changed: Notify,
    poisoned: AtomicBool,
    #[cfg(all(test, feature = "development-runtime"))]
    fixture_authorized: AtomicBool,
    #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
    fixture_next_schedule: Mutex<Option<Arc<hosted_tests::Schedule>>>,
}
struct Registry {
    generation: String, window: Option<String>, document_bound: bool, document_lost: bool,
    revision: u32, exhausted: bool, stopping: bool, disabled: bool,
    active: Option<ActiveOwner>, last: Option<EditProjection>, blocked_projects: BTreeSet<String>,
}
struct ActiveOwner {
    session: Arc<Session>, projection: EditProjection, review_end: Instant, phase_end: Option<Instant>,
    cleanup_start: Option<Instant>, prepare_counters: Option<(u32, u32)>, claimed_seq: u32,
    opened: bool, prepared: bool, terminal: bool, unknown: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Receipt { New, Attempted, Settled, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum PipeAcquisition { Pending, Available, Absent }
struct Pipe<T> { io: Option<T>, close: Receipt }
impl<T> Default for Pipe<T> { fn default() -> Self { Self { io: None, close: Receipt::New } } }
struct Startup { attempted: bool, returned: bool, failed: bool, child: Option<Child> }
impl Default for Startup { fn default() -> Self { Self { attempted: false, returned: false, failed: false, child: None } } }
struct Session {
    id: String, commands: mpsc::Sender<Vec<u8>>, receiver: AsyncMutex<Option<mpsc::Receiver<Vec<u8>>>>,
    stop: watch::Sender<bool>, wake: Notify, force_due: AtomicBool, driver_done: AtomicBool,
    pipes: watch::Sender<PipeAcquisition>, frames: mpsc::Sender<ChildFrame>,
    driver_joined: AtomicBool, driver_join_failed: AtomicBool,
    watchdog_joined: AtomicBool, watchdog_join_failed: AtomicBool, manager_join_failed: AtomicBool,
    driver_join_panicked: AtomicBool, watchdog_join_panicked: AtomicBool, manager_join_panicked: AtomicBool,
    #[cfg(all(test, feature = "development-runtime"))]
    fixture_driver_loss: AtomicBool,
    #[cfg(all(test, feature = "development-runtime"))]
    fixture_watchdog_loss: AtomicBool,
    #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
    fixture_schedule: Arc<hosted_tests::Schedule>,
    resource_unknown: AtomicBool, startup: Mutex<Startup>, resources: AsyncMutex<Resources>,
    input: Arc<AsyncMutex<Pipe<ChildStdin>>>, output: Arc<AsyncMutex<Pipe<ChildStdout>>>,
    error: Arc<AsyncMutex<Pipe<ChildStderr>>>, driver: AsyncMutex<Option<JoinHandle<()>>>,
    watchdog: AsyncMutex<Option<JoinHandle<()>>>, manager: AsyncMutex<Option<JoinHandle<()>>>,
    observer: AsyncMutex<Option<JoinHandle<()>>>,
}
#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>, inspection_joined: bool,
    acquisition: Option<JoinHandle<()>>, acquisition_joined: bool, child: Option<Child>,
    inspection_join_failed: bool, acquisition_join_failed: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    write_join_failed: bool, out_join_failed: bool, err_join_failed: bool,
    frames: Option<mpsc::Receiver<ChildFrame>>,
    waited: Option<ExitStatus>, wait_failed: bool, force_attempted: bool,
    driver_joined: bool, watchdog_joined: bool, manager_joined: bool,
}
struct WriteEnd { frames: usize, closed: bool, failed: bool }
struct ReadEnd { frames: usize, bytes: usize, eof: bool, closed: bool, failed: bool }

fn nonce() -> Result<String, BridgeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| BridgeError::new("edit_unavailable", "Native edit identity generation is unavailable."))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes { value.push(HEX[usize::from(byte >> 4)] as char); value.push(HEX[usize::from(byte & 15)] as char); }
    Ok(value)
}
fn edit_unknown() -> BridgeError { BridgeError::new("cleanup_unknown", "The original configuration edit owner is retained; further edits are disabled.") }
fn invalid_owner() -> BridgeError { BridgeError::new("invalid_edit_owner", "This document does not own that live configuration edit.") }

impl Inner {
    fn hosted_qualified(&self) -> bool {
        // No production/environment bypass. Only the ignored hosted fixture's
        // descendant module can set this private, per-owner test authorization.
        #[cfg(all(test, feature = "development-runtime"))]
        { NATIVE_EDIT_QUALIFIED || self.fixture_authorized.load(Ordering::SeqCst) }
        #[cfg(not(all(test, feature = "development-runtime")))]
        { NATIVE_EDIT_QUALIFIED }
    }
    fn lock(&self) -> MutexGuard<'_, Registry> {
        match self.registry.lock() {
            Ok(guard) => guard,
            Err(error) => { self.poisoned.store(true, Ordering::SeqCst); error.into_inner() }
        }
    }
    fn bump(&self, registry: &mut Registry) {
        if let Some(next) = registry.revision.checked_add(1) { registry.revision = next; }
        else { registry.exhausted = true; registry.disabled = true; }
        self.changes.send_replace(registry.revision);
        self.changed.notify_waiters();
    }
    fn capability(&self, r: &Registry) -> Capability {
        let reason = if r.stopping { EditAvailability::Shutdown }
            else if r.disabled || r.exhausted || self.poisoned.load(Ordering::SeqCst) { EditAvailability::CleanupUnknown }
            else if !(cfg!(target_os = "linux") || cfg!(target_os = "macos")) { EditAvailability::UnsupportedPlatform }
            else if !self.hosted_qualified() || !r.document_bound || r.document_lost { EditAvailability::RuntimeUnqualified }
            else { EditAvailability::Available };
        Capability { available: reason == EditAvailability::Available, reason }
    }
    fn snapshot(&self, r: &Registry) -> Result<ConfigEditStatus, BridgeError> {
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(edit_unknown()); }
        let active = r.active.as_ref().map(|a| {
            let mut projection = a.projection.clone();
            projection.review_remaining_ms = a.review_end.saturating_duration_since(Instant::now()).as_millis().min(u128::from(u32::MAX)) as u32;
            projection
        });
        let status = ConfigEditStatus { schema_version: 1, window_generation: r.generation.clone(), status_revision: r.revision,
            capability: self.capability(r), active, last_terminal: r.last.clone() };
        wire::bounded(&status, wire::STATUS_LIMIT)?;
        Ok(status)
    }
    fn trigger_locked(&self, r: &mut Registry, id: &str, reason: Reason, at: Instant) {
        let Some(a) = r.active.as_mut().filter(|a| a.session.id == id) else { return; };
        if a.cleanup_start.is_none() { a.cleanup_start = Some(at); }
        if a.projection.native_reason == Reason::None && reason != Reason::None { a.projection.native_reason = reason; }
        if !a.unknown { a.projection.phase = Phase::Finalizing; }
        a.phase_end = None;
        a.session.stop.send_replace(true); // Writer EOF is the sole cooperative STOP.
        a.session.wake.notify_waiters();
        self.bump(r);
    }
    fn trigger(&self, id: &str, reason: Reason, at: Instant) {
        let mut r = self.lock();
        self.expire_locked(&mut r, id, Instant::now());
        self.trigger_locked(&mut r, id, reason, at);
    }
    fn unknown(&self, id: &str) {
        let mut r = self.lock();
        self.expire_locked(&mut r, id, Instant::now());
        r.disabled = true;
        if let Some(a) = r.active.as_mut().filter(|a| a.session.id == id) {
            a.unknown = true;
            a.projection.phase = Phase::Unknown;
            a.projection.native_finality = NativeFinality::Unknown;
            if a.projection.native_reason == Reason::None { a.projection.native_reason = Reason::CleanupUnknown; }
            if a.cleanup_start.is_none() { a.cleanup_start = Some(Instant::now()); }
            a.session.stop.send_replace(true);
            a.session.wake.notify_waiters();
        }
        self.bump(&mut r);
    }
    fn deadline(&self, id: &str) -> Option<Instant> {
        let r = self.lock();
        let a = r.active.as_ref().filter(|a| a.session.id == id)?;
        if a.cleanup_start.is_some() { return None; }
        phase_deadline(a.review_end, a.phase_end, a.projection.apply_submitted)
    }
    fn expire_locked(&self, r: &mut Registry, id: &str, now: Instant) {
        let expired = r.active.as_ref().filter(|a| a.session.id == id && a.cleanup_start.is_none()).and_then(|a| {
            expired_phase(a.review_end, a.phase_end, a.projection.apply_submitted, now)
        });
        if let Some((end, reason)) = expired { self.trigger_locked(r, id, reason, end); }
    }
    fn expire(&self, id: &str, now: Instant) {
        let mut r = self.lock();
        self.expire_locked(&mut r, id, now.max(Instant::now()));
    }
    fn admission(&self, r: &Registry, window: &str) -> Result<(), BridgeError> {
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost { return Err(invalid_owner()); }
        match self.capability(r).reason {
            EditAvailability::Available => Ok(()),
            EditAvailability::Shutdown => Err(BridgeError::shutdown()),
            EditAvailability::CleanupUnknown => Err(edit_unknown()),
            _ => Err(BridgeError::unavailable("Native configuration editing is not qualified for this runtime and document.")),
        }
    }
}

impl EditOwner {
    pub fn new(runtime: RuntimeConfig) -> Self {
        let generated = nonce();
        let disabled = generated.is_err();
        let generation = generated.unwrap_or_else(|_| "00000000000000000000000000000000".to_owned());
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner { runtime, changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime"))]
            fixture_authorized: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
            fixture_next_schedule: Mutex::new(None),
            registry: Mutex::new(Registry { generation, window: None, document_bound: false, document_lost: false,
                revision: 0, exhausted: false, stopping: false, disabled, active: None, last: None, blocked_projects: BTreeSet::new() }) }) }
    }
    pub fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub fn status(&self) -> Result<ConfigEditStatus, BridgeError> { self.inner.snapshot(&self.inner.lock()) }
    pub fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || self.inner.poisoned.load(Ordering::SeqCst) || r.exhausted }
    pub fn can_exit(&self) -> bool { self.inner.lock().active.is_none() }

    pub fn initial_document(&self, window: &str) -> Result<(), BridgeError> {
        if window != "main" { return Err(invalid_owner()); }
        let mut r = self.inner.lock();
        if r.document_bound || r.document_lost {
            drop(r);
            self.document_lost(window);
            return Err(invalid_owner());
        }
        r.window = Some(window.to_owned());
        r.document_bound = true;
        self.inner.bump(&mut r);
        Ok(())
    }
    pub fn document_lost(&self, window: &str) {
        let owner = {
            let mut r = self.inner.lock();
            if r.window.as_deref().is_some_and(|bound| bound != window) { return; }
            r.document_lost = true; // Never rebind a later document in this slice.
            match nonce() { Ok(generation) => r.generation = generation, Err(_) => r.disabled = true }
            let owner = r.active.as_ref().map(|a| a.session.id.clone());
            self.inner.bump(&mut r);
            owner
        };
        if let Some(id) = owner { self.inner.trigger(&id, Reason::WindowLost, Instant::now()); }
    }

    pub fn open(&self, window: &str, project_id: String, root: PathBuf) -> Result<ConfigEditStatus, BridgeError> {
        { let r = self.inner.lock(); self.inner.admission(&r, window)?; }
        if project_id.is_empty() || project_id.len() > 128 { return Err(BridgeError::invalid()); }
        let root = root.to_str().filter(|s| s.len() <= 4096).ok_or_else(BridgeError::invalid)?;
        let executor = tokio::runtime::Handle::try_current().map_err(|_| BridgeError::unavailable("The native edit executor is unavailable."))?;
        let id = nonce()?;
        let bytes = wire::request(&id, 0, "open", json!({"root": root}))?;
        let (commands, receiver) = mpsc::channel(1);
        let (stop, _) = watch::channel(false);
        let (pipes, _) = watch::channel(PipeAcquisition::Pending);
        let (frames, frame_rx) = mpsc::channel(3);
        let session = Arc::new(Session { id: id.clone(), commands, receiver: AsyncMutex::new(Some(receiver)), stop,
            wake: Notify::new(), force_due: AtomicBool::new(false), driver_done: AtomicBool::new(false), resource_unknown: AtomicBool::new(false),
            pipes, frames, driver_joined: AtomicBool::new(false), driver_join_failed: AtomicBool::new(false),
            watchdog_joined: AtomicBool::new(false), watchdog_join_failed: AtomicBool::new(false), manager_join_failed: AtomicBool::new(false),
            driver_join_panicked: AtomicBool::new(false), watchdog_join_panicked: AtomicBool::new(false), manager_join_panicked: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime"))]
            fixture_driver_loss: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime"))]
            fixture_watchdog_loss: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
            fixture_schedule: self.inner.fixture_next_schedule.lock().map_err(|_| edit_unknown())?.take().unwrap_or_default(),
            startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(frame_rx), ..Resources::default() }),
            input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())),
            error: Arc::new(AsyncMutex::new(Pipe::default())), driver: AsyncMutex::new(None), watchdog: AsyncMutex::new(None),
            manager: AsyncMutex::new(None), observer: AsyncMutex::new(None) });
        let admission = {
            let mut r = self.inner.lock();
            self.inner.admission(&r, window)?;
            if r.active.is_some() { return Err(BridgeError::new("busy", "One original configuration edit owner is already active.")); }
            if r.blocked_projects.contains(&project_id) { return Err(BridgeError::new("pending_state", "This project requires separately authorized recovery; the desktop cannot retry it.")); }
            let now = Instant::now();
            let generation = r.generation.clone();
            r.active = Some(ActiveOwner { session: session.clone(), review_end: now + REVIEW, phase_end: Some(now + ACTIVE), cleanup_start: None,
                prepare_counters: None, claimed_seq: 0, opened: false, prepared: false, terminal: false, unknown: false,
                projection: EditProjection { project_id, session_id: id.clone(), owner_generation: generation, phase: Phase::Opening,
                    review_remaining_ms: REVIEW.as_millis() as u32, checkout: None, prepared: None, apply_submitted: false,
                    core_outcome: None, native_reason: Reason::None, native_finality: NativeFinality::Pending, late_settled: false } });
            self.inner.bump(&mut r);
            self.inner.snapshot(&r)? // Admission reply captured BEFORE queue/start.
        };
        if session.commands.try_send(bytes).is_err() { self.inner.unknown(&id); return Err(edit_unknown()); }
        if register_original_tasks(&executor, self.inner.clone(), session.clone()).is_err() {
            session.resource_unknown.store(true, Ordering::SeqCst);
            self.inner.unknown(&id);
            return Err(edit_unknown());
        }
        Ok(admission)
    }

    pub fn prepare(&self, window: &str, args: PrepareConfigEdit) -> Result<ConfigEditStatus, BridgeError> {
        if !wire::token(&args.session_id) || !wire::token(&args.revision) { return Err(BridgeError::invalid()); }
        let bytes = wire::request(&args.session_id, 1, "prepare", json!({"revision": &args.revision, "expectedBase": &args.expected_base, "draft": &args.draft}))?;
        let (session, reply) = {
            let mut r = self.inner.lock();
            self.inner.admission(&r, window)?;
            let now = Instant::now(); // Time and claim share the registry race.
            let generation = r.generation.clone();
            let a = r.active.as_mut().filter(|a| a.session.id == args.session_id && a.projection.owner_generation == generation).ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Editing || a.prepare_counters.is_some() || !a.opened { return Err(invalid_owner()); }
            let Some(phase_end) = claim_phase(a.review_end, now) else {
                let at = a.review_end; self.inner.trigger_locked(&mut r, &args.session_id, Reason::ReviewExpired, at); return Err(invalid_owner());
            };
            // Wrong revisions do not revise an original checkout or renew time.
            if a.projection.checkout.as_ref().map(|c| c.revision.as_str()) != Some(args.revision.as_str()) { return Err(invalid_owner()); }
            a.prepare_counters = Some((args.draft_revision, args.baseline_generation));
            a.claimed_seq = 1;
            a.phase_end = Some(phase_end);
            a.projection.phase = Phase::Preparing;
            let session = a.session.clone();
            self.inner.bump(&mut r);
            (session, self.inner.snapshot(&r)?)
        };
        if session.commands.try_send(bytes).is_err() { self.inner.trigger(&session.id, Reason::IoError, Instant::now()); self.inner.unknown(&session.id); }
        session.wake.notify_waiters();
        Ok(reply)
    }

    pub fn apply(&self, window: &str, session_id: &str, plan_token: &str) -> Result<ConfigEditStatus, BridgeError> {
        if !wire::token(session_id) || !wire::token(plan_token) { return Err(BridgeError::invalid()); }
        let bytes = wire::request(session_id, 2, "apply", json!({"planToken": plan_token}))?;
        let (session, reply) = {
            let mut r = self.inner.lock();
            if r.window.as_deref() != Some(window) || r.document_lost { return Err(invalid_owner()); }
            // Repeated exact Apply is observation only, including terminal/Unknown.
            let existing = r.active.as_ref().map(|a| &a.projection).filter(|p| p.session_id == session_id).or_else(|| r.last.as_ref().filter(|p| p.session_id == session_id));
            if existing.is_some_and(|p| p.owner_generation == r.generation && p.apply_submitted && p.prepared.as_ref().is_some_and(|p| p.plan_token == plan_token)) {
                return self.inner.snapshot(&r);
            }
            self.inner.admission(&r, window)?;
            let now = Instant::now();
            let generation = r.generation.clone();
            let a = r.active.as_mut().filter(|a| a.session.id == session_id && a.projection.owner_generation == generation).ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Reviewing || !a.prepared || a.projection.prepared.as_ref().map(|p| p.plan_token.as_str()) != Some(plan_token) { return Err(invalid_owner()); }
            let Some(phase_end) = claim_phase(a.review_end, now) else {
                let at = a.review_end; self.inner.trigger_locked(&mut r, session_id, Reason::ReviewExpired, at); return Err(invalid_owner());
            };
            a.projection.apply_submitted = true; // Consume BEFORE send/acquisition.
            a.projection.phase = Phase::Applying;
            a.claimed_seq = 2;
            a.phase_end = Some(phase_end);
            let session = a.session.clone();
            self.inner.bump(&mut r);
            (session, self.inner.snapshot(&r)?)
        };
        if session.commands.try_send(bytes).is_err() { self.inner.trigger(session_id, Reason::IoError, Instant::now()); self.inner.unknown(session_id); }
        session.wake.notify_waiters();
        Ok(reply)
    }

    pub fn close(&self, window: &str, session_id: &str) -> Result<ConfigEditStatus, BridgeError> {
        if !wire::token(session_id) { return Err(BridgeError::invalid()); }
        let mut r = self.inner.lock();
        self.inner.expire_locked(&mut r, session_id, Instant::now());
        let reason = {
            if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost { return Err(invalid_owner()); }
            if r.last.as_ref().is_some_and(|p| p.session_id == session_id && p.owner_generation == r.generation) { return self.inner.snapshot(&r); }
            let a = r.active.as_ref().filter(|a| a.session.id == session_id && a.projection.owner_generation == r.generation).ok_or_else(invalid_owner)?;
            if a.cleanup_start.is_some() { return self.inner.snapshot(&r); }
            if a.projection.apply_submitted { Reason::Cancelled } else { Reason::Discarded }
        };
        self.inner.trigger_locked(&mut r, session_id, reason, Instant::now());
        self.inner.snapshot(&r)
    }

    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        let id = {
            let mut r = self.inner.lock();
            r.stopping = true;
            let id = r.active.as_ref().map(|a| a.session.id.clone());
            self.inner.bump(&mut r);
            id
        };
        if let Some(id) = id { self.inner.trigger(&id, Reason::Shutdown, Instant::now()); }
        loop {
            let changed = self.inner.changed.notified();
            if self.can_exit() { return Ok(()); }
            if self.disabled() { return Err(edit_unknown()); }
            // The original watchdog supplies the sole cleanup endpoint. This
            // observer adds no clock and cannot abort or drop a live owner.
            changed.await;
        }
    }
}

fn register_original_tasks(executor: &tokio::runtime::Handle, inner: Arc<Inner>, owner: Arc<Session>) -> Result<(), BridgeError> {
    // All original task slots are held before the first task is started. The
    // driver cannot acquire its book until the complete fixed roster exists.
    // No survivor may create a replacement driver, reader, or startup task.
    let mut book = owner.resources.try_lock().map_err(|_| edit_unknown())?;
    let mut driver = owner.driver.try_lock().map_err(|_| edit_unknown())?;
    let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| edit_unknown())?;
    let mut manager = owner.manager.try_lock().map_err(|_| edit_unknown())?;
    let mut observer = owner.observer.try_lock().map_err(|_| edit_unknown())?;
    *watchdog_slot = Some(executor.spawn(watchdog(inner.clone(), owner.clone())));
    book.writer = Some(executor.spawn(write_requests(inner.clone(), owner.clone())));
    book.stdout = Some(executor.spawn(read_output(inner.clone(), owner.clone(), owner.output.clone(), false, owner.frames.clone())));
    book.stderr = Some(executor.spawn(read_output(inner.clone(), owner.clone(), owner.error.clone(), true, owner.frames.clone())));
    *driver = Some(executor.spawn(drive(inner.clone(), owner.clone())));
    *manager = Some(executor.spawn(manage(inner.clone(), owner.clone())));
    *observer = Some(executor.spawn(observe_final(inner, owner.clone())));
    Ok(())
}

trait OriginalClose { fn original_close(self) -> Result<(), ()>; }
macro_rules! close_pipe {
    ($kind:ty) => {
        impl OriginalClose for $kind {
            fn original_close(self) -> Result<(), ()> {
                #[cfg(unix)]
                {
                    let owned = self.into_owned_fd().map_err(|_| ())?;
                    // Safe consuming close, exactly once, retaining real errno.
                    // Tokio shutdown()/Drop is never positive close evidence.
                    nix::unistd::close(owned).map_err(|_| ())
                }
                #[cfg(not(unix))]
                { let _ = self; Err(()) } // No admitted Windows edit backend.
            }
        }
    };
}
close_pipe!(ChildStdin);
close_pipe!(ChildStdout);
close_pipe!(ChildStderr);

fn close_original<T: OriginalClose>(pipe: &mut Pipe<T>) -> bool {
    if pipe.close == Receipt::Settled { return true; }
    if pipe.close != Receipt::New { return false; }
    pipe.close = Receipt::Attempted; // Original slot retired before conversion.
    match pipe.io.take() {
        Some(io) => match io.original_close() {
            Ok(()) => { pipe.close = Receipt::Settled; true },
            Err(()) => { pipe.close = Receipt::Unknown; false },
        },
        None => { pipe.close = Receipt::Unknown; false },
    }
}

async fn original_pipes(inner: &Inner, owner: &Session) -> Result<bool, ()> {
    let mut acquisition = owner.pipes.subscribe();
    loop {
        let state = *acquisition.borrow_and_update();
        match state {
            PipeAcquisition::Available => return Ok(true),
            PipeAcquisition::Absent => return Ok(false),
            PipeAcquisition::Pending => {},
        }
        if acquisition.changed().await.is_err() {
            owner.resource_unknown.store(true, Ordering::SeqCst);
            inner.unknown(&owner.id);
            return Err(());
        }
    }
}

async fn write_requests(inner: Arc<Inner>, owner: Arc<Session>) -> WriteEnd {
    match original_pipes(&inner, &owner).await {
        Ok(true) => {},
        result => return WriteEnd { frames: 0, closed: false, failed: result.is_err() },
    }
    let mut pipe = owner.input.lock().await;
    let mut receiver = owner.receiver.lock().await;
    let Some(receiver) = receiver.as_mut() else {
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.unknown(&owner.id);
        return WriteEnd { frames: 0, closed: close_original(&mut pipe), failed: true };
    };
    let mut stop = owner.stop.subscribe();
    let mut failed = false;
    let mut sent = 0usize;
    let mut completed = 0usize;
    loop {
        if *stop.borrow() { break; }
        let bytes = tokio::select! {
            biased;
            _ = stop.changed() => break,
            next = receiver.recv() => match next { Some(bytes) => bytes, None => { failed = true; break; } },
        };
        if sent >= 3 || bytes.len() > wire::REQUEST_LIMIT { failed = true; break; }
        sent += 1;
        let Some(writer) = pipe.io.as_mut() else { failed = true; break; };
        // A blocked/partial write never delays the independently sticky STOP.
        // Cancelling write_all discards its partial frame, then closes the sole
        // original writer once; the child cannot apply an incomplete request.
        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
        let write = owner.fixture_schedule.write_original(writer, &bytes, sent);
        #[cfg(not(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos"))))]
        let write = writer.write_all(&bytes);
        let complete = tokio::select! {
            biased;
            _ = stop.changed() => false,
            result = write => {
                if result.is_err() { failed = true; }
                result.is_ok()
            },
        };
        if !complete { break; }
        completed += 1; // A receipt counts only a fully returned original write.
        // Intentionally retain stdin after Apply (and between requests).
        // Normal early EOF would be indistinguishable from cancellation.
    }
    while receiver.try_recv().is_ok() {} // Retire bounded unsent draft bytes.
    let closed = close_original(&mut pipe);
    if failed { inner.trigger(&owner.id, Reason::IoError, Instant::now()); }
    if !closed { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); }
    WriteEnd { frames: completed, closed, failed }
}

async fn read_output<T: AsyncRead + Unpin + OriginalClose>(inner: Arc<Inner>, owner: Arc<Session>, slot: Arc<AsyncMutex<Pipe<T>>>,
    stderr: bool, frames: mpsc::Sender<ChildFrame>) -> ReadEnd {
    match original_pipes(&inner, &owner).await {
        Ok(true) => {},
        result => return ReadEnd { frames: 0, bytes: 0, eof: false, closed: false, failed: result.is_err() },
    }
    let mut pipe = slot.lock().await;
    let mut buffer = [0u8; 8192];
    let mut frame = Vec::new();
    let mut total = 0usize;
    let mut count = 0usize;
    let mut observed_frames = 0usize;
    let mut discard = false;
    let mut failed = false;
    let mut eof = false;
    loop {
        let Some(reader) = pipe.io.as_mut() else { failed = true; break; };
        match reader.read(&mut buffer).await {
            Ok(0) => {
                eof = true;
                if !stderr && !frame.is_empty() { failed = true; inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id); }
                #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
                if stderr && !owner.fixture_schedule.stderr_complete() {
                    failed = true;
                    inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id);
                }
                break;
            }
            Ok(length) => {
                let limit = if stderr { wire::STDERR_LIMIT } else { wire::STDOUT_LIMIT };
                total = total.saturating_add(length);
                if !stderr {
                    // Count complete LF frames even while discard-draining;
                    // this is read evidence, never a protocol-validity claim.
                    observed_frames = observed_frames.saturating_add(buffer[..length].iter().filter(|byte| **byte == b'\n').count());
                }
                if total > limit && !discard {
                    discard = true;
                    failed = true;
                    frame.clear();
                    inner.trigger(&owner.id, Reason::OutputLimit, Instant::now());
                    inner.unknown(&owner.id);
                }
                #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
                if stderr && !discard && !owner.fixture_schedule.observe_stderr(&buffer[..length]) {
                    failed = true; discard = true;
                    inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id);
                }
                if stderr || discard { continue; } // Still drain to actual EOF.
                for byte in &buffer[..length] {
                    if discard { break; }
                    frame.push(*byte);
                    if frame.len() > wire::RESPONSE_LIMIT {
                        discard = true; failed = true; frame.clear();
                        inner.trigger(&owner.id, Reason::OutputLimit, Instant::now()); inner.unknown(&owner.id);
                    } else if *byte == b'\n' {
                        count += 1;
                        let parsed = if count <= 3 { wire::decode(&frame, &owner.id) } else { Err(BridgeError::protocol()) };
                        match parsed {
                            Ok(parsed) => {
                                #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
                                owner.fixture_schedule.before_frame(&parsed).await;
                                if frames.try_send(parsed).is_err() {
                                    failed = true; discard = true;
                                    inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id);
                                }
                            },
                            Err(_) => {
                                failed = true; discard = true;
                                inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id);
                            }
                        }
                        frame.clear();
                    }
                }
            }
            Err(_) => {
                // Error is not EOF, and dropping a reader is not settlement.
                failed = true;
                inner.trigger(&owner.id, Reason::IoError, Instant::now());
                inner.unknown(&owner.id);
                break;
            }
        }
    }
    let closed = close_original(&mut pipe);
    if !closed { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); }
    ReadEnd { frames: observed_frames, bytes: total, eof, closed, failed }
}

fn accept_frame(inner: &Inner, owner: &Session, frame: ChildFrame) {
    let mut r = inner.lock();
    let now = Instant::now();
    inner.expire_locked(&mut r, &owner.id, now); // Receipt and expiry serialize.
    let Some(a) = r.active.as_mut().filter(|a| a.session.id == owner.id) else { return; };
    let mut invalid = a.terminal;
    let mut terminal = false;
    let mut uncertain = false;
    if !invalid {
        match frame {
            ChildFrame::Opened(opened) => {
                if a.opened || a.prepared || a.claimed_seq != 0 { invalid = true; }
                else {
                    a.opened = true;
                    a.projection.checkout = Some(Checkout { revision: opened.revision, base: opened.base });
                    if a.cleanup_start.is_none() { a.projection.phase = Phase::Editing; a.phase_end = None; }
                }
            }
            ChildFrame::Prepared(prepared) => {
                if !a.opened || a.prepared || a.claimed_seq != 1
                    || a.projection.checkout.as_ref().map(|c| c.revision.as_str()) != Some(prepared.revision.as_str()) {
                    invalid = true;
                } else if let Some((draft_revision, baseline_generation)) = a.prepare_counters {
                    a.prepared = true;
                    a.projection.prepared = Some(Prepared { revision: prepared.revision, plan_token: prepared.plan_token,
                        draft_revision, baseline_generation, view: prepared.view });
                    if a.cleanup_start.is_none() { a.projection.phase = Phase::Reviewing; a.phase_end = None; }
                } else { invalid = true; }
            }
            ChildFrame::Terminal(seq, result) => {
                let lowest = if a.prepared { 1 } else { 0 };
                let correlated = if a.cleanup_start.is_some() { seq >= lowest && seq <= a.claimed_seq } else { seq == a.claimed_seq };
                let expected = a.projection.prepared.as_ref().map(|p| p.plan_token.as_str());
                let core = result.outcome();
                if !correlated || result.plan_token.as_deref() != expected
                    || !a.projection.apply_submitted && (!matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                        || !matches!(core.journal, Journal::NotCreated | Journal::Unknown))
                    || core.reason == CoreReason::None && a.projection.apply_submitted
                        && !matches!((&core.effect, &core.journal), (Effect::Committed, Journal::Clean) | (Effect::Unchanged, Journal::NotCreated)) {
                    invalid = true;
                } else {
                    uncertain = core.resources == ResourceState::Unknown || core.effect == Effect::Unknown || core.journal == Journal::Unknown;
                    a.projection.core_outcome = Some(core);
                    a.terminal = true;
                    terminal = true;
                    #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
                    owner.fixture_schedule.accepted_terminal(seq);
                }
            }
        }
    }
    inner.bump(&mut r);
    drop(r);
    if invalid {
        inner.trigger(&owner.id, Reason::ProtocolError, now);
        inner.unknown(&owner.id);
    } else if terminal {
        inner.trigger(&owner.id, Reason::None, now);
        if uncertain { inner.unknown(&owner.id); }
    }
    owner.wake.notify_waiters();
}

fn clock_endpoint(inner: &Inner, owner: &Session) -> Option<Instant> {
    loop {
        inner.expire(&owner.id, Instant::now());
        let (phase, review, applying, cleanup, unknown) = {
            let r = inner.lock();
            let a = r.active.as_ref().filter(|a| a.session.id == owner.id)?;
            (a.phase_end, a.review_end, a.projection.apply_submitted, a.cleanup_start, a.unknown)
        };
        let now = Instant::now();
        return if let Some(start) = cleanup {
            if now >= start + FINALIZATION && !unknown { inner.unknown(&owner.id); continue; }
            if now >= start + SOFT_STOP {
                if !owner.force_due.swap(true, Ordering::SeqCst) { owner.wake.notify_waiters(); }
                if unknown { None } else { Some(start + FINALIZATION) }
            } else { Some(start + SOFT_STOP) }
        } else {
            let end = phase_deadline(review, phase, applying).unwrap_or(review);
            if now >= end {
                inner.expire(&owner.id, now); // Recheck the live serialized phase.
                continue;
            }
            Some(end)
        };
    }
}

async fn clock_wait(endpoint: Option<Instant>) {
    match endpoint {
        Some(end) => tokio::time::sleep_until(tokio::time::Instant::from_std(end)).await,
        None => pending().await,
    }
}

async fn watchdog(inner: Arc<Inner>, owner: Arc<Session>) {
    loop {
        let wake = owner.wake.notified();
        #[cfg(all(test, feature = "development-runtime"))]
        if owner.fixture_watchdog_loss.swap(false, Ordering::SeqCst) { panic!("fixed hosted original watchdog loss"); }
        if owner.driver_done.load(Ordering::SeqCst) { return; }
        let endpoint = clock_endpoint(&inner, &owner);
        tokio::select! { _ = wake => {}, _ = clock_wait(endpoint) => {} }
    }
}

fn spawn_original(runtime: VerifiedRuntime, inner: &Inner, owner: &Session) {
    #[cfg(not(all(unix, feature = "development-runtime", debug_assertions)))]
    {
        let _ = runtime;
        inner.trigger(&owner.id, Reason::RuntimeUnavailable, Instant::now());
        return; // Packaged execution and unsupported backends never fall back.
    }
    #[cfg(all(unix, feature = "development-runtime", debug_assertions))]
    {
        let now = Instant::now();
        inner.expire(&owner.id, now);
        let stopped = *owner.stop.borrow();
        if stopped || inner.deadline(&owner.id).is_none_or(|end| now >= end) { return; }
        let mut command = Command::new(&runtime.python);
        command.args(["-I", "-S", "-B"]);
        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
        if owner.fixture_schedule.eof_case().is_some() {
            command.arg(hosted_tests::eof_bootstrap());
        } else { command.arg(&runtime.bootstrap); }
        #[cfg(not(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos"))))]
        command.arg(&runtime.bootstrap);
        command.arg(&runtime.core);
        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
        if let Some(case) = owner.fixture_schedule.eof_case() { command.arg(case.name()); }
        command.current_dir(&runtime.cwd).env_clear().env("LC_ALL", "C").env("LANG", "C")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
        let mut slot = match owner.startup.lock() {
            Ok(slot) => slot,
            Err(error) => { owner.resource_unknown.store(true, Ordering::SeqCst); drop(error.into_inner()); inner.unknown(&owner.id); return; }
        };
        // Register the original acquisition before spawn; its late result is
        // stored here, never returned as a disposable renderer future's value.
        let now = Instant::now();
        inner.expire(&owner.id, now);
        let stopped = *owner.stop.borrow();
        if stopped || inner.deadline(&owner.id).is_none_or(|end| now >= end) { return; }
        slot.attempted = true;
        match command.spawn() {
            Ok(child) => { slot.child = Some(child); slot.returned = true; }
            Err(_) => {
                slot.failed = true;
                // Command does not expose failed-acquisition pipe-close
                // receipts. It is intentionally not classified as settled.
                owner.resource_unknown.store(true, Ordering::SeqCst);
                drop(slot);
                inner.trigger(&owner.id, Reason::SpawnFailed, Instant::now());
                inner.unknown(&owner.id);
            }
        }
    }
}

async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match slot { Some(task) => task.await, None => pending().await }
}
async fn join_with_clock<T>(slot: &mut Option<JoinHandle<T>>, inner: &Inner, owner: &Session) -> Result<T, tokio::task::JoinError> {
    loop {
        let wake = owner.wake.notified();
        let endpoint = clock_endpoint(inner, owner);
        tokio::select! {
            result = join_slot(slot) => return result,
            _ = wake => {},
            _ = clock_wait(endpoint) => {},
        }
    }
}
async fn wait_child(child: &mut Option<Child>) -> std::io::Result<ExitStatus> {
    match child { Some(child) => child.wait().await, None => pending().await }
}
async fn next_frame(frames: &mut Option<mpsc::Receiver<ChildFrame>>) -> Option<ChildFrame> {
    match frames { Some(frames) => frames.recv().await, None => pending().await }
}
fn drain_frames(book: &mut Resources, inner: &Inner, owner: &Session) {
    if let Some(frames) = book.frames.as_mut() {
        while let Ok(frame) = frames.try_recv() { accept_frame(inner, owner, frame); }
    }
}
fn require_terminal(inner: &Inner, owner: &Session) {
    let terminal = { let r = inner.lock(); r.active.as_ref().is_some_and(|a| a.session.id == owner.id && a.terminal) };
    if !terminal { inner.trigger(&owner.id, Reason::ProtocolError, Instant::now()); inner.unknown(&owner.id); }
}
enum Event { Wait(std::io::Result<ExitStatus>), Write(Result<WriteEnd, tokio::task::JoinError>), Out(Result<ReadEnd, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Frame(Option<ChildFrame>), Wake }

async fn start_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    let mut book = owner.resources.lock().await;
    let now = Instant::now();
    inner.expire(&owner.id, now);
    let endpoint = inner.deadline(&owner.id);
    let stopped = *owner.stop.borrow();
    if stopped || endpoint.is_none_or(|end| now >= end) {
        inner.trigger(&owner.id, Reason::Cancelled, Instant::now());
        return;
    }
    let endpoint = match endpoint { Some(end) => end, None => return };
    let runtime = inner.runtime.clone();
    #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
    let schedule = owner.fixture_schedule.clone();
    book.inspection = Some(tokio::task::spawn_blocking(move || {
        let result = runtime.resolve_edit(endpoint);
        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
        schedule.inspected(result.is_ok());
        result
    }));
    let inspected = join_with_clock(&mut book.inspection, inner, owner).await;
    let runtime = match inspected {
        Ok(result) => {
            book.inspection_joined = true;
            book.inspection.take();
            inner.expire(&owner.id, Instant::now());
            match result { Ok(runtime) => runtime, Err(_) => { inner.trigger(&owner.id, Reason::RuntimeUnavailable, Instant::now()); return; } }
        }
        Err(_) => { book.inspection_join_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); return; }
    };
    let now = Instant::now();
    inner.expire(&owner.id, now);
    let stopped = *owner.stop.borrow();
    if stopped || inner.deadline(&owner.id).is_none_or(|end| now >= end) {
        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
        owner.fixture_schedule.refused_acquisition();
        inner.trigger(&owner.id, Reason::Cancelled, Instant::now());
        return;
    }
    let startup_owner = owner.clone();
    // The caller supplies the original registry Arc; there is only this one
    // acquisition site. Survivors never call start_original or resolve/spawn.
    let startup_inner = inner.clone();
    book.acquisition = Some(tokio::task::spawn_blocking(move || spawn_original(runtime, &startup_inner, &startup_owner)));
}

async fn drive(inner: Arc<Inner>, owner: Arc<Session>) {
    start_original(&inner, &owner).await;
    continue_original(inner, owner, true).await;
}

async fn continue_original(inner: Arc<Inner>, owner: Arc<Session>, _original_driver: bool) {
    // Called normally by the one driver, or inline by its surviving monitor
    // only after that original driver has failed and released this book.
    // Pending startup/pipe/IO objects remain here across a dropped future.
    let mut book = owner.resources.lock().await;
    if book.inspection.is_some() && !book.inspection_joined && !book.inspection_join_failed {
        match join_with_clock(&mut book.inspection, &inner, &owner).await {
            Ok(_) => { book.inspection_joined = true; book.inspection.take(); },
            Err(_) => { book.inspection_join_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); },
        }
        // Even a late verified runtime is only data here: never spawn from it.
    }
    if book.acquisition.is_some() && !book.acquisition_joined && !book.acquisition_join_failed {
        match join_with_clock(&mut book.acquisition, &inner, &owner).await {
            Ok(()) => { book.acquisition_joined = true; book.acquisition.take(); },
            Err(_) => {
                book.acquisition_join_failed = true;
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
            },
        }
    }
    let child_expected = {
        let mut startup = match owner.startup.lock() {
            Ok(startup) => startup,
            Err(error) => { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); error.into_inner() }
        };
        if book.child.is_none() { book.child = startup.child.take(); }
        else if startup.child.is_some() { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); }
        startup.returned || book.child.is_some()
    };
    let acquisition = *owner.pipes.borrow();
    if acquisition == PipeAcquisition::Pending {
        if let Some(child) = book.child.as_mut() {
            // IO tasks are already registered and parked. Transfer each exact
            // endpoint without overwriting an earlier interrupted handoff.
            let mut input = owner.input.lock().await;
            let mut output = owner.output.lock().await;
            let mut error = owner.error.lock().await;
            if input.io.is_none() && input.close == Receipt::New { input.io = child.stdin.take(); }
            if output.io.is_none() && output.close == Receipt::New { output.io = child.stdout.take(); }
            if error.io.is_none() && error.close == Receipt::New { error.io = child.stderr.take(); }
            if input.io.is_none() || output.io.is_none() || error.io.is_none()
                || child.stdin.is_some() || child.stdout.is_some() || child.stderr.is_some() {
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
            }
            owner.pipes.send_replace(PipeAcquisition::Available);
        } else {
            // Absent is a no-original-endpoint fact, NOT a close/EOF receipt.
            // Each parked IO task returns empty, negative close/EOF evidence.
            owner.pipes.send_replace(PipeAcquisition::Absent);
            inner.trigger(&owner.id, Reason::RuntimeUnavailable, Instant::now());
        }
    }
    // A prior monitor may have been lost after recording a failed IO join but
    // before dispatching its independent close. Resume only an unattempted
    // original slot; an ambiguous close is never retried.
    if book.write_join_failed { let mut pipe = owner.input.lock().await; let _ = close_original(&mut pipe); }
    if book.out_join_failed { let mut pipe = owner.output.lock().await; let _ = close_original(&mut pipe); }
    if book.err_join_failed { let mut pipe = owner.error.lock().await; let _ = close_original(&mut pipe); }
    let mut frames_open = book.frames.is_some();
    loop {
        let wake = owner.wake.notified();
        #[cfg(all(test, feature = "development-runtime"))]
        if _original_driver && owner.fixture_driver_loss.swap(false, Ordering::SeqCst) { panic!("fixed hosted original driver loss"); }
        let endpoint = clock_endpoint(&inner, &owner);
        if owner.force_due.load(Ordering::SeqCst) && book.child.is_some() && !book.force_attempted && book.waited.is_none() {
            book.force_attempted = true;
            if let Some(child) = book.child.as_mut() {
                if child.start_kill().is_err() { inner.unknown(&owner.id); }
            } else { inner.unknown(&owner.id); }
        }
        let wait_pending = book.child.is_some() && book.waited.is_none() && !book.wait_failed;
        let write_pending = book.writer.is_some() && !book.write_join_failed;
        let out_pending = book.stdout.is_some() && !book.out_join_failed;
        let err_pending = book.stderr.is_some() && !book.err_join_failed;
        let force_pending = book.child.is_some() && book.waited.is_none() && !book.force_attempted;
        if !wait_pending && !write_pending && !out_pending && !err_pending && !force_pending {
            // Consume all bounded already-queued receipts before finality.
            drain_frames(&mut book, &inner, &owner);
            break;
        }
        let event = {
            let Resources { child, writer, stdout, stderr, frames, .. } = &mut *book;
            tokio::select! {
                result = wait_child(child), if wait_pending => Event::Wait(result),
                result = join_slot(writer), if write_pending => Event::Write(result),
                result = join_slot(stdout), if out_pending => Event::Out(result),
                result = join_slot(stderr), if err_pending => Event::Err(result),
                frame = next_frame(frames), if frames_open => Event::Frame(frame),
                _ = wake => Event::Wake,
                _ = clock_wait(endpoint) => Event::Wake,
            }
        };
        match event {
            Event::Wait(Ok(status)) => {
                let success = status.success();
                book.waited = Some(status);
                if !success { inner.trigger(&owner.id, Reason::IoError, Instant::now()); inner.unknown(&owner.id); }
            }
            Event::Wait(Err(_)) => { book.wait_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner.id); }
            Event::Write(Ok(end)) => { book.writer.take(); book.write_end = Some(end); }
            Event::Out(Ok(end)) => {
                book.stdout.take();
                book.out_end = Some(end);
                // The sole stdout task has finished, so its bounded queued
                // frames precede this final EOF/read receipt. Accept them
                // before deciding whether the terminal frame is missing.
                drain_frames(&mut book, &inner, &owner);
                if child_expected { require_terminal(&inner, &owner); }
            }
            Event::Err(Ok(end)) => { book.stderr.take(); book.err_end = Some(end); }
            Event::Write(Err(_)) => {
                book.write_join_failed = true;
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
                let mut pipe = owner.input.lock().await;
                let _ = close_original(&mut pipe);
            }
            Event::Out(Err(_)) => {
                book.out_join_failed = true;
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
                let mut pipe = owner.output.lock().await;
                let _ = close_original(&mut pipe);
            }
            Event::Err(Err(_)) => {
                book.err_join_failed = true;
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
                let mut pipe = owner.error.lock().await;
                let _ = close_original(&mut pipe);
            }
            Event::Frame(Some(frame)) => accept_frame(&inner, &owner, frame),
            Event::Frame(None) => frames_open = false,
            Event::Wake => {},
        }
        // A failed join retains its original handle and an explicit no-repoll
        // latch. Independent original closes, wait/joins, and the same force
        // endpoint continue; no sibling abort or replacement owner is created.
    }
    if child_expected { require_terminal(&inner, &owner); }
}

struct ManagerGuard { inner: Arc<Inner>, owner: Arc<Session>, completed: bool }
impl Drop for ManagerGuard {
    fn drop(&mut self) { if !self.completed { self.inner.unknown(&self.owner.id); } }
}
type Continuation = Pin<Box<dyn Future<Output = ()> + Send>>;
async fn continue_slot(slot: &mut Option<Continuation>) {
    match slot { Some(continuation) => continuation.await, None => pending().await }
}
enum MonitorEvent { Driver(Result<(), tokio::task::JoinError>), Watchdog(Result<(), tokio::task::JoinError>), Continued, Wake }

async fn monitor_original(inner: Arc<Inner>, owner: Arc<Session>) {
    // These task slots are distinct from the resource book. Never wait for the
    // book while a live original driver holds it: the surviving clock must not
    // queue behind the blocking startup/wait it is meant to supervise.
    let mut driver = owner.driver.lock().await;
    let mut watchdog_slot = owner.watchdog.lock().await;
    let mut continuation: Option<Continuation> = None;
    loop {
        let wake = owner.wake.notified();
        let endpoint = clock_endpoint(&inner, &owner);
        let driver_known = owner.driver_joined.load(Ordering::SeqCst) || owner.driver_join_failed.load(Ordering::SeqCst);
        let watchdog_known = owner.watchdog_joined.load(Ordering::SeqCst) || owner.watchdog_join_failed.load(Ordering::SeqCst);
        if driver.is_none() && !driver_known {
            owner.driver_join_failed.store(true, Ordering::SeqCst);
            owner.resource_unknown.store(true, Ordering::SeqCst);
            inner.unknown(&owner.id);
            continue;
        }
        if watchdog_slot.is_none() && !watchdog_known {
            owner.watchdog_join_failed.store(true, Ordering::SeqCst);
            owner.resource_unknown.store(true, Ordering::SeqCst);
            inner.unknown(&owner.id);
            continue;
        }
        if owner.driver_join_failed.load(Ordering::SeqCst) && !owner.driver_done.load(Ordering::SeqCst) && continuation.is_none() {
            // Inline progress of the SAME original book, not another task,
            // reader, resolve/spawn attempt, request, owner, or cleanup clock.
            continuation = Some(Box::pin(continue_original(inner.clone(), owner.clone(), false)));
        }
        if owner.driver_done.load(Ordering::SeqCst) && driver_known && watchdog_known && continuation.is_none() { break; }
        let continuing = continuation.is_some();
        let event = tokio::select! {
            result = join_slot(&mut driver), if !driver_known => MonitorEvent::Driver(result),
            result = join_slot(&mut watchdog_slot), if !watchdog_known => MonitorEvent::Watchdog(result),
            _ = continue_slot(&mut continuation), if continuing => MonitorEvent::Continued,
            _ = wake => MonitorEvent::Wake,
            _ = clock_wait(endpoint) => MonitorEvent::Wake,
        };
        match event {
            MonitorEvent::Driver(Ok(())) => {
                owner.driver_joined.store(true, Ordering::SeqCst);
                driver.take();
                owner.driver_done.store(true, Ordering::SeqCst);
                owner.wake.notify_waiters();
            }
            MonitorEvent::Driver(Err(error)) => {
                // Bounded classification only, derived from the actual Err
                // branch; the failed original handle is retained, never repolled.
                owner.driver_join_panicked.store(error.is_panic() && !error.is_cancelled(), Ordering::SeqCst);
                owner.driver_join_failed.store(true, Ordering::SeqCst);
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
            }
            MonitorEvent::Watchdog(Ok(())) => {
                owner.watchdog_joined.store(true, Ordering::SeqCst);
                watchdog_slot.take();
                if !owner.driver_done.load(Ordering::SeqCst) {
                    owner.resource_unknown.store(true, Ordering::SeqCst);
                    inner.unknown(&owner.id);
                }
            }
            MonitorEvent::Watchdog(Err(error)) => {
                owner.watchdog_join_panicked.store(error.is_panic() && !error.is_cancelled(), Ordering::SeqCst);
                owner.watchdog_join_failed.store(true, Ordering::SeqCst);
                owner.resource_unknown.store(true, Ordering::SeqCst);
                inner.unknown(&owner.id);
                // This loop's same-deadline clock survives watchdog loss while
                // the original driver continues wait/force/IO settlement.
            }
            MonitorEvent::Continued => {
                continuation.take();
                owner.driver_done.store(true, Ordering::SeqCst);
                owner.wake.notify_waiters();
            }
            MonitorEvent::Wake => {},
        }
    }
    let mut book = owner.resources.lock().await;
    book.driver_joined = owner.driver_joined.load(Ordering::SeqCst);
    book.watchdog_joined = owner.watchdog_joined.load(Ordering::SeqCst);
}

async fn manage(inner: Arc<Inner>, owner: Arc<Session>) {
    let mut guard = ManagerGuard { inner: inner.clone(), owner: owner.clone(), completed: false };
    monitor_original(inner, owner).await;
    guard.completed = true;
}

async fn observe_final(inner: Arc<Inner>, owner: Arc<Session>) {
    let mut guard = ManagerGuard { inner: inner.clone(), owner: owner.clone(), completed: false };
    let manager_joined = {
        let mut manager = owner.manager.lock().await;
        if manager.is_none() {
            // A missing slot is no join receipt. Fail closed without parking
            // forever before the retained exceptional custodian can progress.
            owner.manager_join_failed.store(true, Ordering::SeqCst);
            false
        } else {
            match join_slot(&mut manager).await {
                Ok(()) => { manager.take(); true },
                Err(error) => {
                    owner.manager_join_panicked.store(error.is_panic() && !error.is_cancelled(), Ordering::SeqCst);
                    owner.manager_join_failed.store(true, Ordering::SeqCst);
                    false
                },
            }
        }
    };
    if !manager_joined {
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.unknown(&owner.id);
        // The final observer is normally pure. A lost manager makes this
        // already-retained observer an exceptional original-only custodian;
        // it may finish outstanding cleanup, but can NEVER retire this owner
        // or restore the missing manager/driver receipt or native capability.
        monitor_original(inner.clone(), owner.clone()).await;
        guard.completed = true;
        pending::<()>().await;
        return;
    }
    let settled = {
        let mut book = owner.resources.lock().await;
        book.manager_joined = true;
        let startup = match owner.startup.lock() {
            Ok(startup) => startup,
            Err(error) => { owner.resource_unknown.store(true, Ordering::SeqCst); error.into_inner() }
        };
        let startup_settled = book.inspection.is_none() && book.acquisition.is_none()
            && !book.inspection_join_failed && !book.acquisition_join_failed && !startup.failed
            && (!startup.attempted || startup.returned && book.acquisition_joined);
        let io_joined = book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
            && !book.write_join_failed && !book.out_join_failed && !book.err_join_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some();
        let child_settled = if startup.returned {
            book.waited.is_some() && !book.wait_failed
                && book.write_end.as_ref().is_some_and(|end| end.closed)
                && book.out_end.as_ref().is_some_and(|end| end.eof && end.closed)
                && book.err_end.as_ref().is_some_and(|end| end.eof && end.closed)
        } else { book.child.is_none() && startup.child.is_none() };
        startup_settled && io_joined && child_settled && book.driver_joined && book.watchdog_joined
            && !owner.driver_join_failed.load(Ordering::SeqCst) && !owner.watchdog_join_failed.load(Ordering::SeqCst)
            && !owner.resource_unknown.load(Ordering::SeqCst)
    };
    if !settled {
        inner.unknown(&owner.id);
        guard.completed = true;
        pending::<()>().await; // Pure retained observer once original work ended.
        return;
    }
    let mut r = inner.lock();
    let Some(a) = r.active.as_ref().filter(|a| a.session.id == owner.id) else { guard.completed = true; return; };
    let expired = a.cleanup_start.is_some_and(|start| Instant::now() >= start + FINALIZATION);
    if expired && !a.unknown { drop(r); inner.unknown(&owner.id); r = inner.lock(); }
    if let Some(mut a) = r.active.take() {
        if a.session.id != owner.id { r.active = Some(a); guard.completed = true; return; }
        if a.projection.core_outcome.as_ref().is_some_and(|core| core.journal == Journal::RecoveryRequired) {
            // IDs only, bounded by the native 64-project picker registry. No
            // retained private history or guessed recovery controller.
            if r.blocked_projects.len() < 64 { r.blocked_projects.insert(a.projection.project_id.clone()); }
            else { r.disabled = true; }
        }
        if a.unknown {
            a.projection.phase = Phase::Unknown;
            a.projection.native_finality = NativeFinality::Unknown;
            a.projection.late_settled = true;
        } else {
            a.projection.phase = Phase::Final;
            a.projection.native_finality = NativeFinality::Settled;
        }
        r.last = Some(a.projection); // Atomic active -> one terminal projection.
        inner.bump(&mut r);
    }
    guard.completed = true;
}

#[cfg(all(test, feature = "development-runtime"))]
#[path = "edit_hosted_tests.rs"]
mod hosted_tests;

#[cfg(test)]
mod clock_tests {
    use super::{ACTIVE, FINALIZATION, REVIEW, SOFT_STOP, Reason, claim_phase, expired_phase, phase_deadline};
    use std::time::{Duration, Instant};

    #[test]
    fn review_claim_and_deadline_boundaries() {
        // Inert same-clock values only: no owner, entropy, channels, runtime,
        // environment, filesystem, subprocess or 15-minute elapsed-time claim.
        assert_eq!((ACTIVE.as_secs(), REVIEW.as_secs(), SOFT_STOP.as_secs(), FINALIZATION.as_secs()), (30, 900, 8, 10));
        let registered = Instant::now();
        let review = registered + REVIEW;
        assert_eq!(phase_deadline(review, Some(registered + ACTIVE), false), Some(registered + ACTIVE));
        assert_eq!(phase_deadline(review, None, false), Some(review));
        let before = review - Duration::from_nanos(1);
        let claimed = claim_phase(review, before).expect("claim strictly before original review endpoint");
        assert_eq!(claimed, before + ACTIVE);
        assert_eq!(phase_deadline(review, Some(claimed), false), Some(review)); // Preparing remains capped.
        assert_eq!(phase_deadline(review, Some(claimed), true), Some(claimed)); // Accepted Apply is not capped.
        assert_eq!(claim_phase(review, review), None);
        assert_eq!(claim_phase(review, review + ACTIVE), None);
        assert_eq!(expired_phase(review, Some(claimed), true, review), None);
        assert_eq!(expired_phase(review, Some(claimed), true, claimed), Some((claimed, Reason::ActiveTimeout)));
        // Repeated decisions cannot renew the caller's original review value.
        assert_eq!(phase_deadline(review, None, false), Some(registered + REVIEW));
    }

    #[test]
    fn expiry_uses_original_scheduled_endpoint() {
        let registered = Instant::now();
        let review = registered + REVIEW;
        let active = registered + ACTIVE;
        assert_eq!(expired_phase(review, Some(active), false, active - Duration::from_nanos(1)), None);
        assert_eq!(expired_phase(review, Some(active), false, active), Some((active, Reason::ActiveTimeout)));
        assert_eq!(expired_phase(review, Some(active), false, active + FINALIZATION), Some((active, Reason::ActiveTimeout)));
        assert_eq!(expired_phase(review, None, false, review), Some((review, Reason::ReviewExpired)));
        assert_eq!(expired_phase(review, None, false, review + FINALIZATION), Some((review, Reason::ReviewExpired)));
        assert_eq!(expired_phase(review, Some(review + ACTIVE), false, review), Some((review, Reason::ReviewExpired)));
        assert_eq!(expired_phase(review, None, true, review + ACTIVE), None);
    }
}
