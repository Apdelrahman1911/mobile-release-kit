//! One retained finite native owner, separate from disposable passive queries.
//!
//! Source qualification is NOT enablement. Both this admission gate and the
//! packaged spawn gate remain closed. No Windows edit backend is admitted.
use std::{collections::BTreeSet, future::{Future, pending}, path::PathBuf, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use serde_json::{json, Value};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::{Mutex as AsyncMutex, Notify, mpsc, watch}, task::JoinHandle};
#[cfg(all(unix, feature = "development-runtime", debug_assertions))]
use {std::process::Stdio, tokio::process::Command};
use crate::{edit_protocol::{self as wire, Capability, Checkout, ChildFrame, ConfigEditStatus, CoreReason,
    EditAvailability, EditDomain, EditProjection, Effect, Journal, NativeEditReason as Reason, NativeFinality, Phase,
    PrepareConfigEdit, Prepared, ResourceState}, github_workflow_edit_protocol::{self as workflow_wire, PrepareWorkflowEdit, WorkflowEditStatus},
    metadata_text_edit_protocol::{self as metadata_wire, MetadataTextEditStatus, PrepareMetadataTextEdit},
    error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}};

const NATIVE_EDIT_QUALIFIED: bool = false;
const NATIVE_WORKFLOW_EDIT_QUALIFIED: bool = false;
const NATIVE_METADATA_TEXT_EDIT_QUALIFIED: bool = false;
const ACTIVE: Duration = Duration::from_secs(30);
const REVIEW: Duration = Duration::from_secs(15 * 60);
const SOFT_STOP: Duration = Duration::from_secs(8);
const FINALIZATION: Duration = Duration::from_secs(10);

fn qualified(domain: EditDomain, configuration_fixture: bool) -> bool {
    match domain {
        EditDomain::Configuration => NATIVE_EDIT_QUALIFIED || configuration_fixture,
        EditDomain::GitHubWorkflows => NATIVE_WORKFLOW_EDIT_QUALIFIED,
        EditDomain::MetadataText => NATIVE_METADATA_TEXT_EDIT_QUALIFIED,
    }
}
fn capability_reason(domain: EditDomain, active: Option<EditDomain>, stopping: bool, disabled: bool,
    domain_qualified: bool, document_live: bool) -> EditAvailability {
    // Opposite-domain pending/Unknown is never presented as globally idle,
    // even when a separate reason also closes this domain's qualification.
    if active.is_some_and(|owner| owner != domain) { EditAvailability::OtherEditActive }
    else if stopping { EditAvailability::Shutdown }
    else if disabled { EditAvailability::CleanupUnknown }
    else if match domain {
        EditDomain::Configuration => !(cfg!(target_os = "linux") || cfg!(target_os = "macos")),
        EditDomain::GitHubWorkflows => !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")),
        EditDomain::MetadataText => !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")),
    } { EditAvailability::UnsupportedPlatform }
    else if !domain_qualified || !document_live { EditAvailability::RuntimeUnqualified }
    else { EditAvailability::Available }
}
fn exact_apply_receipt(projection: &EditProjection, domain: EditDomain, generation: &str, session: &str, plan: &str) -> bool {
    projection.domain == domain && projection.owner_generation == generation && projection.session_id == session
        && projection.apply_submitted && projection.plan_token() == Some(plan)
}
fn request_bytes(domain: EditDomain, session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    match domain {
        EditDomain::Configuration => wire::request(session, seq, op, params),
        EditDomain::GitHubWorkflows => workflow_wire::request(session, seq, op, params),
        EditDomain::MetadataText => metadata_wire::request(session, seq, op, params),
    }
}
enum DomainStatus { Configuration(ConfigEditStatus), GitHubWorkflows(WorkflowEditStatus), MetadataText(MetadataTextEditStatus) }
impl DomainStatus {
    fn configuration(self) -> Result<ConfigEditStatus, BridgeError> {
        match self { Self::Configuration(status) => Ok(status), _ => Err(BridgeError::protocol()) }
    }
    fn workflows(self) -> Result<WorkflowEditStatus, BridgeError> {
        match self { Self::GitHubWorkflows(status) => Ok(status), _ => Err(BridgeError::protocol()) }
    }
    fn metadata_text(self) -> Result<MetadataTextEditStatus, BridgeError> {
        match self { Self::MetadataText(status) => Ok(status), _ => Err(BridgeError::protocol()) }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RegisteredEditRoot {
    pub(crate) generation: u32, pub(crate) root: crate::asset_source::RegisteredRoot,
}
// Keep existing workflow callers/fixtures bound to their original API. The
// shared root proof is not a domain permit; admission and tickets remain tagged.
pub(crate) type WorkflowRegistration = RegisteredEditRoot;
pub(crate) struct RegisteredOpenTicket { owner: Arc<Inner>, domain: EditDomain, id: String, executor: tokio::runtime::Handle }
pub(crate) type WorkflowOpenTicket = RegisteredOpenTicket;

// Only the ignored headless workflow fixture can construct this private value,
// after its fixed hosted/root/source/runtime/payload admission. No environment
// flag, configuration fixture, renderer command, or production build mints it.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct WorkflowFixturePermit {
    owner: std::sync::Weak<Inner>, roots: Vec<PathBuf>, python: PathBuf, core: PathBuf,
    bootstrap: PathBuf, cwd: PathBuf, binding_sha256: String, eof: bool,
}
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl WorkflowFixturePermit {
    fn owns(&self, inner: &Inner) -> bool {
        self.owner.upgrade().is_some_and(|original| std::ptr::eq(Arc::as_ptr(&original), inner))
            && self.binding_sha256.len() == 64
            && self.binding_sha256.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }
    fn root(&self, inner: &Inner, path: &std::path::Path) -> bool {
        self.owns(inner) && self.roots.iter().any(|root| root == path)
    }
    fn bootstrap_case(eof: bool, path: &std::path::Path, case: Option<hosted_tests::EofCase>) -> bool {
        match (eof, case) {
            (false, None) => true,
            (true, Some(case)) => case.domain() == EditDomain::GitHubWorkflows
                && path.file_name().and_then(|name| name.to_str()) == Some(case.name()),
            _ => false,
        }
    }
    fn spawn(&self, inner: &Inner, session: &Session, runtime: &VerifiedRuntime) -> bool {
        session.domain == EditDomain::GitHubWorkflows
            && session.registration.as_ref().is_some_and(|registration| self.root(inner, &registration.root.path)
                && Self::bootstrap_case(self.eof, &registration.root.path, session.fixture_schedule.eof_case()))
            && runtime.python == self.python && runtime.core == self.core
            && runtime.bootstrap == self.bootstrap && runtime.cwd == self.cwd
    }
}

// Separate, finite metadata fixture authority. The registered root itself,
// configuration's test flag and a workflow permit are not metadata authority.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct MetadataFixturePermit {
    owner: std::sync::Weak<Inner>, selections: Vec<(PathBuf, metadata_wire::Platform, String)>,
    python: PathBuf, core: PathBuf, bootstrap: PathBuf, cwd: PathBuf,
    binding_sha256: String, zip: bool, eof: bool,
}
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl MetadataFixturePermit {
    fn owns(&self, inner: &Inner) -> bool {
        self.owner.upgrade().is_some_and(|original| std::ptr::eq(Arc::as_ptr(&original), inner))
            && !self.selections.is_empty() && self.selections.len() <= 15
            && self.binding_sha256.len() == 64
            && self.binding_sha256.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && (!self.eof || !self.zip)
    }
    fn root(&self, inner: &Inner, path: &std::path::Path) -> bool {
        self.owns(inner) && self.selections.iter().any(|(root, _, _)| root == path)
    }
    fn selection(&self, inner: &Inner, path: &std::path::Path, context: &metadata_wire::Context) -> bool {
        self.owns(inner) && self.selections.iter().any(|(root, platform, locale)|
            root == path && *platform == context.platform && *locale == context.locale)
    }
    fn bootstrap_case(eof: bool, path: &std::path::Path, case: Option<hosted_tests::EofCase>) -> bool {
        match (eof, case) {
            (false, None) => true,
            (true, Some(case)) => case.domain() == EditDomain::MetadataText
                && path.file_name().and_then(|name| name.to_str()) == Some(case.name()),
            _ => false,
        }
    }
    fn spawn(&self, inner: &Inner, session: &Session, runtime: &VerifiedRuntime) -> bool {
        session.domain == EditDomain::MetadataText
            && session.registration.as_ref().is_some_and(|registration|
                session.fixture_metadata_context.as_ref().is_some_and(|context|
                    self.selection(inner, &registration.root.path, context))
                && Self::bootstrap_case(self.eof, &registration.root.path, session.fixture_schedule.eof_case()))
            && runtime.python == self.python && runtime.core == self.core
            && runtime.bootstrap == self.bootstrap && runtime.cwd == self.cwd
            && runtime.core.file_name().and_then(|name| name.to_str()) == Some(if self.zip { "core.zip" } else { "src" })
    }
}

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
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture_workflow: Mutex<Option<Arc<WorkflowFixturePermit>>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture_metadata: Mutex<Option<Arc<MetadataFixturePermit>>>,
    #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
    fixture_next_schedule: Mutex<Option<Arc<hosted_tests::Schedule>>>,
}
struct Registry {
    generation: String, loss_generation: String, window: Option<String>, document_bound: bool, document_lost: bool,
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
    domain: EditDomain, registration: Option<WorkflowRegistration>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture_workflow: Option<Arc<WorkflowFixturePermit>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture_metadata: Option<Arc<MetadataFixturePermit>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture_metadata_context: Option<metadata_wire::Context>,
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
fn edit_unknown() -> BridgeError { BridgeError::new("cleanup_unknown", "The original edit owner is retained; further edits are disabled.") }
fn invalid_owner() -> BridgeError { BridgeError::new("invalid_edit_owner", "This document does not own that live edit domain.") }

impl Inner {
    fn hosted_qualified(&self, domain: EditDomain) -> bool {
        // No production/environment bypass. Only the ignored hosted fixture's
        // descendant module can set this private, per-owner test authorization.
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if domain == EditDomain::GitHubWorkflows
            && self.fixture_workflow.lock().is_ok_and(|permit| permit.as_ref().is_some_and(|permit| permit.owns(self))) { return true; }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if domain == EditDomain::MetadataText
            && self.fixture_metadata.lock().is_ok_and(|permit| permit.as_ref().is_some_and(|permit| permit.owns(self))) { return true; }
        #[cfg(all(test, feature = "development-runtime"))]
        { qualified(domain, self.fixture_authorized.load(Ordering::SeqCst)) }
        #[cfg(not(all(test, feature = "development-runtime")))]
        { qualified(domain, false) }
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
    fn capability(&self, r: &Registry, domain: EditDomain) -> Capability {
        let reason = capability_reason(domain, r.active.as_ref().map(|a| a.session.domain), r.stopping,
            r.disabled || r.exhausted || self.poisoned.load(Ordering::SeqCst), self.hosted_qualified(domain),
            r.document_bound && !r.document_lost);
        Capability { available: reason == EditAvailability::Available, reason }
    }
    fn snapshot(&self, r: &Registry) -> Result<ConfigEditStatus, BridgeError> {
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(edit_unknown()); }
        let active = r.active.as_ref().filter(|a| a.session.domain == EditDomain::Configuration).map(|a| {
            let mut projection = a.projection.clone();
            projection.review_remaining_ms = a.review_end.saturating_duration_since(Instant::now()).as_millis().min(u128::from(u32::MAX)) as u32;
            projection
        });
        let status = ConfigEditStatus { schema_version: 1, window_generation: r.generation.clone(), status_revision: r.revision,
            capability: self.capability(r, EditDomain::Configuration), active,
            last_terminal: r.last.as_ref().filter(|p| p.domain == EditDomain::Configuration).cloned() };
        wire::bounded(&status, wire::STATUS_LIMIT)?;
        Ok(status)
    }
    fn workflow_snapshot(&self, r: &Registry) -> Result<WorkflowEditStatus, BridgeError> {
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(edit_unknown()); }
        let active = r.active.as_ref().filter(|a| a.session.domain == EditDomain::GitHubWorkflows).map(|a| {
            let mut projection = a.projection.workflow_projection()?;
            projection.review_remaining_ms = a.review_end.saturating_duration_since(Instant::now()).as_millis().min(REVIEW.as_millis()) as u32;
            Ok::<workflow_wire::Projection, BridgeError>(projection)
        }).transpose()?;
        let last_terminal = r.last.as_ref().filter(|p| p.domain == EditDomain::GitHubWorkflows)
            .map(EditProjection::workflow_projection).transpose()?;
        let status = WorkflowEditStatus { schema_version: 1, domain: workflow_wire::DOMAIN, window_generation: r.generation.clone(),
            status_revision: r.revision, capability: self.capability(r, EditDomain::GitHubWorkflows), active, last_terminal };
        wire::bounded(&status, workflow_wire::STATUS_LIMIT)?;
        Ok(status)
    }
    fn metadata_text_snapshot(&self, r: &Registry) -> Result<MetadataTextEditStatus, BridgeError> {
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(edit_unknown()); }
        let active = r.active.as_ref().filter(|a| a.session.domain == EditDomain::MetadataText).map(|a| {
            let mut projection = a.projection.metadata_text_projection()?;
            projection.review_remaining_ms = a.review_end.saturating_duration_since(Instant::now()).as_millis().min(REVIEW.as_millis()) as u32;
            Ok::<metadata_wire::Projection, BridgeError>(projection)
        }).transpose()?;
        let last_terminal = r.last.as_ref().filter(|p| p.domain == EditDomain::MetadataText)
            .map(EditProjection::metadata_text_projection).transpose()?;
        let status = MetadataTextEditStatus { schema_version: 1, domain: metadata_wire::DOMAIN, window_generation: r.generation.clone(),
            status_revision: r.revision, capability: self.capability(r, EditDomain::MetadataText), active, last_terminal };
        wire::bounded(&status, metadata_wire::STATUS_LIMIT)?;
        Ok(status)
    }
    fn snapshot_for(&self, r: &Registry, domain: EditDomain) -> Result<DomainStatus, BridgeError> {
        match domain {
            EditDomain::Configuration => self.snapshot(r).map(DomainStatus::Configuration),
            EditDomain::GitHubWorkflows => self.workflow_snapshot(r).map(DomainStatus::GitHubWorkflows),
            EditDomain::MetadataText => self.metadata_text_snapshot(r).map(DomainStatus::MetadataText),
        }
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
    fn admission(&self, r: &Registry, window: &str, domain: EditDomain) -> Result<(), BridgeError> {
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost { return Err(invalid_owner()); }
        match self.capability(r, domain).reason {
            EditAvailability::Available => Ok(()),
            EditAvailability::OtherEditActive => Err(BridgeError::new("busy", "One original edit owner is already active in the other domain.")),
            EditAvailability::Shutdown => Err(BridgeError::shutdown()),
            EditAvailability::CleanupUnknown => Err(edit_unknown()),
            _ => Err(BridgeError::unavailable("This native edit domain is not qualified for the runtime and original document.")),
        }
    }
}

// A loss tombstone is never an admission/session identity. Precompute it before
// any DocumentBinding lock exists, so actual first loss needs no RNG/allocation.
// Preserve the closed 32-lowercase-hex status grammar even on redacted cleanup.
fn loss_tombstone(generation: &str) -> String {
    if generation == "00000000000000000000000000000000" { "10000000000000000000000000000000".to_owned() }
    else { "00000000000000000000000000000000".to_owned() }
}
fn invalidate_generation(generation: &mut String, tombstone: &mut String, lost: &mut bool) {
    if !*lost { std::mem::swap(generation, tombstone); *lost = true; }
}

impl EditOwner {
    pub fn new(runtime: RuntimeConfig) -> Self {
        let generated = nonce();
        let disabled = generated.is_err();
        let generation = generated.unwrap_or_else(|_| "00000000000000000000000000000000".to_owned());
        let loss_generation = loss_tombstone(&generation);
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner { runtime, changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, feature = "development-runtime"))]
            fixture_authorized: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture_workflow: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture_metadata: Mutex::new(None),
            #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
            fixture_next_schedule: Mutex::new(None),
            registry: Mutex::new(Registry { generation, loss_generation, window: None, document_bound: false, document_lost: false,
                revision: 0, exhausted: false, stopping: false, disabled, active: None, last: None, blocked_projects: BTreeSet::new() }) }) }
    }
    pub fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub fn status(&self) -> Result<ConfigEditStatus, BridgeError> { self.inner.snapshot(&self.inner.lock()) }
    pub(crate) fn workflow_status(&self) -> Result<WorkflowEditStatus, BridgeError> { self.inner.workflow_snapshot(&self.inner.lock()) }
    pub(crate) fn metadata_text_status(&self) -> Result<MetadataTextEditStatus, BridgeError> { self.inner.metadata_text_snapshot(&self.inner.lock()) }
    pub fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || self.inner.poisoned.load(Ordering::SeqCst) || r.exhausted }
    pub fn can_exit(&self) -> bool { self.inner.lock().active.is_none() }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn workflow_fixture_registration_permitted(&self, path: &std::path::Path) -> bool {
        self.inner.fixture_workflow.lock().is_ok_and(|permit| permit.as_ref().is_some_and(|permit| permit.root(&self.inner, path)))
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn metadata_fixture_registration_permitted(&self, path: &std::path::Path) -> bool {
        self.inner.fixture_metadata.lock().is_ok_and(|permit| permit.as_ref().is_some_and(|permit| permit.root(&self.inner, path)))
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn session_gtk_idle(&self, stopping: bool) -> Result<serde_json::Value, &'static str> {
        let r = self.inner.lock();
        if self.inner.fixture_authorized.load(Ordering::SeqCst) || self.inner.poisoned.load(Ordering::SeqCst)
            || r.disabled || r.exhausted || !r.document_bound || r.document_lost || r.stopping != stopping
            || r.active.is_some() || r.last.is_some() || !r.blocked_projects.is_empty() { return Err("sg1_edit_not_fresh_idle"); }
        Ok(serde_json::json!({"documentBound":true,"documentLost":false,"authorized":false,"sessions":0,"children":0,"stopping":stopping}))
    }

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
            let Registry { generation, loss_generation, document_lost, .. } = &mut *r;
            invalidate_generation(generation, loss_generation, document_lost);
            let owner = r.active.as_ref().map(|a| a.session.clone());
            self.inner.bump(&mut r);
            owner
        };
        if let Some(owner) = owner { self.inner.trigger(&owner.id, Reason::WindowLost, Instant::now()); }
    }

    pub fn open(&self, window: &str, project_id: String, root: PathBuf) -> Result<ConfigEditStatus, BridgeError> {
        self.open_domain(window, project_id, root, EditDomain::Configuration, None, None, None)?.configuration()
    }
    pub(crate) fn workflow_open_ticket(&self, window: &str) -> Result<WorkflowOpenTicket, BridgeError> {
        self.registered_open_ticket(window, EditDomain::GitHubWorkflows)
    }
    pub(crate) fn metadata_text_open_ticket(&self, window: &str) -> Result<RegisteredOpenTicket, BridgeError> {
        self.registered_open_ticket(window, EditDomain::MetadataText)
    }
    fn registered_open_ticket(&self, window: &str, domain: EditDomain) -> Result<RegisteredOpenTicket, BridgeError> {
        if !matches!(domain, EditDomain::GitHubWorkflows | EditDomain::MetadataText) { return Err(invalid_owner()); }
        { let r = self.inner.lock(); self.inner.admission(&r, window, domain)?; }
        // Entropy is obtained before the real document/selection mutex. This
        // private ticket performs no observation, registration, claim or spawn.
        let executor = tokio::runtime::Handle::try_current().map_err(|_| BridgeError::unavailable("The native edit executor is unavailable."))?;
        Ok(RegisteredOpenTicket { owner: self.inner.clone(), domain, id: nonce()?, executor })
    }
    pub(crate) fn open_workflow(&self, window: &str, project_id: String, registration: WorkflowRegistration,
        ticket: WorkflowOpenTicket) -> Result<WorkflowEditStatus, BridgeError> {
        let root = registration.root.path.clone();
        self.open_domain(window, project_id, root, EditDomain::GitHubWorkflows, Some(registration), Some(ticket), None)?.workflows()
    }
    pub(crate) fn open_metadata_text(&self, window: &str, project_id: String, context: metadata_wire::Context,
        registration: RegisteredEditRoot, ticket: RegisteredOpenTicket) -> Result<MetadataTextEditStatus, BridgeError> {
        if !context.valid() { return Err(BridgeError::invalid()); }
        let root = registration.root.path.clone();
        self.open_domain(window, project_id, root, EditDomain::MetadataText, Some(registration), Some(ticket), Some(context))?.metadata_text()
    }
    fn open_domain(&self, window: &str, project_id: String, root: PathBuf, domain: EditDomain,
        registration: Option<RegisteredEditRoot>, ticket: Option<RegisteredOpenTicket>, metadata: Option<metadata_wire::Context>) -> Result<DomainStatus, BridgeError> {
        { let r = self.inner.lock(); self.inner.admission(&r, window, domain)?; }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let fixture_workflow = if domain == EditDomain::GitHubWorkflows && !NATIVE_WORKFLOW_EDIT_QUALIFIED {
            let permit = self.inner.fixture_workflow.lock().map_err(|_| edit_unknown())?.clone().ok_or_else(invalid_owner)?;
            if !permit.root(&self.inner, &root) { return Err(invalid_owner()); }
            Some(permit) // This exact immutable original permit travels to spawn.
        } else { None };
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let fixture_metadata = if domain == EditDomain::MetadataText && !NATIVE_METADATA_TEXT_EDIT_QUALIFIED {
            let permit = self.inner.fixture_metadata.lock().map_err(|_| edit_unknown())?.clone().ok_or_else(invalid_owner)?;
            if !metadata.as_ref().is_some_and(|context| permit.selection(&self.inner, &root, context)) { return Err(invalid_owner()); }
            Some(permit)
        } else { None };
        if project_id.is_empty() || project_id.len() > 128 { return Err(BridgeError::invalid()); }
        let root = root.to_str().filter(|s| s.len() <= 4096).ok_or_else(BridgeError::invalid)?;
        let (id, executor) = match (domain, ticket) {
            (EditDomain::Configuration, None) => {
                let executor = tokio::runtime::Handle::try_current().map_err(|_| BridgeError::unavailable("The native edit executor is unavailable."))?;
                (nonce()?, executor)
            },
            (EditDomain::GitHubWorkflows | EditDomain::MetadataText, Some(ticket))
                if ticket.domain == domain && Arc::ptr_eq(&self.inner, &ticket.owner) => (ticket.id, ticket.executor),
            _ => return Err(invalid_owner()),
        };
        let params = match (domain, registration.as_ref(), metadata.as_ref()) {
            (EditDomain::Configuration, None, None) => json!({"root": root}),
            (EditDomain::GitHubWorkflows, Some(binding), None) => json!({"root":root,"registeredIdentity":binding.root.identity.workflow_identity()}),
            (EditDomain::MetadataText, Some(binding), Some(context)) if context.valid() => json!({"root":root,
                "registeredIdentity":binding.root.identity.workflow_identity(),"platform":context.platform,"locale":context.locale}),
            _ => return Err(invalid_owner()),
        };
        let bytes = request_bytes(domain, &id, 0, "open", params)?;
        let (commands, receiver) = mpsc::channel(1);
        let (stop, _) = watch::channel(false);
        let (pipes, _) = watch::channel(PipeAcquisition::Pending);
        let (frames, frame_rx) = mpsc::channel(3);
        let session = Arc::new(Session { domain, registration, id: id.clone(), commands, receiver: AsyncMutex::new(Some(receiver)), stop,
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture_workflow,
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture_metadata,
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture_metadata_context: metadata.clone(),
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
            self.inner.admission(&r, window, domain)?;
            if r.active.is_some() { return Err(BridgeError::new("busy", "One original edit owner is already active.")); }
            if r.blocked_projects.contains(&project_id) { return Err(BridgeError::new("pending_state", "This project requires separately authorized recovery; the desktop cannot retry it.")); }
            let now = Instant::now();
            let generation = r.generation.clone();
            r.active = Some(ActiveOwner { session: session.clone(), review_end: now + REVIEW, phase_end: Some(now + ACTIVE), cleanup_start: None,
                prepare_counters: None, claimed_seq: 0, opened: false, prepared: false, terminal: false, unknown: false,
                projection: EditProjection { domain, workflow: (domain == EditDomain::GitHubWorkflows).then(workflow_wire::Details::default),
                    metadata_text: metadata.map(metadata_wire::Details::new),
                    project_id, session_id: id.clone(), owner_generation: generation, phase: Phase::Opening,
                    review_remaining_ms: REVIEW.as_millis() as u32, checkout: None, prepared: None, apply_submitted: false,
                    core_outcome: None, native_reason: Reason::None, native_finality: NativeFinality::Pending, late_settled: false } });
            self.inner.bump(&mut r);
            self.inner.snapshot_for(&r, domain)? // Admission reply captured BEFORE queue/start.
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
        self.prepare_domain(window, EditDomain::Configuration, &args.session_id, &args.revision,
            (args.draft_revision, args.baseline_generation),
            json!({"revision": &args.revision, "expectedBase": &args.expected_base, "draft": &args.draft}), None, None)?.configuration()
    }
    pub(crate) fn prepare_workflow(&self, window: &str, args: PrepareWorkflowEdit, registration: WorkflowRegistration) -> Result<WorkflowEditStatus, BridgeError> {
        self.prepare_domain(window, EditDomain::GitHubWorkflows, &args.session_id, &args.revision,
            (args.draft_revision, args.baseline_generation), json!({"revision":&args.revision,"draft":&args.draft,
                "toolingRepository":&args.tooling_repository,"toolingSha":&args.tooling_sha}), Some(registration), None)?.workflows()
    }
    pub(crate) fn prepare_metadata_text(&self, window: &str, args: PrepareMetadataTextEdit,
        registration: RegisteredEditRoot) -> Result<MetadataTextEditStatus, BridgeError> {
        let params = json!({"revision":&args.revision,"expectedBaseline":&args.expected_baseline,"fields":&args.fields});
        let submission = metadata_wire::Submission { expected_baseline: args.expected_baseline, fields: args.fields };
        self.prepare_domain(window, EditDomain::MetadataText, &args.session_id, &args.revision,
            (args.draft_revision, args.baseline_generation), params, Some(registration), Some(submission))?.metadata_text()
    }
    fn prepare_domain(&self, window: &str, domain: EditDomain, session_id: &str, revision: &str,
        counters: (u32, u32), params: Value, registration: Option<RegisteredEditRoot>, submission: Option<metadata_wire::Submission>) -> Result<DomainStatus, BridgeError> {
        if !wire::token(session_id) || !wire::token(revision)
            || domain != EditDomain::Configuration && (counters.0 == u32::MAX || counters.1 == u32::MAX) { return Err(BridgeError::invalid()); }
        let bytes = request_bytes(domain, session_id, 1, "prepare", params)?;
        let (session, reply) = {
            let mut r = self.inner.lock();
            self.inner.admission(&r, window, domain)?;
            let now = Instant::now(); // Time and claim share the registry race.
            let generation = r.generation.clone();
            let a = r.active.as_mut().filter(|a| a.session.domain == domain && a.session.id == session_id && a.projection.owner_generation == generation).ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Editing || a.prepare_counters.is_some() || !a.opened { return Err(invalid_owner()); }
            if a.session.registration != registration {
                self.inner.trigger_locked(&mut r, session_id, Reason::CallerLost, now); return Err(invalid_owner());
            }
            let Some(phase_end) = claim_phase(a.review_end, now) else {
                let at = a.review_end; self.inner.trigger_locked(&mut r, session_id, Reason::ReviewExpired, at); return Err(invalid_owner());
            };
            // Wrong revisions do not revise an original checkout or renew time.
            if a.projection.revision() != Some(revision) {
                if matches!(domain, EditDomain::GitHubWorkflows | EditDomain::MetadataText) { self.inner.trigger_locked(&mut r, session_id, Reason::CallerLost, now); }
                return Err(invalid_owner());
            }
            match (domain, submission) {
                (EditDomain::MetadataText, Some(submission)) => {
                    let valid = a.projection.metadata_text.as_ref().is_some_and(|detail| detail.submission.is_none() && submission.valid_for(detail.platform));
                    if !valid { self.inner.trigger_locked(&mut r, session_id, Reason::CallerLost, now); return Err(invalid_owner()); }
                    if let Some(detail) = a.projection.metadata_text.as_mut() { detail.submission = Some(submission); }
                },
                (EditDomain::Configuration | EditDomain::GitHubWorkflows, None) => {},
                _ => return Err(invalid_owner()),
            }
            a.prepare_counters = Some(counters);
            a.claimed_seq = 1;
            a.phase_end = Some(phase_end);
            a.projection.phase = Phase::Preparing;
            let session = a.session.clone();
            self.inner.bump(&mut r);
            (session, self.inner.snapshot_for(&r, domain)?)
        };
        if session.commands.try_send(bytes).is_err() { self.inner.trigger(&session.id, Reason::IoError, Instant::now()); self.inner.unknown(&session.id); }
        session.wake.notify_waiters();
        Ok(reply)
    }

    pub fn apply(&self, window: &str, session_id: &str, plan_token: &str) -> Result<ConfigEditStatus, BridgeError> {
        self.apply_domain(window, EditDomain::Configuration, session_id, plan_token, None)?.configuration()
    }
    pub(crate) fn apply_workflow(&self, window: &str, session_id: &str, plan_token: &str, registration: WorkflowRegistration) -> Result<WorkflowEditStatus, BridgeError> {
        self.apply_domain(window, EditDomain::GitHubWorkflows, session_id, plan_token, Some(registration))?.workflows()
    }
    pub(crate) fn apply_metadata_text(&self, window: &str, session_id: &str, plan_token: &str,
        registration: RegisteredEditRoot) -> Result<MetadataTextEditStatus, BridgeError> {
        self.apply_domain(window, EditDomain::MetadataText, session_id, plan_token, Some(registration))?.metadata_text()
    }
    fn apply_domain(&self, window: &str, domain: EditDomain, session_id: &str, plan_token: &str,
        registration: Option<WorkflowRegistration>) -> Result<DomainStatus, BridgeError> {
        if !wire::token(session_id) || !wire::token(plan_token) { return Err(BridgeError::invalid()); }
        let bytes = request_bytes(domain, session_id, 2, "apply", json!({"planToken": plan_token}))?;
        let (session, reply) = {
            let mut r = self.inner.lock();
            if r.window.as_deref() != Some(window) || r.document_lost { return Err(invalid_owner()); }
            // Repeated exact Apply is observation only, including terminal/Unknown.
            let existing = r.active.as_ref().map(|a| &a.projection).filter(|p| p.domain == domain && p.session_id == session_id)
                .or_else(|| r.last.as_ref().filter(|p| p.domain == domain && p.session_id == session_id));
            if existing.is_some_and(|p| exact_apply_receipt(p, domain, &r.generation, session_id, plan_token)) {
                return self.inner.snapshot_for(&r, domain);
            }
            self.inner.admission(&r, window, domain)?;
            let now = Instant::now();
            let generation = r.generation.clone();
            let a = r.active.as_mut().filter(|a| a.session.domain == domain && a.session.id == session_id && a.projection.owner_generation == generation).ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Reviewing || !a.prepared { return Err(invalid_owner()); }
            if a.session.registration != registration || a.projection.plan_token() != Some(plan_token) {
                if matches!(domain, EditDomain::GitHubWorkflows | EditDomain::MetadataText) { self.inner.trigger_locked(&mut r, session_id, Reason::CallerLost, now); }
                return Err(invalid_owner());
            }
            let Some(phase_end) = claim_phase(a.review_end, now) else {
                let at = a.review_end; self.inner.trigger_locked(&mut r, session_id, Reason::ReviewExpired, at); return Err(invalid_owner());
            };
            a.projection.apply_submitted = true; // Consume BEFORE send/acquisition.
            a.projection.phase = Phase::Applying;
            a.claimed_seq = 2;
            a.phase_end = Some(phase_end);
            let session = a.session.clone();
            self.inner.bump(&mut r);
            (session, self.inner.snapshot_for(&r, domain)?)
        };
        if session.commands.try_send(bytes).is_err() { self.inner.trigger(session_id, Reason::IoError, Instant::now()); self.inner.unknown(session_id); }
        session.wake.notify_waiters();
        Ok(reply)
    }

    pub fn close(&self, window: &str, session_id: &str) -> Result<ConfigEditStatus, BridgeError> {
        self.close_domain(window, EditDomain::Configuration, session_id)?.configuration()
    }
    pub(crate) fn close_workflow(&self, window: &str, session_id: &str) -> Result<WorkflowEditStatus, BridgeError> {
        self.close_domain(window, EditDomain::GitHubWorkflows, session_id)?.workflows()
    }
    pub(crate) fn close_metadata_text(&self, window: &str, session_id: &str) -> Result<MetadataTextEditStatus, BridgeError> {
        self.close_domain(window, EditDomain::MetadataText, session_id)?.metadata_text()
    }
    fn close_domain(&self, window: &str, domain: EditDomain, session_id: &str) -> Result<DomainStatus, BridgeError> {
        if !wire::token(session_id) { return Err(BridgeError::invalid()); }
        let mut r = self.inner.lock();
        self.inner.expire_locked(&mut r, session_id, Instant::now());
        let reason = {
            if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost { return Err(invalid_owner()); }
            if r.last.as_ref().is_some_and(|p| p.domain == domain && p.session_id == session_id && p.owner_generation == r.generation) { return self.inner.snapshot_for(&r, domain); }
            let a = r.active.as_ref().filter(|a| a.session.domain == domain && a.session.id == session_id && a.projection.owner_generation == r.generation).ok_or_else(invalid_owner)?;
            if a.cleanup_start.is_some() { return self.inner.snapshot_for(&r, domain); }
            if a.projection.apply_submitted { Reason::Cancelled } else { Reason::Discarded }
        };
        self.inner.trigger_locked(&mut r, session_id, reason, Instant::now());
        self.inner.snapshot_for(&r, domain)
    }
    pub(crate) fn workflow_project(&self, window: &str, session_id: &str) -> Result<String, BridgeError> {
        self.registered_edit_project(window, session_id, EditDomain::GitHubWorkflows)
    }
    pub(crate) fn metadata_text_project(&self, window: &str, session_id: &str) -> Result<String, BridgeError> {
        self.registered_edit_project(window, session_id, EditDomain::MetadataText)
    }
    fn registered_edit_project(&self, window: &str, session_id: &str, domain: EditDomain) -> Result<String, BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || !wire::token(session_id) { return Err(invalid_owner()); }
        let projection = r.active.as_ref().map(|a| &a.projection).filter(|p| p.session_id == session_id)
            .or_else(|| r.last.as_ref().filter(|p| p.session_id == session_id)).ok_or_else(invalid_owner)?;
        if projection.domain != domain || projection.owner_generation != r.generation
            || !matches!(domain, EditDomain::GitHubWorkflows | EditDomain::MetadataText) { return Err(invalid_owner()); }
        Ok(projection.project_id.clone())
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
                    let response_limit = match owner.domain {
                        EditDomain::Configuration => wire::RESPONSE_LIMIT,
                        EditDomain::GitHubWorkflows => workflow_wire::RESPONSE_LIMIT,
                        EditDomain::MetadataText => metadata_wire::RESPONSE_LIMIT,
                    };
                    if frame.len() > response_limit {
                        discard = true; failed = true; frame.clear();
                        inner.trigger(&owner.id, Reason::OutputLimit, Instant::now()); inner.unknown(&owner.id);
                    } else if *byte == b'\n' {
                        count += 1;
                        let parsed = if count <= 3 {
                            match owner.domain {
                                EditDomain::Configuration => wire::decode(&frame, &owner.id),
                                EditDomain::GitHubWorkflows => workflow_wire::decode(&frame, &owner.id),
                                EditDomain::MetadataText => metadata_wire::decode(&frame, &owner.id),
                            }
                        } else { Err(BridgeError::protocol()) };
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

fn terminal_sequence(seq: u32, claimed: u32, prepared: bool, cleaning: bool) -> bool {
    let lowest = if prepared { 1 } else { 0 };
    if cleaning { seq >= lowest && seq <= claimed } else { seq == claimed }
}
fn terminal_projection_admissible(projection: &EditProjection, plan_token: Option<&str>, core: &wire::CoreEditOutcome) -> bool {
    if plan_token != projection.plan_token()
        || !projection.apply_submitted && (!matches!(core.effect, Effect::NotStarted | Effect::Unknown)
            || !matches!(core.journal, Journal::NotCreated | Journal::Unknown))
        || core.reason == CoreReason::None && projection.apply_submitted
            && !matches!((&core.effect, &core.journal), (Effect::Committed, Journal::Clean) | (Effect::Unchanged, Journal::NotCreated)) { return false; }
    if matches!(core.effect, Effect::Unchanged | Effect::Committed | Effect::RolledBack) {
        let changes = match projection.domain {
            EditDomain::Configuration => None, // Preserve the existing configuration outcome contract.
            EditDomain::GitHubWorkflows => {
                let Some(prepared) = projection.workflow.as_ref().and_then(|w| w.prepared.as_ref()) else { return false; };
                Some(prepared.view.files.iter().any(|f| f.action == workflow_wire::Action::Create))
            },
            EditDomain::MetadataText => {
                let Some(prepared) = projection.metadata_text.as_ref().and_then(|m| m.prepared.as_ref()) else { return false; };
                Some(prepared.view.files.iter().any(|f| f.action != metadata_wire::Action::Preserve))
            },
        };
        if changes.is_some_and(|changes| (core.effect == Effect::Unchanged) == changes) { return false; }
    }
    true
}
fn terminal_admissible(a: &ActiveOwner, seq: u32, plan_token: Option<&str>, core: &wire::CoreEditOutcome) -> bool {
    terminal_sequence(seq, a.claimed_seq, a.prepared, a.cleanup_start.is_some())
        && terminal_projection_admissible(&a.projection, plan_token, core)
}

fn accept_frame(inner: &Inner, owner: &Session, frame: ChildFrame) {
    let mut r = inner.lock();
    let now = Instant::now();
    inner.expire_locked(&mut r, &owner.id, now); // Receipt and expiry serialize.
    let Some(a) = r.active.as_mut().filter(|a| a.session.id == owner.id) else { return; };
    let mut invalid = a.terminal || frame.domain() != owner.domain || a.projection.domain != owner.domain;
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
                let core = result.outcome();
                if !terminal_admissible(a, seq, result.plan_token.as_deref(), &core) {
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
            ChildFrame::WorkflowOpened(opened) => {
                if a.opened || a.prepared || a.claimed_seq != 0 { invalid = true; }
                else if let Some(detail) = a.projection.workflow.as_mut() {
                    detail.checkout = Some(workflow_wire::Checkout { revision: opened.revision, observed: opened.observed });
                    a.opened = true;
                    if a.cleanup_start.is_none() { a.projection.phase = Phase::Editing; a.phase_end = None; }
                } else { invalid = true; }
            }
            ChildFrame::WorkflowPrepared(prepared) => {
                if !a.opened || a.prepared || a.claimed_seq != 1 || a.projection.revision() != Some(prepared.revision.as_str()) {
                    invalid = true;
                } else if let (Some((draft_revision, baseline_generation)), Some(detail)) = (a.prepare_counters, a.projection.workflow.as_mut()) {
                    if !detail.checkout.as_ref().is_some_and(|old| prepared.view.matches_observed(&old.observed)) { invalid = true; }
                    else {
                        detail.prepared = Some(workflow_wire::Prepared { revision: prepared.revision, plan_token: prepared.plan_token,
                            draft_revision, baseline_generation, view: prepared.view });
                        a.prepared = true;
                        if a.cleanup_start.is_none() { a.projection.phase = Phase::Reviewing; a.phase_end = None; }
                    }
                } else { invalid = true; }
            }
            ChildFrame::WorkflowTerminal(seq, result) => {
                let core = result.outcome();
                if let workflow_wire::TerminalReply::Conflict { revision, conflict, .. } = &result {
                    if !a.opened || a.prepared || a.projection.apply_submitted || seq != 1
                        || a.projection.revision() != Some(revision.as_str())
                        || !a.projection.workflow.as_ref().and_then(|w| w.checkout.as_ref())
                            .is_some_and(|old| conflict.matches_observed(&old.observed)) { invalid = true; }
                }
                if !terminal_admissible(a, seq, result.plan_token(), &core) { invalid = true; }
                if !invalid {
                    if let workflow_wire::TerminalReply::Conflict { conflict, .. } = result {
                        if let Some(detail) = a.projection.workflow.as_mut() { detail.conflict = Some(conflict); }
                        else { invalid = true; }
                    }
                    if !invalid {
                        uncertain = core.resources == ResourceState::Unknown || core.effect == Effect::Unknown || core.journal == Journal::Unknown;
                        a.projection.core_outcome = Some(core);
                        a.terminal = true;
                        terminal = true;
                        #[cfg(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos")))]
                        owner.fixture_schedule.accepted_terminal(seq);
                    }
                }
            }
            ChildFrame::MetadataTextOpened(opened) => {
                if a.opened || a.prepared || a.claimed_seq != 0 { invalid = true; }
                else if let Some(detail) = a.projection.metadata_text.as_mut() {
                    if !opened.baseline.valid_for(detail.platform)
                        || !metadata_wire::target_context(&opened.metadata_root, detail.platform, &detail.locale) { invalid = true; }
                    else {
                        detail.checkout = Some(metadata_wire::Checkout { revision: opened.revision,
                            metadata_root: opened.metadata_root, baseline: opened.baseline });
                        a.opened = true;
                        if a.cleanup_start.is_none() { a.projection.phase = Phase::Editing; a.phase_end = None; }
                    }
                } else { invalid = true; }
            }
            ChildFrame::MetadataTextPrepared(prepared) => {
                if !a.opened || a.prepared || a.claimed_seq != 1 || a.projection.revision() != Some(prepared.revision.as_str()) {
                    invalid = true;
                } else if let (Some((draft_revision, baseline_generation)), Some(detail)) = (a.prepare_counters, a.projection.metadata_text.as_mut()) {
                    if !detail.checkout.as_ref().is_some_and(|old| prepared.view.matches_checkout(old, detail.platform, &detail.locale)
                        && detail.submission.as_ref().is_some_and(|submitted| submitted.matches(old, &prepared.view))) {
                        invalid = true;
                    } else {
                        detail.submission = None; // The accepted exact view retains these same bytes once.
                        detail.prepared = Some(metadata_wire::Prepared { revision: prepared.revision, plan_token: prepared.plan_token,
                            draft_revision, baseline_generation, view: prepared.view });
                        a.prepared = true;
                        if a.cleanup_start.is_none() { a.projection.phase = Phase::Reviewing; a.phase_end = None; }
                    }
                } else { invalid = true; }
            }
            ChildFrame::MetadataTextTerminal(seq, result) => {
                let core = result.outcome();
                if !terminal_admissible(a, seq, result.plan_token.as_deref(), &core) { invalid = true; }
                else {
                    uncertain = core.resources == ResourceState::Unknown || core.effect == Effect::Unknown || core.journal == Journal::Unknown;
                    if let Some(detail) = a.projection.metadata_text.as_mut() { detail.submission = None; }
                    a.projection.core_outcome = Some(core);
                    a.terminal = true;
                    terminal = true;
                    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    let workflow_allowed = NATIVE_WORKFLOW_EDIT_QUALIFIED;
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let workflow_allowed = workflow_allowed || owner.fixture_workflow.as_ref().is_some_and(|original| {
        inner.fixture_workflow.lock().is_ok_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(current, original)))
            && original.spawn(inner, owner, &runtime)
    });
    let metadata_allowed = NATIVE_METADATA_TEXT_EDIT_QUALIFIED;
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let metadata_allowed = metadata_allowed || owner.fixture_metadata.as_ref().is_some_and(|original| {
        inner.fixture_metadata.lock().is_ok_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(current, original)))
            && original.spawn(inner, owner, &runtime)
    });
    let domain_allowed = match owner.domain {
        EditDomain::Configuration => true, // Existing separate configuration admission/spawn policy follows.
        EditDomain::GitHubWorkflows => workflow_allowed && cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")),
        EditDomain::MetadataText => metadata_allowed
            && cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")),
    };
    if !domain_allowed {
        inner.trigger(&owner.id, Reason::RuntimeUnavailable, Instant::now());
        return; // Neither a configuration nor workflow permit qualifies metadata.
    }
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
        if let Some(case) = owner.fixture_schedule.eof_case() {
            if case.domain() != owner.domain { inner.trigger(&owner.id, Reason::RuntimeUnavailable, Instant::now()); return; }
            command.arg(hosted_tests::eof_bootstrap());
        } else { command.arg(&runtime.bootstrap); }
        #[cfg(not(all(test, feature = "development-runtime", any(target_os = "linux", target_os = "macos"))))]
        command.arg(&runtime.bootstrap);
        command.arg(&runtime.core);
        match owner.domain {
            EditDomain::Configuration => {},
            EditDomain::GitHubWorkflows => { command.arg("github_workflows"); },
            EditDomain::MetadataText => { command.arg("metadata_text"); },
        }
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
    fn first_loss_swaps_a_valid_non_authorizing_tombstone_without_rng_or_allocation() {
        for original in ["00000000000000000000000000000000", "0123456789abcdef0123456789abcdef"] {
            let mut generation = original.to_owned();
            let mut tombstone = super::loss_tombstone(&generation);
            let prepared_pointer = tombstone.as_ptr();
            let mut lost = false;
            super::invalidate_generation(&mut generation, &mut tombstone, &mut lost);
            assert!(lost); assert_ne!(generation, original);
            assert_eq!(generation.as_ptr(), prepared_pointer);
            assert_eq!(generation.len(), 32);
            assert!(generation.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            super::invalidate_generation(&mut generation, &mut tombstone, &mut lost);
            assert_eq!(generation.as_ptr(), prepared_pointer); // Never swap back.
            assert_ne!(generation, original);
        }
    }

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

#[cfg(test)]
mod workflow_domain_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const GENERATION: &str = "fedcba9876543210fedcba9876543210";
    const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PLAN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn projection(preserve: bool) -> EditProjection {
        // Pure DTOs only; not an alternate owner/supervisor, native registry,
        // runtime, channel, task, root, clock or fixture authorization.
        use workflow_wire::{Action, FileView, Generated, Observation, ObservedFile, WorkflowId};
        let content = "name: inert\n";
        let hash = format!("{:x}",Sha256::digest(content.as_bytes()));
        let roster = [(WorkflowId::Preflight,".github/workflows/mobile-preflight.yml"),
            (WorkflowId::Candidate,".github/workflows/mobile-candidate.yml"),
            (WorkflowId::ExternalTesting,".github/workflows/mobile-external-testing.yml"),
            (WorkflowId::ProductionSubmit,".github/workflows/mobile-production-submit.yml")];
        let files = roster.into_iter().map(|(id,path)| FileView { id,path:path.into(),
            action:if preserve { Action::Preserve } else { Action::Create },
            observed:if preserve { Observation::Present { byte_length:content.len() as u32,sha256:hash.clone() } } else { Observation::Absent {} },
            generated:Generated { content:content.into(),byte_length:content.len() as u32,sha256:hash.clone() } }).collect();
        let observed = roster.into_iter().map(|(id,_)| if preserve {
            ObservedFile::Present { id,byte_length:content.len() as u32,sha256:hash.clone() }
        } else { ObservedFile::Absent { id } }).collect();
        let view = workflow_wire::PreparedView { schema_version:1,files,create_directories:Vec::new(),
            template_set:workflow_wire::TemplateSet { core_version:"0.3.0".into(),resource_version:1,resource_sha256:"a".repeat(64) },
            tooling:workflow_wire::Tooling { repository:"example/toolkit".into(),sha:"0".repeat(40),
                schema_reference:format!("https://raw.githubusercontent.com/example/toolkit/{}/schemas/project.schema.json","0".repeat(40)),state:"format-only".into() } };
        EditProjection { domain:EditDomain::GitHubWorkflows,metadata_text:None,workflow:Some(workflow_wire::Details {
            checkout:Some(workflow_wire::Checkout { revision:REVISION.into(),observed }),
            prepared:Some(workflow_wire::Prepared { revision:REVISION.into(),plan_token:PLAN.into(),draft_revision:1,baseline_generation:0,view }),conflict:None }),
            project_id:"project-1".into(),session_id:SESSION.into(),owner_generation:GENERATION.into(),phase:Phase::Reviewing,
            review_remaining_ms:900000,checkout:None,prepared:None,apply_submitted:false,core_outcome:None,
            native_reason:Reason::None,native_finality:NativeFinality::Pending,late_settled:false }
    }
    fn outcome(effect: Effect, journal: Journal, reason: CoreReason) -> wire::CoreEditOutcome {
        wire::CoreEditOutcome { effect,journal,resources:ResourceState::Settled,reason }
    }
    #[test]
    fn configuration_fixture_never_qualifies_workflow_or_hides_an_opposite_unknown_owner() {
        assert!(!NATIVE_WORKFLOW_EDIT_QUALIFIED);
        assert!(!NATIVE_METADATA_TEXT_EDIT_QUALIFIED);
        assert!(!qualified(EditDomain::GitHubWorkflows,false));
        assert!(!qualified(EditDomain::GitHubWorkflows,true));
        assert!(!qualified(EditDomain::MetadataText,false));
        assert!(!qualified(EditDomain::MetadataText,true));
        assert!(!qualified(EditDomain::Configuration,false));
        assert!(qualified(EditDomain::Configuration,true));
        for domain in [EditDomain::Configuration,EditDomain::GitHubWorkflows,EditDomain::MetadataText] {
            for other in [EditDomain::Configuration,EditDomain::GitHubWorkflows,EditDomain::MetadataText].into_iter().filter(|other| *other != domain) {
            for stopping in [false,true] { for disabled in [false,true] {
                assert_eq!(capability_reason(domain,Some(other),stopping,disabled,false,false),EditAvailability::OtherEditActive);
            } }
            }
            assert_eq!(capability_reason(domain,Some(domain),false,true,false,true),EditAvailability::CleanupUnknown);
            assert_eq!(capability_reason(domain,None,true,false,false,true),EditAvailability::Shutdown);
        }
    }
    #[test]
    fn only_exact_already_submitted_domain_session_generation_and_token_are_observation() {
        let mut p = projection(false);
        assert!(!exact_apply_receipt(&p,EditDomain::GitHubWorkflows,GENERATION,SESSION,PLAN));
        p.apply_submitted = true;
        for phase in [Phase::Applying,Phase::Finalizing,Phase::Unknown,Phase::Final] {
            p.phase = phase;
            assert!(exact_apply_receipt(&p,EditDomain::GitHubWorkflows,GENERATION,SESSION,PLAN));
            assert!(!exact_apply_receipt(&p,EditDomain::Configuration,GENERATION,SESSION,PLAN));
            assert!(!exact_apply_receipt(&p,EditDomain::GitHubWorkflows,REVISION,SESSION,PLAN));
            assert!(!exact_apply_receipt(&p,EditDomain::GitHubWorkflows,GENERATION,REVISION,PLAN));
            assert!(!exact_apply_receipt(&p,EditDomain::GitHubWorkflows,GENERATION,SESSION,REVISION));
        }
    }
    #[test]
    fn terminal_sequence_keeps_claim_and_original_cleanup_correlation() {
        for claimed in 0..=2 { for received in 0..=2 {
            assert_eq!(terminal_sequence(received,claimed,false,false),received == claimed);
            assert_eq!(terminal_sequence(received,claimed,false,true),received <= claimed);
            assert_eq!(terminal_sequence(received,claimed,true,true),received >= 1 && received <= claimed);
        } }
        let mut refused = projection(false);
        refused.workflow.as_mut().unwrap().prepared = None;
        let stopped = outcome(Effect::NotStarted,Journal::NotCreated,CoreReason::None);
        assert!(terminal_projection_admissible(&refused,None,&stopped));
        assert!(!terminal_projection_admissible(&refused,Some(PLAN),&stopped)); // No dummy refusal token.
        assert!(!terminal_projection_admissible(&refused,None,&outcome(Effect::Committed,Journal::Clean,CoreReason::None)));
    }
    #[test]
    fn workflow_unchanged_and_created_results_require_the_original_action_set() {
        let mut creates = projection(false); creates.apply_submitted = true;
        let mut preserves = projection(true); preserves.apply_submitted = true;
        let installed = outcome(Effect::Committed,Journal::Clean,CoreReason::None);
        let unchanged = outcome(Effect::Unchanged,Journal::NotCreated,CoreReason::None);
        let rollback = outcome(Effect::RolledBack,Journal::Clean,CoreReason::FilesystemError);
        assert!(terminal_projection_admissible(&creates,Some(PLAN),&installed));
        assert!(!terminal_projection_admissible(&creates,Some(PLAN),&unchanged));
        assert!(terminal_projection_admissible(&creates,Some(PLAN),&rollback));
        assert!(terminal_projection_admissible(&preserves,Some(PLAN),&unchanged));
        assert!(!terminal_projection_admissible(&preserves,Some(PLAN),&installed));
        assert!(!terminal_projection_admissible(&preserves,Some(PLAN),&rollback));
        assert!(!terminal_projection_admissible(&creates,Some(REVISION),&installed));
        creates.apply_submitted = false;
        assert!(!terminal_projection_admissible(&creates,Some(PLAN),&installed));
    }
    #[test]
    fn configuration_wire_and_projection_never_gain_workflow_authority_fields() {
        let params = json!({"root":"/inert/project"});
        assert_eq!(request_bytes(EditDomain::Configuration,SESSION,0,"open",params.clone()).unwrap(),
            wire::request(SESSION,0,"open",params.clone()).unwrap());
        assert!(request_bytes(EditDomain::GitHubWorkflows,SESSION,0,"open",params.clone()).is_err());
        assert!(request_bytes(EditDomain::MetadataText,SESSION,0,"open",params).is_err());
        let p = projection(false);
        let workflow = serde_json::to_value(p.workflow_projection().unwrap()).unwrap();
        assert_eq!(workflow["domain"],"github_workflows");
        assert!(workflow.get("root").is_none()); assert!(workflow.get("registeredIdentity").is_none());
        let mut configuration = p; configuration.domain = EditDomain::Configuration; configuration.workflow = None;
        assert!(configuration.workflow_projection().is_err());
        let encoded = serde_json::to_value(configuration).unwrap();
        assert!(encoded.get("domain").is_none()); assert!(encoded.get("workflow").is_none());
        assert!(encoded.get("metadata_text").is_none());
        assert!(encoded.get("conflict").is_none()); assert_eq!(encoded["checkout"],Value::Null);
    }
    #[test]
    fn metadata_actions_and_receipts_cannot_become_configuration_or_workflow_authority() {
        use metadata_wire::{Action, Before, ContentDigest, FieldId, Platform, TextContent};
        let make = |action: Action| {
            let mut projection = projection(false);
            projection.domain = EditDomain::MetadataText; projection.workflow = None;
            let after = "Public"; let old = if action == Action::Preserve { after } else { "Prior" };
            let hash = |text: &str| format!("{:x}",Sha256::digest(text.as_bytes()));
            let ids = [(FieldId::Title,"title.txt"),(FieldId::ShortDescription,"short_description.txt"),(FieldId::FullDescription,"full_description.txt")];
            let fields = ids.iter().map(|(id,_)| if action == Action::Create { metadata_wire::BaselineField::Absent { id:*id } }
                else { metadata_wire::BaselineField::Present { id:*id,byte_length:old.len() as u32,sha256:hash(old) } }).collect();
            let checkout = metadata_wire::Checkout { revision:REVISION.into(),metadata_root:"release/metadata".into(),
                baseline:metadata_wire::Baseline { config:ContentDigest { byte_length:2,sha256:hash("{}") },fields } };
            let files = ids.iter().map(|(id,name)| metadata_wire::FileView { id:*id,path:format!("release/metadata/android/en-US/{name}"),action,
                before:if action == Action::Create { Before::Absent {} } else { Before::Present { text:old.into(),byte_length:old.len() as u32,sha256:hash(old) } },
                after:TextContent { text:after.into(),byte_length:after.len() as u32,sha256:hash(after) },line_endings_changed:false }).collect();
            let validation = metadata_wire::ValidationResult { schema_version:1,platform:Platform::Android,valid:true,state:metadata_wire::ValidationState::FormatValid,
                fields:ids.iter().map(|(id,_)| metadata_wire::ValidatedField { id:*id,valid:true,character_count:6,limit:32768,issues:Vec::new() }).collect(),
                assurance:metadata_wire::Assurance { basis:"schema-policy".into(),project_code_executed:false,tools_probed:false,credentials_read:false,
                    git_observed:false,store_contacted:false,writes_performed:false,release_readiness:"unknown".into() } };
            let view = metadata_wire::PreparedView { schema_version:1,platform:Platform::Android,locale:"en-US".into(),metadata_root:"release/metadata".into(),files,create_directories:Vec::new(),validation };
            projection.metadata_text = Some(metadata_wire::Details { platform:Platform::Android,locale:"en-US".into(),checkout:Some(checkout),
                prepared:Some(metadata_wire::Prepared { revision:REVISION.into(),plan_token:PLAN.into(),draft_revision:1,baseline_generation:0,view }),submission:None });
            projection
        };
        for action in [Action::Create,Action::Replace,Action::Preserve] {
            let mut original = make(action);
            assert!(original.workflow_projection().is_err());
            let view = serde_json::to_value(original.metadata_text_projection().unwrap()).unwrap();
            for key in ["root","registeredIdentity","conflict","workflow","submission"] { assert!(view.get(key).is_none()); }
            assert_eq!(view["domain"],"metadata_text"); assert_eq!(view["platform"],"android"); assert_eq!(view["locale"],"en-US");
            assert!(!exact_apply_receipt(&original,EditDomain::MetadataText,GENERATION,SESSION,PLAN));
            original.apply_submitted = true;
            for phase in [Phase::Applying,Phase::Finalizing,Phase::Unknown,Phase::Final] {
                original.phase = phase;
                assert!(exact_apply_receipt(&original,EditDomain::MetadataText,GENERATION,SESSION,PLAN));
                for domain in [EditDomain::Configuration,EditDomain::GitHubWorkflows] { assert!(!exact_apply_receipt(&original,domain,GENERATION,SESSION,PLAN)); }
                assert!(!exact_apply_receipt(&original,EditDomain::MetadataText,REVISION,SESSION,PLAN));
                assert!(!exact_apply_receipt(&original,EditDomain::MetadataText,GENERATION,REVISION,PLAN));
                assert!(!exact_apply_receipt(&original,EditDomain::MetadataText,GENERATION,SESSION,REVISION));
            }
            let no_op = action == Action::Preserve;
            assert_eq!(terminal_projection_admissible(&original,Some(PLAN),&outcome(Effect::Unchanged,Journal::NotCreated,CoreReason::None)),no_op);
            assert_eq!(terminal_projection_admissible(&original,Some(PLAN),&outcome(Effect::Committed,Journal::Clean,CoreReason::None)),!no_op);
            assert_eq!(terminal_projection_admissible(&original,Some(PLAN),&outcome(Effect::RolledBack,Journal::Clean,CoreReason::FilesystemError)),!no_op);
            assert!(!terminal_projection_admissible(&original,Some(REVISION),&outcome(Effect::Committed,Journal::Clean,CoreReason::None)));
            original.apply_submitted = false;
            assert!(!terminal_projection_admissible(&original,Some(PLAN),&outcome(Effect::Committed,Journal::Clean,CoreReason::None)));
        }
    }
}
