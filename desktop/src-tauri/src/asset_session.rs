//! One real document gate, one retained native operation, session-only records.
//! The capability intentionally remains false. Source authoring/pure tests do
//! not qualify GTK, source custody, runtime IO, allocation bounds or assignment.
use std::{future::Future, pin::Pin, sync::{Arc, Mutex, MutexGuard, Weak, atomic::{AtomicBool, Ordering}}, task::{Context as TaskContext, Poll, Waker}, time::{Duration, Instant}};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use tokio::{sync::{Mutex as AsyncMutex, Notify, oneshot, watch}, task::JoinHandle};
use crate::{asset_commands::{self as commands, AssetError, CommandError, Fields, Kind, Platform, Purpose, Reason, Stage}, asset_source::{self, OriginWitness, SourceBook},
    bridge::{DesktopBridge, Project, ProjectRoster}, credential_assessment::{AssessmentRequest, AssessmentResult, assess_supplied}, credential_format::{self, FileObservation},
    document_lifetime::{DocumentAction, DocumentLifetime}, error::BridgeError};

const MAIN: &str = "main";
const WORK: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(2);
const REVIEW: Duration = Duration::from_secs(300);
const RECORD_LIMIT: usize = 32;
const SESSION_BYTES: usize = 64 * 1024 * 1024;
// Conservative per-record backing charge: bounded parser projection, native
// origin/path/ancestry and record/field/control cells. This is inside, not in
// addition to, the unchanged session quota. Shared Arc leases charge once.
const RECORD_METADATA_BYTES: usize = 1024 * 1024;
// Never inferred from crate presence, a renderer boolean, or R1 DTO passes.
const NATIVE_QUALIFIED: bool = false;

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct Token(String);
struct TokenBatch { selection: Token, record: Token, preview: Token, bind: Token }
#[derive(Clone, PartialEq, Eq)]
struct RecordKey { id: Token, revision: u32 }
struct NativeContext {
    revision: u32, project_id: String, project: asset_source::RegisteredRoot, registry_generation: u32,
    draft: Vec<u8>, platform: Platform, stage: Stage, purpose: Purpose,
}
struct Material { captured: asset_source::CapturedSource, observation: FileObservation }
struct Payload { kind: Kind, material: Option<Arc<Material>>, fields: Option<Fields> }
impl Payload {
    fn bytes(&self) -> usize {
        RECORD_METADATA_BYTES + self.material.as_ref().map_or(0, |m| m.captured.bytes.capacity()) + self.fields.as_ref().map_or(0, Fields::byte_count)
    }
    fn usable_source(&self) -> bool { self.kind.file().is_none() || self.material.as_ref().is_some_and(|m| m.observation.is_observed()) }
}
struct Record { key: RecordKey, payload: Arc<Payload>, mutation_pending: bool }
struct Candidate { payload: Arc<Payload>, record_id: Token, existing: Option<RecordKey> }
#[derive(Clone)]
struct SafeAssessment(Arc<AssessmentResult>);
impl Serialize for SafeAssessment { fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { self.0.serialize(serializer) } }
impl SafeAssessment { fn permits(&self) -> bool { self.0.permits_session_preview() } }

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Idle, Admitting, Picking, Capturing, Selected, Assessing, Preview, Mutating, Stopping, Unknown }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Operation { ChooseFile, ChooseProject, Prepare, PrepareDelete, Commit, Bind, Discard, Lock }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SourceState { NotRun, Pending, Captured, Refused, Unknown }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Settlement { Pending, Known, Unknown, LateKnown }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Action { Save, Bind, Delete }
struct Preview { token: Token, action: Action, bind_token: Option<Token>, record: Option<RecordKey>, subject: PreviewSubject }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum SubjectChange { New, Replace, Assign, Delete }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewSubject { kind: Kind, change: SubjectChange, record_id: Option<Token>, record_revision: Option<u32> }
impl PreviewSubject {
    fn new(kind: Kind, change: SubjectChange, record: Option<&RecordKey>) -> Self {
        Self { kind, change, record_id: record.map(|record| record.id.clone()), record_revision: record.map(|record| record.revision) }
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Assignment { kind: Kind, record_id: Token, record_revision: u32, context_revision: u32, availability: AssignmentAvailability }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum AssignmentAvailability { Available, Unavailable }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssetStatus {
    schema_version: u8, status_revision: u32, mode: &'static str, capability: Capability,
    context: Option<ContextStatus>, operation: Option<OperationStatus>, records: Vec<RecordStatus>, assignments: Vec<Assignment>,
}
#[derive(Serialize)]
struct Capability { available: bool, reason: Reason }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextStatus { revision: u32, project_id: String, platform: Platform, stage: Stage, purpose: Purpose }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationStatus {
    operation_id: u32, operation: Operation, phase: Phase, reason: Reason, source: SourceState, settlement: Settlement,
    selection_token: Option<Token>, assessment: Option<SafeAssessment>, preview: Option<PreviewStatus>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewStatus { token: Token, action: Action, expires_in_ms: u32, subject: PreviewSubject }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordStatus { record_id: Token, revision: u32, kind: Kind, availability: &'static str }

#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinReceipt { New, Pending, Returned, Failed }
#[cfg(feature = "desktop-shell")]
type CoordinatorHandle = tauri::async_runtime::JoinHandle<()>;
#[cfg(not(feature = "desktop-shell"))]
type CoordinatorHandle = JoinHandle<()>;
struct CoordinatorBook { handle: Option<CoordinatorHandle>, receipt: JoinReceipt }
struct ChildBook { handle: Option<JoinHandle<ChildEnd>>, receipt: JoinReceipt }

// Only already-closed/positively-joined data is put here. The original operation
// retains this holding before a locked replacement/removal becomes visible.
// Its off-lock drain has a separate receipt, never a Drop-as-native-settlement
// interpretation. At most one holding is populated at a time.
#[derive(Default)]
struct Retirement {
    old_slot: Option<Box<Slot>>, candidate: Option<Candidate>, staged: Option<Staged>,
    payload: Option<Arc<Payload>>, context: Option<Arc<NativeContext>>, slot_context: Option<Arc<NativeContext>>,
    assessment: Option<SafeAssessment>, records: Vec<Record>, assignments: Vec<Assignment>,
}

pub(crate) struct OriginalWork {
    pub(crate) id: u32, stop: AtomicBool, ended: AtomicBool, deadline: Mutex<Option<Instant>>,
    pub(crate) wake: Notify, coordinator: Mutex<CoordinatorBook>, child: AsyncMutex<ChildBook>,
    source: Arc<Mutex<SourceBook>>, pub(crate) gui: Arc<GuiCall>,
    retirement: Mutex<Retirement>, retired: AtomicBool,
}
impl OriginalWork {
    fn new(id: u32, gui_needed: bool, document: Weak<Inner>) -> Arc<Self> {
        Arc::new_cyclic(|owner| Self { id, stop: AtomicBool::new(false), ended: AtomicBool::new(false), deadline: Mutex::new(Some(Instant::now() + WORK)),
            wake: Notify::new(), coordinator: Mutex::new(CoordinatorBook { handle: None, receipt: JoinReceipt::New }),
            child: AsyncMutex::new(ChildBook { handle: None, receipt: JoinReceipt::New }), source: Arc::new(Mutex::new(SourceBook::new())),
            retirement: Mutex::new(Retirement::default()), retired: AtomicBool::new(true),
            gui: Arc::new(GuiCall { owner: owner.clone(), document, facts: Mutex::new(GuiFacts { dispatched: false, constructing: false,
                created: false, showing: false, response: false, accepted: false, accepted_at: None,
                destroyed: false, released: !gui_needed, not_created: !gui_needed, close_queued: false, close_ack: false, release_queued: false,
                selected: None, refusal: None }), wake: Notify::new() }) })
    }
    pub(crate) fn stopped(&self) -> bool { self.stop.load(Ordering::SeqCst) }
    fn stop(&self) { self.stop.store(true, Ordering::SeqCst); self.wake.notify_one(); self.gui.wake.notify_one(); }
    pub(crate) fn endpoint(&self) -> Option<Instant> { match self.deadline.lock() { Ok(end) => *end, Err(_) => Some(Instant::now()) } }
    pub(crate) fn set_endpoint(&self, end: Option<Instant>) { match self.deadline.lock() { Ok(mut value) => *value = end, Err(_) => self.stop() } }
    pub(crate) fn interrupted(&self) -> bool { self.stopped() || self.endpoint().is_some_and(|end| Instant::now() >= end) }
    fn join_if_ended(&self) -> Option<bool> {
        if !self.ended.load(Ordering::SeqCst) { return None; }
        let Ok(mut book) = self.coordinator.try_lock() else { return None; };
        if book.receipt == JoinReceipt::Returned { return Some(true); }
        if book.receipt == JoinReceipt::Failed { return Some(false); }
        let handle = book.handle.as_mut()?;
        // An end-of-body flag is only permission to poll the retained original;
        // it is NEVER completion evidence. Pending retains exactly this handle.
        let mut cx = TaskContext::from_waker(Waker::noop());
        match Pin::new(handle).poll(&mut cx) {
            Poll::Pending => None,
            Poll::Ready(result) => {
                let normal = result.is_ok();
                book.receipt = if normal { JoinReceipt::Returned } else { JoinReceipt::Failed };
                book.handle.take(); Some(normal)
            }
        }
    }
    fn original_resources_settled(&self) -> bool {
        let coordinator = self.coordinator.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::Returned | JoinReceipt::Failed) && book.handle.is_none());
        let child = self.child.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned | JoinReceipt::Failed) && book.handle.is_none());
        let source = self.source.try_lock().is_ok_and(|book| book.not_started() || book.settled());
        coordinator && child && source && self.gui.settled()
    }
    fn resources_settled(&self) -> bool { self.original_resources_settled() && self.retired.load(Ordering::SeqCst) }
    fn retain_retirement(&self, retirement: Retirement) -> Result<(), Retirement> {
        let Ok(mut holding) = self.retirement.try_lock() else { return Err(retirement); };
        if !self.retired.swap(false, Ordering::SeqCst) { return Err(retirement); }
        *holding = retirement; Ok(())
    }
    fn release_retirement(&self) -> bool {
        let retirement = match self.retirement.try_lock() { Ok(mut holding) => std::mem::take(&mut *holding), Err(_) => return false };
        drop(retirement); // No admission lock, native handle or await here.
        self.retired.store(true, Ordering::SeqCst); true
    }
}
// Not object ownership: shell.rs retains the actual GTK object on its original
// main thread. These receipts never authorize replacement/Drop-as-settlement.
pub(crate) struct GuiCall { owner: Weak<OriginalWork>, document: Weak<Inner>, facts: Mutex<GuiFacts>, pub(crate) wake: Notify }
pub(crate) struct GuiFacts {
    pub(crate) dispatched: bool, pub(crate) constructing: bool,
    pub(crate) created: bool, pub(crate) showing: bool, pub(crate) response: bool, pub(crate) accepted: bool,
    pub(crate) accepted_at: Option<Instant>,
    pub(crate) destroyed: bool, pub(crate) released: bool, pub(crate) not_created: bool,
    pub(crate) close_queued: bool, pub(crate) close_ack: bool, pub(crate) release_queued: bool, pub(crate) selected: Option<std::path::PathBuf>,
    pub(crate) refusal: Option<Reason>,
}
impl GuiCall {
    pub(crate) fn owner(&self) -> Option<Arc<OriginalWork>> { self.owner.upgrade() }
    pub(crate) fn facts(&self) -> Option<MutexGuard<'_, GuiFacts>> { self.facts.lock().ok() }
    pub(crate) fn changed(&self) { self.wake.notify_one(); }
    pub(crate) fn settled(&self) -> bool { self.facts.lock().is_ok_and(|facts| facts.not_created || facts.destroyed && facts.released) }
    pub(crate) fn not_created(&self, reason: Reason) {
        if let Some(mut facts) = self.facts() {
            // Only the original construction path may prove no object exists.
            if !facts.created { facts.not_created = true; facts.released = true; facts.refusal = Some(reason); }
        }
        self.changed();
    }
    pub(crate) fn failed(&self, reason: Reason) {
        let Some(inner) = self.document.upgrade() else { return; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return; };
        let mut state = document.lock();
        if let Some(mut facts) = self.facts() { if facts.refusal.is_none() { facts.refusal = Some(reason); } }
        let now = Instant::now();
        if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) { slot.stop(reason, now); }
        if state.quit.as_ref().is_some_and(|quit| Arc::ptr_eq(quit, &owner)) { stop_quit(&mut state, now); }
        owner.stop(); document.bump(&mut state); self.changed();
    }
    pub(crate) fn begin_response(&self, accepted: bool, quit: bool) -> Option<bool> {
        let Some(inner) = self.document.upgrade() else { return None; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return None; };
        document.gui_response(&owner, accepted, quit)
    }
    pub(crate) fn selected_path(&self, path: Result<std::path::PathBuf, Reason>) {
        let Some(inner) = self.document.upgrade() else { return; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return; };
        let mut state = document.lock();
        if let Some(mut facts) = self.facts() {
            match path {
                Ok(path) if facts.accepted && !owner.interrupted() => facts.selected = Some(path),
                Ok(_) => {},
                Err(reason) => {
                    facts.refusal = Some(reason);
                    if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) { slot.stop(reason, Instant::now()); }
                }
            }
        }
        document.bump(&mut state); self.changed();
    }
    pub(crate) fn presented(&self) {
        let Some(inner) = self.document.upgrade() else { return; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return; };
        let mut state = document.lock();
        if owner.interrupted() || self.facts().is_none_or(|facts| facts.response) { return; }
        if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) {
            if slot.cleanup_end.is_none() { slot.phase = Phase::Picking; owner.set_endpoint(None); document.bump(&mut state); }
        } else if state.quit.as_ref().is_some_and(|work| Arc::ptr_eq(work, &owner)) {
            owner.set_endpoint(None);
        }
    }
}

struct Slot {
    owner: Arc<OriginalWork>, operation: Operation, phase: Phase, reason: Reason, source: SourceState, settlement: Settlement,
    context: Option<Arc<NativeContext>>, target: Option<RecordKey>, review_end: Option<Instant>, cleanup_end: Option<Instant>,
    candidate: Option<Candidate>, selection: Option<Token>, assessment: Option<SafeAssessment>, preview: Option<Preview>,
    assessment_context_revision: Option<u32>,
    staged: Option<Staged>, error: Option<CommandError>, project: Option<Project>, discard: bool,
    kind: Option<Kind>, result_record: Option<RecordKey>, retired_payload: Option<Arc<Payload>>,
}
impl Slot {
    fn stop(&mut self, reason: Reason, at: Instant) {
        self.selection = None; self.preview = None; self.discard = true;
        if self.reason == Reason::None { self.reason = reason; }
        if self.cleanup_end.is_none() { self.cleanup_end = Some(first_cleanup_end(at, self.owner.endpoint(), self.review_end)); }
        if self.phase != Phase::Unknown { self.phase = Phase::Stopping; }
        self.owner.stop();
    }
}
struct DocumentState {
    lifetime: DocumentLifetime, revision: u32, next_operation: u32, next_context: u32, exhausted: bool, lost_observed: bool,
    session: bool, stopping: bool, unknown: bool, quit_pending: bool, retiring: bool, lock_pending: bool,
    context: Option<Arc<NativeContext>>, slot: Option<Slot>, records: Vec<Record>, assignments: Vec<Assignment>,
    quit: Option<Arc<OriginalWork>>, quit_accepted: bool, quit_cleanup_end: Option<Instant>,
}
// A late observer/lifecycle callback cannot move an already-due work or review
// endpoint forward. The first STOP owns the only cleanup clock.
fn first_cleanup_end(at: Instant, work: Option<Instant>, review: Option<Instant>) -> Instant {
    let first = work.map_or(at, |end| at.min(end));
    review.map_or(first, |end| first.min(end)) + CLEANUP
}
fn status_successor(revision: u32) -> Option<u32> { revision.checked_add(1).filter(|next| *next < u32::MAX) }
fn stop_quit(state: &mut DocumentState, at: Instant) {
    if let Some(quit) = &state.quit {
        if state.quit_cleanup_end.is_none() { state.quit_cleanup_end = Some(first_cleanup_end(at, quit.endpoint(), None)); }
        quit.stop();
    }
}
fn session_data_empty(state: &DocumentState) -> bool {
    state.records.is_empty() && state.assignments.is_empty() && state.context.is_none()
        && state.slot.as_ref().is_none_or(|slot| slot.candidate.is_none() && slot.staged.is_none() && slot.context.is_none()
            && slot.retired_payload.is_none() && slot.selection.is_none() && slot.preview.is_none())
}
struct Inner { state: Mutex<DocumentState>, bridge: Arc<DesktopBridge>, changes: watch::Sender<u32> }
#[derive(Clone)]
pub(crate) struct DocumentBinding { inner: Arc<Inner> }

impl DocumentBinding {
    pub(crate) fn new(bridge: Arc<DesktopBridge>) -> Self {
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner { bridge, changes, state: Mutex::new(DocumentState { lifetime: DocumentLifetime::default(), revision: 0,
            next_operation: 0, next_context: 0, exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None, quit_accepted: false, quit_cleanup_end: None }) }) }
    }
    fn lock(&self) -> MutexGuard<'_, DocumentState> {
        match self.inner.state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                // A poisoned gate cannot emit differing DTOs at one ordinary
                // revision. Freeze the same final redacted authority while
                // retaining all originals for conservative settlement/exit.
                if !state.exhausted { self.exhaust(&mut state); }
                state
            }
        }
    }
    fn bump(&self, state: &mut DocumentState) {
        if state.exhausted { return; }
        match status_successor(state.revision) {
            Some(next) => { state.revision = next; self.inner.changes.send_replace(next); }
            None => self.exhaust(state),
        }
    }
    fn exhaust(&self, state: &mut DocumentState) {
        state.exhausted = true; state.unknown = true; state.stopping = true; state.lost_observed = true;
        state.lifetime.invalidate(); invalidate_all(state);
        if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::CleanupUnknown, Instant::now()); slot.phase = Phase::Unknown; }
        stop_quit(state, Instant::now());
        self.inner.bridge.edits.document_lost(MAIN);
        state.revision = u32::MAX; self.inner.changes.send_replace(u32::MAX);
    }
    fn next_operation(&self, state: &mut DocumentState) -> Result<u32, AssetError> {
        let Some(next) = state.next_operation.checked_add(1) else { self.exhaust(state); return Err(AssetError::new(Reason::CleanupUnknown)); };
        state.next_operation = next; Ok(next)
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    fn loss_locked(&self, state: &mut DocumentState) {
        state.lost_observed = true;
        invalidate_all(state);
        if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::DocumentLost, Instant::now()); }
        stop_quit(state, Instant::now());
        // This actual loss path is synchronous under the same admission lock.
        // EditOwner's first-loss tombstone was preallocated, with no loss RNG.
        self.inner.bridge.edits.document_lost(MAIN); self.bump(state);
    }
    fn apply(&self, state: &mut DocumentState, action: DocumentAction) {
        match action {
            DocumentAction::Bind => {
                if self.inner.bridge.edits.initial_document(MAIN).is_err() { state.lifetime.invalidate(); self.loss_locked(state); }
                else { self.bump(state); }
            }
            DocumentAction::Lost => self.loss_locked(state), DocumentAction::None => {},
        }
    }
    pub(crate) fn observe(&self, event: impl FnOnce(&mut DocumentLifetime) -> DocumentAction) {
        let mut state = self.lock(); let action = event(&mut state.lifetime); self.apply(&mut state, action);
    }
    pub(crate) fn navigation(&self, trusted: bool) -> bool {
        let mut state = self.lock(); let (allowed, action) = state.lifetime.navigation(trusted); self.apply(&mut state, action); allowed
    }
    pub(crate) fn lost(&self) { self.observe(DocumentLifetime::invalidate); }
    pub(crate) fn hook_installed(&self) { self.observe(DocumentLifetime::crash_hook_installed); }
    fn gate(&self, state: &DocumentState, session: bool) -> Result<(), AssetError> {
        if !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
        if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
        if state.stopping { return Err(AssetError::new(Reason::Shutdown)); }
        if state.quit_pending || state.retiring || state.lock_pending { return Err(AssetError::new(Reason::Busy)); }
        if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { return Err(AssetError::new(Reason::UnsupportedPlatform)); }
        if !NATIVE_QUALIFIED { return Err(AssetError::new(Reason::Unqualified)); }
        if session && !state.session { return Err(AssetError::new(Reason::Closed)); } Ok(())
    }
    fn registry_result<T>(&self, state: &mut DocumentState, result: Result<T, AssetError>) -> Result<T, AssetError> {
        if result.as_ref().is_err_and(|error| error.reason == Reason::CleanupUnknown) { self.coordinator_failed(state); }
        result
    }
    fn current_context(&self, state: &mut DocumentState, revision: u32) -> Result<Arc<NativeContext>, AssetError> {
        let context = state.context.as_ref().filter(|context| context.revision == revision).cloned().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
        let matches = self.context_matches(state, &context);
        if !self.registry_result(state, matches)? { return Err(AssetError::new(Reason::ContextStale)); } Ok(context)
    }
    fn context_matches(&self, state: &DocumentState, context: &Arc<NativeContext>) -> Result<bool, AssetError> {
        if !state.lifetime.original_bound() || state.stopping || state.unknown { return Ok(false); }
        let Some(current) = &state.context else { return Ok(false); };
        if !Arc::ptr_eq(current, context) || current.revision != context.revision || self.inner.bridge.registry_generation() != context.registry_generation { return Ok(false); }
        let (generation, root) = self.inner.bridge.native_project(&context.project_id)?;
        Ok(generation == context.registry_generation && root.identity == context.project.identity && root.path == context.project.path)
    }
    fn expire(&self, state: &mut DocumentState, now: Instant) {
        let mut changed = false;
        if let Some(slot) = state.slot.as_mut() {
            if slot.cleanup_end.is_none() && slot.phase != Phase::Idle {
                let work = slot.owner.endpoint();
                let due = match (work, slot.review_end) {
                    (Some(work), Some(review)) if work <= review => Some((work, Reason::Deadline)),
                    (_, Some(review)) => Some((review, Reason::ReviewExpired)),
                    (Some(work), None) => Some((work, Reason::Deadline)),
                    (None, None) => None,
                };
                if let Some((end, reason)) = due.filter(|(end, _)| now >= *end) { slot.stop(reason, end); changed = true; }
            }
            if slot.phase != Phase::Unknown && slot.cleanup_end.is_some_and(|end| now >= end) && !slot.owner.resources_settled() {
                slot.phase = Phase::Unknown; slot.source = SourceState::Unknown; slot.settlement = Settlement::Unknown; state.unknown = true;
                changed = true;
            }
        }
        if let Some(quit) = &state.quit {
            if state.quit_cleanup_end.is_none() {
                if let Some(end) = quit.endpoint().filter(|end| now >= *end) {
                    state.quit_cleanup_end = Some(end + CLEANUP); quit.stop(); changed = true;
                }
            }
            if state.quit_cleanup_end.is_some_and(|end| now >= end) && !quit.resources_settled() && !state.unknown {
                state.unknown = true; changed = true;
            }
        }
        if state.unknown {
            invalidate_all(state);
            if let Some(slot) = state.slot.as_mut() {
                if slot.cleanup_end.is_none() && slot.phase != Phase::Idle { slot.stop(Reason::CleanupUnknown, now); changed = true; }
            }
        }
        if changed { self.bump(state); }
    }
    fn snapshot(&self, state: &DocumentState) -> AssetStatus {
        // A saturated public sequence is one stable final redacted snapshot.
        // Internal originals may still settle for exit; no wrapped/new epoch is
        // offered to a renderer to compare against the exhausted authority.
        if state.exhausted {
            return AssetStatus { schema_version: 1, status_revision: u32::MAX, mode: "closed", capability: Capability { available: false, reason: Reason::CleanupUnknown },
                context: None, operation: None, records: Vec::new(), assignments: Vec::new() };
        }
        let redacted = !state.lifetime.original_bound();
        let capability_reason = if state.unknown { Reason::CleanupUnknown } else if state.stopping { Reason::Shutdown }
            else if state.lost_observed { Reason::DocumentLost }
            else if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { Reason::UnsupportedPlatform }
            else if !NATIVE_QUALIFIED { Reason::Unqualified } else if redacted { Reason::Closed } else { Reason::None };
        let operation = state.slot.as_ref().map(|slot| OperationStatus { operation_id: slot.owner.id, operation: slot.operation,
            phase: slot.phase, reason: slot.reason, source: slot.source, settlement: slot.settlement,
            selection_token: if redacted { None } else { slot.selection.clone() },
            assessment: if redacted || !slot.assessment_context_revision.is_some_and(|revision| state.context.as_ref().is_some_and(|context| context.revision == revision)) {
                None
            } else { slot.assessment.clone() },
            preview: if redacted { None } else { slot.preview.as_ref().filter(|preview| preview_subject_valid(state, slot, preview)).map(|preview| PreviewStatus {
                token: preview.token.clone(), action: preview.action, subject: preview.subject.clone(),
                expires_in_ms: u32::try_from(slot.review_end.map_or(Duration::ZERO, |end| end.saturating_duration_since(Instant::now())).as_millis()).unwrap_or(u32::MAX) }) } });
        AssetStatus { schema_version: 1, status_revision: state.revision, mode: if state.session { "session" } else { "closed" },
            capability: Capability { available: capability_reason == Reason::None, reason: capability_reason },
            context: if redacted { None } else { state.context.as_ref().map(|context| ContextStatus { revision: context.revision, project_id: context.project_id.clone(),
                platform: context.platform, stage: context.stage, purpose: context.purpose }) }, operation,
            records: if redacted { Vec::new() } else { state.records.iter().map(|record| RecordStatus { record_id: record.key.id.clone(), revision: record.key.revision,
                kind: record.payload.kind, availability: if record.mutation_pending { "mutation-pending" } else if state.assignments.iter().any(|a| a.record_id == record.key.id && a.record_revision == record.key.revision && a.availability == AssignmentAvailability::Available) { "assigned" } else { "unassigned" } }).collect() },
            assignments: if redacted { Vec::new() } else { state.assignments.clone() } }
    }
    pub(crate) fn status(&self) -> AssetStatus {
        self.reconcile();
        let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.snapshot(&state)
    }
    pub(crate) fn open_session(&self) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, false)?;
        idle(&state)?;
        if state.session { return Ok(self.snapshot(&state)); }
        let remaining_records = RECORD_LIMIT.saturating_sub(state.records.len());
        let remaining_assignments = 8usize.saturating_sub(state.assignments.len());
        state.records.try_reserve_exact(remaining_records).map_err(|_| AssetError::new(Reason::Capacity))?;
        state.assignments.try_reserve_exact(remaining_assignments).map_err(|_| AssetError::new(Reason::Capacity))?;
        state.session = true; self.bump(&mut state); Ok(self.snapshot(&state))
    }
    pub(crate) fn context(&self, args: commands::Context<'_>) -> Result<AssetStatus, AssetError> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?;
        let (registry_generation, project) = self.registry_result(&mut state, self.inner.bridge.native_project(args.project_id))?;
        let Some(revision) = state.next_context.checked_add(1) else { self.exhaust(&mut state); return Err(AssetError::new(Reason::CleanupUnknown)); };
        // Bounded, already-admitted Value serialization, not source parsing or
        // external IO. Keep only exact bytes, never another long-lived Value.
        let draft = commands::draft_bytes(args.draft)?;
        let project_id = commands::copy_text(args.project_id)?;
        invalidate_all(&mut state);
        if let Some(slot) = state.slot.as_mut() {
            slot.error = Some(AssetError::new(Reason::ContextStale).into());
            slot.stop(Reason::ContextStale, Instant::now());
        }
        state.next_context = revision;
        let old = state.context.replace(Arc::new(NativeContext { revision, project_id, project, registry_generation, draft,
            platform: args.platform, stage: args.stage, purpose: args.purpose }));
        // Keep even this data-only retirement registered. Another context
        // admission cannot accumulate caller-local old draft buffers while an
        // earlier caller is descheduled between unlock and its off-lock drop.
        state.retiring = true;
        self.bump(&mut state); let status = self.snapshot(&state); drop(state); drop(old);
        let mut state = self.lock(); state.retiring = false; Ok(status)
    }
    pub(crate) fn discard(&self, id: u32) -> Result<AssetStatus, AssetError> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        if !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
        if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
        let slot = state.slot.as_mut().filter(|slot| slot.owner.id == id).ok_or_else(AssetError::invalid)?;
        slot.operation = Operation::Discard; slot.stop(Reason::UserCancelled, Instant::now()); self.bump(&mut state);
        drop(state); Ok(self.status())
    }
    pub(crate) fn lock_session(&self) -> Result<AssetStatus, AssetError> {
        let mut state = self.lock();
        if !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
        invalidate_all(&mut state); state.lock_pending = true;
        if let Some(slot) = state.slot.as_mut() { slot.operation = Operation::Lock; slot.stop(Reason::UserCancelled, Instant::now()); }
        self.bump(&mut state); drop(state); Ok(self.status())
    }
}

fn idle(state: &DocumentState) -> Result<(), AssetError> {
    if state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled()) { return Err(AssetError::new(Reason::Busy)); } Ok(())
}
fn invalidate_all(state: &mut DocumentState) {
    for assignment in &mut state.assignments { assignment.availability = AssignmentAvailability::Unavailable; }
    if let Some(slot) = state.slot.as_mut() { slot.selection = None; slot.preview = None; }
}
fn revoke_record(state: &mut DocumentState, key: &RecordKey) {
    for assignment in &mut state.assignments { if assignment.record_id == key.id && assignment.record_revision == key.revision { assignment.availability = AssignmentAvailability::Unavailable; } }
    if let Some(record) = state.records.iter_mut().find(|record| record.key == *key) { record.mutation_pending = true; }
    if state.slot.as_ref().is_some_and(|slot| slot.target.as_ref() == Some(key)) { if let Some(slot) = state.slot.as_mut() { slot.preview = None; slot.selection = None; } }
}
fn own_record(reference: commands::RecordRef<'_>) -> Result<RecordKey, AssetError> { Ok(RecordKey { id: Token(commands::copy_text(reference.record_id)?), revision: reference.expected_revision }) }
fn target(state: &DocumentState, reference: Option<commands::RecordRef<'_>>, kind: Kind) -> Result<Option<RecordKey>, AssetError> {
    let Some(reference) = reference else { if state.records.len() >= RECORD_LIMIT { return Err(AssetError::new(Reason::Capacity)); } return Ok(None); };
    let key = own_record(reference)?;
    if !state.records.iter().any(|record| record.key == key && record.payload.kind == kind && !record.mutation_pending) { return Err(AssetError::invalid()); } Ok(Some(key))
}

enum ChildJob { Tokens, Capture { path: std::path::PathBuf, roots: Vec<asset_source::RegisteredRoot>, kind: credential_format::FileKind }, Probe { path: std::path::PathBuf, origins: Vec<Arc<OriginWitness>> } }
enum ChildEnd { Tokens(TokenBatch), Captured(Material), Probed(asset_source::ProjectProbe), Refused(Reason) }
enum Staged {
    Selected { payload: Arc<Payload>, tokens: TokenBatch }, Prepared { result: Result<SafeAssessment, CommandError>, tokens: TokenBatch },
    Delete(TokenBatch), Project { proof: asset_source::ProjectProbe, generation: u32 },
    Committed { bind: Option<Token> }, Bound(Assignment), Refused(Reason),
}
#[cfg(feature = "desktop-shell")]
enum Job {
    Choose { app: tauri::AppHandle, kind: Kind, roster: ProjectRoster },
    Project { app: tauri::AppHandle, generation: u32, origins: Vec<Arc<OriginWitness>> },
    Prepare { payload: Arc<Payload>, context: Arc<NativeContext> }, Delete, Retire { bind: Option<Token> }, Bind(Assignment),
}

async fn child(owner: &Arc<OriginalWork>, job: ChildJob) -> Result<ChildEnd, Reason> {
    let mut book = owner.child.lock().await;
    if book.handle.is_some() || !matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned) { return Err(Reason::CleanupUnknown); }
    if owner.interrupted() { return Err(Reason::UserCancelled); }
    book.receipt = JoinReceipt::Pending;
    let (start, enter) = oneshot::channel();
    let worker = owner.clone();
    book.handle = Some(tokio::task::spawn_blocking(move || {
        if enter.blocking_recv().is_err() { return ChildEnd::Refused(Reason::UserCancelled); }
        execute_child(&worker, job)
    }));
    // No blocking child can enter RNG/native work before its ORIGINAL handle
    // and resource slots above exist. Dropping an invoke never touches them.
    if start.send(()).is_err() { owner.stop(); }
    let result = match book.handle.as_mut() { Some(handle) => handle.await, None => { book.receipt = JoinReceipt::Failed; return Err(Reason::CleanupUnknown); } };
    book.handle.take(); // Only after this original join returned.
    match result { Ok(result) => { book.receipt = JoinReceipt::Returned; Ok(result) }, Err(_) => { book.receipt = JoinReceipt::Failed; Err(Reason::CleanupUnknown) } }
}
fn execute_child(owner: &Arc<OriginalWork>, job: ChildJob) -> ChildEnd {
    let mut stop = || owner.interrupted();
    if stop() { return ChildEnd::Refused(Reason::UserCancelled); }
    match job {
        ChildJob::Tokens => match random_tokens(&mut stop) { Ok(tokens) => ChildEnd::Tokens(tokens), Err(reason) => ChildEnd::Refused(reason) },
        ChildJob::Capture { path, roots, kind } => {
            let captured = match owner.source.lock() { Ok(mut book) => asset_source::capture(&mut book, path, &roots, kind, &mut stop), Err(_) => Err(Reason::CleanupUnknown) };
            match captured {
                Ok(captured) => match credential_format::inspect(kind, &captured.bytes, &mut stop) {
                    Ok(observation) => ChildEnd::Captured(Material { captured, observation }), Err(_) => ChildEnd::Refused(Reason::UserCancelled),
                },
                Err(reason) => ChildEnd::Refused(reason),
            }
        }
        ChildJob::Probe { path, origins } => match owner.source.lock() {
            Ok(mut book) => match asset_source::probe_project(&mut book, path, &origins, &mut stop) { Ok(probe) => ChildEnd::Probed(probe), Err(reason) => ChildEnd::Refused(reason) },
            Err(_) => ChildEnd::Refused(Reason::CleanupUnknown),
        },
    }
}
fn random_tokens(stop: &mut dyn FnMut() -> bool) -> Result<TokenBatch, Reason> {
    fn one(stop: &mut dyn FnMut() -> bool) -> Result<Token, Reason> {
        if stop() { return Err(Reason::UserCancelled); }
        let mut bytes = [0u8; 16]; getrandom::fill(&mut bytes).map_err(|_| Reason::SourceRefused)?;
        if stop() { return Err(Reason::UserCancelled); }
        let mut token = String::new(); token.try_reserve_exact(32).map_err(|_| Reason::Capacity)?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in &bytes { token.push(char::from(HEX[usize::from(byte >> 4)])); token.push(char::from(HEX[usize::from(byte & 15)])); }
        bytes.fill(0); Ok(Token(token)) // Best effort only, not an erasure claim.
    }
    Ok(TokenBatch { selection: one(stop)?, record: one(stop)?, preview: one(stop)?, bind: one(stop)? })
}

fn assemble_request(payload: &Payload, context: &NativeContext) -> Result<AssessmentRequest, CommandError> {
    let draft = crate::protocol::strict_json(&context.draft).map_err(|_| AssetError::invalid())?;
    let fields = payload.fields.as_ref().ok_or_else(AssetError::invalid)?.into_value();
    let observation = match &payload.material { Some(material) => serde_json::to_value(&material.observation).map_err(|_| AssetError::invalid())?, None => Value::Null };
    // Move Values into maps. json! on an already-owned Value can add a hidden
    // overlapping tree. Drop the entire assembled Value before awaiting R1.
    let mut ctx = Map::new(); ctx.insert("draft".into(), draft);
    ctx.insert("platform".into(), serde_json::to_value(context.platform).map_err(|_| AssetError::invalid())?);
    ctx.insert("stage".into(), serde_json::to_value(context.stage).map_err(|_| AssetError::invalid())?);
    ctx.insert("purpose".into(), serde_json::to_value(context.purpose).map_err(|_| AssetError::invalid())?);
    let mut input = Map::new(); input.insert("kind".into(), Value::String(payload.kind.name().into())); input.insert("fields".into(), fields); input.insert("observation".into(), observation);
    let mut root = Map::new(); root.insert("schemaVersion".into(), Value::from(1)); root.insert("policyVersion".into(), Value::String(commands::POLICY.into()));
    root.insert("context".into(), Value::Object(ctx)); root.insert("input".into(), Value::Object(input));
    let value = Value::Object(root);
    let request = AssessmentRequest::admit(&value)?;
    drop(value); Ok(request)
}

impl Slot {
    fn new(owner: Arc<OriginalWork>, operation: Operation, context: Option<Arc<NativeContext>>, target: Option<RecordKey>, review_end: Option<Instant>) -> Self {
        let assessment_context_revision = context.as_ref().map(|context| context.revision);
        Self { owner, operation, phase: Phase::Admitting, reason: Reason::None, source: SourceState::NotRun, settlement: Settlement::Pending,
            context, target, review_end, cleanup_end: None, candidate: None, selection: None, assessment: None, preview: None,
            assessment_context_revision, staged: None, error: None, project: None, discard: false, kind: None, result_record: None, retired_payload: None }
    }
}

// Set before spawning, so loss of an unpolled future also permits observation of
// the ORIGINAL join. This guard proves no resource settlement, normal return or
// success. A failed join remains a spent receipt in its original book.
struct CoordinatorEnd(Arc<OriginalWork>);
impl Drop for CoordinatorEnd {
    fn drop(&mut self) { self.0.ended.store(true, Ordering::SeqCst); self.0.wake.notify_one(); }
}

impl DocumentBinding {
    fn gui_response(&self, owner: &Arc<OriginalWork>, accepted: bool, quit: bool) -> Option<bool> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let mut facts = owner.gui.facts()?;
        if facts.response { return None; }
        facts.response = true; facts.showing = false;
        let now = Instant::now();
        let original = if quit { state.quit.as_ref().is_some_and(|work| Arc::ptr_eq(work, owner)) }
            else { state.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, owner)) && state.lifetime.original_bound() && !state.stopping && !state.unknown };
        facts.accepted = accepted && original && !owner.interrupted();
        if facts.accepted { facts.accepted_at = Some(now); owner.set_endpoint(Some(now + WORK)); }
        let read_one_path = facts.accepted && !quit;
        if quit {
            if facts.accepted {
                // Actual native OK linearizes with admission, not a later
                // dialog-return or renderer callback. Cancel changes none of
                // the settled assignments and never renews review time.
                state.quit_accepted = true; state.stopping = true; invalidate_all(&mut state);
                if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::Shutdown, now); }
                stop_quit(&mut state, now);
            } else { stop_quit(&mut state, now); }
        } else if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) {
            if read_one_path {
                slot.phase = Phase::Capturing;
                slot.source = if slot.operation == Operation::ChooseFile { SourceState::Pending } else { SourceState::NotRun };
                if slot.review_end.is_none() { slot.review_end = Some(now + REVIEW); }
            } else { slot.stop(Reason::UserCancelled, now); }
        }
        drop(facts); self.bump(&mut state); owner.gui.changed(); Some(read_one_path)
    }

    fn phase(&self, owner: &Arc<OriginalWork>, phase: Phase) -> Result<(), Reason> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        if state.stopping || state.unknown || !state.lifetime.original_bound() || owner.interrupted() { return Err(Reason::UserCancelled); }
        let slot = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)).ok_or(Reason::ContextStale)?;
        if slot.cleanup_end.is_some() { return Err(slot.reason); }
        if slot.phase != phase { slot.phase = phase; self.bump(&mut state); } Ok(())
    }
    fn tick(&self) { let mut state = self.lock(); self.expire(&mut state, Instant::now()); }
    fn stage(&self, owner: &Arc<OriginalWork>, staged: Staged) {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) {
            // Exactly one original coordinator stages once. Never overwrite a
            // possibly secret-bearing result or publish before its normal join.
            if slot.staged.is_none() { slot.staged = Some(staged); self.bump(&mut state); return; }
            slot.stop(Reason::CleanupUnknown, Instant::now()); state.unknown = true; self.bump(&mut state);
        }
        drop(state); drop(staged);
    }
    fn coordinator_failed(&self, state: &mut DocumentState) {
        state.unknown = true; invalidate_all(state);
        if let Some(slot) = state.slot.as_mut() {
            slot.stop(Reason::CleanupUnknown, Instant::now()); slot.phase = Phase::Unknown;
            slot.reason = Reason::CleanupUnknown; slot.settlement = Settlement::Unknown;
        }
        self.bump(state);
    }

    /// Joins only ended originals and drains closed data outside this real
    /// admission mutex. No task, picker, syscall or assessment is started here.
    fn reconcile(&self) {
        let mut release: Option<Arc<OriginalWork>> = None;
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        if state.retiring { return; }

        // Quit has its own original join receipt but shares the one GTK book.
        // No new quit coordinator is created to recheck an earlier Unknown.
        if let Some(quit) = state.quit.clone() {
            if let Some(normal) = quit.join_if_ended() {
                if !normal && !state.unknown { state.unknown = true; invalidate_all(&mut state); self.bump(&mut state); }
                if normal && quit.resources_settled() && state.quit_pending {
                    quit.set_endpoint(None);
                    state.quit_pending = false;
                    if !state.quit_accepted && !state.unknown { state.quit_cleanup_end = None; }
                    self.bump(&mut state);
                }
            }
        }

        let Some(mut slot) = state.slot.take() else {
            // An empty session has no original resource roster to await.
            if state.lock_pending || state.stopping || !state.lifetime.original_bound() {
                let records = std::mem::take(&mut state.records);
                let assignments = std::mem::take(&mut state.assignments);
                let context = state.context.take();
                let changed = state.session || state.lock_pending || context.is_some() || !records.is_empty() || !assignments.is_empty();
                state.retiring = true; drop(state); drop((records, assignments, context));
                let mut state = self.lock(); state.retiring = false; state.session = false; state.lock_pending = false;
                if changed { self.bump(&mut state); }
            }
            return;
        };
        let joined = slot.owner.join_if_ended();
        if joined == Some(false) && slot.settlement != Settlement::LateKnown {
            slot.stop(Reason::CleanupUnknown, Instant::now()); slot.phase = Phase::Unknown;
            slot.reason = Reason::CleanupUnknown; slot.settlement = Settlement::Unknown;
            if !state.unknown { state.unknown = true; self.bump(&mut state); }
        }

        // The coordinator's failed/returned join cannot dispose an unjoined
        // original blocking child. Observe it separately without a new worker.
        let mut orphan_result = None;
        if joined.is_some() {
            if let Ok(mut book) = slot.owner.child.try_lock() {
                if let Some(handle) = book.handle.as_mut().filter(|handle| handle.is_finished()) {
                    let mut cx = TaskContext::from_waker(Waker::noop());
                    if let Poll::Ready(result) = Pin::new(handle).poll(&mut cx) {
                        book.handle.take();
                        book.receipt = if result.is_ok() { JoinReceipt::Returned } else { JoinReceipt::Failed };
                        orphan_result = result.ok();
                    }
                }
            }
        }

        let resources = slot.owner.resources_settled();
        let tuple_result = slot.context.as_ref().map_or(Ok(true), |context| self.context_matches(&state, context));
        let tuple_ok = self.registry_result(&mut state, tuple_result).unwrap_or(false);
        if !tuple_ok && slot.cleanup_end.is_none() {
            slot.error = Some(AssetError::new(Reason::ContextStale).into());
            slot.stop(Reason::ContextStale, Instant::now()); self.bump(&mut state);
        }
        if state.stopping || !state.lifetime.original_bound() || state.lock_pending {
            if slot.cleanup_end.is_none() {
                let reason = if state.stopping { Reason::Shutdown } else if state.lock_pending { Reason::UserCancelled } else { Reason::DocumentLost };
                slot.stop(reason, Instant::now()); self.bump(&mut state);
            }
        }
        if joined == Some(true) && resources && slot.cleanup_end.is_none() {
            // The actual original normal join was observed inside its endpoint.
            // A pending quit confirmation may defer publication, not retain or
            // renew a completed work clock. Review remains absolute.
            slot.owner.set_endpoint(None);
            if !state.quit_pending && !state.unknown {
                if let Some(staged) = slot.staged.take() {
                    self.publish(&mut state, &mut slot, staged);
                    self.bump(&mut state);
                }
            }
        }
        if resources && (slot.discard || slot.phase == Phase::Idle || state.lock_pending || state.stopping || state.unknown) {
            let retire_context = slot.cleanup_end.is_some() || slot.candidate.is_some() || state.lock_pending || state.stopping || state.unknown || !state.lifetime.original_bound();
            let mut retirement = Retirement { candidate: slot.candidate.take(), staged: slot.staged.take(),
                payload: slot.retired_payload.take(), slot_context: if retire_context { slot.context.take() } else { None }, ..Retirement::default() };
            // Keep the sanitized explanation for the terminal idle receipt, but
            // release all native candidate leases before known settlement.
            if state.lock_pending || state.stopping || !state.lifetime.original_bound() {
                retirement.records = std::mem::take(&mut state.records);
                retirement.assignments = std::mem::take(&mut state.assignments);
                retirement.context = state.context.take();
            }
            for record in &mut state.records {
                if slot.target.as_ref() == Some(&record.key) || slot.result_record.as_ref() == Some(&record.key) { record.mutation_pending = false; }
            }
            let had_data = retirement.candidate.is_some() || retirement.staged.is_some() || retirement.payload.is_some() || retirement.slot_context.is_some() || !retirement.records.is_empty()
                || !retirement.assignments.is_empty() || retirement.context.is_some();
            if had_data || slot.phase != Phase::Idle && slot.settlement != Settlement::LateKnown {
                match slot.owner.retain_retirement(retirement) {
                    Ok(()) => {
                        // A concurrent status observer cannot call data disposal
                        // settled while this original holding is being drained.
                        slot.phase = if state.unknown { Phase::Unknown } else { Phase::Stopping };
                        slot.settlement = if state.unknown { Settlement::Unknown } else { Settlement::Pending };
                        state.retiring = true; release = Some(slot.owner.clone());
                        self.bump(&mut state);
                    },
                    Err(retirement) => {
                        // This is only already-closed data. No native handle is
                        // forgotten; keep the slot unqualified if its holding
                        // could not be established.
                        slot.candidate = retirement.candidate; slot.staged = retirement.staged;
                        slot.retired_payload = retirement.payload; slot.context = retirement.slot_context;
                        if !retirement.records.is_empty() { state.records = retirement.records; }
                        if !retirement.assignments.is_empty() { state.assignments = retirement.assignments; }
                        if retirement.context.is_some() { state.context = retirement.context; }
                        state.unknown = true; slot.phase = Phase::Unknown; slot.settlement = Settlement::Unknown;
                        self.bump(&mut state);
                    }
                }
            }
        }
        state.slot = Some(slot);
        if state.unknown { invalidate_all(&mut state); }
        drop(state);
        // A completed abandoned child result is never a new usable selection.
        drop(orphan_result);
        if let Some(owner) = release {
            let disposed = owner.release_retirement();
            let mut state = self.lock();
            state.retiring = false;
            if !disposed { self.coordinator_failed(&mut state); return; }
            let unknown = state.unknown;
            if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) {
                slot.owner.set_endpoint(None); slot.selection = None; slot.preview = None;
                slot.settlement = if unknown { Settlement::LateKnown } else { Settlement::Known };
                slot.phase = if unknown { Phase::Unknown } else { Phase::Idle };
            }
            // Lock/loss/quit may have arrived during a candidate-only off-lock
            // drain. Keep that request pending until a subsequent reconcile
            // retires its whole session roster; never report closed over data
            // that this earlier holding did not include.
            if (state.lock_pending || state.stopping || !state.lifetime.original_bound()) && session_data_empty(&state) {
                state.session = false; state.lock_pending = false;
            }
            self.bump(&mut state);
        }
    }

    fn publish(&self, state: &mut DocumentState, slot: &mut Slot, staged: Staged) {
        // This function performs bounded memory-only publication. Every source,
        // GTK, parser and original coordinator/child join has already settled.
        match staged {
            Staged::Selected { payload, tokens } => {
                if !tokens_distinct(&tokens) || state.records.iter().any(|record| record.key.id == tokens.record) {
                    slot.staged = Some(Staged::Selected { payload, tokens }); slot.stop(Reason::SourceRefused, Instant::now()); return;
                }
                slot.kind = Some(payload.kind); slot.source = SourceState::Captured;
                slot.candidate = Some(Candidate { payload, record_id: tokens.record, existing: slot.target.clone() });
                slot.selection = Some(tokens.selection); slot.phase = Phase::Selected; slot.settlement = Settlement::Known;
            }
            Staged::Prepared { result, tokens } => {
                if !tokens_distinct(&tokens) { slot.stop(Reason::SourceRefused, Instant::now()); return; }
                if let Some(candidate) = slot.candidate.as_mut() {
                    if candidate.record_id.0.is_empty() {
                        if state.records.iter().any(|record| record.key.id == tokens.record) { slot.stop(Reason::SourceRefused, Instant::now()); return; }
                        candidate.record_id = tokens.record;
                    }
                }
                match result {
                    Ok(result) => {
                        let payload = slot.candidate.as_ref().map(|candidate| &candidate.payload).or_else(||
                            slot.target.as_ref().and_then(|target| state.records.iter().find(|record| &record.key == target).map(|record| &record.payload)));
                        let usable = payload.is_some_and(|payload| payload.usable_source());
                        let permitted = result.permits() && usable;
                        slot.assessment = Some(result);
                        if slot.candidate.as_ref().is_some_and(|candidate| candidate.payload.kind.file().is_some()) { slot.selection = Some(tokens.selection); }
                        if permitted {
                            let save = slot.candidate.is_some();
                            let Some(kind) = slot.kind else { slot.stop(Reason::SourceRefused, Instant::now()); return; };
                            let existing = slot.candidate.as_ref().and_then(|candidate| candidate.existing.as_ref());
                            let subject = PreviewSubject::new(kind, if save { if existing.is_some() { SubjectChange::Replace } else { SubjectChange::New } } else { SubjectChange::Assign },
                                if save { existing } else { slot.target.as_ref() });
                            let preview = Preview { token: tokens.preview, action: if save { Action::Save } else { Action::Bind },
                                bind_token: if save { Some(tokens.bind) } else { None }, record: if save { None } else { slot.target.clone() }, subject };
                            offer_preview(state, slot, preview);
                        } else if slot.selection.is_some() { slot.phase = Phase::Selected; }
                        else { slot.phase = Phase::Idle; slot.discard = true; }
                    }
                    Err(error) => {
                        slot.error = Some(error);
                        if slot.candidate.as_ref().is_some_and(|candidate| candidate.payload.kind.file().is_some()) {
                            slot.selection = Some(tokens.selection); slot.phase = Phase::Selected;
                        } else { slot.phase = Phase::Idle; slot.discard = true; }
                    }
                }
                slot.settlement = Settlement::Known;
            }
            Staged::Delete(tokens) => {
                if !tokens_distinct(&tokens) || !slot.target.as_ref().is_some_and(|key| state.records.iter().any(|record| record.key == *key && record.mutation_pending)) {
                    slot.stop(Reason::SourceChanged, Instant::now()); return;
                }
                let Some(kind) = slot.kind else { slot.stop(Reason::SourceRefused, Instant::now()); return; };
                let preview = Preview { token: tokens.preview, action: Action::Delete, bind_token: None, record: slot.target.clone(),
                    subject: PreviewSubject::new(kind, SubjectChange::Delete, slot.target.as_ref()) };
                offer_preview(state, slot, preview); slot.settlement = Settlement::Known;
            }
            #[cfg(feature = "desktop-shell")]
            Staged::Project { proof, generation } => match self.inner.bridge.publish_checked_project(proof, generation) {
                Ok(project) => {
                    invalidate_all(state);
                    slot.project = Some(project); slot.source = SourceState::NotRun; slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
                    // Registry generation is part of every old context tuple.
                    // Keep its bounded bytes only until this off-lock retirement.
                }
                Err(error) => {
                    let reason = error.reason; slot.error = Some(error.into()); slot.stop(reason, Instant::now());
                    if reason == Reason::CleanupUnknown { state.unknown = true; }
                }
            },
            #[cfg(not(feature = "desktop-shell"))]
            Staged::Project { .. } => slot.stop(Reason::Unqualified, Instant::now()),
            Staged::Committed { bind } => {
                if let Some(token) = bind {
                    let record = slot.result_record.clone();
                    if !record.as_ref().is_some_and(|key| state.records.iter().any(|record| record.key == *key && record.payload.usable_source())) {
                        slot.stop(Reason::SourceChanged, Instant::now()); return;
                    }
                    if let Some(key) = &record { for row in &mut state.records { if row.key == *key { row.mutation_pending = false; } } }
                    let Some(kind) = slot.kind else { slot.stop(Reason::SourceRefused, Instant::now()); return; };
                    let subject = PreviewSubject::new(kind, SubjectChange::Assign, record.as_ref());
                    offer_preview(state, slot, Preview { token, action: Action::Bind, bind_token: None, record, subject });
                } else { slot.phase = Phase::Idle; slot.discard = true; }
                slot.settlement = Settlement::Known;
            }
            Staged::Bound(assignment) => {
                let context_result = slot.context.as_ref().map_or(Ok(false), |context| {
                    if context.revision != assignment.context_revision { Ok(false) } else { self.context_matches(state, context) }
                });
                let context_ok = self.registry_result(state, context_result).unwrap_or(false);
                if !state.records.iter().any(|record| record.key.id == assignment.record_id && record.key.revision == assignment.record_revision
                    && record.payload.kind == assignment.kind && !record.mutation_pending && record.payload.usable_source())
                    || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits)
                    || !context_ok {
                    slot.stop(Reason::ContextStale, Instant::now()); slot.error = Some(AssetError::new(Reason::ContextStale).into()); return;
                }
                if let Some(existing) = state.assignments.iter_mut().find(|existing| existing.kind == assignment.kind) { *existing = assignment; }
                else if state.assignments.len() < 8 { state.assignments.push(assignment); }
                else { slot.stop(Reason::Capacity, Instant::now()); return; }
                slot.phase = Phase::Idle; slot.settlement = Settlement::Known; slot.discard = true;
            }
            Staged::Refused(reason) => {
                slot.error = Some(AssetError::new(reason).into());
                if slot.source == SourceState::Pending { slot.source = SourceState::Refused; }
                slot.stop(reason, Instant::now()); if reason == Reason::CleanupUnknown { state.unknown = true; }
            }
        }
    }
}

fn tokens_distinct(tokens: &TokenBatch) -> bool {
    let tokens = [&tokens.selection, &tokens.record, &tokens.preview, &tokens.bind];
    tokens.iter().enumerate().all(|(i, token)| token.0.len() == 32 && token.0.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && tokens[i + 1..].iter().all(|other| *token != *other))
}

fn preview_subject_valid(state: &DocumentState, slot: &Slot, preview: &Preview) -> bool {
    let subject = &preview.subject;
    if !subject.kind.enabled() || slot.kind != Some(subject.kind) { return false; }
    let referenced = match (&subject.record_id, subject.record_revision) {
        (None, None) => false,
        (Some(id), Some(revision)) => {
            if !state.records.iter().any(|record| record.key.id == *id && record.key.revision == revision && record.payload.kind == subject.kind) { return false; }
            true
        }
        _ => return false,
    };
    let matches = |key: &RecordKey| subject.record_id.as_ref() == Some(&key.id) && subject.record_revision == Some(key.revision);
    match (preview.action, subject.change) {
        (Action::Save, SubjectChange::New) => !referenced && preview.record.is_none() && preview.bind_token.is_some() && slot.target.is_none()
            && slot.candidate.as_ref().is_some_and(|candidate| candidate.existing.is_none() && candidate.payload.kind == subject.kind),
        (Action::Save, SubjectChange::Replace) => referenced && preview.record.is_none() && preview.bind_token.is_some() && slot.target.as_ref().is_some_and(matches)
            && slot.candidate.as_ref().is_some_and(|candidate| candidate.existing.as_ref().is_some_and(matches) && candidate.payload.kind == subject.kind),
        (Action::Bind, SubjectChange::Assign) => referenced && preview.bind_token.is_none() && preview.record.as_ref().is_some_and(matches)
            && slot.result_record.as_ref().or(slot.target.as_ref()).is_some_and(matches),
        (Action::Delete, SubjectChange::Delete) => referenced && preview.bind_token.is_none() && preview.record.as_ref().is_some_and(matches) && slot.target.as_ref().is_some_and(matches),
        _ => false,
    }
}
fn offer_preview(state: &DocumentState, slot: &mut Slot, preview: Preview) {
    if !preview_subject_valid(state, slot, &preview) {
        slot.error = Some(AssetError::new(Reason::SourceChanged).into());
        slot.stop(Reason::SourceChanged, Instant::now()); return;
    }
    slot.selection = None; slot.preview = Some(preview); slot.phase = Phase::Preview;
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn install(&self, state: &mut DocumentState, slot: Slot, job: Job) -> Result<oneshot::Sender<()>, AssetError> {
        let owner = slot.owner.clone();
        let old_slot = state.slot.take().map(Box::new);
        if let Err(retirement) = owner.retain_retirement(Retirement { old_slot, ..Retirement::default() }) {
            state.slot = retirement.old_slot.map(|slot| *slot); state.unknown = true;
            return Err(AssetError::new(Reason::CleanupUnknown));
        }
        state.slot = Some(slot);
        let mut book = match owner.coordinator.lock() { Ok(book) => book, Err(_) => { self.coordinator_failed(state); return Err(AssetError::new(Reason::CleanupUnknown)); } };
        book.receipt = JoinReceipt::Pending;
        let (start, enter) = oneshot::channel();
        let document = self.clone(); let worker = owner.clone(); let end = CoordinatorEnd(owner.clone());
        book.handle = Some(tauri::async_runtime::spawn(async move {
            let _end = end;
            if enter.await.is_err() {
                worker.gui.not_created(Reason::UserCancelled);
                worker.release_retirement(); document.stage(&worker, Staged::Refused(Reason::UserCancelled)); return;
            }
            run_job(document, worker, job).await;
        }));
        // The original handle, GUI acquisition facts and child/resource slots
        // exist before this sender can be used. The caller releases the actual
        // DocumentBinding lock before opening the start barrier.
        self.bump(state); Ok(start)
    }
    pub(crate) fn choose(&self, app: tauri::AppHandle, args: commands::Choose<'_>) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?; idle(&state)?;
        if args.kind.file().is_none() { return Err(AssetError::new(Reason::UnsupportedFormat)); }
        let context = self.current_context(&mut state, args.context_revision)?;
        let target = target(&state, args.replacement, args.kind)?;
        let roster = self.registry_result(&mut state, self.inner.bridge.native_roster())?;
        if roster.generation != context.registry_generation { return Err(AssetError::new(Reason::ContextStale)); }
        let id = self.next_operation(&mut state)?;
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner, Operation::ChooseFile, Some(context), target.clone(), None);
        slot.kind = Some(args.kind); slot.source = SourceState::Pending;
        if let Some(target) = &target { revoke_record(&mut state, target); }
        let start = self.install(&mut state, slot, Job::Choose { app, kind: args.kind, roster })?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }

    pub(crate) fn prepare(&self, args: commands::Prepare<'_>) -> Result<u32, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?;
        let context = self.current_context(&mut state, args.context_revision)?;
        let now = Instant::now();
        let (payload, candidate, target, review_end) = match args.source {
            commands::Source::Selection(token) => {
                let slot = state.slot.as_ref().filter(|slot| matches!(slot.phase, Phase::Selected | Phase::Preview) && slot.owner.resources_settled()
                    && slot.selection.as_ref().is_some_and(|selection| selection.0 == token)).ok_or_else(AssetError::invalid)?;
                if !slot.context.as_ref().is_some_and(|bound| Arc::ptr_eq(bound, &context)) { return Err(AssetError::new(Reason::ContextStale)); }
                let original = slot.candidate.as_ref().ok_or_else(AssetError::invalid)?;
                let fields = commands::own_fields(original.payload.kind, args.fields.ok_or_else(AssetError::invalid)?)?;
                let payload = Arc::new(Payload { kind: original.payload.kind, material: original.payload.material.clone(), fields: Some(fields) });
                let candidate = Candidate { payload: payload.clone(), record_id: original.record_id.clone(), existing: original.existing.clone() };
                (payload, Some(candidate), slot.target.clone(), slot.review_end)
            }
            commands::Source::Record(reference) => {
                idle(&state)?; let key = own_record(reference)?;
                let record = state.records.iter().find(|record| record.key == key && !record.mutation_pending).ok_or_else(AssetError::invalid)?;
                (record.payload.clone(), None, Some(key), Some(now + REVIEW))
            }
            commands::Source::Scalar { kind, replacement } => {
                idle(&state)?;
                if !matches!(kind, Kind::GoogleWif | Kind::ProjectReadToken) { return Err(AssetError::new(Reason::UnsupportedFormat)); }
                let target = target(&state, replacement, kind)?;
                let fields = commands::own_fields(kind, args.fields.ok_or_else(AssetError::invalid)?)?;
                let payload = Arc::new(Payload { kind, material: None, fields: Some(fields) });
                let candidate = Candidate { payload: payload.clone(), record_id: Token(String::new()), existing: target.clone() };
                (payload, Some(candidate), target, Some(now + REVIEW))
            }
        };
        let id = self.next_operation(&mut state)?;
        let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner, Operation::Prepare, Some(context.clone()), target.clone(), review_end);
        slot.kind = Some(payload.kind); slot.source = if payload.material.is_some() { SourceState::Captured } else { SourceState::NotRun };
        let is_mutation = candidate.is_some(); slot.candidate = candidate;
        // A selection token and any dependent preview are consumed at admission,
        // before new RNG/assessment. Stored-record reassessment is not mutation.
        if let Some(old) = state.slot.as_mut() { old.selection = None; old.preview = None; }
        if is_mutation { if let Some(target) = &target { revoke_record(&mut state, target); } }
        let start = self.install(&mut state, slot, Job::Prepare { payload, context })?;
        drop(state); let _ = start.send(()); Ok(id)
    }

    pub(crate) fn prepare_delete(&self, reference: commands::RecordRef<'_>) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?; idle(&state)?;
        let key = own_record(reference)?;
        let kind = state.records.iter().find(|record| record.key == key && !record.mutation_pending).map(|record| record.payload.kind).ok_or_else(AssetError::invalid)?;
        let id = self.next_operation(&mut state)?; let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner, Operation::PrepareDelete, None, Some(key.clone()), Some(Instant::now() + REVIEW)); slot.kind = Some(kind);
        revoke_record(&mut state, &key);
        let start = self.install(&mut state, slot, Job::Delete)?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }

    /// No original resource/handle or secret-bearing result is removed into this
    /// waiter. Abandonment is just loss of an observer, including during R1 IO.
    pub(crate) async fn prepared(&self, id: u32) -> Result<AssetStatus, CommandError> {
        loop {
            self.reconcile();
            {
                let state = self.lock();
                let slot = state.slot.as_ref().filter(|slot| slot.owner.id == id).ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                if state.unknown || slot.settlement == Settlement::Unknown || slot.settlement == Settlement::LateKnown { return Err(AssetError::new(Reason::CleanupUnknown).into()); }
                if slot.owner.resources_settled() && matches!(slot.phase, Phase::Selected | Phase::Preview | Phase::Idle) {
                    if slot.reason == Reason::ContextStale { return Err(AssetError::new(Reason::ContextStale).into()); }
                    if let Some(error) = &slot.error { return Err(error.clone()); }
                    if slot.reason != Reason::None { return Err(AssetError::new(slot.reason).into()); }
                    return Ok(self.snapshot(&state));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[cfg(feature = "desktop-shell")]
async fn run_job(document: DocumentBinding, owner: Arc<OriginalWork>, job: Job) {
    if !owner.release_retirement() {
        // No GUI dispatch has happened on this original path yet.
        owner.gui.not_created(Reason::CleanupUnknown);
        document.stage(&owner, Staged::Refused(Reason::CleanupUnknown)); return;
    }
    let operation = execute_job(&document, &owner, job);
    tokio::pin!(operation);
    // One original coordinator drives cancellation while retaining (not
    // dropping/replacing) its exact child/R1 future. Timers only forbid future
    // success and set STOP; an unresponsive syscall/query still owns its slot.
    let staged = loop {
        tokio::select! {
            result = &mut operation => break result,
            _ = owner.wake.notified() => document.tick(),
            _ = tokio::time::sleep(Duration::from_millis(25)) => document.tick(),
        }
    };
    document.stage(&owner, staged);
}

#[cfg(feature = "desktop-shell")]
async fn execute_job(document: &DocumentBinding, owner: &Arc<OriginalWork>, job: Job) -> Staged {
    if owner.interrupted() { owner.gui.not_created(Reason::UserCancelled); return Staged::Refused(Reason::UserCancelled); }
    match job {
        Job::Retire { bind } => Staged::Committed { bind },
        Job::Bind(assignment) => Staged::Bound(assignment),
        Job::Choose { app, kind, roster } => {
            let tokens = match child(owner, ChildJob::Tokens).await {
                Ok(ChildEnd::Tokens(tokens)) => tokens,
                Ok(ChildEnd::Refused(reason)) | Err(reason) => { owner.gui.not_created(reason); return Staged::Refused(reason); },
                _ => { owner.gui.not_created(Reason::CleanupUnknown); return Staged::Refused(Reason::CleanupUnknown); },
            };
            let file_kind = match kind.file() { Some(kind) => kind, None => { owner.gui.not_created(Reason::UnsupportedFormat); return Staged::Refused(Reason::UnsupportedFormat); } };
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::File(file_kind)).await {
                Ok(Some(path)) => path, Ok(None) => return Staged::Refused(Reason::UserCancelled), Err(reason) => return Staged::Refused(reason),
            };
            if let Err(reason) = document.phase(owner, Phase::Capturing) { return Staged::Refused(reason); }
            match child(owner, ChildJob::Capture { path, roots: roster.roots, kind: file_kind }).await {
                Ok(ChildEnd::Captured(material)) => Staged::Selected { payload: Arc::new(Payload { kind, material: Some(Arc::new(material)), fields: None }), tokens },
                Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
            }
        }
        Job::Prepare { payload, context } => {
            let tokens = match child(owner, ChildJob::Tokens).await {
                Ok(ChildEnd::Tokens(tokens)) => tokens,
                Ok(ChildEnd::Refused(reason)) | Err(reason) => return Staged::Refused(reason), _ => return Staged::Refused(Reason::CleanupUnknown),
            };
            if let Err(reason) = document.phase(owner, Phase::Assessing) { return Staged::Refused(reason); }
            let result = match assemble_request(&payload, &context) {
                Ok(request) => {
                    if owner.interrupted() { return Staged::Refused(Reason::UserCancelled); }
                    assess_supplied(&document.inner.bridge.supervisor, request).await.map(|result| SafeAssessment(Arc::new(result))).map_err(CommandError::from)
                }
                Err(error) => Err(error),
            };
            // An R1 cleanup-unknown receipt is not its child settlement. The
            // unchanged Supervisor exposes only a conservative all-originals
            // can-exit view. Retain this exact coordinator/payload until that
            // view settles; do not cancel unrelated queries or fabricate a new
            // per-query lease. Unknown remains sticky even on late settlement.
            if document.inner.bridge.supervisor.disabled() {
                { let mut state = document.lock(); document.coordinator_failed(&mut state); }
                while !document.inner.bridge.supervisor.can_exit() { tokio::time::sleep(Duration::from_millis(50)).await; }
            }
            if owner.interrupted() { return Staged::Refused(Reason::UserCancelled); }
            Staged::Prepared { result, tokens }
        }
        Job::Delete => match child(owner, ChildJob::Tokens).await {
            Ok(ChildEnd::Tokens(tokens)) => Staged::Delete(tokens),
            Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
        },
        Job::Project { app, generation, origins } => {
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::Project).await {
                Ok(Some(path)) => path, Ok(None) => return Staged::Refused(Reason::UserCancelled), Err(reason) => return Staged::Refused(reason),
            };
            if let Err(reason) = document.phase(owner, Phase::Capturing) { return Staged::Refused(reason); }
            match child(owner, ChildJob::Probe { path, origins }).await {
                Ok(ChildEnd::Probed(proof)) => Staged::Project { proof, generation },
                Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
            }
        }
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn consume_preview(&self, state: &mut DocumentState, token: &str, bind: bool) -> Result<Preview, AssetError> {
        if state.slot.as_ref().is_some_and(|slot| slot.preview.as_ref().is_some_and(|preview| !preview_subject_valid(state, slot, preview))) {
            return Err(self.refuse_consumed(state, AssetError::invalid()));
        }
        let slot = state.slot.as_mut().ok_or_else(AssetError::invalid)?;
        if slot.reason == Reason::ContextStale { return Err(AssetError::new(Reason::ContextStale)); }
        if slot.phase != Phase::Preview || !slot.owner.resources_settled() { return Err(AssetError::new(Reason::Busy)); }
        let preview = slot.preview.as_ref().filter(|preview| preview.token.0 == token && (preview.action == Action::Bind) == bind).ok_or_else(AssetError::invalid)?;
        let _ = preview; // Validate the exact action/token before consuming.
        let preview = slot.preview.take().ok_or_else(AssetError::invalid)?;
        slot.selection = None;
        self.bump(state); Ok(preview)
    }
    fn refuse_consumed(&self, state: &mut DocumentState, error: AssetError) -> AssetError {
        if let Some(slot) = state.slot.as_mut() { slot.error = Some(error.into()); slot.stop(error.reason, Instant::now()); }
        if error.reason == Reason::CleanupUnknown { state.unknown = true; invalidate_all(state); }
        self.bump(state); error
    }

    pub(crate) fn commit(&self, token: &str) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?;
        let preview = self.consume_preview(&mut state, token, false)?;
        // All checks after consumption either admit this exact finite effect or
        // leave the old record bytes unassigned. No implicit retry/reassessment.
        let decision = (|| -> Result<(Option<RecordKey>, Option<Arc<Payload>>, Option<Token>, Kind), AssetError> {
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let kind = slot.kind.ok_or_else(AssetError::invalid)?;
            match preview.action {
                Action::Save => {
                    let context = slot.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                    if !self.context_matches(&state, context)? { return Err(AssetError::new(Reason::ContextStale)); }
                    let candidate = slot.candidate.as_ref().ok_or_else(AssetError::invalid)?;
                    if candidate.payload.kind != kind || !candidate.payload.usable_source() || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits) {
                        return Err(AssetError::new(Reason::SourceRefused));
                    }
                    let (key, previous_bytes) = match &candidate.existing {
                        Some(expected) => {
                            let record = state.records.iter().find(|record| record.key == *expected && record.payload.kind == kind && record.mutation_pending).ok_or_else(AssetError::invalid)?;
                            let revision = record.key.revision.checked_add(1).ok_or_else(|| AssetError::new(Reason::CleanupUnknown))?;
                            (RecordKey { id: record.key.id.clone(), revision }, record.payload.bytes())
                        }
                        None => {
                            if state.records.len() >= RECORD_LIMIT || candidate.record_id.0.len() != 32 || state.records.iter().any(|record| record.key.id == candidate.record_id) {
                                return Err(AssetError::new(Reason::Capacity));
                            }
                            (RecordKey { id: candidate.record_id.clone(), revision: 1 }, 0)
                        }
                    };
                    let occupied = state.records.iter().try_fold(0usize, |total, record| total.checked_add(record.payload.bytes())).ok_or_else(|| AssetError::new(Reason::Capacity))?;
                    let next = occupied.checked_sub(previous_bytes).and_then(|bytes| bytes.checked_add(candidate.payload.bytes())).ok_or_else(|| AssetError::new(Reason::Capacity))?;
                    if next > SESSION_BYTES { return Err(AssetError::new(Reason::Capacity)); }
                    Ok((Some(key), Some(candidate.payload.clone()), Some(preview.bind_token.clone().ok_or_else(|| AssetError::new(Reason::CleanupUnknown))?), kind))
                }
                Action::Delete => {
                    let key = preview.record.clone().ok_or_else(AssetError::invalid)?;
                    if !state.records.iter().any(|record| record.key == key && record.payload.kind == kind && record.mutation_pending) { return Err(AssetError::invalid()); }
                    Ok((Some(key), None, None, kind))
                }
                Action::Bind => Err(AssetError::invalid()),
            }
        })();
        let (key, payload, bind, kind) = match decision {
            Ok(decision) => decision,
            Err(error) => {
                if error.reason == Reason::CleanupUnknown { self.exhaust(&mut state); }
                return Err(self.refuse_consumed(&mut state, error));
            }
        };
        let id = self.next_operation(&mut state)?;
        let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        let mut slot = Slot::new(owner, Operation::Commit, old.context.clone(), old.target.clone(), old.review_end);
        slot.kind = Some(kind); slot.source = old.source; slot.phase = Phase::Mutating; slot.assessment = old.assessment.clone();
        slot.result_record = if payload.is_some() { key.clone() } else { None };
        let key = key.ok_or_else(AssetError::invalid)?;
        let retired_payload = if let Some(payload) = payload {
            if let Some(record) = state.records.iter_mut().find(|record| record.key.id == key.id) {
                record.key = key; record.mutation_pending = true; Some(std::mem::replace(&mut record.payload, payload))
            } else { state.records.push(Record { key, payload, mutation_pending: true }); None }
        } else {
            let index = state.records.iter().position(|record| record.key == key).ok_or_else(AssetError::invalid)?;
            let removed = state.records.remove(index);
            state.assignments.retain(|assignment| assignment.record_id != key.id);
            Some(removed.payload)
        };
        // The old payload is attached to the existing original slot before its
        // record reference disappears. install transfers that closed holding to
        // the newly admitted original coordinator for an off-lock drain.
        if let Some(old) = state.slot.as_mut() { old.retired_payload = retired_payload; }
        let start = self.install(&mut state, slot, Job::Retire { bind })?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }

    pub(crate) fn bind(&self, token: &str) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?;
        let preview = self.consume_preview(&mut state, token, true)?;
        let decision = (|| -> Result<(RecordKey, Kind, Arc<NativeContext>), AssetError> {
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let context = slot.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
            if !self.context_matches(&state, context)? { return Err(AssetError::new(Reason::ContextStale)); }
            let key = preview.record.clone().ok_or_else(AssetError::invalid)?;
            let kind = slot.kind.ok_or_else(AssetError::invalid)?;
            if !state.records.iter().any(|record| record.key == key && record.payload.kind == kind && !record.mutation_pending && record.payload.usable_source())
                || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits) { return Err(AssetError::new(Reason::SourceRefused)); }
            if state.assignments.len() >= 8 && !state.assignments.iter().any(|assignment| assignment.kind == kind) { return Err(AssetError::new(Reason::Capacity)); }
            Ok((key, kind, context.clone()))
        })();
        let (key, kind, context) = match decision { Ok(decision) => decision, Err(error) => return Err(self.refuse_consumed(&mut state, error)) };
        let id = self.next_operation(&mut state)?; let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        let mut slot = Slot::new(owner, Operation::Bind, Some(context.clone()), Some(key.clone()), old.review_end);
        slot.kind = Some(kind); slot.source = old.source; slot.phase = Phase::Mutating; slot.assessment = old.assessment.clone();
        for assignment in &mut state.assignments { if assignment.kind == kind { assignment.availability = AssignmentAvailability::Unavailable; } }
        let assignment = Assignment { kind, record_id: key.id, record_revision: key.revision, context_revision: context.revision, availability: AssignmentAvailability::Available };
        let start = self.install(&mut state, slot, Job::Bind(assignment))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }

    pub(crate) fn choose_project(&self, app: tauri::AppHandle) -> Result<u32, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, false)?; idle(&state)?;
        // Acquire the registry's checked generation before any native work;
        // poison is sticky document Unknown, never merely a later picker error.
        let generation = self.registry_result(&mut state, self.inner.bridge.native_generation())?;
        let mut origins = Vec::new(); origins.try_reserve_exact(state.records.len()).map_err(|_| AssetError::new(Reason::Capacity))?;
        for record in &state.records { if let Some(material) = &record.payload.material { origins.push(material.captured.origin.clone()); } }
        let id = self.next_operation(&mut state)?;
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let slot = Slot::new(owner, Operation::ChooseProject, None, None, None);
        // A later registration probes every retained source. Its admission,
        // not only success, revokes old use; cancel/refusal never restores it.
        invalidate_all(&mut state);
        let start = self.install(&mut state, slot, Job::Project { app, generation, origins })?;
        drop(state); let _ = start.send(()); Ok(id)
    }
    pub(crate) async fn project_result(&self, id: u32) -> Result<Option<Project>, AssetError> {
        loop {
            self.reconcile();
            {
                let state = self.lock();
                let slot = state.slot.as_ref().filter(|slot| slot.owner.id == id).ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
                if slot.phase == Phase::Idle && slot.owner.resources_settled() {
                    if slot.reason == Reason::None || slot.reason == Reason::UserCancelled { return Ok(slot.project.clone()); }
                    return Err(AssetError::new(slot.reason));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub(crate) fn not_quitting(&self) -> Result<(), BridgeError> {
        let state = self.lock();
        if state.unknown { return Err(BridgeError::cleanup_unknown()); }
        if state.stopping { return Err(BridgeError::shutdown()); }
        if state.quit_pending { return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before starting another action.")); }
        Ok(())
    }
    fn assets_can_exit_locked(state: &DocumentState) -> bool {
        !state.retiring && session_data_empty(state) && state.slot.as_ref().is_none_or(|slot| slot.owner.resources_settled())
    }
    pub(crate) fn assets_can_exit(&self) -> bool {
        self.reconcile(); Self::assets_can_exit_locked(&self.lock())
    }
    async fn shutdown_assets(&self) -> Result<(), AssetError> {
        // Native OK set stopping/revoked authority under the real gate before
        // this future exists. This observer never grants a new cleanup endpoint.
        loop {
            self.reconcile();
            {
                let state = self.lock();
                if Self::assets_can_exit_locked(&state) { return Ok(()); }
                if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    pub(crate) fn can_exit(&self) -> bool {
        let (ready, quit) = {
            let state = self.lock();
            (state.stopping && state.quit_accepted && Self::assets_can_exit_locked(&state), state.quit.clone())
        };
        // The app's data-only observer does not run general session publication.
        // Only this already-ended quit original is joined here.
        ready && quit.is_some_and(|quit| quit.join_if_ended() == Some(true) && quit.resources_settled())
            && self.inner.bridge.supervisor.can_exit() && self.inner.bridge.edits.can_exit()
    }
    pub(crate) fn request_quit(&self, app: tauri::AppHandle) {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        // A later Close is only an observation/wakeup of the existing originals.
        // In particular it never repeats shutdown or opens a cleanup dialog.
        if state.stopping || state.unknown || state.quit_pending || state.retiring {
            if let Some(quit) = &state.quit { quit.wake.notify_one(); } return;
        }
        if state.slot.as_ref().is_some_and(|slot| !slot.owner.gui.settled()) { return; }
        if state.quit.as_ref().is_some_and(|quit| !quit.resources_settled()) { return; }
        let id = match self.next_operation(&mut state) { Ok(id) => id, Err(_) => return };
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let previous = state.quit.replace(owner.clone());
        state.quit_pending = true; state.quit_accepted = false; state.quit_cleanup_end = None;
        let (start, enter) = oneshot::channel();
        let document = self.clone(); let worker = owner.clone(); let end = CoordinatorEnd(owner.clone());
        let mut book = match owner.coordinator.lock() {
            Ok(book) => book,
            Err(_) => { state.unknown = true; self.bump(&mut state); return; }
        };
        book.receipt = JoinReceipt::Pending;
        book.handle = Some(tauri::async_runtime::spawn(async move {
            let _end = end;
            if enter.await.is_err() { worker.gui.not_created(Reason::UserCancelled); return; }
            run_quit(document, worker, app).await;
        }));
        self.bump(&mut state); drop(book); drop(state); drop(previous); let _ = start.send(());
    }
}

#[cfg(feature = "desktop-shell")]
async fn run_quit(document: DocumentBinding, owner: Arc<OriginalWork>, app: tauri::AppHandle) {
    let dialog = crate::shell::run_owned_dialog(&app, &owner, crate::shell::DialogChoice::Quit);
    tokio::pin!(dialog);
    let mut dialog_ended = false;
    loop {
        let accepted = { document.lock().quit_accepted };
        if accepted { break; }
        tokio::select! {
            _ = &mut dialog => {
                dialog_ended = true;
                if !document.lock().quit_accepted { return; }
                break;
            },
            _ = owner.wake.notified() => document.tick(),
            _ = tokio::time::sleep(Duration::from_millis(25)) => document.tick(),
        }
    }
    // Actual OK already latched STOP on the asset slot. Start all three shutdown
    // futures once, even if the original quit dialog is still being disposed.
    // join! does not short-circuit an error or abandon any original future.
    let settlement = async {
        let gui = async { if !dialog_ended { let _ = dialog.as_mut().await; } };
        let _ = tokio::join!(gui, document.shutdown_assets(), document.inner.bridge.supervisor.shutdown(), document.inner.bridge.edits.shutdown());
    };
    tokio::pin!(settlement);
    loop {
        tokio::select! {
            _ = &mut settlement => break,
            _ = owner.wake.notified() => document.tick(),
            _ = tokio::time::sleep(Duration::from_millis(25)) => document.tick(),
        }
    }
    // Late all-positive settlement may permit exit, never a successful import,
    // new owner, reassignment or reuse of this unknown session.
    while !(document.assets_can_exit() && document.inner.bridge.supervisor.can_exit() && document.inner.bridge.edits.can_exit()) {
        tokio::select! {
            _ = owner.wake.notified() => document.tick(),
            _ = tokio::time::sleep(Duration::from_millis(50)) => document.tick(),
        }
    }
    // The fixed data-only exit observer will join this ORIGINAL coordinator and
    // the original relay before setting exit_ready. No task self-join, inline
    // GTK dispatch or body-ended flag is substituted for those joins.
}

#[cfg(test)]
mod tests {
    // Synthetic in-memory predicates only. No DesktopBridge constructor/RNG,
    // runtime, task spawn, dialog, fd, source path access or native receipts.
    use super::*;
    fn token(byte: char) -> Token { Token(byte.to_string().repeat(32)) }
    fn empty_state() -> DocumentState {
        DocumentState { lifetime: DocumentLifetime::default(), revision: 0, next_operation: 0, next_context: 0, exhausted: false, lost_observed: false,
            session: true, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None, quit_accepted: false, quit_cleanup_end: None }
    }
    fn scalar() -> Arc<Payload> { Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None }) }
    fn slot(target: Option<RecordKey>, review: Option<Instant>) -> Slot {
        let mut slot = Slot::new(OriginalWork::new(1, false, Weak::new()), Operation::Prepare, None, target, review);
        slot.kind = Some(Kind::GoogleWif); slot
    }

    #[test]
    fn late_stop_uses_original_due_endpoint_and_never_renews_review_or_cleanup() {
        let start = Instant::now(); let review = start + REVIEW;
        let mut slot = slot(None, Some(review)); slot.owner.set_endpoint(Some(start + WORK));
        slot.stop(Reason::DocumentLost, start + WORK + Duration::from_secs(20));
        assert_eq!(slot.cleanup_end, Some(start + WORK + CLEANUP));
        slot.stop(Reason::UserCancelled, review + Duration::from_secs(20));
        assert_eq!(slot.cleanup_end, Some(start + WORK + CLEANUP));
        assert_eq!(slot.review_end, Some(review)); assert!(slot.owner.stopped());
        assert_eq!(first_cleanup_end(review + WORK, Some(review + WORK), Some(review)), review + CLEANUP);
    }

    #[test]
    fn human_quit_stop_has_one_clock_without_inventing_a_work_endpoint() {
        let at = Instant::now(); let mut state = empty_state();
        let owner = OriginalWork::new(2, false, Weak::new()); owner.set_endpoint(None); state.quit = Some(owner.clone());
        stop_quit(&mut state, at); stop_quit(&mut state, at + WORK);
        assert_eq!(state.quit_cleanup_end, Some(at + CLEANUP)); assert_eq!(owner.endpoint(), None); assert!(owner.stopped());
    }

    #[test]
    fn mutation_admission_and_cancel_never_restore_prior_assignment() {
        let key = RecordKey { id: token('a'), revision: 1 }; let payload = scalar(); let mut state = empty_state();
        state.records.push(Record { key: key.clone(), payload: payload.clone(), mutation_pending: false });
        state.assignments.push(Assignment { kind: Kind::GoogleWif, record_id: key.id.clone(), record_revision: 1, context_revision: 1, availability: AssignmentAvailability::Available });
        state.slot = Some(slot(Some(key.clone()), None));
        revoke_record(&mut state, &key);
        if let Some(slot) = &mut state.slot { slot.stop(Reason::UserCancelled, Instant::now()); }
        assert!(state.records[0].mutation_pending); assert!(Arc::ptr_eq(&state.records[0].payload, &payload));
        assert!(state.assignments[0].availability == AssignmentAvailability::Unavailable);
        invalidate_all(&mut state); assert!(state.assignments[0].availability == AssignmentAvailability::Unavailable);
    }

    #[test]
    fn preview_subject_is_exact_and_offer_never_assigns_or_keeps_a_selection_token() {
        let mut state = empty_state(); let mut slot = slot(None, None);
        slot.selection = Some(token('b'));
        slot.candidate = Some(Candidate { payload: scalar(), record_id: token('a'), existing: None });
        let preview = Preview { token: token('c'), action: Action::Save, bind_token: Some(token('d')), record: None,
            subject: PreviewSubject::new(Kind::GoogleWif, SubjectChange::New, None) };
        offer_preview(&state, &mut slot, preview);
        assert!(slot.phase == Phase::Preview && slot.selection.is_none()); assert!(state.assignments.is_empty());
        let key = RecordKey { id: token('a'), revision: 1 };
        state.records.push(Record { key: key.clone(), payload: scalar(), mutation_pending: false });
        slot.result_record = Some(key.clone());
        let mut preview = Preview { token: token('d'), action: Action::Bind, bind_token: None, record: Some(key.clone()),
            subject: PreviewSubject::new(Kind::GoogleWif, SubjectChange::Assign, Some(&key)) };
        assert!(preview_subject_valid(&state, &slot, &preview)); assert!(state.assignments.is_empty());
        preview.subject.record_revision = Some(0); assert!(!preview_subject_valid(&state, &slot, &preview));
        preview.subject.record_revision = None; assert!(!preview_subject_valid(&state, &slot, &preview));
        offer_preview(&state, &mut slot, preview);
        assert!(slot.phase == Phase::Stopping && slot.preview.is_none()); assert!(state.assignments.is_empty());
    }

    #[test]
    fn end_of_body_alone_cannot_substitute_for_an_original_join() {
        let owner = OriginalWork::new(1, false, Weak::new());
        owner.ended.store(true, Ordering::SeqCst);
        assert_eq!(owner.join_if_ended(), None); assert!(!owner.resources_settled());
    }

    #[test]
    fn token_batch_is_closed_distinct_and_session_charge_includes_metadata() {
        let mut tokens = TokenBatch { selection: token('a'), record: token('b'), preview: token('c'), bind: token('d') };
        assert!(tokens_distinct(&tokens)); tokens.bind = tokens.preview.clone(); assert!(!tokens_distinct(&tokens));
        tokens.bind = token('G'); assert!(!tokens_distinct(&tokens));
        assert_eq!(scalar().bytes(), RECORD_METADATA_BYTES);
    }

    #[test]
    fn maximum_status_revision_is_reserved_for_the_one_redacted_tombstone() {
        assert_eq!(status_successor(u32::MAX - 2), Some(u32::MAX - 1));
        assert_eq!(status_successor(u32::MAX - 1), None); assert_eq!(status_successor(u32::MAX), None);
    }

    #[test]
    fn a_late_lock_cannot_call_a_candidate_only_retirement_an_empty_session() {
        let mut state = empty_state(); state.lock_pending = true;
        state.records.push(Record { key: RecordKey { id: token('a'), revision: 1 }, payload: scalar(), mutation_pending: false });
        assert!(!session_data_empty(&state)); assert!(state.lock_pending && state.session);
        state.records.clear(); assert!(session_data_empty(&state));
        // This predicate is data emptiness only, not a fabricated native join.
    }
}
