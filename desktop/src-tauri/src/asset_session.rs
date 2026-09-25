//! One real document gate, one retained native operation, session-only records.
//! The asset capability intentionally remains false. Project selection has a
//! separate fixed installed profile; it never grants a session. Pure tests do
//! not qualify GTK, source custody, runtime IO, allocation bounds or assignment.
use std::{future::Future, pin::Pin, sync::{Arc, Mutex, MutexGuard, Weak, atomic::{AtomicBool, Ordering}}, task::{Context as TaskContext, Poll, Waker}, time::{Duration, Instant}};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use tokio::{sync::{Mutex as AsyncMutex, Notify, oneshot, watch}, task::JoinHandle};
use crate::{asset_commands::{self as commands, AssetError, CommandError, Fields, Kind, Platform, Purpose, Reason, Stage}, asset_source::{self, OriginWitness, SourceBook},
    bridge::{DesktopBridge, Project, ProjectRoster}, credential_assessment::{AssessmentRequest, AssessmentResult, assess_supplied}, credential_format::{self, FileObservation},
    document_lifetime::{DocumentAction, DocumentLifetime}, error::BridgeError,
    candidate_evidence_protocol::{self as evidence_wire, Problem as EvidenceProblem},
    github_connection_protocol::{self as github_wire, Reason as GitHubReason},
    github_connection_session::{self as github_session, ConnectionState}};

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

// Explicitly ignored component fixture only: no installed window, persistent
// provider admission or renderer command is enabled by compiling this module.
#[cfg(all(test, debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "asset_session_gnome_transport_fixture.rs"]
mod gnome_transport_fixture;

fn installed_evidence_profile(evidence_selection: bool, candidate_method: bool) -> bool {
    // An advertised development method or broad asset fixture is not authority
    // for this separate installed, documents-only picker.
    evidence_selection && candidate_method
}

fn evidence_selection_gate(state: &DocumentState) -> Result<(), BridgeError> {
    idle(state).map_err(|_| evidence_wire::refused(EvidenceProblem::Busy))?;
    if state.evidence.revoked { return Err(evidence_wire::refused(EvidenceProblem::StaleSelection)); }
    Ok(())
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
use crate::shell::qualification::{EventKind as FixtureEvent, FixtureAdmission, Qualification};
macro_rules! fixture_event {
    ($owner:expr, $kind:ident, $detail:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        $owner.fixture_event(FixtureEvent::$kind, $detail);
    };
}

// Private transition labels, not public errors or new lifecycle authority.
// Unrelated/unsupported transitions deliberately keep NotRecorded provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnknownOrigin {
    NotRecorded, OperationCleanup(Reason), Registry, CoordinatorLock, CoordinatorJoin,
    SupervisorDisabled, StagedCollision, InstallRetirement, RetirementRetain, RetirementDrain,
    StagedRefusal, GatePoisoned, Exhausted,
}
macro_rules! first_unknown_origin {
    ($state:ident, $origin:expr, $owner:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if !$state.unknown && !$state.exhausted && $state.first_origin.is_none() {
            // Split fields rather than borrowing the whole state: a caller may
            // still hold the exact slot at its fresh transition. Never recover
            // an association later from a restored/current slot or public DTO.
            $state.first_origin = installed_session_observation::FirstOrigin::at_transition($origin, $owner);
        }
    };
}

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
// Native admission tuple for one DATA-only browse. It is neither an asset
// context nor a project registration and contains no draft/record authority.
struct ProjectPathBinding {
    project_id: String, field: commands::ProjectPathField, root: asset_source::RegisteredRoot, generation: u32,
}
impl ProjectPathBinding {
    fn registration_matches(&self, generation: u32, root: &asset_source::RegisteredRoot) -> bool {
        self.generation == generation && self.root == *root
    }
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
enum Operation { ChooseFile, ChooseProject, ChooseProjectPath, ChooseEvidenceFolder, InspectEvidence, Prepare, PrepareDelete, Commit, Bind, Discard, Lock }
impl Operation {
    fn evidence(self) -> bool { matches!(self, Self::ChooseEvidenceFolder | Self::InspectEvidence) }
    fn project_path(self) -> bool { self == Self::ChooseProjectPath }
    fn blocks_context(self) -> bool { self == Self::ChooseProject || self.project_path() || self.evidence() }
}
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeResponse { Accept, Decline, Other }
fn admitted_response(response: NativeResponse, original: bool, interrupted: bool, allow_decline: bool) -> (bool, bool) {
    let admitted = original && !interrupted;
    (admitted && response == NativeResponse::Accept, admitted && allow_decline && response == NativeResponse::Decline)
}
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    keyring: Mutex<crate::vault_keyring_linux::LookupBook>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    large_work_started: AtomicBool,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed_capture: Mutex<Option<Arc<asset_source::InstalledCaptureCheckpoint>>>,
    #[cfg(all(test, debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    gnome_transport_gate: Mutex<Option<Arc<gnome_transport_fixture::BoundaryGate>>>,
}
impl OriginalWork {
    fn new(id: u32, gui_needed: bool, document: Weak<Inner>) -> Arc<Self> {
        Arc::new_cyclic(|owner| Self { id, stop: AtomicBool::new(false), ended: AtomicBool::new(false), deadline: Mutex::new(Some(Instant::now() + WORK)),
            wake: Notify::new(), coordinator: Mutex::new(CoordinatorBook { handle: None, receipt: JoinReceipt::New }),
            child: AsyncMutex::new(ChildBook { handle: None, receipt: JoinReceipt::New }), source: Arc::new(Mutex::new(SourceBook::new())),
            retirement: Mutex::new(Retirement::default()), retired: AtomicBool::new(true),
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            keyring: Mutex::new(crate::vault_keyring_linux::LookupBook::new()),
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            large_work_started: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            installed_capture: Mutex::new(None),
            #[cfg(all(test, debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            gnome_transport_gate: Mutex::new(None),
            gui: Arc::new(GuiCall { owner: owner.clone(), document, facts: Mutex::new(GuiFacts { dispatched: false, constructing: false,
                created: false, showing: false, response: false, accepted: false, declined: false, accepted_at: None,
                destroyed: false, released: !gui_needed, not_created: !gui_needed, close_queued: false, close_ack: false, release_queued: false,
                selected: None, refusal: None }), wake: Notify::new(),
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
                    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
                    target_os = "macos", target_arch = "aarch64"))]
                installed_native_response_witness: Mutex::new(None),
            }) })
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
                book.handle.take();
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(context) = self.fixture() {
                    let source = self.source.try_lock().ok().and_then(|source| source.fixture_facts());
                    context.original_joined(self.id, normal, source);
                }
                Some(normal)
            }
        }
    }
    fn original_resources_settled(&self) -> bool {
        let coordinator = self.coordinator.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::Returned | JoinReceipt::Failed) && book.handle.is_none());
        let child = self.child.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned | JoinReceipt::Failed) && book.handle.is_none());
        let source = self.source.try_lock().is_ok_and(|book| book.not_started() || book.settled());
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let keyring = self.keyring.try_lock().is_ok_and(|book| book.resources_settled());
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let keyring = true;
        coordinator && child && source && self.gui.settled() && keyring
    }
    fn resources_settled(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let allocations = self.keyring.try_lock().is_ok_and(|book| book.allocations_released());
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let allocations = true;
        self.original_resources_settled() && self.retired.load(Ordering::SeqCst) && allocations
    }
    fn lookup_allocations_allowed(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.keyring.try_lock().is_ok_and(|book| !book.memory_held()) }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { true }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn dispose_keyring_storage(&self) -> bool {
        let Ok(retirement) = self.retirement.try_lock() else { return false; };
        if !self.retired.load(Ordering::SeqCst) || !lookup_memory::retirement_empty(&retirement)
            || !self.original_resources_settled() { return false; }
        let Ok(mut book) = self.keyring.try_lock() else { return false; };
        book.dispose_settled_storage()
    }
    fn normally_declined(&self) -> bool {
        // A normal body may also return after refusal/not-created. Neither that
        // nor a failed join is evidence of a genuine native Cancel response.
        self.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && self.gui.facts().is_some_and(|facts| facts.created && !facts.not_created && facts.response
                && facts.declined && !facts.accepted && facts.refusal.is_none()
                && facts.destroyed && facts.released && facts.close_ack)
    }
    fn project_path_settled(&self, selected: bool) -> bool {
        // A generic resources_settled allows FAILED joins. Path success/Cancel
        // instead require the exact normal originals, plus their GUI facts.
        self.resources_settled()
            && self.stopped() != selected
            && self.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && self.child.try_lock().is_ok_and(|book| book.handle.is_none()
                && book.receipt == (if selected { JoinReceipt::Returned } else { JoinReceipt::New }))
            && self.source.try_lock().is_ok_and(|book| if selected { !book.not_started() && book.settled() } else { book.not_started() })
            && self.gui.facts().is_some_and(|facts| project_path_gui_settled(&facts, selected))
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn fixture(&self) -> Option<Arc<Qualification>> { self.gui.document.upgrade()?.fixture.as_ref()?.upgrade() }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn fixture_event(&self, kind: FixtureEvent, detail: u32) {
        if let Some(context) = self.fixture() { context.event(kind, self.id, detail); }
    }
    fn retain_retirement(&self, retirement: Retirement) -> Result<(), Retirement> {
        let Ok(mut holding) = self.retirement.try_lock() else { return Err(retirement); };
        if !self.retired.swap(false, Ordering::SeqCst) { return Err(retirement); }
        *holding = retirement; Ok(())
    }
    fn release_retirement(&self) -> bool {
        let Ok(mut holding) = self.retirement.try_lock() else { return false; };
        let retirement = std::mem::take(&mut *holding);
        // Still off the document/admission lock, but retain THIS custody mutex
        // through the actual drop and receipt. A census cannot see empty data
        // while an off-lock drain is merely scheduled or still in progress.
        drop(retirement);
        self.retired.store(true, Ordering::SeqCst); true
    }
}
// Not object ownership: shell.rs retains the actual GTK object on its original
// main thread. These receipts never authorize replacement/Drop-as-settlement.
pub(crate) struct GuiCall {
    owner: Weak<OriginalWork>, document: Weak<Inner>, facts: Mutex<GuiFacts>, pub(crate) wake: Notify,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    installed_native_response_witness: Mutex<Option<InstalledNativeResponseWitness>>,
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub(crate) struct InstalledNativeResponseWitness {
    pub(crate) operation_id: u32,
    pub(crate) response: NativeResponse,
    pub(crate) selected: Option<std::path::PathBuf>,
    pub(crate) callback_returned: bool,
}
pub(crate) struct GuiFacts {
    pub(crate) dispatched: bool, pub(crate) constructing: bool,
    pub(crate) created: bool, pub(crate) showing: bool, pub(crate) response: bool, pub(crate) accepted: bool, pub(crate) declined: bool,
    pub(crate) accepted_at: Option<Instant>,
    pub(crate) destroyed: bool, pub(crate) released: bool, pub(crate) not_created: bool,
    pub(crate) close_queued: bool, pub(crate) close_ack: bool, pub(crate) release_queued: bool, pub(crate) selected: Option<std::path::PathBuf>,
    pub(crate) refusal: Option<Reason>,
}
fn project_path_gui_settled(facts: &GuiFacts, selected: bool) -> bool {
    facts.dispatched && facts.created && !facts.constructing && !facts.showing && !facts.not_created
        && facts.response && facts.refusal.is_none() && facts.destroyed && facts.close_queued && facts.close_ack
        && facts.release_queued && facts.released && facts.selected.is_none()
        && (if selected { facts.accepted && !facts.declined && facts.accepted_at.is_some() }
            else { facts.declined && !facts.accepted && facts.accepted_at.is_none() })
}
impl GuiCall {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn record_installed_native_response(self: &Arc<Self>, id: u32, response: NativeResponse,
        selected: Option<&std::path::Path>) -> Result<(), ()> {
        let owner = self.owner().ok_or(())?;
        if owner.id != id || !Arc::ptr_eq(&owner.gui, self) { return Err(()); }
        let mut witness = self.installed_native_response_witness.lock().map_err(|_| ())?;
        if witness.is_some() { return Err(()); } // First real response is immutable.
        // Sole caller is the original main-thread PanelState::Responded tick.
        // Both mrk_panel_poll state-1 branches require !callbackActive, and no
        // native work occurs after the completion clears that final flag.
        // Its path is already bounded to 4096 bytes by the original native poll.
        *witness = Some(InstalledNativeResponseWitness { operation_id: id, response,
            selected: selected.map(std::path::Path::to_path_buf), callback_returned: true });
        Ok(())
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn installed_native_response(&self) -> Result<Option<InstalledNativeResponseWitness>, ()> {
        // This data stays with the same original call, not a global panel
        // history. Read before replacing its slot; it grants no settlement.
        self.installed_native_response_witness.lock().map(|witness| witness.clone()).map_err(|_| ())
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn fixture_context(&self) -> Option<Arc<Qualification>> { self.owner()?.fixture() }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn fixture_event(&self, kind: FixtureEvent, detail: u32) {
        if let Some(owner) = self.owner() { owner.fixture_event(kind, detail); }
    }
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
        self.failed_at(reason, Instant::now());
    }
    pub(crate) fn failed_at(&self, reason: Reason, at: Instant) {
        // The original failure time precedes lock acquisition. A delayed
        // observer cannot grant this same operation another cleanup allowance.
        let Some(inner) = self.document.upgrade() else { return; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return; };
        let mut state = document.lock();
        fail_gui_original_locked(&mut state, self, &owner, reason, at);
        document.bump(&mut state); self.changed();
    }
    pub(crate) fn begin_response(&self, response: NativeResponse, quit: bool) -> Option<bool> {
        let Some(inner) = self.document.upgrade() else { return None; };
        let document = DocumentBinding { inner };
        let Some(owner) = self.owner() else { return None; };
        document.gui_response(&owner, response, quit)
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

fn fail_gui_original_locked(state: &mut DocumentState, call: &GuiCall, owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
    // Same transition and notification order as the ordinary native failure
    // path. This only requests STOP; it supplies no response or settlement.
    if let Some(mut facts) = call.facts() { if facts.refusal.is_none() { facts.refusal = Some(reason); } }
    if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) { slot.stop(reason, at); }
    if state.quit.as_ref().is_some_and(|quit| Arc::ptr_eq(quit, owner)) { stop_quit(state, at); }
    owner.stop();
}

struct Slot {
    owner: Arc<OriginalWork>, operation: Operation, phase: Phase, reason: Reason, source: SourceState, settlement: Settlement,
    context: Option<Arc<NativeContext>>, target: Option<RecordKey>, review_end: Option<Instant>, cleanup_end: Option<Instant>,
    candidate: Option<Candidate>, selection: Option<Token>, assessment: Option<SafeAssessment>, preview: Option<Preview>,
    assessment_context_revision: Option<u32>,
    staged: Option<Staged>, error: Option<CommandError>, project: Option<Project>, discard: bool,
    kind: Option<Kind>, result_record: Option<RecordKey>, retired_payload: Option<Arc<Payload>>,
    evidence: Option<EvidenceBinding>, project_path: Option<Arc<ProjectPathBinding>>, path_result: Option<commands::ProjectPathResult>,
}
impl Slot {
    fn stop(&mut self, reason: Reason, at: Instant) {
        self.selection = None; self.preview = None; self.path_result = None; self.discard = true;
        if self.reason == Reason::None { self.reason = reason; }
        if self.cleanup_end.is_none() { self.cleanup_end = Some(first_cleanup_end(at, self.owner.endpoint(), self.review_end)); }
        if self.phase != Phase::Unknown { self.phase = Phase::Stopping; }
        self.owner.stop();
    }
}
struct DocumentState {
    lifetime: DocumentLifetime, revision: u32, next_operation: u32, next_context: u32, exhausted: bool, lost_observed: bool,
    session: bool, stopping: bool, unknown: bool, quit_pending: bool, retiring: bool, lock_pending: bool,
    compatibility_picker_pending: bool,
    session_owner_reason: Option<Reason>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    first_origin: Option<installed_session_observation::FirstOrigin>,
    context: Option<Arc<NativeContext>>, slot: Option<Slot>, records: Vec<Record>, assignments: Vec<Assignment>,
    quit: Option<Arc<OriginalWork>>, quit_accepted: bool, quit_cleanup_end: Option<Instant>,
    github: ConnectionState,
    evidence: EvidenceRegistry,
}
fn project_path_pending(state: &DocumentState) -> bool {
    state.slot.as_ref().is_some_and(|slot| slot.operation.project_path()
        && (slot.phase != Phase::Idle || !slot.owner.resources_settled()))
}

// One purpose-bound selection for this original document. It is never inserted
// into DesktopBridge.projects and cannot change source drafts or GitHub context.
#[derive(Clone, PartialEq, Eq)]
struct EvidenceBinding { operation_id: u32, kind: evidence_wire::OperationKind, selection_id: Option<String>, epoch: u64 }
impl EvidenceBinding {
    fn public(&self) -> evidence_wire::Operation {
        evidence_wire::Operation { operation_id: self.operation_id.to_string(), kind: self.kind, selection_id: self.selection_id.clone() }
    }
}
struct EvidenceSelection { view: evidence_wire::Selection, root: asset_source::RegisteredRoot, epoch: u64 }
struct EvidenceRegistry {
    revision: u64, epoch: u64, revoked: bool, selection: Option<EvidenceSelection>, operation: Option<EvidenceBinding>,
    phase: evidence_wire::Phase, result: Option<evidence_wire::Observation>, problem: Option<EvidenceProblem>,
}
impl EvidenceRegistry {
    fn new() -> Self { Self { revision: 0, epoch: 0, revoked: false, selection: None, operation: None,
        phase: evidence_wire::Phase::Idle, result: None, problem: None } }
    fn revoke(&mut self, unknown: bool) {
        self.revoked = true; self.selection = None; self.result = None;
        self.phase = if unknown { evidence_wire::Phase::Unknown } else { evidence_wire::Phase::Refused };
        self.problem = Some(if unknown { EvidenceProblem::CleanupUnknown } else { EvidenceProblem::StaleSelection });
    }
    fn matches(&self, slot: &Slot) -> bool {
        let Some(binding) = &slot.evidence else { return false; };
        slot.operation.evidence() && self.operation.as_ref() == Some(binding) && binding.operation_id == slot.owner.id
            && binding.epoch == self.epoch
            && matches!((slot.operation, binding.kind), (Operation::ChooseEvidenceFolder, evidence_wire::OperationKind::Choose)
                | (Operation::InspectEvidence, evidence_wire::OperationKind::Observe))
    }
    fn selection_matches(&self, binding: &EvidenceBinding) -> bool {
        !self.revoked && self.selection.as_ref().is_some_and(|selection| selection.epoch == binding.epoch
            && binding.selection_id.as_deref() == Some(selection.view.selection_id.as_str()))
    }
}
fn evidence_reason(reason: Reason) -> EvidenceProblem {
    match reason {
        Reason::CleanupUnknown => EvidenceProblem::CleanupUnknown,
        Reason::Deadline | Reason::ReviewExpired => EvidenceProblem::Deadline,
        Reason::UserCancelled => EvidenceProblem::Cancelled,
        Reason::Capacity | Reason::MaterialLimit | Reason::ParserLimit => EvidenceProblem::Limit,
        Reason::Busy => EvidenceProblem::Busy,
        Reason::ContextStale | Reason::SourceChanged | Reason::DocumentLost | Reason::Shutdown => EvidenceProblem::StaleSelection,
        Reason::SourceRefused | Reason::ProjectOverlap | Reason::ExclusionUnconfirmed => EvidenceProblem::UnsafeSelection,
        Reason::UnsupportedPlatform | Reason::UnsupportedFilesystem | Reason::Unqualified | Reason::Closed => EvidenceProblem::Unavailable,
        _ => EvidenceProblem::ObservationFailed,
    }
}
fn cancel_evidence_locked(state: &mut DocumentState, args: &evidence_wire::Cancel, at: Instant) -> Result<bool, BridgeError> {
    // A STOP identifies the exact original job, not merely its folder. Match
    // before clock reconciliation or any change to unrelated shared state.
    let id = evidence_wire::operation_id(&args.operation_id).ok_or_else(evidence_wire::invalid)?;
    let binding = state.evidence.operation.as_ref().filter(|binding| binding.operation_id == id
        && binding.selection_id == args.selection_id && binding.epoch == state.evidence.epoch)
        .ok_or_else(|| evidence_wire::refused(EvidenceProblem::StaleSelection))?.clone();
    let matching = state.slot.as_ref().is_some_and(|slot| state.evidence.matches(slot) && slot.evidence.as_ref() == Some(&binding));
    if !matching {
        // A retained terminal operation no longer has an owner to stop. Never
        // route it into the different shared job now occupying the slot.
        return if matches!(state.evidence.phase, evidence_wire::Phase::Selected | evidence_wire::Phase::Observed | evidence_wire::Phase::Cancelled | evidence_wire::Phase::Refused) {
            Ok(false)
        } else { Err(evidence_wire::refused(EvidenceProblem::StaleSelection)) };
    }
    let slot = state.slot.as_mut().ok_or_else(evidence_wire::invalid)?;
    if slot.phase == Phase::Idle && slot.owner.resources_settled() { return Ok(false); }
    let reason = if slot.owner.endpoint().is_some_and(|end| at >= end) { Reason::Deadline } else { Reason::UserCancelled };
    slot.stop(reason, at); Ok(true)
}
fn record_evidence_failure(state: &mut DocumentState, owner: &Arc<OriginalWork>, problem: EvidenceProblem, at: Instant) -> bool {
    let Some(slot) = state.slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, owner) && state.evidence.matches(slot)) else { return false; };
    // The first STOP owns both timing and public explanation. A late ordinary
    // core error cannot relabel a user's cancellation or the original deadline.
    // Unconfirmed cleanup remains a conservative, sticky authority reduction.
    if (slot.reason != Reason::None || slot.cleanup_end.is_some()) && problem != EvidenceProblem::CleanupUnknown { return false; }
    let problem = if problem != EvidenceProblem::CleanupUnknown && slot.owner.endpoint().is_some_and(|end| at >= end) {
        EvidenceProblem::Deadline
    } else { problem };
    state.evidence.problem = Some(problem); state.evidence.result = None;
    let reason = match problem { EvidenceProblem::Deadline => Reason::Deadline, EvidenceProblem::CleanupUnknown => Reason::CleanupUnknown,
        EvidenceProblem::Limit => Reason::Capacity, EvidenceProblem::Cancelled => Reason::UserCancelled, _ => Reason::SourceRefused };
    if let Some(slot) = state.slot.as_mut() { slot.stop(reason, at); }
    if problem == EvidenceProblem::CleanupUnknown { state.unknown = true; }
    true
}
fn evidence_display_name(path: &std::path::Path) -> String {
    path.file_name().and_then(|name| name.to_str()).filter(|name|
        evidence_wire::display_text(name, 128, 512) && !name.contains(['/', '\\']))
        .unwrap_or("Selected evidence folder").to_owned()
}
fn evidence_snapshot(state: &DocumentState, available: bool) -> evidence_wire::Status {
    let registry = &state.evidence;
    if !available { return evidence_wire::Status::unavailable(registry.revision); }
    let mut phase = registry.phase;
    let mut problem = registry.problem;
    if state.unknown || state.exhausted {
        phase = evidence_wire::Phase::Unknown; problem = Some(EvidenceProblem::CleanupUnknown);
    } else if let Some(slot) = state.slot.as_ref().filter(|slot| registry.matches(slot)) {
        if slot.phase == Phase::Unknown || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
            phase = evidence_wire::Phase::Unknown; problem = Some(EvidenceProblem::CleanupUnknown);
        } else if slot.cleanup_end.is_some() {
            // STOP is not terminal until all ORIGINAL resources and their data
            // retirement have settled. A late positive result cannot revive it.
            phase = if slot.phase == Phase::Idle && slot.owner.resources_settled() {
                if !registry.revoked && slot.reason == Reason::UserCancelled { evidence_wire::Phase::Cancelled } else { evidence_wire::Phase::Refused }
            } else { evidence_wire::Phase::Stopping };
            problem = Some(problem.unwrap_or_else(|| evidence_reason(slot.reason)));
        }
    }
    evidence_wire::Status { schema_version: 1, revision: registry.revision.to_string(), availability: "available", phase,
        selection: if registry.revoked { None } else { registry.selection.as_ref().map(|selection| selection.view.clone()) },
        operation: registry.operation.as_ref().map(EvidenceBinding::public),
        result: if phase == evidence_wire::Phase::Observed { registry.result.clone() } else { None }, problem }
}
fn settle_evidence_status(state: &mut DocumentState) {
    if state.slot.as_ref().is_some_and(|slot| state.evidence.matches(slot) && slot.phase == Phase::Idle && slot.owner.resources_settled()) {
        let status = evidence_snapshot(state, true);
        state.evidence.phase = status.phase; state.evidence.problem = status.problem;
        if status.phase != evidence_wire::Phase::Observed { state.evidence.result = None; }
    }
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
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
fn accepted_quit_cleanup_end(state: &DocumentState) -> Option<Instant> {
    if state.stopping && state.quit_accepted && state.quit.as_ref().is_some_and(|quit| quit.stopped()) {
        state.quit_cleanup_end
    } else { None }
}
fn session_data_empty(state: &DocumentState) -> bool {
    state.records.is_empty() && state.assignments.is_empty() && state.context.is_none()
        && state.slot.as_ref().is_none_or(|slot| slot.candidate.is_none() && slot.staged.is_none() && slot.context.is_none()
            && slot.retired_payload.is_none() && slot.selection.is_none() && slot.preview.is_none())
}
fn assets_can_exit_locked(state: &DocumentState) -> bool {
    !state.retiring && session_data_empty(state) && state.slot.as_ref().is_none_or(|slot| slot.owner.resources_settled())
}
fn complete_empty_session_lock(state: &mut DocumentState) -> bool {
    // The caller must have reinserted its exact original slot. Empty data alone
    // cannot settle a pending coordinator/source/GUI or off-lock retirement.
    if state.lock_pending && assets_can_exit_locked(state) {
        state.session = false; state.lock_pending = false; true
    } else { false }
}
fn quit_question_admitted(state: &DocumentState) -> bool {
    if state.stopping || state.quit_accepted || state.quit_pending || state.retiring
        || state.slot.as_ref().is_some_and(|slot| !slot.owner.gui.settled())
        || state.quit.as_ref().is_some_and(|quit| !quit.resources_settled()) { return false; }
    if !state.unknown { return true; } // Preserve ordinary quit admission.
    // This grants only a question after genuine late settlement and a closed
    // session. Unknown, old endpoints, and original receipts are not reset.
    !state.exhausted && !state.lost_observed && state.lifetime.original_bound()
        && !state.session && !state.lock_pending && assets_can_exit_locked(state)
        && state.quit.as_ref().is_none_or(|quit| quit.normally_declined())
}
struct Inner {
    state: Mutex<DocumentState>, bridge: Arc<DesktopBridge>, changes: watch::Sender<u32>,
    session_identity: Arc<()>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed_session: Mutex<Option<installed_session_observation::Book>>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture: Option<Weak<Qualification>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    github_fixture: Option<crate::supervisor::GitHubDocumentFixtureBinding>,
}
#[derive(Clone)]
pub(crate) struct DocumentBinding { inner: Arc<Inner> }

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_slot_gate(state: &DocumentState, owner: &Arc<OriginalWork>, step: Option<crate::vault_keyring_linux::Step>, now: Instant)
    -> Result<Instant, crate::vault_keyring_linux::Problem> {
    use crate::vault_keyring_linux::Problem;
    let slot = state.slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, owner) && slot.operation == Operation::Prepare)
        .ok_or(Problem::Interrupted)?;
    // Fixed own-session close/subscription removal may pass after STOP/loss.
    // It still belongs to this exact current OriginalWork; no public Boolean
    // can substitute for the book's expected step or real slot identity.
    if step.is_some_and(crate::vault_keyring_linux::Step::cleanup) {
        return keyring_cleanup_endpoint(state, owner, now);
    }
    if !state.lifetime.original_bound() || state.lost_observed || state.exhausted || state.unknown || state.stopping
        || state.quit_pending || state.retiring || state.lock_pending || owner.interrupted()
        || slot.phase != Phase::Assessing || slot.cleanup_end.is_some()
    { return Err(Problem::Interrupted); }
    owner.endpoint().filter(|end| now < *end).ok_or(Problem::Interrupted)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_cleanup_endpoint(state: &DocumentState, owner: &Arc<OriginalWork>, now: Instant)
    -> Result<Instant, crate::vault_keyring_linux::Problem> {
    use crate::vault_keyring_linux::Problem;
    let slot = state.slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, owner) && slot.operation == Operation::Prepare)
        .ok_or(Problem::Interrupted)?;
    // STOP/loss never grants a new lease. This same endpoint guards both remote
    // session close/removal and DISTINCT local shutdown, including first poll.
    let end = slot.cleanup_end.or_else(|| owner.endpoint()).ok_or(Problem::CleanupUnknown)?;
    if now >= end || state.unknown || state.exhausted || slot.phase == Phase::Unknown
        || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown)
    { return Err(Problem::CleanupUnknown); }
    Ok(end)
}

// Only the actual document/current-slot gate can construct this non-Clone
// token. It is consumed immediately under the same locked original book; it is
// neither a caller Boolean nor a fake Step::RemoveMatch.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) struct KeyringShutdownAdmission { endpoint: Instant }
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl KeyringShutdownAdmission {
    pub(crate) fn into_endpoint(self) -> Instant { self.endpoint }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_shutdown_gate(state: &DocumentState, owner: &Arc<OriginalWork>, book: &crate::vault_keyring_linux::LookupBook, now: Instant)
    -> Result<KeyringShutdownAdmission, crate::vault_keyring_linux::Problem> {
    if !book.shutdown_waiting_first_poll() { return Err(crate::vault_keyring_linux::Problem::CleanupUnknown); }
    Ok(KeyringShutdownAdmission { endpoint: keyring_cleanup_endpoint(state, owner, now)? })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_poll_gate(state: &DocumentState, owner: &Arc<OriginalWork>, book: &crate::vault_keyring_linux::LookupBook, now: Instant)
    -> Result<Instant, crate::vault_keyring_linux::Problem> {
    keyring_slot_gate(state, owner, book.current_step(), now)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_problem_stop(state: &mut DocumentState, owner: &Arc<OriginalWork>,
    problem: Option<(crate::vault_keyring_linux::Problem, Instant)>) -> bool {
    use crate::vault_keyring_linux::Problem;
    if let (Some((problem, at)), Some(slot)) = (problem,
        state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner))) {
        let reason = match problem {
            Problem::Interrupted => Reason::UserCancelled,
            Problem::CleanupUnknown => Reason::CleanupUnknown,
            Problem::Capacity => Reason::Capacity,
            _ => Reason::SourceRefused,
        };
        if slot.cleanup_end.is_none() { slot.stop(reason, at); return true; }
    }
    false
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn keyring_constrain_cleanup(state: &DocumentState, owner: &Arc<OriginalWork>, book: &mut crate::vault_keyring_linux::LookupBook) {
    if let Some(end) = state.slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, owner)
        && slot.operation == Operation::Prepare).and_then(|slot| slot.cleanup_end) {
        // Slot::stop is the sole writer: first_cleanup_end always adds CLEANUP
        // to the first stop/due timestamp. Never derive this from observer-now.
        book.constrain_cleanup_endpoint(end - CLEANUP, end);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl DocumentBinding {
    // Deliberately PRIVATE and UNCALLED by renderer/session prepare/bind. A later
    // native profile must integrate this into the already-registered coordinator;
    // no second task or alternate owner is created by this source-only phase.
    fn enter_keyring_lookup(&self, owner: &Arc<OriginalWork>, input: crate::vault_keyring_linux::LookupInput)
        -> Result<(), crate::vault_keyring_linux::Problem> {
        let mut state = self.lock(); let now = Instant::now(); self.expire(&mut state, now);
        let dispatch_end = keyring_slot_gate(&state, owner, None, now)?;
        lookup_memory::enter(&state, owner, input, dispatch_end)
        // No IO is polled while the document/registry mutex is held.
    }
    fn admit_keyring_step(&self, owner: &Arc<OriginalWork>, step: crate::vault_keyring_linux::Step)
        -> Result<(), crate::vault_keyring_linux::Problem> {
        use crate::vault_keyring_linux::Problem;
        let mut state = self.lock(); let now = Instant::now(); self.expire(&mut state, now);
        let dispatch_end = keyring_slot_gate(&state, owner, Some(step), now)?;
        let mut book = owner.keyring.lock().map_err(|_| Problem::CleanupUnknown)?;
        if !book.expected(step) { return Err(Problem::CleanupUnknown); }
        book.admit(step, dispatch_end)
    }
    fn admit_keyring_shutdown(&self, owner: &Arc<OriginalWork>)
        -> Result<(), crate::vault_keyring_linux::Problem> {
        use crate::vault_keyring_linux::Problem;
        let mut state = self.lock(); let now = Instant::now(); self.expire(&mut state, now);
        let mut book = owner.keyring.lock().map_err(|_| Problem::CleanupUnknown)?;
        self.record_keyring_problem(&mut state, owner, book.problem().zip(book.problem_at()), book.document_cleanup_unknown());
        let end = keyring_cleanup_endpoint(&state, owner, Instant::now())?;
        book.admit_shutdown(end)
    }
    fn report_keyring_problem(&self, owner: &Arc<OriginalWork>) {
        // Read and RELEASE the backend mutex before acquiring the document gate.
        let (problem, cleanup_unknown) = match owner.keyring.lock() {
            Ok(book) => (book.problem().zip(book.problem_at()), book.document_cleanup_unknown()),
            Err(error) => { drop(error); let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return; }
        };
        let mut state = self.lock();
        self.record_keyring_problem(&mut state, owner, problem, cleanup_unknown);
    }
    fn record_keyring_problem(&self, state: &mut DocumentState, owner: &Arc<OriginalWork>,
        problem: Option<(crate::vault_keyring_linux::Problem, Instant)>, cleanup_unknown: bool) {
        // The first failure time, not this later observer tick, owns cleanup.
        if keyring_problem_stop(state, owner, problem) { self.bump(state); }
        // Record the real first failure clock BEFORE generic Unknown handling,
        // whose fallback timestamp must not accidentally renew cleanup.
        // The installed-session diagnostic vocabulary does not describe this
        // private keyring path; never invent a session/query association.
        if cleanup_unknown && !state.unknown { self.coordinator_failed(state, UnknownOrigin::NotRecorded, None); }
    }
    async fn drive_keyring_lookup(&self, owner: &Arc<OriginalWork>, input: crate::vault_keyring_linux::LookupInput)
        -> Result<(), crate::vault_keyring_linux::Problem> {
        use crate::vault_keyring_linux::{Next, Problem};
        self.enter_keyring_lookup(owner, input)?;
        loop {
            let next = std::future::poll_fn(|cx| {
                let turn = {
                    let mut state = self.lock(); self.expire(&mut state, Instant::now());
                    let mut book = match owner.keyring.lock() { Ok(book) => book, Err(_) => return Poll::Ready(Err(Problem::CleanupUnknown)) };
                    if owner.interrupted() { book.interrupt(); }
                    self.record_keyring_problem(&mut state, owner, book.problem().zip(book.problem_at()), book.document_cleanup_unknown());
                    keyring_constrain_cleanup(&state, owner, &mut book);
                    drop(state); // Never poll native work under the document mutex.
                    book.poll(cx)
                }; // Release book BEFORE acquiring document: never inverted locks.
                match turn {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(next @ (Next::Admit(_) | Next::AdmitShutdown | Next::Settled)) => Poll::Ready(Ok(next)),
                    Poll::Ready(Next::FirstPoll) => {
                        // FINAL admission after bounded stream work. The current
                        // exact slot/Unknown/effective cutoff is read under the
                        // original document -> book order. This is the local
                        // linearization point: later cancellation cannot revoke
                        // an already-consumed admission retroactively. It is not
                        // an instantaneous-stop/no-later-native-poll guarantee.
                        let mut state = self.lock(); self.expire(&mut state, Instant::now());
                        let mut book = match owner.keyring.lock() { Ok(book) => book, Err(_) => return Poll::Ready(Err(Problem::CleanupUnknown)) };
                        if owner.interrupted() { book.interrupt(); }
                        self.record_keyring_problem(&mut state, owner, book.problem().zip(book.problem_at()), book.document_cleanup_unknown());
                        keyring_constrain_cleanup(&state, owner, &mut book);
                        let current_gate = keyring_poll_gate(&state, owner, &book, Instant::now());
                        drop(state);
                        // No stream turn, await, lock or fallible setup here.
                        book.first_poll(cx, current_gate);
                        Poll::Pending
                    }
                    Poll::Ready(Next::FirstPollShutdown) => {
                        let mut state = self.lock(); self.expire(&mut state, Instant::now());
                        let mut book = match owner.keyring.lock() { Ok(book) => book, Err(_) => return Poll::Ready(Err(Problem::CleanupUnknown)) };
                        if owner.interrupted() { book.interrupt(); }
                        self.record_keyring_problem(&mut state, owner, book.problem().zip(book.problem_at()), book.document_cleanup_unknown());
                        keyring_constrain_cleanup(&state, owner, &mut book);
                        let admission = keyring_shutdown_gate(&state, owner, &book, Instant::now());
                        drop(state);
                        // The typed grant is consumed now: no await, new lock,
                        // stream work or successor setup can intervene.
                        book.first_poll_shutdown(cx, admission);
                        Poll::Pending
                    }
                }
            });
            tokio::pin!(next);
            let next = tokio::select! {
                next = &mut next => Some(next),
                _ = owner.wake.notified() => None,
                _ = tokio::time::sleep(Duration::from_millis(25)) => None,
            };
            self.report_keyring_problem(owner);
            match next {
                Some(Ok(Next::Admit(step))) => {
                    // The ignored headless fixture may defer only this fixed
                    // successor. Re-enter THIS driver to keep pumping its real
                    // owner stream/deadline; no alternate IO loop or grant.
                    #[cfg(all(test, debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if gnome_transport_fixture::hold_successor(owner, step).await { continue; }
                    // Prepare fallible RNG/DH outside the document lock, under
                    // this same already-charged original coordinator. The real
                    // document/slot gate still must admit and first-poll the RPC.
                    let prepared = if step == crate::vault_keyring_linux::Step::OpenSession {
                        match owner.keyring.lock() {
                            Ok(mut book) => { if owner.interrupted() { book.interrupt(); } book.prepare_exchange() }
                            Err(error) => { drop(error); let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return Err(Problem::CleanupUnknown); }
                        }
                    } else { Ok(()) };
                    if let Err(problem) = prepared.and_then(|()| self.admit_keyring_step(owner, step)) {
                        match owner.keyring.lock() {
                            Ok(mut book) => book.admission_refused(step, problem),
                            Err(error) => { drop(error); let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return Err(Problem::CleanupUnknown); }
                        }
                    }
                },
                Some(Ok(Next::AdmitShutdown)) => if let Err(problem) = self.admit_keyring_shutdown(owner) {
                    match owner.keyring.lock() {
                        Ok(mut book) => book.shutdown_admission_refused(problem),
                        Err(error) => { drop(error); let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return Err(Problem::CleanupUnknown); }
                    }
                },
                Some(Ok(Next::Settled)) => {
                    let book = owner.keyring.lock().map_err(|_| Problem::CleanupUnknown)?;
                    if !book.resources_settled() { return Err(Problem::CleanupUnknown); }
                    // This settles only this local child phase. The original
                    // coordinator join/stage and Unknown/LateKnown gates still
                    // decide retirement and any operation/result authority.
                    return book.problem().map_or(Ok(()), Err);
                },
                Some(Ok(Next::FirstPoll | Next::FirstPollShutdown)) => {
                    let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None);
                    return Err(Problem::CleanupUnknown);
                },
                Some(Err(problem)) => {
                    let mut state = self.lock(); self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None);
                    // Failed coordinator cannot continue polling. Its actual
                    // poisoned book/resources remain retained and unfinal.
                    return Err(problem);
                }
                None => self.tick(),
            }
            // Candidate/Absent or RemoveMatch alone cannot return/stage. All
            // retained originals continue until the SDK's real local finality.
        }
    }
}


#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod lookup_memory {
    use super::*;
    use crate::vault_keyring_linux::Problem;

    const WORKING_BYTES: usize = 96 * 1024 * 1024;
    const IDENTITIES: usize = 128;
    const ARC_CELLS: usize = 2 * std::mem::size_of::<usize>();

    const FIXED_CONTROL_BYTES: usize = crate::vault_keyring_linux::LOOKUP_CONTROL_BYTES
        + std::mem::size_of::<OriginalWork>() + std::mem::size_of::<GuiCall>() + std::mem::size_of::<Slot>()
        + std::mem::size_of::<Mutex<SourceBook>>() + 16 * std::mem::size_of::<usize>();
    // SDK futures <=32KiB and other SDK cells <=16KiB leave THIS app share
    // <=16KiB, not another control allowance on top of the fixed 64KiB row.
    const _: () = assert!(FIXED_CONTROL_BYTES <= 16 * 1024);

    // Constructible only by this document's locked census. It is not Clone,
    // configurable wire credit, a global allocator or a process-RSS promise.
    pub(crate) struct Admission { _private: () }
    impl Admission {
        fn checked(live: usize, scratch: usize) -> Result<Self, Problem> {
            let total = live.checked_add(scratch)
                .and_then(|bytes| bytes.checked_add(zbus::connection::OwnedConnectionAttempt::KEYRING_WIRE_BYTES))
                // Explicit additional crypto row, not spent wire headroom.
                // The total working/resident limits remain unchanged.
                .and_then(|bytes| bytes.checked_add(secret_service::checked_lookup::RETRIEVAL_CRYPTO_BYTES))
                .ok_or(Problem::Capacity)?;
            if total > WORKING_BYTES { return Err(Problem::Capacity); }
            Ok(Self { _private: () })
        }
        #[cfg(test)]
        pub(crate) fn data(live: usize, scratch: usize) -> Result<Self, Problem> { Self::checked(live, scratch) }
    }

    struct Seen { ids: [usize; IDENTITIES], used: usize }
    impl Seen {
        fn new() -> Self { Self { ids: [0; IDENTITIES], used: 0 } }
        fn insert<T>(&mut self, value: &Arc<T>) -> Result<bool, Problem> {
            let id = Arc::as_ptr(value) as usize;
            if self.ids[..self.used].contains(&id) { return Ok(false); }
            if self.used == self.ids.len() { return Err(Problem::Capacity); }
            self.ids[self.used] = id; self.used += 1; Ok(true)
        }
    }

    pub(super) fn retirement_empty(value: &Retirement) -> bool {
        value.old_slot.is_none() && value.candidate.is_none() && value.staged.is_none() && value.payload.is_none()
            && value.context.is_none() && value.slot_context.is_none() && value.assessment.is_none()
            && value.records.capacity() == 0 && value.assignments.capacity() == 0
    }
    fn retirement_known(owner: &OriginalWork, value: &Retirement) -> Result<(), Problem> {
        // Empty + no positive drain receipt is NOT zero live bytes. The actual
        // off-document drop now retains this same retirement mutex throughout.
        if owner.retired.load(Ordering::SeqCst) != retirement_empty(value) { return Err(Problem::CleanupUnknown); }
        Ok(())
    }
    fn child_joined(book: &ChildBook) -> bool {
        book.handle.is_none() && matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned)
    }

    struct Census<'a> {
        current: &'a Arc<OriginalWork>, current_source: &'a SourceBook, current_retirement: &'a Retirement,
        bytes: usize, payloads: Seen, materials: Seen, contexts: Seen, sources: Seen, owners: Seen,
    }
    impl<'a> Census<'a> {
        fn new(current: &'a Arc<OriginalWork>, source: &'a SourceBook, retirement: &'a Retirement) -> Self {
            Self { current, current_source: source, current_retirement: retirement, bytes: 0,
                payloads: Seen::new(), materials: Seen::new(), contexts: Seen::new(), sources: Seen::new(), owners: Seen::new() }
        }
        fn add(&mut self, bytes: usize) -> Result<(), Problem> {
            self.bytes = self.bytes.checked_add(bytes).ok_or(Problem::Capacity)?; Ok(())
        }
        fn cells<T>(&mut self, count: usize) -> Result<(), Problem> {
            self.add(count.checked_mul(std::mem::size_of::<T>()).ok_or(Problem::Capacity)?)
        }
        fn arc_cells<T>(&mut self) -> Result<(), Problem> { self.add(std::mem::size_of::<T>())?; self.add(ARC_CELLS) }
        fn token(&mut self, token: &Token) -> Result<(), Problem> { self.add(token.0.capacity()) }
        fn key(&mut self, key: &RecordKey) -> Result<(), Problem> { self.token(&key.id) }
        fn context(&mut self, context: &Arc<NativeContext>) -> Result<(), Problem> {
            if !self.contexts.insert(context)? { return Ok(()); }
            self.arc_cells::<NativeContext>()?;
            self.add(context.draft.capacity())?; self.add(context.project_id.capacity())?; self.add(context.project.path.capacity())
        }
        fn payload(&mut self, payload: &Arc<Payload>) -> Result<(), Problem> {
            if !self.payloads.insert(payload)? { return Ok(()); }
            // This unchanged per-payload metadata allowance includes the native
            // FileObservation projection: one exact-capacity 256-cell vector
            // plus <=64KiB exact-capacity strings, not a retained parser arena.
            self.add(RECORD_METADATA_BYTES)?;
            if let Some(fields) = &payload.fields { self.add(fields.retained_bytes().ok_or(Problem::Capacity)?)?; }
            if let Some(material) = &payload.material {
                if self.materials.insert(material)? {
                    self.arc_cells::<Material>()?; self.add(material.captured.bytes.capacity())?;
                    self.add(material.captured.origin.retained_bytes().ok_or(Problem::Capacity)?)?; self.add(ARC_CELLS)?;
                }
            }
            Ok(())
        }
        fn source(&mut self, source: &Arc<Mutex<SourceBook>>, book: &SourceBook) -> Result<(), Problem> {
            if !self.sources.insert(source)? { return Ok(()); }
            self.arc_cells::<Mutex<SourceBook>>()?; self.add(book.retained_bytes().ok_or(Problem::Capacity)?)
        }
        fn records(&mut self, records: &Vec<Record>) -> Result<(), Problem> {
            self.cells::<Record>(records.capacity())?;
            for record in records { self.key(&record.key)?; self.payload(&record.payload)?; } Ok(())
        }
        fn assignments(&mut self, values: &Vec<Assignment>) -> Result<(), Problem> {
            self.cells::<Assignment>(values.capacity())?;
            for value in values { self.token(&value.record_id)?; } Ok(())
        }
        fn candidate(&mut self, candidate: &Candidate) -> Result<(), Problem> {
            self.payload(&candidate.payload)?; self.token(&candidate.record_id)?;
            if let Some(key) = &candidate.existing { self.key(key)?; } Ok(())
        }
        fn tokens(&mut self, tokens: &TokenBatch) -> Result<(), Problem> {
            for token in [&tokens.selection, &tokens.record, &tokens.preview, &tokens.bind] { self.token(token)?; } Ok(())
        }
        fn command_error(&mut self) -> Result<(), Problem> {
            // CommandError is an Arc of a two-variant enum whose two payloads
            // contain static strings/scalars only; sum both alternatives plus
            // tag/alignment and Arc cells rather than inspect/private-clone it.
            self.add(std::mem::size_of::<AssetError>())?;
            self.add(std::mem::size_of::<crate::credential_assessment::AssessmentError>())?;
            self.add(2 * ARC_CELLS)
        }
        fn staged(&mut self, staged: &Staged) -> Result<(), Problem> {
            match staged {
                Staged::Selected { payload, tokens } => { self.payload(payload)?; self.tokens(tokens) },
                Staged::Prepared { result: Err(_), tokens } => { self.command_error()?; self.tokens(tokens) },
                Staged::Delete(tokens) => self.tokens(tokens),
                Staged::Committed { bind } => { if let Some(token) = bind { self.token(token)?; } Ok(()) },
                Staged::Bound(value) => self.token(&value.record_id),
                Staged::Refused(_) => Ok(()),
                // No invented census for opaque AssessmentResult vectors or
                // unrelated project/evidence/path DTOs in this closed slice.
                _ => Err(Problem::Unavailable),
            }
        }
        fn slot(&mut self, slot: &Slot) -> Result<(), Problem> {
            if slot.assessment.is_some() || slot.project.is_some() || slot.evidence.is_some()
                || slot.project_path.is_some() || slot.path_result.is_some() { return Err(Problem::Unavailable); }
            self.add(std::mem::size_of::<Slot>())?;
            if let Some(context) = &slot.context { self.context(context)?; }
            if let Some(key) = &slot.target { self.key(key)?; }
            if let Some(candidate) = &slot.candidate { self.candidate(candidate)?; }
            if let Some(token) = &slot.selection { self.token(token)?; }
            if let Some(preview) = &slot.preview {
                self.token(&preview.token)?;
                if let Some(token) = &preview.bind_token { self.token(token)?; }
                if let Some(key) = &preview.record { self.key(key)?; }
                if let Some(token) = &preview.subject.record_id { self.token(token)?; }
            }
            if let Some(staged) = &slot.staged { self.staged(staged)?; }
            if slot.error.is_some() { self.command_error()?; }
            if let Some(key) = &slot.result_record { self.key(key)?; }
            if let Some(payload) = &slot.retired_payload { self.payload(payload)?; }
            self.owner(&slot.owner)
        }
        fn retirement(&mut self, retirement: &Retirement) -> Result<(), Problem> {
            if retirement.assessment.is_some() { return Err(Problem::Unavailable); }
            if let Some(candidate) = &retirement.candidate { self.candidate(candidate)?; }
            if let Some(staged) = &retirement.staged { self.staged(staged)?; }
            if let Some(payload) = &retirement.payload { self.payload(payload)?; }
            if let Some(context) = &retirement.context { self.context(context)?; }
            if let Some(context) = &retirement.slot_context { self.context(context)?; }
            self.records(&retirement.records)?; self.assignments(&retirement.assignments)?;
            if let Some(slot) = &retirement.old_slot { self.slot(slot)?; } Ok(())
        }
        fn owner(&mut self, owner: &Arc<OriginalWork>) -> Result<(), Problem> {
            if !self.owners.insert(owner)? { return Ok(()); }
            self.arc_cells::<OriginalWork>()?; self.arc_cells::<GuiCall>()?;
            let gui = owner.gui.facts.try_lock().map_err(|_| Problem::CleanupUnknown)?;
            if !(gui.not_created || gui.destroyed && gui.released) { return Err(Problem::CleanupUnknown); }
            if let Some(path) = &gui.selected { self.add(path.capacity())?; }
            if Arc::ptr_eq(owner, self.current) {
                retirement_known(owner, self.current_retirement)?;
                self.source(&owner.source, self.current_source)?; self.retirement(self.current_retirement)
            } else {
                // A retained old/quit owner has no remaining original which may
                // allocate after this snapshot. Busy/failed/ambiguous is refusal.
                let coordinator = owner.coordinator.try_lock().map_err(|_| Problem::CleanupUnknown)?;
                let child = owner.child.try_lock().map_err(|_| Problem::CleanupUnknown)?;
                let source = owner.source.try_lock().map_err(|_| Problem::CleanupUnknown)?;
                let retirement = owner.retirement.try_lock().map_err(|_| Problem::CleanupUnknown)?;
                let keyring = owner.keyring.try_lock().map_err(|_| Problem::CleanupUnknown)?;
                if coordinator.receipt != JoinReceipt::Returned || coordinator.handle.is_some() || !child_joined(&child)
                    || !(source.not_started() || source.settled()) || !keyring.resources_settled() || !keyring.allocations_released()
                { return Err(Problem::CleanupUnknown); }
                retirement_known(owner, &retirement)?;
                self.source(&owner.source, &source)?; self.retirement(&retirement)
            }
        }
        fn document(&mut self, state: &DocumentState) -> Result<(), Problem> {
            if state.retiring { return Err(Problem::CleanupUnknown); }
            self.add(std::mem::size_of::<DocumentState>())?;
            self.records(&state.records)?; self.assignments(&state.assignments)?;
            if let Some(context) = &state.context { self.context(context)?; }
            if let Some(slot) = &state.slot { self.slot(slot)?; }
            if let Some(quit) = &state.quit { self.owner(quit)?; } Ok(())
        }
    }

    pub(super) fn live_bytes(state: &DocumentState, owner: &Arc<OriginalWork>, source: &SourceBook, retirement: &Retirement) -> Result<usize, Problem> {
        let mut census = Census::new(owner, source, retirement); census.document(state)?; Ok(census.bytes)
    }
    pub(super) fn enter(state: &DocumentState, owner: &Arc<OriginalWork>,
        input: crate::vault_keyring_linux::LookupInput, end: Instant) -> Result<(), Problem> {
        let coordinator = owner.coordinator.try_lock().map_err(|_| Problem::CleanupUnknown)?;
        let child = owner.child.try_lock().map_err(|_| Problem::CleanupUnknown)?;
        let source = owner.source.try_lock().map_err(|_| Problem::CleanupUnknown)?;
        let retirement = owner.retirement.try_lock().map_err(|_| Problem::CleanupUnknown)?;
        let mut book = owner.keyring.try_lock().map_err(|_| Problem::CleanupUnknown)?;
        if coordinator.receipt != JoinReceipt::Pending || coordinator.handle.is_none() || !child_joined(&child)
            || !(source.not_started() || source.settled()) || owner.large_work_started.load(Ordering::SeqCst)
            || !book.can_begin() { return Err(Problem::CleanupUnknown); }
        let live = live_bytes(state, owner, &source, &retirement)?;
        // Child/parser originals are positively joined; credential_format drops
        // arenas before ChildEnd. Non-Token child/R1/Value work has NEVER
        // started in this owner; no caller-local Captured result is omitted.
        // Thus no parser/request scratch is silently presumed inside 6MiB.
        let charge = Admission::checked(live, 0)?;
        let result = book.begin(input, end, charge);
        // These are the ACTUAL child/source/retirement dispatch locks; none is
        // released between the census and publishing the one nonduplicable charge.
        drop((book, retirement, source, child, coordinator)); result
    }

    #[cfg(test)]
    mod tests {
        // Fixed-census DATA only. Synthetic bookkeeping below is never a native
        // source/SDK/coordinator receipt, allocation measurement or provider test.
        use super::*;

        fn empty_payload() -> Arc<Payload> { Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None }) }
        fn material(capacity: usize) -> Arc<Material> {
            let observation = credential_format::inspect(credential_format::FileKind::AndroidKeystore, &[], &mut || false)
                .ok().expect("inert empty observation");
            Arc::new(Material { captured: asset_source::CapturedSource::memory_data(Vec::with_capacity(capacity)), observation })
        }
        fn data_context() -> Arc<NativeContext> {
            Arc::new(NativeContext { revision: 1, project_id: "data-project".into(),
                project: asset_source::RegisteredRoot { path: "/inert/project".into(), identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
                registry_generation: 1, draft: Vec::with_capacity(97), platform: Platform::Android, stage: Stage::Candidate, purpose: Purpose::Signing })
        }
        fn tokens() -> TokenBatch {
            TokenBatch { selection: Token(String::new()), record: Token(String::new()), preview: Token(String::new()), bind: Token(String::new()) }
        }
        fn live(state: &DocumentState, owner: &Arc<OriginalWork>) -> Result<usize, Problem> {
            let source = owner.source.lock().unwrap(); let retirement = owner.retirement.lock().unwrap();
            live_bytes(state, owner, &source, &retirement)
        }

        #[test]
        fn app_control_cells_fit_the_shared_sixteen_kib_row() {
            assert!(FIXED_CONTROL_BYTES <= 16 * 1024);
            assert_eq!(zbus::connection::OwnedConnectionAttempt::KEYRING_WIRE_BYTES, 1024 * 1024);
        }
        #[test]
        fn lookup_allowance_checks_boundary_overflow_and_capture_overlap() {
            let reserved = zbus::connection::OwnedConnectionAttempt::KEYRING_WIRE_BYTES
                + secret_service::checked_lookup::RETRIEVAL_CRYPTO_BYTES;
            assert_eq!(secret_service::checked_lookup::RETRIEVAL_CRYPTO_BYTES, 32 * 1024);
            assert!(Admission::checked(WORKING_BYTES - reserved, 0).is_ok());
            assert!(matches!(Admission::checked(WORKING_BYTES - reserved + 1, 0), Err(Problem::Capacity)));
            assert!(matches!(Admission::checked(usize::MAX, 1), Err(Problem::Capacity)));
            assert!(matches!(Admission::checked(1, usize::MAX), Err(Problem::Capacity)));
            assert!(matches!(Admission::checked(SESSION_BYTES, 32 * 1024 * 1024 + 1), Err(Problem::Capacity)));
            assert_eq!(SESSION_BYTES, 64 * 1024 * 1024); // The committed quota is independent and unchanged.
            let owner = OriginalWork::new(1, false, Weak::new()); let source = SourceBook::new(); let retirement = Retirement::default();
            let mut census = Census::new(&owner, &source, &retirement);
            assert_eq!(census.cells::<Record>(usize::MAX), Err(Problem::Capacity));
        }
        #[test]
        fn lookup_identity_census_is_fixed_and_duplicate_arcs_spend_no_slot() {
            let values: Vec<_> = (0..IDENTITIES + 1).map(Arc::new).collect();
            let mut seen = Seen::new();
            for value in &values[..IDENTITIES] { assert_eq!(seen.insert(value), Ok(true)); }
            assert_eq!(seen.insert(&values[0].clone()), Ok(false));
            assert_eq!(seen.insert(&values[IDENTITIES]), Err(Problem::Capacity));
            assert_eq!(seen.used, IDENTITIES);
        }
        #[test]
        fn lookup_payload_material_context_and_source_arcs_deduplicate_separately() {
            let owner = OriginalWork::new(1, false, Weak::new()); let source = SourceBook::new(); let retirement = Retirement::default();
            let mut census = Census::new(&owner, &source, &retirement);
            let captured = material(29);
            let first = Arc::new(Payload { kind: Kind::AndroidKeystore, material: Some(captured.clone()), fields: None });
            census.payload(&first).unwrap(); let once = census.bytes;
            census.payload(&first.clone()).unwrap(); assert_eq!(census.bytes, once);
            let second = Arc::new(Payload { kind: Kind::AndroidKeystore, material: Some(captured), fields: None });
            census.payload(&second).unwrap(); assert_eq!(census.bytes, once + RECORD_METADATA_BYTES);
            let distinct = material(29);
            let extra = RECORD_METADATA_BYTES + std::mem::size_of::<Material>() + ARC_CELLS
                + distinct.captured.bytes.capacity() + distinct.captured.origin.retained_bytes().unwrap() + ARC_CELLS;
            let third = Arc::new(Payload { kind: Kind::AndroidKeystore, material: Some(distinct), fields: None });
            let before = census.bytes; census.payload(&third).unwrap(); assert_eq!(census.bytes, before + extra);

            let context = data_context(); census.context(&context).unwrap(); let once = census.bytes;
            census.context(&context.clone()).unwrap(); assert_eq!(census.bytes, once);
            let extra = std::mem::size_of::<NativeContext>() + ARC_CELLS + context.draft.capacity()
                + context.project_id.capacity() + context.project.path.capacity();
            let other = data_context(); census.context(&other).unwrap(); assert_eq!(census.bytes, once + extra);

            let source = Arc::new(Mutex::new(SourceBook::unstarted_backing_data()));
            let book = source.lock().unwrap(); census.source(&source, &book).unwrap(); let once = census.bytes;
            census.source(&source.clone(), &book).unwrap(); assert_eq!(census.bytes, once);
            let other = Arc::new(Mutex::new(SourceBook::unstarted_backing_data()));
            let other_book = other.lock().unwrap(); let extra = std::mem::size_of::<Mutex<SourceBook>>() + ARC_CELLS + other_book.retained_bytes().unwrap();
            census.source(&other, &other_book).unwrap(); assert_eq!(census.bytes, once + extra);
        }
        #[test]
        fn lookup_census_counts_retained_old_slots_records_contexts_and_refused_source_backing() {
            let owner = OriginalWork::new(1, false, Weak::new()); let mut state = crate::asset_session::tests::empty_state();
            state.slot = Some(Slot::new(owner.clone(), Operation::Prepare, None, None, None));
            let baseline = live(&state, &owner).unwrap();
            let old = OriginalWork::new(2, false, Weak::new());
            old.coordinator.lock().unwrap().receipt = JoinReceipt::Returned; // Model only, no claimed original task.
            *old.source.lock().unwrap() = SourceBook::unstarted_backing_data();
            let retained_source = old.source.lock().unwrap().retained_bytes().unwrap();
            let shared = empty_payload(); let old_payload = empty_payload(); let retained_record = empty_payload(); let context = data_context();
            let mut old_slot = Slot::new(old, Operation::ChooseFile, Some(context.clone()), None, None);
            old_slot.candidate = Some(Candidate { payload: old_payload.clone(), record_id: Token(String::new()), existing: None });
            old_slot.staged = Some(Staged::Selected { payload: old_payload, tokens: tokens() });
            let retirement = Retirement { old_slot: Some(Box::new(old_slot)), payload: Some(shared.clone()), context: Some(context),
                records: vec![Record { key: RecordKey { id: Token(String::new()), revision: 1 }, payload: retained_record, mutation_pending: false }],
                ..Retirement::default() };
            assert!(owner.retain_retirement(retirement).is_ok());
            state.slot.as_mut().unwrap().candidate = Some(Candidate { payload: shared.clone(), record_id: Token(String::new()), existing: None });
            state.slot.as_mut().unwrap().retired_payload = Some(shared);
            let total = live(&state, &owner).unwrap();
            assert!(total >= baseline + 3 * RECORD_METADATA_BYTES + retained_source + 97);
            state.retiring = true; assert_eq!(live(&state, &owner), Err(Problem::CleanupUnknown)); state.retiring = false;
            assert!(owner.release_retirement()); // DATA-only drop, no original resource to settle.
            state.slot.as_mut().unwrap().candidate = None; state.slot.as_mut().unwrap().retired_payload = None;
            assert_eq!(live(&state, &owner), Ok(baseline));
            owner.retired.store(false, Ordering::SeqCst);
            assert_eq!(live(&state, &owner), Err(Problem::CleanupUnknown)); // Empty in-flight holding is not zero.
        }
        #[test]
        fn lookup_census_refuses_unsupported_retained_dto_shapes() {
            let owner = OriginalWork::new(1, false, Weak::new()); let mut state = crate::asset_session::tests::empty_state();
            let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None);
            slot.evidence = Some(EvidenceBinding { operation_id: 1, kind: evidence_wire::OperationKind::Observe, selection_id: None, epoch: 1 });
            state.slot = Some(slot);
            assert_eq!(live(&state, &owner), Err(Problem::Unavailable));
            state.slot.as_mut().unwrap().evidence = None;
            assert!(live(&state, &owner).is_ok());
        }
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use lookup_memory::Admission as KeyringMemoryAdmission;

fn lookup_allocation_gate(state: &DocumentState) -> Result<(), AssetError> {
    // All large/copy admissions share the current document mutex. STOP, status,
    // lock/loss and reconciliation intentionally do not call this predicate.
    if state.slot.as_ref().is_some_and(|slot| !slot.owner.lookup_allocations_allowed()) {
        return Err(AssetError::new(Reason::Busy));
    }
    Ok(())
}
fn passive_document_gate(state: &DocumentState) -> Result<(), BridgeError> {
    // Existing passive services do not require editing/crash-hook qualification.
    // The caller still holds this same document mutex through Supervisor claim.
    if state.unknown || state.exhausted { return Err(BridgeError::cleanup_unknown()); }
    if state.stopping { return Err(BridgeError::shutdown()); }
    if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending || project_path_pending(state) {
        return Err(BridgeError::new("busy", "Finish the original native operation first."));
    }
    Ok(())
}
fn common_document_gate(state: &DocumentState, session: bool, owner_gate: impl FnOnce() -> Result<(), AssetError>) -> Result<(), AssetError> {
    // Shared native lifecycle/state checks only. The caller retains the real
    // document mutex; each route must still apply its own qualification gate.
    if !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
    if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
    if state.stopping { return Err(AssetError::new(Reason::Shutdown)); }
    owner_gate()?;
    if state.compatibility_picker_pending { return Err(AssetError::new(Reason::Busy)); }
    if session && state.slot.as_ref().is_some_and(|slot| (slot.operation.evidence() || slot.operation.project_path())
        && (slot.phase != Phase::Idle || !slot.owner.resources_settled())) { return Err(AssetError::new(Reason::Busy)); }
    if state.quit_pending || state.retiring || state.lock_pending { return Err(AssetError::new(Reason::Busy)); }
    lookup_allocation_gate(state)
}
fn session_owner_reason(supervisor_disabled: bool, edit_disabled: bool, supervisor_stopping: bool, edit_stopping: bool) -> Option<Reason> {
    if supervisor_disabled || edit_disabled { Some(Reason::CleanupUnknown) }
    else if supervisor_stopping || edit_stopping { Some(Reason::Shutdown) } else { None }
}
fn observe_session_owner_reason(state: &mut DocumentState, reason: Option<Reason>) -> bool {
    if state.session_owner_reason == reason { return false; }
    state.session_owner_reason = reason; true
}
fn ordinary_asset_platform_gate() -> Result<(), AssetError> {
    // Private asset custody is separate from the installed project-only
    // profile. Sharing document checks must not qualify either native route.
    if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { return Err(AssetError::new(Reason::UnsupportedPlatform)); }
    Ok(())
}
fn preflight_document_gate(state: &DocumentState, profile: Option<crate::offline_preflight_protocol::Profile>)
    -> Option<crate::offline_preflight_protocol::Availability> {
    use crate::offline_preflight_protocol::Availability;
    // A missing platform backend is not a lost qualified original. Before the
    // first Finished event, no run/intent exists and binding is merely pending.
    if profile.is_none() { Some(Availability::UnsupportedPlatform) }
    else if state.lost_observed { Some(Availability::DocumentLost) }
    else if !state.lifetime.original_bound() { Some(Availability::Busy) }
    else { None }
}
fn android_build_document_gate(state: &DocumentState, profile: Option<crate::android_build_protocol::Profile>)
    -> Option<crate::android_build_protocol::Availability> {
    use crate::android_build_protocol::Availability;
    // Unsupported/no-original is not cleanup failure. Initial Finished is
    // still pending; an absent Android owner must not poison passive services.
    if profile.is_none() { Some(Availability::UnsupportedPlatform) }
    else if state.lost_observed { Some(Availability::DocumentLost) }
    else if !state.lifetime.original_bound() { Some(Availability::Busy) }
    else { None }
}

impl DocumentBinding {
    pub(crate) fn new(bridge: Arc<DesktopBridge>) -> Self {
        let (changes, _) = watch::channel(0);
        let document = Self { inner: Arc::new(Inner { bridge, changes, session_identity: Arc::new(()),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            installed_session: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            fixture: None,
            #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            github_fixture: None,
            state: Mutex::new(DocumentState { lifetime: DocumentLifetime::default(), revision: 0,
            next_operation: 0, next_context: 0, exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            compatibility_picker_pending: false, session_owner_reason: None,
            context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None, quit_accepted: false, quit_cleanup_end: None,
            github: ConnectionState::new(), evidence: EvidenceRegistry::new(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            first_origin: None }) }) };
        // One memory-only binding to the Supervisor created in the ordinary
        // DesktopBridge constructor. A later document cannot rebind its lease.
        document.inner.bridge.supervisor.bind_original_session_document(&document.inner.session_identity);
        document
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn for_fixture(bridge: Arc<DesktopBridge>, permit: FixtureAdmission) -> Result<Self, &'static str> {
        let mut document = Self::new(bridge);
        let context = permit.consume()?;
        Arc::get_mut(&mut document.inner).ok_or("sg1_new_document_not_exclusive")?.fixture = Some(Arc::downgrade(&context));
        context.bind_original(document.clone())?;
        Ok(document)
    }
    /// One consumed G1 permission for this new document and its original
    /// Supervisor only. No asset/workflow/GUI qualification is conferred.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn for_github_fixture(bridge: Arc<DesktopBridge>, permit: crate::supervisor::GitHubDocumentFixturePermit) -> Result<Self, &'static str> {
        let binding = permit.consume(&bridge.supervisor)?;
        let mut document = Self::new(bridge);
        Arc::get_mut(&mut document.inner).ok_or("g1_new_document_not_exclusive")?.github_fixture = Some(binding);
        Ok(document)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn github_fixture_permitted(&self) -> bool {
        self.inner.github_fixture.as_ref().is_some_and(|binding| binding.permits(&self.inner.bridge.supervisor))
    }
    fn github_qualified(&self) -> bool {
        if github_session::qualified() { return true; }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if self.github_fixture_permitted() { return true; }
        false
    }
    fn native_qualified(&self) -> bool {
        if NATIVE_QUALIFIED { return true; }
        if self.inner.bridge.installed_session_available(&self.inner.session_identity) { return true; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(context) = self.inner.fixture.as_ref().and_then(Weak::upgrade) { return context.permits(self); }
        false
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
        target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn admit_installed_session(&self, permit: crate::shell::installed_observation::SessionAdmission) -> Result<(), BridgeError> {
        // Setup only, before original navigation/IPC. The ordinary constructor
        // has already bound this exact identity to its one Supervisor.
        let state = self.lock();
        if state.next_operation != 0 || state.next_context != 0 || state.session || state.slot.is_some()
            || state.context.is_some() || state.quit.is_some() || state.lost_observed || state.stopping || state.unknown
            || self.live_session_owner_reason().is_some() { return Err(BridgeError::invalid()); }
        let case = permit.consume()?;
        self.inner.bridge.supervisor.admit_installed_session_once(&self.inner.session_identity)?;
        let mut observation = self.inner.installed_session.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if observation.is_some() { return Err(BridgeError::invalid()); }
        *observation = Some(installed_session_observation::Book::new(case)); Ok(())
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn admit_installed_commands(&self, tools: crate::shell::installed_observation::commands::ToolsAdmission,
        offline: crate::shell::installed_observation::commands::OfflineAdmission) -> Result<(), BridgeError> {
        let state = self.lock();
        if state.next_operation != 0 || state.next_context != 0 || state.session || state.slot.is_some() || state.context.is_some()
            || state.quit.is_some() || state.lost_observed || state.stopping || state.unknown || self.live_session_owner_reason().is_some() {
            return Err(BridgeError::invalid());
        }
        self.inner.bridge.diagnostics.admit_installed_observation(tools)?;
        self.inner.bridge.preflight.admit_installed_observation(offline)
    }
    fn project_selection_qualified(&self) -> bool {
        if self.inner.bridge.installed_project_selection_available() { return true; }
        // Preserve SG1's existing, separately consumed development permission.
        // It is not installed-profile authority and does not select that core.
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(context) = self.inner.fixture.as_ref().and_then(Weak::upgrade) { return context.permits(self); }
        false
    }
    pub(crate) fn project_selection_available(&self) -> bool {
        // Profile/display DATA, never live lifecycle permission. Windows uses
        // the same retained original project route as its profile admission;
        // a compatibility pathname result cannot enable native registration.
        self.project_selection_qualified() || cfg!(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos", target_os = "windows"))))
    }
    pub(crate) fn project_path_selection_available(&self) -> bool {
        // Exact installed-profile DATA only. Neither the compatibility picker
        // nor SG1 nor the still-false asset capability qualifies this purpose.
        self.inner.bridge.installed_project_path_selection_available()
    }
    fn evidence_qualified(&self) -> bool {
        // Existing fixture permits do NOT authorize the new picker/query route.
        installed_evidence_profile(self.inner.bridge.installed_evidence_selection_available(),
            self.inner.bridge.supervisor.passive_method_available("artifacts.candidate.observe"))
    }
    fn lock(&self) -> MutexGuard<'_, DocumentState> {
        match self.inner.state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                // A poisoned gate cannot emit differing DTOs at one ordinary
                // revision. Freeze the same final redacted authority while
                // retaining all originals for conservative settlement/exit.
                if !state.exhausted { self.exhaust(&mut state, UnknownOrigin::GatePoisoned); }
                state
            }
        }
    }
    fn bump(&self, state: &mut DocumentState) {
        if state.exhausted { return; }
        if state.unknown { state.github.unknown(); state.evidence.revoke(true); }
        let Some(revision) = state.evidence.revision.checked_add(1) else { self.exhaust(state, UnknownOrigin::Exhausted); return; };
        state.evidence.revision = revision;
        match status_successor(state.revision) {
            Some(next) => { state.revision = next; self.inner.changes.send_replace(next); }
            None => self.exhaust(state, UnknownOrigin::Exhausted),
        }
    }
    fn exhaust(&self, state: &mut DocumentState, _origin: UnknownOrigin) {
        first_unknown_origin!(state, _origin, None);
        state.exhausted = true; state.unknown = true; state.stopping = true; state.lost_observed = true;
        state.github.exhaust();
        state.evidence.revision = u64::MAX; state.evidence.revoke(true);
        state.lifetime.invalidate(); invalidate_all(state);
        if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::CleanupUnknown, Instant::now()); slot.phase = Phase::Unknown; }
        stop_quit(state, Instant::now());
        self.inner.bridge.edits.document_lost(MAIN);
        self.inner.bridge.diagnostics.document_lost();
        self.inner.bridge.preflight.document_lost();
        self.inner.bridge.android_build.document_lost();
        state.revision = u32::MAX; self.inner.changes.send_replace(u32::MAX);
    }
    fn next_operation(&self, state: &mut DocumentState) -> Result<u32, AssetError> {
        let Some(next) = state.next_operation.checked_add(1) else { self.exhaust(state, UnknownOrigin::Exhausted); return Err(AssetError::new(Reason::CleanupUnknown)); };
        state.next_operation = next; Ok(next)
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    fn loss_locked(&self, state: &mut DocumentState) {
        state.lost_observed = true;
        state.evidence.revoke(false);
        state.github.retire(GitHubReason::Cancelled);
        invalidate_all(state);
        if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::DocumentLost, Instant::now()); }
        stop_quit(state, Instant::now());
        // This actual loss path is synchronous under the same admission lock.
        // EditOwner's first-loss tombstone was preallocated, with no loss RNG.
        self.inner.bridge.edits.document_lost(MAIN);
        self.inner.bridge.diagnostics.document_lost(); self.inner.bridge.preflight.document_lost();
        self.inner.bridge.android_build.document_lost(); self.bump(state);
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
    fn environment_gate(&self, state: &DocumentState) -> crate::environment_diagnostics_protocol::Availability {
        use crate::environment_diagnostics_protocol::Availability;
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled()
            || self.inner.bridge.preflight.disabled() || self.inner.bridge.android_build.disabled() { return Availability::CleanupUnknown; }
        if state.stopping || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping()
            || self.inner.bridge.preflight.stopping() || self.inner.bridge.android_build.stopping() { return Availability::Shutdown; }
        if !state.lifetime.original_bound() || state.lost_observed { return Availability::DocumentLost; }
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending
            || state.slot.as_ref().is_some_and(|slot| !slot.owner.resources_settled())
            || state.github.native_work_pending() || !self.inner.bridge.edits.can_exit()
            || !self.inner.bridge.supervisor.can_exit() || self.inner.bridge.preflight.busy()
            || self.inner.bridge.android_build.busy() { return Availability::Busy; }
        Availability::Available
    }
    pub(crate) fn environment_diagnostics_status(&self) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
        // DATA only: inspect existing state/registry generation and already-ended
        // original task joins. Never poll a tool or start a replacement owner.
        let state = self.lock();
        if !self.inner.bridge.diagnostics.registration_matches(self.inner.bridge.registry_generation()) { self.inner.bridge.diagnostics.context_changed(); }
        self.inner.bridge.diagnostics.status(self.environment_gate(&state))
    }
    pub(crate) fn environment_diagnostics_subscribe(&self) -> watch::Receiver<u32> { self.inner.bridge.diagnostics.subscribe() }
    fn preflight_gate(&self, state: &DocumentState) -> crate::offline_preflight_protocol::Availability {
        use crate::offline_preflight_protocol::Availability;
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled()
            || self.inner.bridge.edits.disabled() || self.inner.bridge.diagnostics.disabled()
            || self.inner.bridge.android_build.disabled() { return Availability::CleanupUnknown; }
        if state.stopping || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping()
            || self.inner.bridge.diagnostics.stopping() || self.inner.bridge.android_build.stopping() { return Availability::Shutdown; }
        if let Some(reason) = preflight_document_gate(state, crate::offline_preflight_protocol::Profile::current()) { return reason; }
        // Saved checks require Disconnect, not merely an idle GitHub ticket.
        // Observe the actual retained private session, never a public tombstone.
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending
            || state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
            || state.github.registration().is_some() || !self.inner.bridge.edits.can_exit() || self.inner.bridge.edits.preflight_attention()
            || !self.inner.bridge.supervisor.can_exit() || self.inner.bridge.diagnostics.busy()
            || self.inner.bridge.android_build.busy() { return Availability::Busy; }
        Availability::Available
    }
    pub(crate) fn offline_preflight_subscribe(&self) -> watch::Receiver<u32> { self.inner.bridge.preflight.subscribe() }
    pub(crate) fn offline_preflight_relay_lost(&self) {
        // A lost status channel retires consent/sends original STOP; it never
        // deletes the owner, reopens a slot or asserts native finality.
        let _state = self.lock(); self.inner.bridge.preflight.document_lost();
    }
    pub(crate) fn offline_preflight_status(&self) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
        let state = self.lock();
        if !self.inner.bridge.preflight.registration_matches(self.inner.bridge.registry_generation()) { self.inner.bridge.preflight.context_changed(); }
        self.inner.bridge.preflight.status(self.preflight_gate(&state))
    }
    pub(crate) fn prepare_offline_preflight(&self, args: crate::offline_preflight_protocol::Prepare) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
        let mut state = self.lock();
        let gate = self.preflight_gate(&state);
        // All fixed errors here precede intent allocation. No project is opened.
        if gate != crate::offline_preflight_protocol::Availability::Available {
            return Err(if gate == crate::offline_preflight_protocol::Availability::Busy {
                BridgeError::new("offline_preflight_busy", "Finish or cancel the original operation before reviewing saved offline checks.")
            } else { crate::offline_preflight_owner::unavailable() });
        }
        let selected = self.registry_result(&mut state, self.inner.bridge.native_project(&args.project_id), None);
        let (generation, root) = selected.map_err(|_| crate::offline_preflight_owner::unavailable())?;
        self.inner.bridge.preflight.prepare(args, generation, root, gate)
    }
    pub(crate) fn start_offline_preflight(&self, args: crate::offline_preflight_protocol::Start) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
        let admitted_at = Instant::now(); // Native T before lock/lookup/executor/runtime/enqueue/await.
        let mut state = self.lock();
        let project = self.inner.bridge.preflight.prepared_project(&args.operation_id, &args.owner_generation)?;
        let selected = self.registry_result(&mut state, self.inner.bridge.native_project(&project), None).ok();
        let admitted = self.inner.bridge.preflight.start(args, admitted_at, selected, self.preflight_gate(&state))?;
        // Real document/context/quit decisions cannot interleave registration,
        // one-use consent consumption, original roster claim and release.
        drop(state); Ok(admitted.release())
    }
    pub(crate) fn cancel_offline_preflight(&self, args: crate::offline_preflight_protocol::Cancel) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
        let state = self.lock();
        self.inner.bridge.preflight.cancel(&args.operation_id, &args.owner_generation, self.preflight_gate(&state))
    }
    fn android_build_gate(&self, state: &DocumentState) -> crate::android_build_protocol::Availability {
        use crate::android_build_protocol::Availability;
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled()
            || self.inner.bridge.edits.disabled() || self.inner.bridge.diagnostics.disabled()
            || self.inner.bridge.preflight.disabled() { return Availability::CleanupUnknown; }
        if state.stopping || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping()
            || self.inner.bridge.diagnostics.stopping() || self.inner.bridge.preflight.stopping() { return Availability::Shutdown; }
        if let Some(reason) = android_build_document_gate(state, crate::android_build_protocol::Profile::current()) { return reason; }
        // Require actual Disconnect, not an idle/retired public GitHub ticket.
        // Asset phase AND original resources must settle, as must all edits,
        // recovery attention, passive queries and the other saved-command owner.
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending
            || state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
            || state.github.registration().is_some() || !self.inner.bridge.edits.can_exit() || self.inner.bridge.edits.preflight_attention()
            || !self.inner.bridge.supervisor.can_exit() || self.inner.bridge.diagnostics.busy()
            || self.inner.bridge.preflight.busy() { return Availability::Busy; }
        Availability::Available
    }
    pub(crate) fn android_build_subscribe(&self) -> watch::Receiver<u32> { self.inner.bridge.android_build.subscribe() }
    pub(crate) fn android_build_relay_lost(&self) {
        // Loss retires consent/STOP under the same gate. It is not settlement,
        // owner deletion, a replacement run or permission to reopen the slot.
        let _state = self.lock(); self.inner.bridge.android_build.document_lost();
    }
    pub(crate) fn android_build_status(&self) -> Result<crate::android_build_protocol::Status, BridgeError> {
        let state = self.lock();
        if !self.inner.bridge.android_build.registration_matches(self.inner.bridge.registry_generation()) { self.inner.bridge.android_build.context_changed(); }
        self.inner.bridge.android_build.status(self.android_build_gate(&state))
    }
    pub(crate) fn prepare_android_build(&self, args: crate::android_build_protocol::Prepare) -> Result<crate::android_build_protocol::Status, BridgeError> {
        let mut state = self.lock();
        let gate = self.android_build_gate(&state);
        if gate != crate::android_build_protocol::Availability::Available {
            return Err(if gate == crate::android_build_protocol::Availability::Busy {
                BridgeError::new("android_build_busy", "Finish or cancel the original operation before reviewing a saved Android build.")
            } else { crate::android_build_owner::unavailable() });
        }
        // Only the existing native root identity/generation, never a renderer
        // path or a diagnostics/offline fixture permit, reaches this owner.
        let selected = self.registry_result(&mut state, self.inner.bridge.native_project(&args.project_id), None);
        let (generation, root) = selected.map_err(|_| crate::android_build_owner::unavailable())?;
        self.inner.bridge.android_build.prepare(args, generation, root, gate)
    }
    pub(crate) fn start_android_build(&self, args: crate::android_build_protocol::Start) -> Result<crate::android_build_protocol::Status, BridgeError> {
        let admitted_at = Instant::now(); // Original T before the document lock, lookup, executor or await.
        let mut state = self.lock();
        let project = self.inner.bridge.android_build.prepared_project(&args.operation_id, &args.owner_generation)?;
        let selected = self.registry_result(&mut state, self.inner.bridge.native_project(&project), None).ok();
        let admitted = self.inner.bridge.android_build.start(args, admitted_at, selected, self.android_build_gate(&state))?;
        // Gate/root/generation, one-use consent and the original roster claim
        // share this document mutex. GO is released only after unlocking it.
        drop(state); Ok(admitted.release())
    }
    pub(crate) fn cancel_android_build(&self, args: crate::android_build_protocol::Cancel) -> Result<crate::android_build_protocol::Status, BridgeError> {
        let state = self.lock();
        // Exact original cancellation remains callable after loss/shutdown or
        // retained Unknown. The availability gate never hides status or STOP.
        self.inner.bridge.android_build.cancel(&args.operation_id, &args.owner_generation, self.android_build_gate(&state))
    }
    /// The existing passive Supervisor claim is synchronous under this SAME
    /// real mutex; a gate check before awaiting query() would leave a race.
    /// This is not an offline-preflight runner or a new query resource owner.
    pub(crate) fn passive_query(&self, bridge: &DesktopBridge, method: crate::protocol::Method, params: serde_json::Value) -> Result<crate::supervisor::PassiveQuery, BridgeError> {
        let state = self.lock();
        if !std::ptr::eq(bridge, self.inner.bridge.as_ref()) { return Err(BridgeError::invalid()); }
        passive_document_gate(&state)?;
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        self.inner.bridge.supervisor.start_passive(method, params)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn environment_fixture_registration(&self,
        permit: &crate::environment_diagnostics_owner::EnvironmentRegistrationPermit, change: bool) -> Result<(), BridgeError> {
        let state = self.lock();
        if state.unknown || state.exhausted || !state.lifetime.original_bound() || state.lost_observed || state.stopping { return Err(BridgeError::cleanup_unknown()); }
        self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.environment_fixture_registration(permit, change)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn offline_fixture_registration(&self,
        permit: &crate::offline_preflight_owner::OfflineRegistrationPermit) -> Result<(), BridgeError> {
        let state = self.lock();
        if self.preflight_gate(&state) != crate::offline_preflight_protocol::Availability::Available {
            return Err(crate::offline_preflight_owner::unavailable());
        }
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.offline_fixture_registration(permit)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn offline_fixture_gate(&self, permit: &crate::offline_preflight_owner::OfflineRegistrationPermit,
        gate: &str, present: bool) -> Result<(), BridgeError> {
        let (id, _, generation) = permit.validate(&self.inner.bridge.preflight)?;
        if !permit.gate_evidence() { return Err(crate::offline_preflight_owner::unavailable()); }
        let mut state = self.lock();
        if state.unknown || state.exhausted || !state.lifetime.original_bound() || state.stopping {
            return Err(crate::offline_preflight_owner::unavailable());
        }
        match (gate, present) {
            ("retained-private", true) if state.github.registration().is_none() => {
                state.github = github_session::offline_fixture_private(permit, &self.inner.bridge.preflight)?;
            },
            ("retained-private", false) if state.github.registration() == Some((id, generation))
                && !state.github.native_work_pending() => {
                // The real disconnect DATA path, not token retirement alone.
                state.github.disconnect("github-session-1", Instant::now(), GitHubReason::None)?;
                if state.github.registration().is_some() { return Err(crate::offline_preflight_owner::unavailable()); }
            },
            ("existing-work", true) if state.slot.is_none() => {
                // Inert retained work: no coordinator/child/GUI is scheduled.
                // Phase and unreturned OriginalWork are the actual gate inputs;
                // removal below is not claimed as native physical settlement.
                state.slot = Some(Slot { owner: OriginalWork::new(u32::MAX - 1, false, Arc::downgrade(&self.inner)),
                    operation: Operation::ChooseFile, phase: Phase::Admitting, reason: Reason::None,
                    source: SourceState::NotRun, settlement: Settlement::Pending, context: None, target: None,
                    review_end: None, cleanup_end: None, candidate: None, selection: None, assessment: None,
                    preview: None, assessment_context_revision: None, staged: None, error: None, project: None,
                    discard: false, kind: None, result_record: None, retired_payload: None, evidence: None, project_path: None, path_result: None });
            },
            ("existing-work", false) if state.slot.as_ref().is_some_and(|slot|
                slot.owner.id == u32::MAX - 1 && slot.phase == Phase::Admitting) => {
                let slot = state.slot.as_ref().ok_or_else(crate::offline_preflight_owner::unavailable)?;
                if slot.owner.coordinator.lock().map_err(|_| BridgeError::cleanup_unknown())?.handle.is_some()
                    || slot.owner.child.try_lock().map_err(|_| BridgeError::cleanup_unknown())?.handle.is_some() {
                    return Err(BridgeError::cleanup_unknown());
                }
                state.slot.take();
            },
            ("recovery-attention", _) => {
                self.inner.bridge.edits.offline_fixture_attention(permit, &self.inner.bridge.preflight, present)?;
            },
            _ => return Err(crate::offline_preflight_owner::unavailable()),
        }
        self.bump(&mut state); Ok(())
    }
    pub(crate) fn start_environment_diagnostics(&self, args: crate::environment_diagnostics_protocol::Start) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
        let ticket = self.inner.bridge.diagnostics.ticket()?; // Original T, entropy/executor before lock/effects.
        let state = self.lock();
        use crate::environment_diagnostics_protocol::Availability;
        match self.environment_gate(&state) {
            Availability::Available => {}, Availability::Busy => return Err(BridgeError::new("environment_diagnostics_busy", "Finish or cancel the original native operation before checking build tools.")),
            Availability::CleanupUnknown => return Err(BridgeError::cleanup_unknown()), Availability::Shutdown => return Err(BridgeError::shutdown()),
            _ => return Err(BridgeError::new("environment_diagnostics_owner", "This request does not identify the original build-tool diagnostics run.")),
        }
        let (generation, root) = self.inner.bridge.environment_registration(&args.project_id)?;
        let admitted = self.inner.bridge.diagnostics.admit(ticket, args, generation, root)?;
        // Real document loss, selection, assets, edits, GitHub and quit cannot
        // interleave lookup/claim/enqueue. All original handles exist before GO.
        drop(state); Ok(admitted.release())
    }
    pub(crate) fn cancel_environment_diagnostics(&self, args: crate::environment_diagnostics_protocol::Cancel) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
        let state = self.lock();
        // Exact original STOP stays usable during shutdown, document loss,
        // deadline or retained Unknown; it never grants start authority.
        self.inner.bridge.diagnostics.cancel(&args.run_id, &args.owner_generation, self.environment_gate(&state))
    }
    /// Configuration operations retire saved-command consent/STOP under the
    /// same document mutex, then wait for original settlement before writing.
    /// Their existing root/owner semantics and diagnostics exclusion remain.
    pub(crate) fn configuration_edit_admit<T>(&self, action: impl FnOnce(&DesktopBridge) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        let state = self.lock();
        if state.unknown || state.exhausted { return Err(BridgeError::cleanup_unknown()); }
        if !state.lifetime.original_bound() || state.lost_observed { return Err(BridgeError::new("invalid_edit_owner", "This document does not own that live edit domain.")); }
        if state.stopping { return Err(BridgeError::shutdown()); }
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending { return Err(BridgeError::new("busy", "Finish the original native operation first.")); }
        if state.slot.as_ref().is_some_and(|slot| slot.operation.evidence()
            && (slot.phase != Phase::Idle || !slot.owner.resources_settled())) { return Err(evidence_wire::refused(EvidenceProblem::Busy)); }
        if project_path_pending(&state) { return Err(BridgeError::new("busy", "Finish the original project-path selection first.")); }
        self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        action(&self.inner.bridge)
    }
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos", target_os = "windows"))))]
    pub(crate) fn compatibility_picker_begin(&self) -> Result<(), BridgeError> {
        let mut state = self.lock();
        self.inner.bridge.diagnostics.context_changed();
        self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        if state.stopping { return Err(BridgeError::shutdown()); }
        if state.compatibility_picker_pending { return Err(BridgeError::new("busy", "A native project picker is already open.")); }
        state.compatibility_picker_pending = true; self.bump(&mut state); Ok(())
    }
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos", target_os = "windows"))))]
    pub(crate) fn compatibility_picker_end(&self) {
        // This preserves the existing compatibility picker reservation; it is
        // NOT evidence for a qualified macOS/Windows document/GUI owner.
        // Android admission also sees this reservation until publication/end;
        // begin already retired any old consent under this same mutex.
        let mut state = self.lock(); state.compatibility_picker_pending = false; self.bump(&mut state);
    }
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos", target_os = "windows"))))]
    pub(crate) fn compatibility_picker_publish(&self, path: std::path::PathBuf) -> Result<Project, BridgeError> {
        let state = self.lock();
        if !state.compatibility_picker_pending { return Err(BridgeError::invalid()); }
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        self.inner.bridge.register_picked_project(path)
    }
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "windows"))))]
    pub(crate) fn compatibility_quit_begin(&self) -> bool {
        let mut state = self.lock();
        if state.compatibility_picker_pending || state.quit_pending { return false; }
        state.quit_pending = true; self.bump(&mut state); true
    }
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "windows"))))]
    pub(crate) fn compatibility_quit_result(&self, accepted: bool) {
        let mut state = self.lock(); state.quit_pending = false;
        if accepted {
            state.stopping = true; self.inner.bridge.diagnostics.request_shutdown();
            self.inner.bridge.preflight.request_shutdown(); self.inner.bridge.android_build.request_shutdown();
        }
        self.bump(&mut state);
    }
    fn common_gate(&self, state: &DocumentState, session: bool) -> Result<(), AssetError> {
        common_document_gate(state, session, || {
            if self.inner.bridge.diagnostics.disabled() { return Err(AssetError::new(Reason::CleanupUnknown)); }
            if self.inner.bridge.preflight.disabled() { return Err(AssetError::new(Reason::CleanupUnknown)); }
            if self.inner.bridge.android_build.disabled() { return Err(AssetError::new(Reason::CleanupUnknown)); }
            if self.inner.bridge.diagnostics.stopping() { return Err(AssetError::new(Reason::Shutdown)); }
            if self.inner.bridge.preflight.stopping() { return Err(AssetError::new(Reason::Shutdown)); }
            if self.inner.bridge.android_build.stopping() { return Err(AssetError::new(Reason::Shutdown)); }
            if self.inner.bridge.diagnostics.busy() || self.inner.bridge.preflight.busy() || self.inner.bridge.android_build.busy() {
                return Err(AssetError::new(Reason::Busy));
            }
            Ok(())
        })
    }
    fn gate(&self, state: &DocumentState, session: bool) -> Result<(), AssetError> {
        self.common_gate(state, session)?;
        if let Some(reason) = self.live_session_owner_reason() { return Err(AssetError::new(reason)); }
        ordinary_asset_platform_gate()?;
        if !self.native_qualified() { return Err(AssetError::new(Reason::Unqualified)); }
        if session && !state.session { return Err(AssetError::new(Reason::Closed)); } Ok(())
    }
    fn live_session_owner_reason(&self) -> Option<Reason> {
        session_owner_reason(self.inner.bridge.supervisor.disabled(), self.inner.bridge.edits.disabled(),
            self.inner.bridge.supervisor.stopping(), self.inner.bridge.edits.stopping())
    }
    fn project_path_gate(&self, state: &DocumentState) -> Result<(), AssetError> {
        self.common_gate(state, false)?;
        project_path_idle_gate(state, self.project_path_selection_available())?;
        if self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled() { return Err(AssetError::new(Reason::CleanupUnknown)); }
        if self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping() { return Err(AssetError::new(Reason::Shutdown)); }
        if !self.inner.bridge.supervisor.can_exit() || !self.inner.bridge.edits.can_exit() || state.github.native_work_pending() {
            return Err(AssetError::new(Reason::Busy));
        }
        Ok(())
    }
    fn evidence_gate(&self, state: &DocumentState) -> Result<(), BridgeError> {
        if !self.evidence_qualified() { return Err(evidence_wire::refused(EvidenceProblem::Unavailable)); }
        // Reuse lifecycle/Android/diagnostic gates without granting the broad
        // private-asset profile or requiring a credential session/source project.
        self.common_gate(state, false).map_err(|error| evidence_wire::refused(evidence_reason(error.reason)))?;
        evidence_selection_gate(state)?;
        if self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled() { return Err(evidence_wire::refused(EvidenceProblem::CleanupUnknown)); }
        if self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping() { return Err(evidence_wire::refused(EvidenceProblem::Unavailable)); }
        if !self.inner.bridge.supervisor.can_exit() || !self.inner.bridge.edits.can_exit() || state.github.native_work_pending() {
            return Err(evidence_wire::refused(EvidenceProblem::Busy));
        }
        Ok(())
    }
    pub(crate) fn artifact_evidence_status(&self) -> Result<evidence_wire::Status, BridgeError> {
        self.reconcile();
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        evidence_snapshot(&state, self.evidence_qualified()).checked()
    }
    pub(crate) fn artifact_evidence_cancel(&self, args: evidence_wire::Cancel) -> Result<evidence_wire::Status, BridgeError> {
        // Match before expire/reconcile: a wrong cancellation is not authority
        // even to change another slot's status or its clock.
        let mut state = self.lock();
        // Do not alter credentials/source/G state or invoke Supervisor STOP.
        // The existing coordinator retains the exact in-progress query future.
        if cancel_evidence_locked(&mut state, &args, Instant::now())? { self.bump(&mut state); }
        evidence_snapshot(&state, self.evidence_qualified()).checked()
    }
    #[cfg(feature = "desktop-shell")]
    fn evidence_failed(&self, owner: &Arc<OriginalWork>, problem: EvidenceProblem) {
        let mut state = self.lock();
        if record_evidence_failure(&mut state, owner, problem, Instant::now()) { self.bump(&mut state); }
    }
    fn registry_result<T>(&self, state: &mut DocumentState, result: Result<T, AssetError>, original: Option<&Arc<OriginalWork>>) -> Result<T, AssetError> {
        // Admission/context callers without an explicit original pass None.
        // In particular, state.slot is not a diagnostic association fallback.
        if result.as_ref().is_err_and(|error| error.reason == Reason::CleanupUnknown) {
            self.coordinator_failed(state, UnknownOrigin::Registry, original);
        }
        result
    }
    fn project_path_registration(&self, state: &mut DocumentState, binding: &ProjectPathBinding) -> Result<(), AssetError> {
        let (generation, root) = self.registry_result(state, self.inner.bridge.native_project(&binding.project_id), None)?;
        if !binding.registration_matches(generation, &root) { return Err(AssetError::new(Reason::ContextStale)); }
        Ok(())
    }
    fn github_gate(&self, state: &DocumentState) -> GitHubReason {
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled()
            || self.inner.bridge.diagnostics.disabled() || self.inner.bridge.preflight.disabled()
            || self.inner.bridge.android_build.disabled() { return GitHubReason::CleanupUnknown; }
        if !self.github_qualified() { return GitHubReason::Unqualified; }
        if !state.lifetime.original_bound() || state.lost_observed || state.stopping
            || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping() || self.inner.bridge.diagnostics.stopping()
            || self.inner.bridge.preflight.stopping() || self.inner.bridge.android_build.stopping() { return GitHubReason::Cancelled; }
        if self.inner.bridge.diagnostics.busy() || self.inner.bridge.preflight.busy() || self.inner.bridge.android_build.busy()
            || state.compatibility_picker_pending { return GitHubReason::Busy; }
        if state.quit_pending || state.retiring || state.lock_pending || state.slot.as_ref().is_some_and(|slot|
            slot.operation.blocks_context() && (slot.phase != Phase::Idle || !slot.owner.resources_settled())) { return GitHubReason::Busy; }
        GitHubReason::None
    }
    fn github_observe_locked(&self, state: &mut DocumentState, now: Instant) {
        // Recheck the real document and native ID registry BEFORE consuming a
        // positive receipt. This does not inspect a path, launch work or acquire
        // another document owner; lock order stays document -> registry -> owner.
        if state.exhausted { state.github.exhaust(); }
        else if state.unknown || self.inner.bridge.supervisor.disabled() || self.inner.bridge.edits.disabled() { state.github.unknown(); }
        else if state.lost_observed || !state.lifetime.original_bound() || state.stopping
            || self.inner.bridge.supervisor.stopping() || self.inner.bridge.edits.stopping() { state.github.retire(GitHubReason::Cancelled); }
        let registration = state.github.registration().map(|(id, generation)| (id.to_owned(), generation));
        if let Some((id, original)) = registration {
            match self.registry_result(state, self.inner.bridge.github_registration(&id), None) {
                Ok(generation) if generation == original => {},
                Err(error) if error.reason == Reason::CleanupUnknown => state.github.unknown(),
                _ => state.github.retire(GitHubReason::TargetChanged),
            }
        }
        let gate = self.github_gate(state);
        state.github.reconcile(now, gate);
    }
    pub(crate) fn github_connection_status(&self) -> github_wire::Status {
        let mut state = self.lock(); self.expire(&mut state, Instant::now()); state.github.snapshot()
    }
    pub(crate) fn github_connection_connect_token(&self, value: &Value) -> Result<github_wire::Status, BridgeError> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let gate = self.github_gate(&state);
        // This is BEFORE the borrowed decoder makes its single native-owned
        // credential copy. Unqualified builds never collect a private session.
        if gate != GitHubReason::None { return Err(github_session::refused(gate)); }
        let github_wire::Command::ConnectToken(args) = github_wire::decode_command_value("github_connection_connect_token", value)
            .map_err(|_| github_session::refused(GitHubReason::InvalidInput))? else { return Err(github_session::refused(GitHubReason::InvalidInput)); };
        let generation = self.registry_result(&mut state, self.inner.bridge.github_registration(&args.project_id), None)
            .map_err(|error| github_session::refused(if error.reason == Reason::CleanupUnknown { GitHubReason::CleanupUnknown } else { GitHubReason::TargetChanged }))?;
        let now = Instant::now(); let wall = std::time::SystemTime::now();
        state.github.connect(args, generation, &self.inner.bridge.supervisor, now, wall)
    }
    pub(crate) fn github_connection_refresh(&self, value: &Value) -> Result<github_wire::Status, BridgeError> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let gate = self.github_gate(&state);
        if gate != GitHubReason::None { return Err(github_session::refused(gate)); }
        let github_wire::Command::Refresh(args) = github_wire::decode_command_value("github_connection_refresh", value)
            .map_err(|_| github_session::refused(GitHubReason::InvalidInput))? else { return Err(github_session::refused(GitHubReason::InvalidInput)); };
        state.github.refresh(&args.session_id, args.expected_revision, &self.inner.bridge.supervisor, Instant::now())
    }
    pub(crate) fn github_connection_disconnect(&self, value: &Value) -> Result<github_wire::Status, BridgeError> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let github_wire::Command::Disconnect(args) = github_wire::decode_command_value("github_connection_disconnect", value)
            .map_err(|_| github_session::refused(GitHubReason::InvalidInput))? else { return Err(github_session::refused(GitHubReason::InvalidInput)); };
        // No new admission gate: exact retirement stays usable during Busy,
        // quit, expiry, document loss or retained Unknown. Never sessionless STOP.
        let gate = self.github_gate(&state);
        state.github.disconnect(&args.session_id, Instant::now(), gate)
    }
    /// Controlled integration only: the retained original SourceBook produced
    /// this proof after its own successful terminal checks and closes. Publish
    /// through the real registry under the same document admission mutex; no
    /// workflow permission, fabricated identity or registry repair is involved.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn github_fixture_publish(&self, proof: crate::asset_source::ProjectProbe, generation: u32) -> Result<Project, AssetError> {
        let mut state = self.lock();
        if !state.lifetime.original_bound() || state.lost_observed { return Err(AssetError::new(Reason::DocumentLost)); }
        if state.unknown || state.exhausted { return Err(AssetError::new(Reason::CleanupUnknown)); }
        if state.stopping || state.quit_pending || state.retiring || state.lock_pending || state.slot.is_some()
            || state.session || state.context.is_some() || !state.records.is_empty() || !state.assignments.is_empty()
            || self.inner.bridge.supervisor.stopping() || self.inner.bridge.supervisor.disabled()
            || self.inner.bridge.edits.stopping() || self.inner.bridge.edits.disabled() || !self.github_fixture_permitted() {
            return Err(AssetError::new(Reason::Unqualified));
        }
        // Do not consume a ready G1 receipt before this registration change.
        // The next actual status/reconciliation rechecks this registry first.
        // This supplied event is not native picker-admission/callback evidence.
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.android_build.ensure_idle().map_err(|_| AssetError::new(Reason::Unqualified))?;
        let published = self.registry_result(&mut state, self.inner.bridge.publish_checked_project(proof, generation), None)?;
        self.bump(&mut state);
        Ok(published)
    }
    /// Observation only: never reconcile, retire, consume a receipt, erase a
    /// token, or mark an original settled on the finalizer's behalf. Contention
    /// and poison remain unconfirmed; the caller retains the original document.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn github_fixture_material_settled(&self) -> bool {
        self.github_fixture_permitted() && self.inner.state.try_lock().is_ok_and(|state| state.github.material_settled())
    }
    /// Workflow admission uses this actual document/selection mutex, not a
    /// separate lock or an unlocked not_quitting observation. Both callbacks
    /// are synchronous, bounded in-memory work only; open entropy must already
    /// be in the EditOwner's private ticket. The asset qualification gate is
    /// deliberately NOT workflow qualification.
    pub(crate) fn workflow_edit_admit<T>(
        &self,
        project_id: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::WorkflowRegistration) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.registered_edit_admit(crate::edit_protocol::EditDomain::GitHubWorkflows, project_id, enqueue)
    }
    pub(crate) fn metadata_text_edit_admit<T>(
        &self,
        project_id: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.registered_edit_admit(crate::edit_protocol::EditDomain::MetadataText, project_id, enqueue)
    }
    pub(crate) fn release_version_edit_admit<T>(
        &self,
        project_id: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.registered_edit_admit(crate::edit_protocol::EditDomain::ReleaseVersion, project_id, enqueue)
    }
    // Only the three explicitly registered-root domains use this same mutex and
    // proof. A proof never qualifies a writer or changes configuration custody.
    fn registered_edit_admit<T>(
        &self, domain: crate::edit_protocol::EditDomain,
        project_id: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        if !matches!(domain, crate::edit_protocol::EditDomain::GitHubWorkflows | crate::edit_protocol::EditDomain::MetadataText | crate::edit_protocol::EditDomain::ReleaseVersion) {
            return Err(BridgeError::invalid());
        }
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        if state.unknown || state.exhausted { return Err(BridgeError::cleanup_unknown()); }
        if !state.lifetime.original_bound() || state.lost_observed {
            return Err(BridgeError::new("invalid_edit_owner", "This document does not own that live edit domain."));
        }
        if state.stopping || self.inner.bridge.supervisor.stopping() { return Err(BridgeError::shutdown()); }
        if self.inner.bridge.supervisor.disabled() { return Err(BridgeError::cleanup_unknown()); }
        self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        if state.quit_pending { return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before starting another action.")); }
        if state.retiring || state.lock_pending || state.compatibility_picker_pending || state.slot.as_ref().is_some_and(|slot|
            slot.operation.blocks_context() && (slot.phase != Phase::Idle || !slot.owner.resources_settled())) {
            return Err(BridgeError::new("busy", "The original native project selection has not settled."));
        }
        let id = project_id(&self.inner.bridge)?;
        // Selection admission/publication and document loss cannot interleave
        // this native lookup with the original owner's claim and enqueue. The
        // registry guard is released before taking EditOwner's lock.
        let selected = self.registry_result(&mut state, self.inner.bridge.native_project(&id), None);
        let (generation, root) = selected.map_err(|error| match error.reason {
            Reason::CleanupUnknown => {
                // Registry poison is sticky and revokes the original edit;
                // an error reply alone must not leave a live review token.
                self.inner.bridge.edits.document_lost(MAIN);
                BridgeError::cleanup_unknown()
            }
            Reason::Unqualified => BridgeError::unavailable("The selected project has no qualified native root identity."),
            _ => BridgeError::invalid(),
        })?;
        enqueue(&self.inner.bridge, crate::edit_owner::RegisteredEditRoot { generation, root })
    }
    /// Headless controlled-integration entry only: consume a real, already
    /// settled SourceBook probe under this SAME document admission mutex. It
    /// does not enable asset services or manufacture project/root identities.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn workflow_fixture_publish(&self, proof: crate::asset_source::ProjectProbe, generation: u32) -> Result<Project, AssetError> {
        self.registered_fixture_publish(proof, generation, crate::edit_protocol::EditDomain::GitHubWorkflows)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn metadata_fixture_publish(&self, proof: crate::asset_source::ProjectProbe, generation: u32) -> Result<Project, AssetError> {
        self.registered_fixture_publish(proof, generation, crate::edit_protocol::EditDomain::MetadataText)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn version_fixture_publish(&self, proof: crate::asset_source::ProjectProbe, generation: u32) -> Result<Project, AssetError> {
        self.registered_fixture_publish(proof, generation, crate::edit_protocol::EditDomain::ReleaseVersion)
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn registered_fixture_publish(&self, proof: crate::asset_source::ProjectProbe, generation: u32,
        domain: crate::edit_protocol::EditDomain) -> Result<Project, AssetError> {
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        if !state.lifetime.original_bound() || state.lost_observed { return Err(AssetError::new(Reason::DocumentLost)); }
        if state.unknown || state.exhausted { return Err(AssetError::new(Reason::CleanupUnknown)); }
        let permitted = match domain {
            crate::edit_protocol::EditDomain::GitHubWorkflows => self.inner.bridge.edits.workflow_fixture_registration_permitted(proof.path()),
            crate::edit_protocol::EditDomain::MetadataText => self.inner.bridge.edits.metadata_fixture_registration_permitted(proof.path()),
            crate::edit_protocol::EditDomain::ReleaseVersion => self.inner.bridge.edits.version_fixture_registration_permitted(proof.path()),
            crate::edit_protocol::EditDomain::Configuration => false,
        };
        if state.stopping || state.quit_pending || state.retiring || state.lock_pending || state.slot.is_some()
            || state.session || state.context.is_some() || !state.records.is_empty() || !state.assignments.is_empty()
            || self.inner.bridge.supervisor.stopping() || self.inner.bridge.supervisor.disabled()
            || !permitted {
            return Err(AssetError::new(Reason::Unqualified));
        }
        self.inner.bridge.android_build.context_changed();
        self.inner.bridge.android_build.ensure_idle().map_err(|_| AssetError::new(Reason::Unqualified))?;
        let published = self.registry_result(&mut state, self.inner.bridge.publish_checked_project(proof, generation), None)?;
        self.bump(&mut state);
        Ok(published)
    }
    fn current_context(&self, state: &mut DocumentState, revision: u32) -> Result<Arc<NativeContext>, AssetError> {
        let context = state.context.as_ref().filter(|context| context.revision == revision).cloned().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
        let matches = self.context_matches(state, &context);
        if !self.registry_result(state, matches, None)? { return Err(AssetError::new(Reason::ContextStale)); } Ok(context)
    }
    fn context_matches(&self, state: &DocumentState, context: &Arc<NativeContext>) -> Result<bool, AssetError> {
        if !state.lifetime.original_bound() || state.stopping || state.unknown { return Ok(false); }
        let Some(current) = &state.context else { return Ok(false); };
        if !Arc::ptr_eq(current, context) || current.revision != context.revision || self.inner.bridge.registry_generation() != context.registry_generation { return Ok(false); }
        let (generation, root) = self.inner.bridge.native_project(&context.project_id)?;
        Ok(generation == context.registry_generation && root.identity == context.project.identity && root.path == context.project.path)
    }
    fn expire(&self, state: &mut DocumentState, now: Instant) {
        let owner_reason = self.live_session_owner_reason();
        // Display changes advance the existing native revision. This is
        // capability DATA, not a fabricated asset cleanup result, and does
        // not block original discard/retirement/quit behind new admission.
        let mut changed = observe_session_owner_reason(state, owner_reason);
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
                first_unknown_origin!(state, UnknownOrigin::OperationCleanup(slot.reason), Some(&slot.owner));
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
        self.github_observe_locked(state, now);
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
            else if let Some(reason) = state.session_owner_reason { reason }
            else if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { Reason::UnsupportedPlatform }
            else if !self.native_qualified() { Reason::Unqualified } else if redacted { Reason::Closed } else { Reason::None };
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
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(context) = self.inner.fixture.as_ref().and_then(Weak::upgrade) {
            if !context.context_input(args.project_id) || !args.draft.as_object().is_some_and(|draft| draft.is_empty())
                || args.platform != Platform::Android || args.stage != Stage::Candidate || args.purpose != Purpose::Signing {
                context.refuse(); return Err(AssetError::new(Reason::Unqualified));
            }
        }
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        lookup_allocation_gate(&state)?; // Before draft/project/field backing copies.
        self.inner.bridge.diagnostics.context_changed(); self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed(); self.gate(&state, true)?;
        let (registry_generation, project) = self.registry_result(&mut state, self.inner.bridge.native_project(args.project_id), None)?;
        let Some(revision) = state.next_context.checked_add(1) else { self.exhaust(&mut state, UnknownOrigin::Exhausted); return Err(AssetError::new(Reason::CleanupUnknown)); };
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
        let slot = state.slot.as_mut().filter(|slot| slot.owner.id == id && !slot.operation.evidence() && !slot.operation.project_path()).ok_or_else(AssetError::invalid)?;
        slot.operation = Operation::Discard; slot.stop(Reason::UserCancelled, Instant::now()); self.bump(&mut state);
        drop(state); Ok(self.status())
    }
    pub(crate) fn lock_session(&self) -> Result<AssetStatus, AssetError> {
        let mut state = self.lock();
        if !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
        if project_path_pending(&state) { return Err(AssetError::new(if state.unknown { Reason::CleanupUnknown } else { Reason::Busy })); }
        // Lock retires context DATA; STOP does not claim either saved-command
        // owner's resources settled or turn vault lock into GitHub Disconnect.
        self.inner.bridge.preflight.context_changed(); self.inner.bridge.android_build.context_changed();
        invalidate_all(&mut state); state.lock_pending = true;
        if let Some(slot) = state.slot.as_mut() {
            if !slot.operation.evidence() && !slot.operation.project_path() { slot.operation = Operation::Lock; }
            slot.stop(Reason::UserCancelled, Instant::now());
        }
        self.bump(&mut state); drop(state); Ok(self.status())
    }
}

fn idle(state: &DocumentState) -> Result<(), AssetError> {
    if state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled()) { return Err(AssetError::new(Reason::Busy)); } Ok(())
}
fn project_path_idle_gate(state: &DocumentState, installed_profile: bool) -> Result<(), AssetError> {
    if !installed_profile { return Err(AssetError::new(Reason::Unqualified)); }
    idle(state)
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

enum ChildJob {
    Tokens, Capture { path: std::path::PathBuf, roots: Vec<asset_source::RegisteredRoot>, kind: credential_format::FileKind },
    Probe { path: std::path::PathBuf, origins: Vec<Arc<OriginWitness>> },
    ProjectPath { path: std::path::PathBuf, binding: Arc<ProjectPathBinding> },
}
enum ChildEnd { Tokens(TokenBatch), Captured(Material), Probed(asset_source::ProjectProbe), ProjectPath(asset_source::ProjectPathProbe), Refused(Reason) }
enum Staged {
    Selected { payload: Arc<Payload>, tokens: TokenBatch }, Prepared { result: Result<SafeAssessment, CommandError>, tokens: TokenBatch },
    Delete(TokenBatch), Project { proof: asset_source::ProjectProbe, generation: u32 },
    ProjectPath { proof: asset_source::ProjectPathProbe, binding: Arc<ProjectPathBinding> },
    EvidenceFolder { proof: asset_source::ProjectProbe, tokens: TokenBatch }, EvidenceObserved(evidence_wire::Observation),
    Committed { bind: Option<Token> }, Bound(Assignment), Refused(Reason),
}
#[cfg(feature = "desktop-shell")]
enum Job {
    Choose { app: tauri::AppHandle, kind: Kind, roster: ProjectRoster },
    Project { app: tauri::AppHandle, generation: u32, origins: Vec<Arc<OriginWitness>> },
    ProjectPath { app: tauri::AppHandle, binding: Arc<ProjectPathBinding> },
    ChooseEvidenceFolder { app: tauri::AppHandle }, InspectEvidence { root: asset_source::RegisteredRoot },
    Prepare { payload: Arc<Payload>, context: Arc<NativeContext> }, Delete, Retire { bind: Option<Token> }, Bind(Assignment),
}

async fn child(owner: &Arc<OriginalWork>, job: ChildJob) -> Result<ChildEnd, Reason> {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let fixture_kind = match &job { ChildJob::Probe { .. } => 1, ChildJob::Tokens => 2, ChildJob::Capture { .. } => 3, ChildJob::ProjectPath { .. } => 4 };
    let mut book = owner.child.lock().await;
    if book.handle.is_some() || !matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned) { return Err(Reason::CleanupUnknown); }
    if owner.interrupted() { return Err(Reason::UserCancelled); }
    // Reciprocal to lookup_memory::enter: retain this exact child mutex while
    // checking the charge and registering the original blocking dispatch.
    if !owner.lookup_allocations_allowed() { return Err(Reason::Busy); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if !matches!(&job, ChildJob::Tokens) {
        // A joined Captured ChildEnd may still be a caller-local large holding.
        // This closed slice refuses later lookup in that same owner rather than
        // presume that Returned means the result was published/disposed.
        owner.large_work_started.store(true, Ordering::SeqCst);
    }
    book.receipt = JoinReceipt::Pending;
    let (start, enter) = oneshot::channel();
    let worker = owner.clone();
    book.handle = Some(tokio::task::spawn_blocking(move || {
        if enter.blocking_recv().is_err() { return ChildEnd::Refused(Reason::UserCancelled); }
        execute_child(&worker, job)
    }));
    fixture_event!(owner, ChildRegistered, fixture_kind);
    // No blocking child can enter RNG/native work before its ORIGINAL handle
    // and resource slots above exist. Dropping an invoke never touches them.
    if start.send(()).is_err() { owner.stop(); }
    let result = match book.handle.as_mut() { Some(handle) => handle.await, None => { book.receipt = JoinReceipt::Failed; return Err(Reason::CleanupUnknown); } };
    book.handle.take(); // Only after this original join returned.
    fixture_event!(owner, ChildJoined, fixture_kind * 2 + u32::from(result.is_ok()));
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
                    Ok(observation) => {
                        fixture_event!(owner, HeaderObserved, u32::from(kind == credential_format::FileKind::AndroidKeystore
                            && observation.is_observed() && captured.bytes == [0xfe,0xed,0xfe,0xed,0,0,0,2,0,0,0,0]));
                        ChildEnd::Captured(Material { captured, observation })
                    }, Err(_) => ChildEnd::Refused(Reason::UserCancelled),
                },
                Err(reason) => ChildEnd::Refused(reason),
            }
        }
        ChildJob::Probe { path, origins } => match owner.source.lock() {
            Ok(mut book) => match asset_source::probe_project(&mut book, path, &origins, &mut stop) { Ok(probe) => ChildEnd::Probed(probe), Err(reason) => ChildEnd::Refused(reason) },
            Err(_) => ChildEnd::Refused(Reason::CleanupUnknown),
        },
        ChildJob::ProjectPath { path, binding } => match owner.source.lock() {
            Ok(mut book) => match asset_source::probe_project_path(&mut book, &binding.root, path, binding.field, &mut stop) {
                Ok(proof) => ChildEnd::ProjectPath(proof), Err(reason) => ChildEnd::Refused(reason),
            },
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

fn prepare_copy_start(state: &mut DocumentState, owner: &Arc<OriginalWork>) -> Result<bool, Reason> {
    if state.stopping || state.unknown || !state.lifetime.original_bound() || owner.interrupted() { return Err(Reason::UserCancelled); }
    if state.retiring || state.quit_pending || state.lock_pending || !owner.lookup_allocations_allowed() { return Err(Reason::Busy); }
    let slot = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner) && slot.operation == Operation::Prepare)
        .ok_or(Reason::ContextStale)?;
    if slot.cleanup_end.is_some() { return Err(slot.reason); }
    // Sticky, conservative boundary: this slice refuses lookup after ANY R1
    // request/Value or non-Token child work started in this owner, even after a later phase change.
    // Its memory is not the native parser's 6MiB arena and is not in the census.
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    owner.large_work_started.store(true, Ordering::SeqCst);
    let changed = slot.phase != Phase::Assessing; slot.phase = Phase::Assessing; Ok(changed)
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
            assessment_context_revision, staged: None, error: None, project: None, discard: false, kind: None, result_record: None, retired_payload: None,
            evidence: None, project_path: None, path_result: None }
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
    fn gui_response(&self, owner: &Arc<OriginalWork>, response: NativeResponse, quit: bool) -> Option<bool> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let mut facts = owner.gui.facts()?;
        if facts.response { return None; }
        facts.response = true; facts.showing = false;
        let now = Instant::now();
        let original = if quit { state.quit.as_ref().is_some_and(|work| Arc::ptr_eq(work, owner)) }
            else { state.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, owner)) && state.lifetime.original_bound() && !state.stopping && !state.unknown };
        // Remember the actual native decline before stop_quit changes STOP.
        // A programmatic post-STOP close or rejected late OK is never Cancel.
        let path_choice = !quit && state.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, owner) && slot.operation.project_path());
        // Preserve the existing Project/File/Evidence receipt semantics. This
        // new purpose separately records genuine native Cancel, never Other or
        // a programmatic/late post-STOP close, for its null-only cancellation.
        (facts.accepted, facts.declined) = admitted_response(response, original, owner.interrupted(), quit || path_choice);
        fixture_event!(owner, ResponseDecision, u32::from(facts.accepted) + 2 * u32::from(facts.declined));
        if facts.accepted { facts.accepted_at = Some(now); owner.set_endpoint(Some(now + WORK)); }
        let read_one_path = facts.accepted && !quit;
        if quit {
            if facts.accepted {
                // Actual native OK linearizes with admission, not a later
                // dialog-return or renderer callback. Cancel changes none of
                // the settled assignments and never renews review time.
                state.quit_accepted = true; state.stopping = true; invalidate_all(&mut state);
                state.evidence.revoke(false);
                state.github.retire(GitHubReason::Cancelled);
                self.inner.bridge.diagnostics.request_shutdown();
                self.inner.bridge.preflight.request_shutdown();
                self.inner.bridge.android_build.request_shutdown();
                if let Some(slot) = state.slot.as_mut() { slot.stop(Reason::Shutdown, now); }
                stop_quit(&mut state, now);
                fixture_event!(owner, QuitStop, 1);
            } else { stop_quit(&mut state, now); }
        } else if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) {
            if read_one_path {
                slot.phase = Phase::Capturing;
                slot.source = if slot.operation == Operation::ChooseFile { SourceState::Pending } else { SourceState::NotRun };
                if !slot.operation.project_path() && slot.review_end.is_none() { slot.review_end = Some(now + REVIEW); }
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
    fn begin_prepare_copy(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        if prepare_copy_start(&mut state, owner)? { self.bump(&mut state); } Ok(())
    }
    fn tick(&self) { let mut state = self.lock(); self.expire(&mut state, Instant::now()); }
    fn stage(&self, owner: &Arc<OriginalWork>, staged: Staged) {
        let mut state = self.lock(); self.expire(&mut state, Instant::now());
        if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) {
            // Exactly one original coordinator stages once. Never overwrite a
            // possibly secret-bearing result or publish before its normal join.
            if slot.staged.is_none() { slot.staged = Some(staged); self.bump(&mut state); return; }
            slot.stop(Reason::CleanupUnknown, Instant::now());
            first_unknown_origin!(state, UnknownOrigin::StagedCollision, Some(owner));
            state.unknown = true; self.bump(&mut state);
        }
        drop(state); drop(staged);
    }
    fn coordinator_failed(&self, state: &mut DocumentState, _origin: UnknownOrigin, _original: Option<&Arc<OriginalWork>>) {
        first_unknown_origin!(state, _origin, _original);
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
            first_unknown_origin!(state, UnknownOrigin::CoordinatorJoin, Some(&slot.owner));
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

        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if slot.owner.original_resources_settled() && slot.owner.retired.load(Ordering::SeqCst)
            && slot.owner.keyring.try_lock().is_ok_and(|book| book.memory_held()) {
            // A settled SDK/book still owns its charged backing. Register this
            // disposal before releasing the actual document gate. In particular
            // dispose a just-consumed orphan ChildEnd BEFORE refunding anything.
            let owner = slot.owner.clone(); state.slot = Some(slot); state.retiring = true;
            drop(state); drop(orphan_result);
            let disposed = owner.dispose_keyring_storage();
            let mut state = self.lock(); state.retiring = false;
            if !disposed { self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return; }
            self.bump(&mut state); drop(state);
            // At most one such pass for this one-shot owner: storage is gone,
            // entered/error/Unknown facts are untouched. Continue ordinary
            // publication/retirement now instead of waiting for slot replacement.
            self.reconcile(); return;
        }

        let resources = slot.owner.resources_settled();
        let tuple_result = slot.context.as_ref().map_or(Ok(true), |context| self.context_matches(&state, context));
        let tuple_ok = self.registry_result(&mut state, tuple_result, Some(&slot.owner)).unwrap_or(false);
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
                        first_unknown_origin!(state, UnknownOrigin::RetirementRetain, Some(&slot.owner));
                        state.unknown = true; slot.phase = Phase::Unknown; slot.settlement = Settlement::Unknown;
                        self.bump(&mut state);
                    }
                }
            }
        }
        state.slot = Some(slot);
        settle_evidence_status(&mut state);
        if complete_empty_session_lock(&mut state) { self.bump(&mut state); }
        if state.unknown { invalidate_all(&mut state); }
        drop(state);
        // A completed abandoned child result is never a new usable selection.
        drop(orphan_result);
        if let Some(owner) = release {
            let disposed = owner.release_retirement();
            let mut state = self.lock();
            state.retiring = false;
            if !disposed { self.coordinator_failed(&mut state, UnknownOrigin::RetirementDrain, Some(&owner)); return; }
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
            settle_evidence_status(&mut state);
            self.bump(&mut state);
        }
    }

    fn publish(&self, state: &mut DocumentState, slot: &mut Slot, staged: Staged) {
        // This function performs bounded memory-only publication. Every source,
        // GTK, parser and original coordinator/child join has already settled.
        match staged {
            Staged::ProjectPath { proof, binding } => {
                if !slot.operation.project_path() || !slot.project_path.as_ref().is_some_and(|original| Arc::ptr_eq(original, &binding)) {
                    slot.stop(Reason::ContextStale, Instant::now()); return;
                }
                if !slot.owner.project_path_settled(true) {
                    slot.stop(Reason::CleanupUnknown, Instant::now()); state.unknown = true; return;
                }
                if let Err(error) = self.project_path_registration(state, &binding) {
                    slot.stop(error.reason, Instant::now()); return;
                }
                match commands::project_path_result(&binding.project_id, binding.field, proof.into_relative_path()) {
                    Ok(result) => {
                        // Only bounded relative DATA. No registry/context,
                        // assignment, evidence selection or asset record changes.
                        slot.path_result = Some(result); slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
                    },
                    Err(error) => slot.stop(error.reason, Instant::now()),
                }
            }
            Staged::EvidenceFolder { proof, tokens } => {
                if state.evidence.revoked || !state.evidence.matches(slot) || slot.operation != Operation::ChooseEvidenceFolder || !tokens_distinct(&tokens) {
                    slot.stop(Reason::ContextStale, Instant::now()); return;
                }
                let selection_id = format!("evidence-{}", tokens.selection.0);
                let display_name = evidence_display_name(proof.path());
                state.evidence.selection = Some(EvidenceSelection { view: evidence_wire::Selection { selection_id, display_name },
                    root: asset_source::RegisteredRoot { path: proof.path().to_path_buf(), identity: proof.identity() }, epoch: state.evidence.epoch });
                state.evidence.phase = evidence_wire::Phase::Selected; state.evidence.problem = None; state.evidence.result = None;
                slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
            }
            Staged::EvidenceObserved(result) => {
                if !state.evidence.matches(slot) || slot.operation != Operation::InspectEvidence
                    || !slot.evidence.as_ref().is_some_and(|binding| state.evidence.selection_matches(binding)) {
                    slot.stop(Reason::ContextStale, Instant::now()); return;
                }
                state.evidence.result = Some(result); state.evidence.phase = evidence_wire::Phase::Observed; state.evidence.problem = None;
                slot.phase = Phase::Idle; slot.settlement = Settlement::Known;
            }
            Staged::Selected { payload, tokens } => {
                if !tokens_distinct(&tokens) || state.records.iter().any(|record| record.key.id == tokens.record) {
                    slot.staged = Some(Staged::Selected { payload, tokens }); slot.stop(Reason::SourceRefused, Instant::now()); return;
                }
                slot.kind = Some(payload.kind); slot.source = SourceState::Captured;
                slot.candidate = Some(Candidate { payload, record_id: tokens.record, existing: slot.target.clone() });
                slot.selection = Some(tokens.selection); slot.phase = Phase::Selected; slot.settlement = Settlement::Known;
                fixture_event!(slot.owner, CandidatePublished, 1);
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
                    fixture_event!(slot.owner, ProjectPublished, 1);
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
                let context_ok = self.registry_result(state, context_result, Some(&slot.owner)).unwrap_or(false);
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
                slot.stop(reason, Instant::now());
                if reason == Reason::CleanupUnknown {
                    first_unknown_origin!(state, UnknownOrigin::StagedRefusal, Some(&slot.owner));
                    state.unknown = true;
                }
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
fn restore_failed_install_retirement(state: &mut DocumentState, _owner: &Arc<OriginalWork>, retirement: Retirement) {
    // The failure belongs to the NEW owner, before the old slot is restored.
    first_unknown_origin!(state, UnknownOrigin::InstallRetirement, Some(_owner));
    state.slot = retirement.old_slot.map(|slot| *slot); state.unknown = true;
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn install(&self, state: &mut DocumentState, slot: Slot, job: Job) -> Result<oneshot::Sender<()>, AssetError> {
        // Every caller also has its real reciprocal admission check. Keep the
        // path original nonreplaceable here even if a future caller omits one;
        // an absent path slot in its invoke waiter then implies known settlement.
        if project_path_pending(state) { return Err(AssetError::new(Reason::Busy)); }
        lookup_allocation_gate(state)?;
        settle_evidence_status(state);
        let owner = slot.owner.clone();
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        self.installed_record_original(&owner, Some(slot.operation))?;
        let old_slot = state.slot.take().map(Box::new);
        if let Err(retirement) = owner.retain_retirement(Retirement { old_slot, ..Retirement::default() }) {
            restore_failed_install_retirement(state, &owner, retirement);
            return Err(AssetError::new(Reason::CleanupUnknown));
        }
        state.slot = Some(slot);
        let mut book = match owner.coordinator.lock() { Ok(book) => book, Err(_) => {
            self.coordinator_failed(state, UnknownOrigin::CoordinatorLock, Some(&owner)); return Err(AssetError::new(Reason::CleanupUnknown));
        } };
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
        fixture_event!(owner, CoordinatorRegistered, 0);
        // The original handle, GUI acquisition facts and child/resource slots
        // exist before this sender can be used. The caller releases the actual
        // DocumentBinding lock before opening the start barrier.
        self.bump(state); Ok(start)
    }
    pub(crate) fn choose(&self, app: tauri::AppHandle, args: commands::Choose<'_>) -> Result<AssetStatus, AssetError> {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(context) = self.inner.fixture.as_ref().and_then(Weak::upgrade) {
            if args.kind != Kind::AndroidKeystore || args.replacement.is_some() {
                context.refuse(); return Err(AssetError::new(Reason::Unqualified));
            }
        }
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.gate(&state, true)?; idle(&state)?;
        if args.kind.file().is_none() { return Err(AssetError::new(Reason::UnsupportedFormat)); }
        let context = self.current_context(&mut state, args.context_revision)?;
        let target = target(&state, args.replacement, args.kind)?;
        let roster = self.registry_result(&mut state, self.inner.bridge.native_roster(), None)?;
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
        Job::ChooseEvidenceFolder { app } => {
            let tokens = match child(owner, ChildJob::Tokens).await {
                Ok(ChildEnd::Tokens(tokens)) => tokens,
                Ok(ChildEnd::Refused(reason)) | Err(reason) => { owner.gui.not_created(reason); return Staged::Refused(reason); },
                _ => { owner.gui.not_created(Reason::CleanupUnknown); return Staged::Refused(Reason::CleanupUnknown); },
            };
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::EvidenceFolder, None).await {
                Ok(Some(path)) => path, Ok(None) => return Staged::Refused(Reason::UserCancelled), Err(reason) => return Staged::Refused(reason),
            };
            if let Err(reason) = document.phase(owner, Phase::Capturing) { return Staged::Refused(reason); }
            // Ordinary directory metadata only, no project publication and no
            // credential-source capture or user-selected document paths.
            match child(owner, ChildJob::Probe { path, origins: Vec::new() }).await {
                Ok(ChildEnd::Probed(proof)) => Staged::EvidenceFolder { proof, tokens },
                Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
            }
        }
        Job::InspectEvidence { root } => {
            if let Err(reason) = document.phase(owner, Phase::Assessing) { return Staged::Refused(reason); }
            if owner.interrupted() { return Staged::Refused(Reason::UserCancelled); }
            let result = document.inner.bridge.observe_candidate_evidence(&root).await;
            if let Err(error) = &result { document.evidence_failed(owner, evidence_wire::core_problem(error)); }
            // Keep the same query/coordinator if its Supervisor reported
            // unknown cleanup. No new wait lease, global cancel or clock.
            if document.inner.bridge.supervisor.disabled() {
                { let mut state = document.lock(); document.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); }
                while !document.inner.bridge.supervisor.can_exit() { tokio::time::sleep(Duration::from_millis(50)).await; }
            }
            if owner.interrupted() { return Staged::Refused(Reason::UserCancelled); }
            match result { Ok(result) => Staged::EvidenceObserved(result), Err(_) => Staged::Refused(Reason::SourceRefused) }
        }
        Job::Choose { app, kind, roster } => {
            let tokens = match child(owner, ChildJob::Tokens).await {
                Ok(ChildEnd::Tokens(tokens)) => tokens,
                Ok(ChildEnd::Refused(reason)) | Err(reason) => { owner.gui.not_created(reason); return Staged::Refused(reason); },
                _ => { owner.gui.not_created(Reason::CleanupUnknown); return Staged::Refused(Reason::CleanupUnknown); },
            };
            let file_kind = match kind.file() { Some(kind) => kind, None => { owner.gui.not_created(Reason::UnsupportedFormat); return Staged::Refused(Reason::UnsupportedFormat); } };
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::File(file_kind), None).await {
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
            if let Err(reason) = document.begin_prepare_copy(owner) { return Staged::Refused(reason); }
            let result = match assemble_request(&payload, &context) {
                Ok(request) => {
                    if owner.interrupted() { return Staged::Refused(Reason::UserCancelled); }
                    let assessor = assess_supplied(&document.inner.bridge.supervisor, request);
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    let assessor = document.inner.bridge.supervisor.observe_installed_session_query(owner, assessor);
                    assessor.await.map(|result| SafeAssessment(Arc::new(result))).map_err(CommandError::from)
                }
                Err(error) => Err(error),
            };
            // An R1 cleanup-unknown receipt is not its child settlement. The
            // unchanged Supervisor exposes only a conservative all-originals
            // can-exit view. Retain this exact coordinator/payload until that
            // view settles; do not cancel unrelated queries or fabricate a new
            // per-query lease. Unknown remains sticky even on late settlement.
            if document.inner.bridge.supervisor.disabled() {
                { let mut state = document.lock(); document.coordinator_failed(&mut state, UnknownOrigin::SupervisorDisabled, Some(owner)); }
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
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::Project, None).await {
                Ok(Some(path)) => path, Ok(None) => return Staged::Refused(Reason::UserCancelled), Err(reason) => return Staged::Refused(reason),
            };
            if let Err(reason) = document.phase(owner, Phase::Capturing) { return Staged::Refused(reason); }
            match child(owner, ChildJob::Probe { path, origins }).await {
                Ok(ChildEnd::Probed(proof)) => Staged::Project { proof, generation },
                Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
            }
        }
        Job::ProjectPath { app, binding } => {
            let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::ProjectPath(binding.field), Some(binding.root.path.clone())).await {
                Ok(Some(path)) => path, Ok(None) => return Staged::Refused(Reason::UserCancelled), Err(reason) => return Staged::Refused(reason),
            };
            if let Err(reason) = document.phase(owner, Phase::Capturing) { return Staged::Refused(reason); }
            match child(owner, ChildJob::ProjectPath { path, binding: binding.clone() }).await {
                Ok(ChildEnd::ProjectPath(proof)) => Staged::ProjectPath { proof, binding },
                Ok(ChildEnd::Refused(reason)) | Err(reason) => Staged::Refused(reason), _ => Staged::Refused(Reason::CleanupUnknown),
            }
        }
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(crate) fn artifact_evidence_choose(&self, app: tauri::AppHandle) -> Result<evidence_wire::Status, BridgeError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.evidence_gate(&state)?;
        let Some(epoch) = state.evidence.epoch.checked_add(1) else { self.exhaust(&mut state, UnknownOrigin::Exhausted); return Err(evidence_wire::refused(EvidenceProblem::CleanupUnknown)); };
        let id = self.next_operation(&mut state).map_err(|e| evidence_wire::refused(evidence_reason(e.reason)))?;
        if id == u32::MAX { self.exhaust(&mut state, UnknownOrigin::Exhausted); return Err(evidence_wire::refused(EvidenceProblem::CleanupUnknown)); }
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let binding = EvidenceBinding { operation_id: id, kind: evidence_wire::OperationKind::Choose, selection_id: None, epoch };
        let mut slot = Slot::new(owner, Operation::ChooseEvidenceFolder, None, None, None); slot.evidence = Some(binding.clone());
        // Only an accepted evidence choose revokes the previous evidence ID.
        // Source-project selection, drafts, assignments and G are untouched.
        state.evidence.epoch = epoch; state.evidence.selection = None; state.evidence.result = None; state.evidence.problem = None;
        state.evidence.phase = evidence_wire::Phase::Choosing; state.evidence.operation = Some(binding);
        let start = self.install(&mut state, slot, Job::ChooseEvidenceFolder { app }).map_err(|e| evidence_wire::refused(evidence_reason(e.reason)))?;
        let status = evidence_snapshot(&state, true).checked()?; drop(state); let _ = start.send(()); Ok(status)
    }
    pub(crate) fn artifact_evidence_observe(&self, args: evidence_wire::Observe) -> Result<evidence_wire::Status, BridgeError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.evidence_gate(&state)?;
        let selected = state.evidence.selection.as_ref().filter(|selection| selection.view.selection_id == args.selection_id
            && selection.epoch == state.evidence.epoch).ok_or_else(|| evidence_wire::refused(EvidenceProblem::StaleSelection))?;
        let root = selected.root.clone(); let epoch = selected.epoch;
        let id = self.next_operation(&mut state).map_err(|e| evidence_wire::refused(evidence_reason(e.reason)))?;
        if id == u32::MAX { self.exhaust(&mut state, UnknownOrigin::Exhausted); return Err(evidence_wire::refused(EvidenceProblem::CleanupUnknown)); }
        let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let binding = EvidenceBinding { operation_id: id, kind: evidence_wire::OperationKind::Observe, selection_id: Some(args.selection_id), epoch };
        let mut slot = Slot::new(owner, Operation::InspectEvidence, None, None, None); slot.evidence = Some(binding.clone());
        state.evidence.result = None; state.evidence.problem = None; state.evidence.phase = evidence_wire::Phase::Observing; state.evidence.operation = Some(binding);
        let start = self.install(&mut state, slot, Job::InspectEvidence { root }).map_err(|e| evidence_wire::refused(evidence_reason(e.reason)))?;
        let status = evidence_snapshot(&state, true).checked()?; drop(state); let _ = start.send(()); Ok(status)
    }
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
                if error.reason == Reason::CleanupUnknown { self.exhaust(&mut state, UnknownOrigin::NotRecorded); }
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
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.inner.bridge.diagnostics.context_changed(); self.inner.bridge.preflight.context_changed();
        self.inner.bridge.android_build.context_changed(); self.common_gate(&state, false)?;
        if !self.project_selection_qualified() { return Err(AssetError::new(Reason::Unqualified)); }
        idle(&state)?;
        // Acquire the registry's checked generation before any native work;
        // poison is sticky document Unknown, never merely a later picker error.
        let generation = self.registry_result(&mut state, self.inner.bridge.native_generation(), None)?;
        let mut origins = Vec::new(); origins.try_reserve_exact(state.records.len()).map_err(|_| AssetError::new(Reason::Capacity))?;
        for record in &state.records { if let Some(material) = &record.payload.material { origins.push(material.captured.origin.clone()); } }
        let id = self.next_operation(&mut state)?;
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let slot = Slot::new(owner, Operation::ChooseProject, None, None, None);
        // A later registration probes every retained source. Its admission,
        // not only success, revokes old use; cancel/refusal never restores it.
        invalidate_all(&mut state);
        state.github.retire(GitHubReason::TargetChanged);
        let start = self.install(&mut state, slot, Job::Project { app, generation, origins })?;
        drop(state); let _ = start.send(()); Ok(id)
    }
    pub(crate) async fn project_result(&self, id: u32) -> Result<Option<Project>, AssetError> {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64"))]
        { self.project_result_original(id, None).await }
        #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64")))]
        { self.project_result_original(id).await }
    }
    async fn project_result_original(&self, id: u32,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64"))]
        mut selection: Option<&mut Option<InstalledMacProjectSelectionData>>,
    ) -> Result<Option<Project>, AssetError> {
        loop {
            self.reconcile();
            {
                let state = self.lock();
                let slot = state.slot.as_ref().filter(|slot| slot.owner.id == id).ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
                if slot.phase == Phase::Idle && slot.owner.resources_settled() {
                    if slot.reason == Reason::None || slot.reason == Reason::UserCancelled {
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
                            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
                            target_os = "macos", target_arch = "aarch64"))]
                        if let (Some(companion), Some(project)) = (selection.as_deref_mut(), slot.project.as_ref()) {
                            // This guard still binds the original id/slot. Only
                            // saved DATA crosses the return, never an observer
                            // callback/Record lock or a later success witness.
                            *companion = Some(installed_macos_observation::capture_project_selection(&self.inner, id, slot, project));
                        }
                        return Ok(slot.project.clone());
                    }
                    return Err(AssetError::new(slot.reason));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub(crate) fn choose_project_path(&self, app: tauri::AppHandle, args: commands::ChooseProjectPath<'_>) -> Result<Arc<OriginalWork>, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.project_path_gate(&state)?;
        let (generation, root) = self.registry_result(&mut state, self.inner.bridge.native_project(args.project_id), None)?;
        let project_id = commands::copy_text(args.project_id)?;
        let id = self.next_operation(&mut state)?;
        if id == u32::MAX { self.exhaust(&mut state, UnknownOrigin::Exhausted); return Err(AssetError::new(Reason::CleanupUnknown)); }
        let binding = Arc::new(ProjectPathBinding { project_id, field: args.field, root, generation });
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner.clone(), Operation::ChooseProjectPath, None, None, None);
        slot.project_path = Some(binding.clone());
        // No choose_project reuse, invalidation, RNG, capture or credential
        // session. Install the same original coordinator/GUI/source/child book
        // under the real document gate before releasing its start barrier.
        let start = self.install(&mut state, slot, Job::ProjectPath { app, binding })?;
        drop(state); let _ = start.send(()); Ok(owner)
    }
    pub(crate) async fn project_path_result(&self, owner: Arc<OriginalWork>) -> Result<Option<commands::ProjectPathResult>, AssetError> {
        // This observer removes no original handle or result from the document.
        // Renderer abandonment cannot cancel or replace the retained operation.
        loop {
            self.reconcile();
            {
                let mut state = self.lock();
                if state.unknown || state.exhausted { return Err(AssetError::new(Reason::CleanupUnknown)); }
                let Some(slot) = state.slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) else {
                    if owner.resources_settled() { return Err(AssetError::new(Reason::ContextStale)); }
                    // Not expected: install refuses to remove an unresolved
                    // path original. Never turn missing ownership into Cancel.
                    self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return Err(AssetError::new(Reason::CleanupUnknown));
                };
                if !state.quit_pending && slot.phase == Phase::Idle && owner.resources_settled() {
                    if !state.lifetime.original_bound() || state.lost_observed { return Err(AssetError::new(Reason::DocumentLost)); }
                    if state.stopping { return Err(AssetError::new(Reason::Shutdown)); }
                    let binding = slot.project_path.clone().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                    let reason = slot.reason;
                    let result = slot.path_result.clone();
                    self.project_path_registration(&mut state, &binding)?;
                    if reason == Reason::UserCancelled && owner.project_path_settled(false) { return Ok(None); }
                    if reason != Reason::None { return Err(AssetError::new(reason)); }
                    if owner.project_path_settled(true) {
                        if let Some(result) = result { return Ok(Some(result)); }
                    }
                    self.coordinator_failed(&mut state, UnknownOrigin::NotRecorded, None); return Err(AssetError::new(Reason::CleanupUnknown));
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
        self.inner.bridge.preflight.ensure_idle()?;
        self.inner.bridge.android_build.ensure_idle()?;
        self.inner.bridge.diagnostics.ensure_idle()?;
        Ok(())
    }
    pub(crate) fn assets_can_exit(&self) -> bool {
        self.reconcile(); assets_can_exit_locked(&self.lock())
    }
    fn retained_material_can_exit(&self) -> bool {
        self.reconcile(); let state = self.lock(); assets_can_exit_locked(&state) && state.github.material_settled()
    }
    async fn shutdown_assets(&self) -> Result<(), AssetError> {
        // Native OK set stopping/revoked authority under the real gate before
        // this future exists. This observer never grants a new cleanup endpoint.
        loop {
            self.reconcile();
            {
                let state = self.lock();
                if assets_can_exit_locked(&state) && state.github.material_settled() { return Ok(()); }
                if state.unknown { return Err(AssetError::new(Reason::CleanupUnknown)); }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    pub(crate) fn can_exit(&self) -> bool {
        let (ready, quit) = {
            let state = self.lock();
            (state.stopping && state.quit_accepted && assets_can_exit_locked(&state) && state.github.material_settled(), state.quit.clone())
        };
        // The app's data-only observer does not run general session publication.
        // Only this already-ended quit original is joined here.
        ready && quit.is_some_and(|quit| quit.join_if_ended() == Some(true) && quit.resources_settled())
            && self.inner.bridge.supervisor.can_exit() && self.inner.bridge.edits.can_exit() && self.inner.bridge.diagnostics.can_exit()
            && self.inner.bridge.preflight.can_exit() && self.inner.bridge.android_build.can_exit()
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
    pub(crate) fn exit_cleanup_end(&self) -> Option<Instant> {
        // Observe only the retained accepted Quit's first STOP; never reconcile,
        // start another owner, or create a timestamp in the exit observer.
        accepted_quit_cleanup_end(&self.lock())
    }
    pub(crate) fn request_quit(&self, app: tauri::AppHandle) {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        // An unresolved or already accepted quit only wakes its originals. A
        // settled, closed Unknown session can ask for first consent; this never
        // repairs that session, replaces unresolved work or repeats shutdown.
        if !quit_question_admitted(&state) {
            if let Some(quit) = &state.quit { quit.wake.notify_one(); } return;
        }
        let id = match self.next_operation(&mut state) { Ok(id) => id, Err(_) => return };
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if self.installed_record_original(&owner, None).is_err() { state.unknown = true; self.bump(&mut state); return; }
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
        fixture_event!(owner, CoordinatorRegistered, 1);
        self.bump(&mut state); drop(book); drop(state); drop(previous); let _ = start.send(());
    }
}

#[cfg(feature = "desktop-shell")]
async fn run_quit(document: DocumentBinding, owner: Arc<OriginalWork>, app: tauri::AppHandle) {
    let dialog = crate::shell::run_owned_dialog(&app, &owner, crate::shell::DialogChoice::Quit, None);
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
    // Actual OK already latched STOP on the asset slot. Start all shutdown
    // futures once, even if the original quit dialog is still being disposed.
    // join! does not short-circuit an error or abandon any original future.
    let settlement = async {
        let gui = async { if !dialog_ended { let _ = dialog.as_mut().await; } };
        let _ = tokio::join!(gui, document.shutdown_assets(), document.inner.bridge.supervisor.shutdown(), document.inner.bridge.edits.shutdown(), document.inner.bridge.diagnostics.shutdown(), document.inner.bridge.preflight.shutdown(), document.inner.bridge.android_build.shutdown());
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
    while !(document.retained_material_can_exit() && document.inner.bridge.supervisor.can_exit() && document.inner.bridge.edits.can_exit() && document.inner.bridge.diagnostics.can_exit() && document.inner.bridge.preflight.can_exit() && document.inner.bridge.android_build.can_exit()) {
        tokio::select! {
            _ = owner.wake.notified() => document.tick(),
            _ = tokio::time::sleep(Duration::from_millis(50)) => document.tick(),
        }
    }
    // The fixed data-only exit observer will join this ORIGINAL coordinator and
    // the original relay before setting exit_ready. No task self-join, inline
    // GTK dispatch or body-ended flag is substituted for those joins.
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
mod installed_macos_observation {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SelectionCustody { Bound, Unavailable, Inconsistent }
    impl SelectionCustody {
        pub(crate) fn label(self) -> &'static str { match self {
            Self::Bound => "bound-original-data", Self::Unavailable => "unavailable-original-data",
            Self::Inconsistent => "inconsistent-original-data",
        }}
    }
    // Short-lived, bounded return companion, not a ProjectWitness, native
    // owner or serializable DTO. Only fixed relational labels may be exported.
    pub(crate) struct ProjectSelectionData {
        operation_id: u32, returned: Option<Project>, custody: SelectionCustody,
        selected: Option<std::path::PathBuf>, identity: Option<[u64; 5]>,
    }
    pub(crate) fn selection_path_bounded(path: &std::path::Path) -> bool {
        path.to_str().is_some_and(|text| text.len() <= asset_source::PATH_LIMIT && text.starts_with('/')
            && !text.as_bytes().contains(&0) && (text == "/" || text[1..].split('/').all(|part|
                !part.is_empty() && part != "." && part != ".." && part.len() <= 255)))
    }
    fn selection_project_bounded(project: &Project) -> bool {
        crate::protocol::valid_id(&project.id) && project.name.len() <= 255
            && selection_path_bounded(std::path::Path::new(&project.path))
    }
    fn recorded_identity(root: &asset_source::RegisteredRoot) -> Option<[u64; 5]> {
        // Pure projection of stored scalars. Fixture index5/nlink is NOT part
        // of RegisteredRoot; dev/ino stay lossless u64s, never JSON numbers.
        let identity = root.identity.posix().ok()?.preflight_identity();
        Some([identity.device.parse().ok()?, identity.inode.parse().ok()?,
            u64::from(identity.mode), u64::from(identity.uid), u64::from(identity.gid)])
    }
    fn saved_project_selection(id: u32, original_bound: bool, project: &Project,
        response: Option<&InstalledNativeResponseWitness>, registration: Option<&(u32, asset_source::RegisteredRoot)>) -> ProjectSelectionData {
        let mut data = ProjectSelectionData { operation_id: id, returned: None, custody: SelectionCustody::Inconsistent,
            selected: None, identity: None };
        if !original_bound || id == 0 || !selection_project_bounded(project) { return data; }
        data.returned = Some(project.clone());
        // These independent axes describe saved response/registry facts, even
        // if their transfer is inconsistent. A foreign response id never
        // supplies a selected path; an absent registration supplies no inode.
        data.selected = response.filter(|saved| saved.operation_id == id && saved.response == NativeResponse::Accept)
            .and_then(|saved| saved.selected.as_deref()).filter(|path| selection_path_bounded(path))
            .map(std::path::Path::to_path_buf);
        data.identity = registration.and_then(|(_, root)| recorded_identity(root));
        let inconsistent = response.is_some_and(|saved| saved.operation_id != id || saved.response != NativeResponse::Accept
                || !saved.callback_returned || saved.selected.as_deref().and_then(std::path::Path::to_str) != Some(project.path.as_str()))
            || registration.is_some_and(|(generation, root)| *generation != 2 || root.path.to_str() != Some(project.path.as_str()));
        data.custody = if inconsistent { SelectionCustody::Inconsistent }
            else if response.is_none() || registration.is_none() || data.identity.is_none() { SelectionCustody::Unavailable }
            else { SelectionCustody::Bound };
        data
    }
    impl ProjectSelectionData {
        pub(crate) fn for_result(&self, id: u32, returned: &Project) -> (SelectionCustody, Option<[u64; 5]>, Option<&std::path::Path>) {
            // The shell must carry this companion with that SAME public
            // result. Neither a replaced slot nor renderer id is queried here.
            if self.operation_id != id || !self.returned.as_ref().is_some_and(|project| same_project(project, returned)) {
                return (SelectionCustody::Inconsistent, None, None);
            }
            (self.custody, self.identity, self.selected.as_deref())
        }
    }
    pub(super) fn capture_project_selection(document: &Arc<Inner>, id: u32, slot: &Slot, project: &Project) -> ProjectSelectionData {
        // Called only under project_result_original's existing document guard,
        // immediately before its selected return. No extra lifecycle gate:
        // later owner.ended/joins/edit readiness cannot hide these saved facts.
        let original_bound = slot.operation == Operation::ChooseProject && slot.owner.id == id && original_call(document, &slot.owner)
            && slot.project.as_ref().is_some_and(|saved| same_project(saved, project));
        if !original_bound { return saved_project_selection(id, false, project, None, None); }
        let response = slot.owner.gui.installed_native_response().ok().flatten();
        let registration = if selection_project_bounded(project) { document.bridge.native_project(&project.id).ok() } else { None };
        saved_project_selection(id, original_bound, project, response.as_ref(), registration.as_ref())
    }
    pub(crate) fn selection_saved_data_checks() -> bool {
        // Synthetic stored DATA only. No document/bridge, native object, task,
        // probe, ProjectWitness or runtime is made. These are not receipts.
        let owner = OriginalWork::new(2, false, Weak::new());
        let Ok(mut coordinator) = owner.coordinator.lock() else { return false; };
        coordinator.receipt = JoinReceipt::Returned; drop(coordinator);
        let project = Project { id: "project-1".into(), name: "other".into(), path: "/synthetic/other".into() };
        let root = asset_source::RegisteredRoot { path: project.path.clone().into(), identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        let registration = (2, root);
        let response = InstalledNativeResponseWitness { operation_id: 2, response: NativeResponse::Accept,
            selected: Some(project.path.clone().into()), callback_returned: true };
        let Ok(mut saved) = owner.gui.installed_native_response_witness.lock() else { return false; };
        *saved = Some(response.clone()); drop(saved);
        let Ok(saved) = owner.gui.installed_native_response() else { return false; };
        // The immediate resources_settled predicate can be true while the
        // unchanged completed() predicate's ended/probed-child requirements
        // are false. A synthetic positive binding tests only DATA reduction.
        if !owner.resources_settled() || owner.ended.load(Ordering::SeqCst)
            || !owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::New) { return false; }
        let data = saved_project_selection(2, true, &project, saved.as_ref(), Some(&registration));
        if data.for_result(2, &project) != (SelectionCustody::Bound, Some([1, 2, 0o40700, 123, 123]), Some(std::path::Path::new(&project.path)))
            || owner.ended.load(Ordering::SeqCst) || owner.project_path_settled(true) { return false; }
        for (native, registered, custody, has_identity, has_path) in [
            (None, Some(&registration), SelectionCustody::Unavailable, true, false),
            (Some(&response), None, SelectionCustody::Unavailable, false, true),
            (None, None, SelectionCustody::Unavailable, false, false),
        ] {
            let data = saved_project_selection(2, true, &project, native, registered);
            let (actual, identity, path) = data.for_result(2, &project);
            if actual != custody || identity.is_some() != has_identity || path.is_some() != has_path { return false; }
        }
        for (response, expected_path) in [
            (InstalledNativeResponseWitness { operation_id: 3, ..response.clone() }, None),
            (InstalledNativeResponseWitness { response: NativeResponse::Decline, ..response.clone() }, None),
            (InstalledNativeResponseWitness { selected: None, ..response.clone() }, None),
            (InstalledNativeResponseWitness { selected: Some("/synthetic/first-save".into()), ..response.clone() }, Some(std::path::Path::new("/synthetic/first-save"))),
            (InstalledNativeResponseWitness { callback_returned: false, ..response.clone() }, Some(std::path::Path::new("/synthetic/other"))),
        ] {
            let data = saved_project_selection(2, true, &project, Some(&response), Some(&registration));
            if data.for_result(2, &project) != (SelectionCustody::Inconsistent, Some([1, 2, 0o40700, 123, 123]), expected_path) { return false; }
        }
        for registration in [(3, registration.1.clone()), (2, asset_source::RegisteredRoot { path: "/synthetic/unrelated".into(), ..registration.1.clone() })] {
            if saved_project_selection(2, true, &project, Some(&response), Some(&registration)).for_result(2, &project).0
                != SelectionCustody::Inconsistent { return false; }
        }
        let foreign = saved_project_selection(2, false, &project, Some(&response), Some(&registration));
        if foreign.for_result(2, &project) != (SelectionCustody::Inconsistent, None, None)
            || data.for_result(1, &project) != (SelectionCustody::Inconsistent, None, None) { return false; }
        for changed in [Project { id: "project-2".into(), ..project.clone() }, Project { name: "changed".into(), ..project.clone() },
            Project { path: "/synthetic/changed".into(), ..project.clone() }] {
            if data.for_result(2, &changed) != (SelectionCustody::Inconsistent, None, None) { return false; }
        }
        let maximum = format!("/{}", vec!["x".repeat(255); 16].join("/"));
        if maximum.len() != asset_source::PATH_LIMIT || !selection_path_bounded(std::path::Path::new(&maximum))
            || selection_path_bounded(std::path::Path::new(&(maximum + "/x"))) { return false; }
        for path in ["relative", "/bad/../path", "/bad//path", "/bad/path/", "/bad/\0path"] {
            let malformed = Project { path: path.into(), ..project.clone() };
            if selection_path_bounded(std::path::Path::new(path))
                || saved_project_selection(2, true, &malformed, Some(&response), Some(&registration)).for_result(2, &malformed)
                    != (SelectionCustody::Inconsistent, None, None) { return false; }
        }
        true
    }
    pub(crate) struct ProjectWitness {
        document: Weak<Inner>, owner: Weak<OriginalWork>, project: Project,
        generation: u32, root: asset_source::RegisteredRoot, edit: crate::edit_owner::InstalledMacDocumentWitness,
    }
    pub(crate) struct PickerWitness {
        document: Weak<Inner>, owner: Weak<OriginalWork>, generation: u32,
        edit: crate::edit_owner::InstalledMacDocumentWitness,
    }
    // These observations neither reconcile/publish the document nor acquire a
    // source or GUI owner. The ordinary relay and coordinators own all joins.
    fn quiet(state: &DocumentState) -> bool {
        !state.unknown && !state.exhausted && !state.retiring && !state.session && !state.lock_pending
            && !state.compatibility_picker_pending && state.context.is_none() && state.records.is_empty()
            && state.assignments.is_empty() && !state.github.native_work_pending() && state.github.material_settled()
            && state.github.registration().is_none() && state.evidence.epoch == 0
            && state.evidence.selection.is_none() && state.evidence.operation.is_none() && state.evidence.result.is_none()
    }
    fn live(state: &DocumentState) -> bool {
        quiet(state) && state.lifetime.original_bound() && !state.lost_observed && !state.stopping
            && !state.quit_pending && !state.quit_accepted && !state.evidence.revoked
    }
    fn same_document(document: &Arc<Inner>, witness: &Weak<Inner>) -> bool {
        witness.upgrade().is_some_and(|original| Arc::ptr_eq(document, &original))
    }
    fn original_call(document: &Arc<Inner>, owner: &Arc<OriginalWork>) -> bool {
        same_document(document, &owner.gui.document)
            && owner.gui.owner().is_some_and(|original| Arc::ptr_eq(owner, &original))
    }
    fn project_slot(slot: &Slot) -> bool {
        slot.operation == Operation::ChooseProject && slot.source == SourceState::NotRun
            && slot.context.is_none() && slot.target.is_none() && slot.candidate.is_none() && slot.selection.is_none()
            && slot.assessment.is_none() && slot.preview.is_none() && slot.assessment_context_revision.is_none()
            && slot.staged.is_none() && slot.kind.is_none() && slot.result_record.is_none() && slot.retired_payload.is_none()
            && slot.evidence.is_none() && slot.project_path.is_none() && slot.path_result.is_none()
    }
    fn settled_slot(slot: &Slot) -> bool {
        project_slot(slot) && slot.phase == Phase::Idle && slot.settlement == Settlement::Known && slot.error.is_none()
    }
    fn completed(document: &Arc<Inner>, owner: &Arc<OriginalWork>, response: NativeResponse,
        probed: bool, quit: bool) -> Option<InstalledNativeResponseWitness> {
        if !original_call(document, owner) || !owner.ended.load(Ordering::SeqCst) || !owner.resources_settled()
            || !owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
            || !owner.child.try_lock().is_ok_and(|book| book.handle.is_none()
                && book.receipt == if probed { JoinReceipt::Returned } else { JoinReceipt::New })
            || !owner.source.try_lock().is_ok_and(|book| if probed { !book.not_started() && book.settled() } else { book.not_started() }) {
            return None;
        }
        let witness = owner.gui.installed_native_response().ok()??;
        if witness.operation_id != owner.id || witness.response != response || !witness.callback_returned
            || !owner.gui.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.constructing
                && !facts.showing && !facts.not_created && facts.response && facts.refusal.is_none()
                && facts.accepted == (response == NativeResponse::Accept)
                // Production records genuine Project Cancel only in the
                // original response witness, not GuiFacts.declined.
                && facts.declined == (quit && response == NativeResponse::Decline)
                && facts.accepted_at.is_some() == (response == NativeResponse::Accept)
                && facts.selected.is_none() && facts.destroyed && facts.close_queued && facts.close_ack
                && facts.release_queued && facts.released) { return None; }
        Some(witness)
    }
    fn same_project(left: &Project, right: &Project) -> bool {
        left.id == right.id && left.name == right.name && left.path == right.path
    }
    impl DocumentBinding {
        pub(crate) async fn installed_macos_project_result(&self, id: u32, selection: &mut Option<ProjectSelectionData>) -> Result<Option<Project>, AssetError> {
            *selection = None;
            self.project_result_original(id, Some(selection)).await
        }
        fn macos_registered(&self, witness: &ProjectWitness) -> bool {
            // Call only under this actual document's admission mutex.
            let Ok(roster) = self.inner.bridge.native_roster() else { return false; };
            let Ok((generation, root)) = self.inner.bridge.native_project(&witness.project.id) else { return false; };
            roster.generation == witness.generation && generation == witness.generation && roster.roots.len() == 1
                && root == witness.root && roster.roots[0] == witness.root
                && root.path.to_str() == Some(witness.project.path.as_str())
        }
        fn macos_selected(&self, state: &DocumentState, witness: &ProjectWitness) -> bool {
            let (Some(slot), Some(owner)) = (&state.slot, witness.owner.upgrade()) else { return false; };
            same_document(&self.inner, &witness.document) && Arc::ptr_eq(&slot.owner, &owner)
                && settled_slot(slot) && slot.project.as_ref().is_some_and(|project| same_project(project, &witness.project))
                && self.macos_registered(witness)
                && completed(&self.inner, &owner, NativeResponse::Accept, true, false)
                    .is_some_and(|response| response.selected.as_deref() == Some(witness.root.path.as_path()))
        }
        fn macos_project_loss(&self, state: &DocumentState, witness: &ProjectWitness) -> bool {
            quiet(state) && state.lost_observed && !state.lifetime.original_bound() && state.evidence.revoked
                && self.macos_selected(state, witness) && assets_can_exit_locked(state)
                && state.slot.as_ref().is_some_and(|slot| slot.reason == Reason::DocumentLost
                    && slot.owner.stopped() && slot.cleanup_end.is_some() && slot.discard)
                && self.inner.bridge.edits.installed_macos_document_lost(&witness.edit) && self.inner.bridge.edits.can_exit()
        }
        fn macos_picker_loss(&self, state: &DocumentState, witness: &PickerWitness) -> bool {
            let (Some(slot), Some(owner)) = (&state.slot, witness.owner.upgrade()) else { return false; };
            quiet(state) && state.lost_observed && !state.lifetime.original_bound() && state.evidence.revoked
                && same_document(&self.inner, &witness.document) && Arc::ptr_eq(&slot.owner, &owner)
                && settled_slot(slot) && slot.project.is_none() && slot.reason == Reason::DocumentLost
                && slot.owner.stopped() && slot.cleanup_end.is_some() && slot.review_end.is_none() && slot.discard
                && assets_can_exit_locked(state)
                && completed(&self.inner, &owner, NativeResponse::Other, false, false)
                    .is_some_and(|response| response.selected.is_none())
                && self.inner.bridge.native_roster().is_ok_and(|roster| roster.generation == witness.generation && roster.roots.is_empty())
                && self.inner.bridge.edits.installed_macos_document_lost(&witness.edit) && self.inner.bridge.edits.can_exit()
        }
        pub(crate) fn installed_macos_live(&self) -> bool {
            let Ok(state) = self.inner.state.try_lock() else { return false; };
            // Bootstrap is the actual WK/edit binding, not availability of
            // Android, preflight or another unsupported service/profile.
            live(&state) && state.next_operation == 0 && state.slot.is_none() && state.quit.is_none()
                && self.inner.bridge.edits.installed_macos_document().is_some()
                && self.inner.bridge.native_roster().is_ok_and(|roster| roster.generation == 1 && roster.roots.is_empty())
        }
        pub(crate) fn installed_macos_cancelled(&self, id: u32) -> Option<InstalledNativeResponseWitness> {
            let state = self.inner.state.try_lock().ok()?; let slot = state.slot.as_ref()?;
            if !live(&state) || state.next_operation != id || state.quit.is_some() || slot.owner.id != id
                || !settled_slot(slot) || slot.project.is_some() || slot.reason != Reason::UserCancelled
                || !slot.owner.stopped() || slot.cleanup_end.is_none() || slot.review_end.is_some() || !slot.discard
                || self.inner.bridge.edits.installed_macos_document().is_none() || !self.inner.bridge.edits.can_exit()
                || !self.inner.bridge.native_roster().is_ok_and(|roster| roster.generation == 1 && roster.roots.is_empty()) { return None; }
            let response = completed(&self.inner, &slot.owner, NativeResponse::Decline, false, false)?;
            response.selected.is_none().then_some(response)
        }
        pub(crate) fn installed_macos_project(&self, id: u32) -> Option<(Project, ProjectWitness, InstalledNativeResponseWitness)> {
            let state = self.inner.state.try_lock().ok()?; let slot = state.slot.as_ref()?;
            if !live(&state) || state.next_operation != id || state.quit.is_some() || slot.owner.id != id
                || !settled_slot(slot) || slot.reason != Reason::None || slot.owner.stopped()
                || slot.cleanup_end.is_some() || slot.discard || !self.inner.bridge.edits.can_exit() { return None; }
            let project = slot.project.as_ref()?;
            let response = completed(&self.inner, &slot.owner, NativeResponse::Accept, true, false)?;
            let (generation, root) = self.inner.bridge.native_project(&project.id).ok()?;
            if generation != 2 || response.selected.as_deref() != Some(root.path.as_path()) { return None; }
            let witness = ProjectWitness { document: Arc::downgrade(&self.inner), owner: Arc::downgrade(&slot.owner),
                project: project.clone(), generation, root, edit: self.inner.bridge.edits.installed_macos_document()? };
            self.macos_registered(&witness).then(|| (project.clone(), witness, response))
        }
        pub(crate) fn installed_macos_picker_pending(&self, id: u32) -> Option<PickerWitness> {
            let state = self.inner.state.try_lock().ok()?; let slot = state.slot.as_ref()?; let owner = &slot.owner;
            if !live(&state) || state.next_operation != id || state.quit.is_some() || owner.id != id || !project_slot(slot)
                || slot.phase != Phase::Picking || slot.settlement != Settlement::Pending || slot.reason != Reason::None
                || slot.error.is_some() || slot.project.is_some() || slot.cleanup_end.is_some() || slot.review_end.is_some() || slot.discard
                || owner.stopped() || owner.endpoint().is_some() || owner.ended.load(Ordering::SeqCst) || !original_call(&self.inner, owner)
                || !owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Pending && book.handle.is_some())
                || !owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::New && book.handle.is_none())
                || !owner.source.try_lock().is_ok_and(|book| book.not_started())
                || owner.gui.installed_native_response().ok()?.is_some()
                || !owner.gui.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.constructing
                    && facts.showing && !facts.response && !facts.accepted && !facts.declined && facts.accepted_at.is_none()
                    && facts.refusal.is_none() && facts.selected.is_none() && !facts.not_created && !facts.destroyed
                    && !facts.close_queued && !facts.close_ack && !facts.release_queued && !facts.released)
                || !self.inner.bridge.edits.can_exit() { return None; }
            let roster = self.inner.bridge.native_roster().ok()?;
            if roster.generation != 1 || !roster.roots.is_empty() { return None; }
            Some(PickerWitness { document: Arc::downgrade(&self.inner), owner: Arc::downgrade(owner), generation: roster.generation,
                edit: self.inner.bridge.edits.installed_macos_document()? })
        }
        pub(crate) fn installed_macos_quit_cancelled(&self, id: u32, project: &ProjectWitness) -> Option<InstalledNativeResponseWitness> {
            let state = self.inner.state.try_lock().ok()?; let quit = state.quit.as_ref()?;
            if !live(&state) || state.next_operation != id || quit.id != id || !quit.stopped() || quit.endpoint().is_some()
                || state.quit_cleanup_end.is_some() || !self.macos_selected(&state, project)
                || !state.slot.as_ref().is_some_and(|slot| slot.owner.id < id && slot.reason == Reason::None
                    && !slot.owner.stopped() && slot.cleanup_end.is_none() && !slot.discard)
                || !self.inner.bridge.edits.installed_macos_document_live(&project.edit) { return None; }
            let response = completed(&self.inner, quit, NativeResponse::Decline, false, true)?;
            response.selected.is_none().then_some(response)
        }
        pub(crate) fn installed_macos_picker_lost(&self, witness: &PickerWitness) -> bool {
            self.inner.state.try_lock().is_ok_and(|state| self.macos_picker_loss(&state, witness))
        }
        pub(crate) fn installed_macos_project_lost(&self, witness: &ProjectWitness) -> bool {
            self.inner.state.try_lock().is_ok_and(|state| self.macos_project_loss(&state, witness))
        }
        pub(crate) fn installed_macos_final(&self, id: u32, project: Option<&ProjectWitness>, picker: Option<&PickerWitness>, lost: bool) -> bool {
            let Ok(state) = self.inner.state.try_lock() else { return false; }; let Some(quit) = &state.quit else { return false; };
            // quit_pending is a UI admission flag. The normal exit observer
            // may join this quit before the relay clears that flag; ORIGINAL
            // positive joins/resources below, not flag timing, prove finality.
            if !quiet(&state) || !state.stopping || !state.quit_accepted || state.next_operation != id || quit.id != id
                || state.quit_cleanup_end.is_none() || !quit.stopped() || !assets_can_exit_locked(&state)
                || !state.slot.as_ref().is_some_and(|slot| slot.owner.id < id)
                || !state.evidence.revoked
                || !completed(&self.inner, quit, NativeResponse::Accept, false, true).is_some_and(|response| response.selected.is_none()) { return false; }
            let original = match (project, picker, lost) {
                (Some(project), None, false) => state.lifetime.original_bound() && !state.lost_observed
                    && self.macos_selected(&state, project) && self.inner.bridge.edits.installed_macos_document_live(&project.edit)
                    && state.slot.as_ref().is_some_and(|slot| slot.reason == Reason::Shutdown
                        && slot.owner.stopped() && slot.cleanup_end.is_some() && slot.discard),
                (Some(project), None, true) => self.macos_project_loss(&state, project),
                (None, Some(picker), true) => self.macos_picker_loss(&state, picker),
                _ => false,
            };
            original && !self.inner.bridge.supervisor.disabled() && !self.inner.bridge.edits.disabled()
                && !self.inner.bridge.diagnostics.disabled() && !self.inner.bridge.preflight.disabled() && !self.inner.bridge.android_build.disabled()
                && self.inner.bridge.supervisor.can_exit() && self.inner.bridge.edits.can_exit() && self.inner.bridge.diagnostics.can_exit()
                && self.inner.bridge.preflight.can_exit() && self.inner.bridge.android_build.can_exit()
        }
        pub(crate) fn installed_macos_safe_quit(&self) -> bool {
            // Existing ordinary admission only; never reset Unknown/STOP,
            // create consent, retry a retained panel or replace an owner.
            self.inner.state.try_lock().is_ok_and(|state| quit_question_admitted(&state))
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
    target_os = "macos", target_arch = "aarch64"))]
pub(crate) use installed_macos_observation::{ProjectWitness as InstalledMacProjectWitness, PickerWitness as InstalledMacPickerWitness,
    ProjectSelectionData as InstalledMacProjectSelectionData, SelectionCustody as InstalledMacSelectionCustody,
    selection_path_bounded as installed_macos_selection_path_bounded, selection_saved_data_checks as installed_macos_selection_saved_data_checks};

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod installed_project_observation {
    use super::*;
    pub(crate) struct ProjectWitness {
        project_id: String, generation: u32, root: asset_source::RegisteredRoot,
    }
    pub(crate) struct EvidenceWitness {
        pub(crate) selection: evidence_wire::Selection,
        root: asset_source::RegisteredRoot, epoch: u64,
    }
    // Private DATA observations of the existing originals only. No fixture
    // publication, source path opening, permission, worker or new native owner.
    fn live_closed_document(state: &DocumentState, operation: u32) -> bool {
        state.lifetime.original_bound() && !state.lost_observed && !state.unknown && !state.exhausted
            && !state.stopping && !state.retiring && !state.session && !state.lock_pending
            && !state.quit_pending && !state.quit_accepted && state.quit.is_none()
            && !state.compatibility_picker_pending && state.next_operation == operation
            && state.context.is_none() && state.records.is_empty() && state.assignments.is_empty()
    }
    fn settled_project_slot(slot: &Slot, operation: u32) -> bool {
        slot.operation == Operation::ChooseProject && slot.owner.id == operation
            && slot.phase == Phase::Idle && slot.settlement == Settlement::Known
            && slot.owner.resources_settled() && slot.owner.coordinator.try_lock().is_ok_and(|book|
                book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && slot.staged.is_none() && slot.context.is_none() && slot.candidate.is_none()
            && slot.selection.is_none() && slot.preview.is_none() && slot.retired_payload.is_none()
    }
    fn completed_picker(slot: &Slot, accepted: bool) -> bool {
        slot.owner.gui.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.not_created
            && facts.response && facts.accepted == accepted && !facts.declined
            && facts.accepted_at.is_some() == accepted && facts.refusal.is_none()
            && facts.destroyed && facts.released && facts.close_ack && facts.selected.is_none())
        // The original chooser consumes its filename before the probe. A None
        // here is transfer/consumption, not proof of which filename was read;
        // the existing shell observer compares that actual read separately.
    }
    fn settled_evidence_slot(slot: &Slot, operation: u32, kind: Operation) -> bool {
        slot.operation == kind && slot.owner.id == operation && slot.project.is_none()
            && slot.phase == Phase::Idle && slot.settlement == Settlement::Known
            && slot.owner.resources_settled() && slot.owner.coordinator.try_lock().is_ok_and(|book|
                book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && slot.staged.is_none() && slot.context.is_none() && slot.candidate.is_none()
            && slot.selection.is_none() && slot.preview.is_none() && slot.retired_payload.is_none()
    }
    fn settled_path_slot(slot: &Slot, operation: u32, project: &ProjectWitness, field: commands::ProjectPathField) -> bool {
        slot.operation == Operation::ChooseProjectPath && slot.owner.id == operation
            && slot.project_path.as_ref().is_some_and(|binding| binding.project_id == project.project_id
                && binding.field == field && binding.generation == project.generation && binding.root == project.root)
            && slot.phase == Phase::Idle && slot.settlement == Settlement::Known
            && slot.owner.resources_settled() && slot.owner.coordinator.try_lock().is_ok_and(|book|
                book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && slot.staged.is_none() && slot.context.is_none() && slot.candidate.is_none()
            && slot.selection.is_none() && slot.preview.is_none() && slot.retired_payload.is_none()
            && slot.project.is_none() && slot.evidence.is_none() && slot.kind.is_none()
    }
    impl DocumentBinding {
        pub(super) fn observed_source_unchanged(&self, witness: &ProjectWitness) -> bool {
            let Ok(roster) = self.inner.bridge.native_roster() else { return false; };
            let Ok((generation, root)) = self.inner.bridge.native_project(&witness.project_id) else { return false; };
            generation == witness.generation && roster.generation == witness.generation
                && roster.roots.len() == 1 && roster.roots[0] == witness.root && root == witness.root
        }
        fn observed_runtime_idle(&self) -> bool {
            !self.inner.bridge.supervisor.disabled() && !self.inner.bridge.supervisor.stopping()
                && self.inner.bridge.supervisor.can_exit() && !self.inner.bridge.edits.disabled()
                && !self.inner.bridge.edits.stopping() && self.inner.bridge.edits.can_exit()
        }
        pub(crate) fn installed_observation_cancelled(&self) -> bool {
            self.reconcile(); let state = self.lock();
            live_closed_document(&state, 1) && state.slot.as_ref().is_some_and(|slot|
                settled_project_slot(slot, 1) && completed_picker(slot, false)
                    && slot.reason == Reason::UserCancelled && slot.project.is_none()
                    && slot.owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::New && book.handle.is_none())
                    && slot.owner.source.try_lock().is_ok_and(|book| book.not_started()))
                && self.inner.bridge.native_roster().is_ok_and(|roster| roster.generation == 1 && roster.roots.is_empty())
        }
        pub(crate) fn installed_observation_project(&self) -> Option<Project> {
            self.reconcile(); let state = self.lock(); let slot = state.slot.as_ref()?;
            if !live_closed_document(&state, 2) || !settled_project_slot(slot, 2) || !completed_picker(slot, true)
                || slot.reason != Reason::None || slot.error.is_some() || slot.cleanup_end.is_some() || slot.owner.stopped()
                || !slot.owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
                || !slot.owner.source.try_lock().is_ok_and(|book| !book.not_started() && book.settled()) { return None; }
            let project = slot.project.as_ref()?;
            let roster = self.inner.bridge.native_roster().ok()?;
            let (generation, root) = self.inner.bridge.native_project(&project.id).ok()?;
            if roster.generation != 2 || generation != roster.generation || roster.roots.len() != 1
                || root.path != roster.roots[0].path || root.identity != roster.roots[0].identity
                || root.path.to_str() != Some(project.path.as_str()) { return None; }
            // Genuine registered DTO for private opaque-id correspondence, not
            // a constructed fixture project and never exported as telemetry.
            Some(project.clone())
        }
        pub(crate) fn installed_observation_project_witness(&self, project: &Project) -> Option<ProjectWitness> {
            // Capture only after the existing real op2 proof, not by opening a
            // source path or creating substitute project-registration authority.
            let observed = self.installed_observation_project()?;
            if observed.id != project.id || observed.path != project.path { return None; }
            let state = self.lock();
            if !live_closed_document(&state, 2) || state.evidence.epoch != 0 || state.evidence.revoked
                || state.evidence.selection.is_some() || state.evidence.operation.is_some()
                || state.evidence.result.is_some() { return None; }
            let (generation, root) = self.inner.bridge.native_project(&project.id).ok()?;
            let witness = ProjectWitness { project_id: project.id.clone(), generation, root };
            self.observed_source_unchanged(&witness).then_some(witness)
        }
        pub(crate) fn installed_observation_path(&self, project: &ProjectWitness, operation: u32,
            field: commands::ProjectPathField, reason: Reason, relative: Option<&str>) -> bool {
            self.reconcile(); let state = self.lock();
            let Some(slot) = state.slot.as_ref() else { return false; };
            let cancelled = matches!(operation, 3 | 7);
            let selected = matches!(operation, 4 | 5 | 6 | 8);
            let source_started = !cancelled && operation != 9;
            let result = slot.path_result.as_ref().and_then(|value| serde_json::to_value(value).ok());
            let expected = relative.map(|path| serde_json::json!({"projectId":project.project_id,"field":field,"relativePath":path}));
            live_closed_document(&state, operation) && (3..=13).contains(&operation)
                && self.observed_source_unchanged(project) && self.observed_runtime_idle()
                && !state.github.native_work_pending() && !state.evidence.revoked && state.evidence.epoch == 0
                && state.evidence.selection.is_none() && state.evidence.operation.is_none() && state.evidence.result.is_none()
                && settled_path_slot(slot, operation, project, field) && slot.reason == reason && result == expected
                && selected == relative.is_some() && slot.owner.stopped() != selected
                && slot.owner.child.try_lock().is_ok_and(|book| book.handle.is_none()
                    && book.receipt == (if cancelled { JoinReceipt::New } else { JoinReceipt::Returned }))
                && slot.owner.source.try_lock().is_ok_and(|book| if source_started { !book.not_started() && book.settled() } else { book.not_started() })
                && slot.owner.gui.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.constructing
                    && !facts.not_created && facts.response && facts.accepted == !cancelled && facts.declined == cancelled
                    && facts.accepted_at.is_some() == !cancelled && facts.refusal.is_none() && facts.selected.is_none()
                    && facts.close_queued && facts.close_ack && facts.release_queued && facts.destroyed && facts.released)
        }
        pub(crate) fn installed_observation_paths_final(&self, project: &ProjectWitness) -> bool {
            let state = self.lock();
            state.lifetime.original_bound() && !state.lost_observed && !state.unknown && !state.exhausted
                && state.next_operation == 14 && state.stopping && state.quit_accepted
                && !state.session && !state.lock_pending && state.context.is_none()
                && state.records.is_empty() && state.assignments.is_empty() && assets_can_exit_locked(&state)
                && self.observed_source_unchanged(project) && !state.github.native_work_pending()
                && state.evidence.revoked && state.evidence.selection.is_none() && state.evidence.result.is_none()
                && state.slot.as_ref().is_some_and(|slot| settled_path_slot(slot, 13, project, commands::ProjectPathField::IosWorkspace)
                    && slot.path_result.is_none() && slot.owner.child.try_lock().is_ok_and(|book|
                        book.receipt == JoinReceipt::Returned && book.handle.is_none())
                    && slot.owner.source.try_lock().is_ok_and(|book| !book.not_started() && book.settled()))
                && state.quit.as_ref().is_some_and(|quit| quit.id == 14 && quit.resources_settled()
                    && quit.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()))
        }
        pub(crate) fn installed_observation_evidence_cancelled(&self, project: &ProjectWitness) -> bool {
            self.reconcile(); let state = self.lock();
            let Some(slot) = state.slot.as_ref() else { return false; };
            live_closed_document(&state, 3) && self.observed_source_unchanged(project) && self.observed_runtime_idle()
                && !state.github.native_work_pending() && settled_evidence_slot(slot, 3, Operation::ChooseEvidenceFolder)
                && completed_picker(slot, false) && slot.reason == Reason::UserCancelled
                && slot.owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
                && slot.owner.source.try_lock().is_ok_and(|book| book.not_started())
                && !state.evidence.revoked && state.evidence.epoch == 1 && state.evidence.matches(slot)
                && state.evidence.selection.is_none() && state.evidence.result.is_none()
                && evidence_snapshot(&state, true).phase == evidence_wire::Phase::Cancelled
                && evidence_snapshot(&state, true).problem == Some(EvidenceProblem::Cancelled)
        }
        pub(crate) fn installed_observation_evidence_selected(&self, project: &ProjectWitness) -> Option<EvidenceWitness> {
            self.reconcile(); let state = self.lock(); let slot = state.slot.as_ref()?;
            if !live_closed_document(&state, 4) || !self.observed_source_unchanged(project) || !self.observed_runtime_idle()
                || state.github.native_work_pending() || !settled_evidence_slot(slot, 4, Operation::ChooseEvidenceFolder)
                || !completed_picker(slot, true) || slot.reason != Reason::None || slot.error.is_some()
                || slot.cleanup_end.is_some() || slot.owner.stopped()
                || !slot.owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
                || !slot.owner.source.try_lock().is_ok_and(|book| !book.not_started() && book.settled())
                || state.evidence.revoked || state.evidence.epoch != 2 || !state.evidence.matches(slot)
                || state.evidence.phase != evidence_wire::Phase::Selected || state.evidence.result.is_some()
                || state.evidence.problem.is_some() { return None; }
            let selected = state.evidence.selection.as_ref()?;
            if selected.epoch != state.evidence.epoch { return None; }
            Some(EvidenceWitness { selection: selected.view.clone(), root: selected.root.clone(), epoch: selected.epoch })
        }
        pub(crate) fn installed_observation_evidence_observed(&self, project: &ProjectWitness,
            evidence: &EvidenceWitness) -> Option<evidence_wire::Observation> {
            self.reconcile(); let state = self.lock(); let slot = state.slot.as_ref()?;
            let binding = slot.evidence.as_ref()?; let selected = state.evidence.selection.as_ref()?;
            if !live_closed_document(&state, 5) || !self.observed_source_unchanged(project) || !self.observed_runtime_idle()
                || state.github.native_work_pending() || !settled_evidence_slot(slot, 5, Operation::InspectEvidence)
                || slot.reason != Reason::None || slot.error.is_some() || slot.cleanup_end.is_some() || slot.owner.stopped()
                || !slot.owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::New && book.handle.is_none())
                || !slot.owner.source.try_lock().is_ok_and(|book| book.not_started())
                || !slot.owner.gui.facts().is_some_and(|facts| facts.not_created && !facts.dispatched && !facts.created && facts.released)
                || state.evidence.phase != evidence_wire::Phase::Observed || state.evidence.problem.is_some()
                || !state.evidence.matches(slot) || !state.evidence.selection_matches(binding)
                || selected.epoch != evidence.epoch || selected.root != evidence.root
                || selected.view.selection_id != evidence.selection.selection_id
                || selected.view.display_name != evidence.selection.display_name { return None; }
            // Publication follows the original passive query's successful
            // retirement, plus the real evidence coordinator/slot retirement.
            state.evidence.result.clone()
        }
        pub(crate) fn installed_observation_candidate_final(&self, project: &ProjectWitness) -> bool {
            let state = self.lock();
            state.lifetime.original_bound() && !state.lost_observed && !state.unknown && !state.exhausted
                && state.next_operation == 6 && state.stopping && state.quit_accepted
                && !state.session && !state.lock_pending && state.context.is_none()
                && state.records.is_empty() && state.assignments.is_empty() && assets_can_exit_locked(&state)
                && self.observed_source_unchanged(project) && !state.github.native_work_pending()
                && state.evidence.revoked && state.evidence.selection.is_none() && state.evidence.result.is_none()
                && state.slot.as_ref().is_some_and(|slot| settled_evidence_slot(slot, 5, Operation::InspectEvidence)
                    && state.evidence.matches(slot) && slot.owner.child.try_lock().is_ok_and(|book|
                        book.receipt == JoinReceipt::New && book.handle.is_none())
                    && slot.owner.source.try_lock().is_ok_and(|book| book.not_started()))
                && state.quit.as_ref().is_some_and(|quit| quit.id == 6 && quit.resources_settled()
                    && quit.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()))
        }
        pub(crate) fn installed_observation_final(&self) -> bool {
            let state = self.lock();
            state.lifetime.original_bound() && !state.lost_observed && !state.unknown && !state.exhausted
                && state.next_operation == 3 && state.stopping && state.quit_accepted
                && !state.session && !state.lock_pending && state.context.is_none()
                && state.records.is_empty() && state.assignments.is_empty() && assets_can_exit_locked(&state)
                && state.slot.as_ref().is_some_and(|slot| settled_project_slot(slot, 2) && slot.project.is_some())
                && state.quit.as_ref().is_some_and(|quit| quit.id == 3 && quit.resources_settled()
                    && quit.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()))
        }
    }
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use installed_project_observation::{ProjectWitness as InstalledProjectWitness, EvidenceWitness as InstalledEvidenceWitness};

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod installed_session_observation {
    use super::*;
    use crate::{shell::installed_observation::SessionCase, supervisor::{InstalledSessionQueryDiagnostic, SessionQueryHold}};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum OriginDetail { None, Deadline, ReviewExpired, ContextStale, CleanupUnknown, UserCancelled, Shutdown,
        DocumentLost, Other, New, Pending, Returned, Failed, Unavailable }
    impl OriginDetail {
        fn reason(reason: Reason) -> Self {
            match reason {
                Reason::Deadline => Self::Deadline, Reason::ReviewExpired => Self::ReviewExpired,
                Reason::ContextStale => Self::ContextStale, Reason::CleanupUnknown => Self::CleanupUnknown,
                Reason::UserCancelled => Self::UserCancelled, Reason::Shutdown => Self::Shutdown,
                Reason::DocumentLost => Self::DocumentLost, _ => Self::Other,
            }
        }
        fn child(receipt: Option<JoinReceipt>) -> Self {
            match receipt {
                Some(JoinReceipt::New) => Self::New, Some(JoinReceipt::Pending) => Self::Pending,
                Some(JoinReceipt::Returned) => Self::Returned, Some(JoinReceipt::Failed) => Self::Failed,
                None => Self::Unavailable,
            }
        }
        fn token(self) -> &'static [u8] {
            match self {
                Self::None => b"none", Self::Deadline => b"deadline", Self::ReviewExpired => b"review-expired",
                Self::ContextStale => b"context-stale", Self::CleanupUnknown => b"cleanup-unknown",
                Self::UserCancelled => b"user-cancelled", Self::Shutdown => b"shutdown", Self::DocumentLost => b"document-lost",
                Self::Other => b"other", Self::New => b"new", Self::Pending => b"pending", Self::Returned => b"returned",
                Self::Failed => b"failed", Self::Unavailable => b"unavailable",
            }
        }
    }
    impl UnknownOrigin {
        fn token(self) -> &'static [u8] {
            match self {
                Self::NotRecorded => b"not-recorded", Self::OperationCleanup(_) => b"op-cleanup", Self::Registry => b"registry",
                Self::CoordinatorLock => b"coord-lock", Self::CoordinatorJoin => b"coord-join",
                Self::SupervisorDisabled => b"supervisor-disabled", Self::StagedCollision => b"staged-collision",
                Self::InstallRetirement => b"install-retire", Self::RetirementRetain => b"retain-retire",
                Self::RetirementDrain => b"drain-retire", Self::StagedRefusal => b"staged-refusal",
                Self::GatePoisoned => b"gate-poisoned", Self::Exhausted => b"exhausted",
            }
        }
    }
    pub(super) struct FirstOrigin {
        origin: UnknownOrigin, detail: OriginDetail, original: Option<Weak<OriginalWork>>,
    }
    impl FirstOrigin {
        pub(super) fn at_transition(origin: UnknownOrigin, original: Option<&Arc<OriginalWork>>) -> Option<Self> {
            if origin == UnknownOrigin::NotRecorded { return None; }
            let detail = match origin {
                UnknownOrigin::OperationCleanup(reason) => OriginDetail::reason(reason),
                UnknownOrigin::CoordinatorJoin => OriginDetail::Failed,
                UnknownOrigin::StagedRefusal => OriginDetail::child(original.and_then(|owner|
                    owner.child.try_lock().ok().map(|book| book.receipt))),
                _ => OriginDetail::None,
            };
            // Correlation only, not ownership or proof of the source of a
            // Supervisor-wide disablement. Never serialized or backfilled.
            Some(Self { origin, detail, original: original.map(Arc::downgrade) })
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Failure {
        origin: UnknownOrigin, detail: OriginDetail, bound: bool, query: InstalledSessionQueryDiagnostic,
    }
    impl Failure {
        pub(crate) const fn not_recorded() -> Self {
            Self { origin: UnknownOrigin::NotRecorded, detail: OriginDetail::None, bound: false,
                query: InstalledSessionQueryDiagnostic::not_applicable() }
        }
        pub(crate) fn origin_token(self) -> &'static [u8] { self.origin.token() }
        pub(crate) fn detail_token(self) -> &'static [u8] { self.detail.token() }
        pub(crate) fn association_token(self) -> &'static [u8] { if self.bound { b"bound" } else { b"unassociated" } }
        pub(crate) fn query_token(self) -> ([u8; 26], usize) { self.query.query_token() }
        pub(crate) fn worker_token(self) -> &'static [u8] { self.query.worker_token() }
        pub(crate) fn unknown_boundary_token(self) -> &'static [u8] { self.query.unknown_boundary_token() }
        // Pure closed-value example for the existing frame contract, never a
        // native receipt. These types exist only in the installed test build.
        pub(crate) fn contract_sample() -> Self {
            Self { origin: UnknownOrigin::SupervisorDisabled, detail: OriginDetail::None, bound: true,
                query: InstalledSessionQueryDiagnostic::contract_sample() }
        }
    }

    pub(super) struct Book {
        case: SessionCase, originals: Vec<(Arc<OriginalWork>, Option<Operation>)>, choose: u8, assess: u8,
        failure: Option<Failure>,
    }
    impl Book {
        pub(super) fn new(case: SessionCase) -> Self { Self { case, originals: Vec::new(), choose: 0, assess: 0, failure: None } }
        fn first_failure(&mut self, first: Option<&FirstOrigin>, query: impl FnOnce(&Weak<OriginalWork>) -> InstalledSessionQueryDiagnostic) -> Failure {
            if let Some(failure) = self.failure { return failure; }
            let failure = match first {
                Some(first) => Failure { origin: first.origin, detail: first.detail, bound: first.original.is_some(),
                    query: match &first.original { Some(original) => query(original), None => InstalledSessionQueryDiagnostic::not_applicable() } },
                None => Failure::not_recorded(),
            };
            // One projection at the existing first Unknown snapshot. Even
            // unavailable DATA is final here: no retry, wait or latest-owner
            // fallback if a book subsequently becomes accessible.
            self.failure = Some(failure); failure
        }
    }
    // No private material is copied. Native pointer/opaque-token equality is
    // private comparison DATA and must never enter an exported receipt.
    #[derive(Clone)]
    pub(crate) struct Snapshot {
        pub(crate) status: Value, pub(crate) owner: Option<Arc<OriginalWork>>,
        pub(crate) review_end: Option<Instant>, pub(crate) cleanup_end: Option<Instant>, pub(crate) work_end: Option<Instant>,
        pub(crate) payloads: Vec<(String, u32, usize)>, pub(crate) sources: Vec<(u32, asset_source::InstalledSourceFacts)>,
        pub(crate) settled: bool, pub(crate) lost: bool, pub(crate) bound: bool, pub(crate) unknown: bool,
        pub(crate) quit_pending: bool, pub(crate) quit_declined: bool, pub(crate) empty: bool,
        pub(crate) first_failure: Option<Failure>,
    }
    impl Snapshot {
        pub(crate) fn same_payloads(&self, other: &Self) -> bool { self.payloads == other.payloads }
        pub(crate) fn same_review(&self, other: &Self) -> bool {
            self.status["operation"]["preview"]["token"] == other.status["operation"]["preview"]["token"]
                && self.status["context"] == other.status["context"] && self.review_end == other.review_end
                && self.work_end == other.work_end && self.cleanup_end == other.cleanup_end
                && self.owner.as_ref().zip(other.owner.as_ref()).is_some_and(|(a,b)| Arc::ptr_eq(a,b))
        }
    }
    pub(super) fn assert_first_origin_contract() {
        // Inert association/formatting models under the existing selector.
        // No task, native source, query, GUI or original settlement is made.
        fn query(failure: Failure) -> Vec<u8> { let (bytes, length) = failure.query_token(); bytes[..length].to_vec() }
        let old = OriginalWork::new(1, false, Weak::new());
        let new = OriginalWork::new(2, false, Weak::new());
        let same_id = OriginalWork::new(2, false, Weak::new());
        let mut restored = super::tests::empty_state();
        restored.slot = Some(Slot::new(old.clone(), Operation::Prepare, None, None, None));
        let holding = new.retirement.try_lock().unwrap();
        let old_slot = restored.slot.take().map(Box::new);
        let retirement = match new.retain_retirement(Retirement { old_slot, ..Retirement::default() }) {
            Err(retirement) => retirement, Ok(()) => panic!("contended original holding was not refused"),
        };
        restore_failed_install_retirement(&mut restored, &new, retirement);
        drop(holding);
        assert!(restored.unknown && restored.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, &old)));
        first_unknown_origin!(restored, UnknownOrigin::Registry, Some(&old));
        let first = restored.first_origin.as_ref().unwrap();
        assert!(first.origin == UnknownOrigin::InstallRetirement
            && first.original.as_ref().is_some_and(|original| Weak::ptr_eq(original, &Arc::downgrade(&new))));

        let mut taken = super::tests::empty_state();
        taken.slot = Some(Slot::new(new.clone(), Operation::Prepare, None, None, None));
        let local = taken.slot.take().unwrap();
        first_unknown_origin!(taken, UnknownOrigin::CoordinatorJoin, Some(&local.owner));
        taken.unknown = true;
        assert!(taken.slot.is_none() && taken.first_origin.as_ref().is_some_and(|first|
            first.origin == UnknownOrigin::CoordinatorJoin && first.detail == OriginDetail::Failed
                && first.original.as_ref().is_some_and(|original| Weak::ptr_eq(original, &Arc::downgrade(&new)))));

        let mut admission = super::tests::empty_state();
        admission.slot = Some(Slot::new(old.clone(), Operation::Prepare, None, None, None));
        first_unknown_origin!(admission, UnknownOrigin::Registry, None);
        admission.unknown = true;
        let unassociated = Book::new(SessionCase::Inputs).first_failure(admission.first_origin.as_ref(), |_| panic!("pre-admission query lookup"));
        assert!(unassociated.origin_token() == b"registry" && unassociated.detail_token() == b"none"
            && unassociated.association_token() == b"unassociated" && query(unassociated) == b"na" && unassociated.worker_token() == b"na"
            && unassociated.unknown_boundary_token() == b"na");
        let mut unsupported = super::tests::empty_state(); unsupported.unknown = true;
        first_unknown_origin!(unsupported, UnknownOrigin::SupervisorDisabled, Some(&new));
        assert!(unsupported.first_origin.is_none());
        unsupported.unknown = false; unsupported.exhausted = true;
        first_unknown_origin!(unsupported, UnknownOrigin::Exhausted, Some(&new));
        assert!(unsupported.first_origin.is_none());
        let mut absent = Book::new(SessionCase::Inputs);
        let unavailable_origin = absent.first_failure(None, |_| panic!("absent-origin query lookup"));
        assert!(unavailable_origin == Failure::not_recorded());
        assert!(unavailable_origin.unknown_boundary_token() == b"na");
        assert!(absent.first_failure(restored.first_origin.as_ref(), |_| panic!("late origin backfill")) == unavailable_origin);

        let unavailable_query = crate::supervisor::assert_installed_session_query_diagnostic_contract(&new, &same_id);
        let mut book = Book::new(SessionCase::Inputs);
        let failure = book.first_failure(restored.first_origin.as_ref(), |original| {
            assert!(Weak::ptr_eq(original, &Arc::downgrade(&new))); unavailable_query
        });
        assert!(failure.association_token() == b"bound" && query(failure) == b"unavailable" && failure.worker_token() == b"unavailable"
            && failure.unknown_boundary_token() == b"unavailable");
        assert!(book.first_failure(taken.first_origin.as_ref(), |_| panic!("first failure was resampled")) == failure);
        let mut known_book = Book::new(SessionCase::Inputs);
        let known = known_book.first_failure(restored.first_origin.as_ref(), |_| InstalledSessionQueryDiagnostic::contract_sample());
        assert!(known.unknown_boundary_token() == b"settlement" && Failure::contract_sample().unknown_boundary_token() == b"settlement");
        assert!(known_book.first_failure(taken.first_origin.as_ref(), |_| panic!("known boundary was resampled")) == known);

        let mut expiry = super::tests::empty_state();
        expiry.slot = Some(Slot::new(new.clone(), Operation::Prepare, None, None, None));
        let slot = expiry.slot.as_mut().unwrap();
        let at = Instant::now(); slot.stop(Reason::ReviewExpired, at); let cleanup = slot.cleanup_end;
        slot.stop(Reason::Deadline, at + Duration::from_secs(1));
        first_unknown_origin!(expiry, UnknownOrigin::OperationCleanup(slot.reason), Some(&slot.owner));
        assert!(slot.reason == Reason::ReviewExpired && slot.cleanup_end == cleanup);
        assert!(expiry.first_origin.as_ref().is_some_and(|first| first.detail == OriginDetail::ReviewExpired));
        for (reason, token) in [(Reason::Deadline,b"deadline".as_slice()), (Reason::ReviewExpired,b"review-expired"),
            (Reason::ContextStale,b"context-stale"), (Reason::CleanupUnknown,b"cleanup-unknown"), (Reason::UserCancelled,b"user-cancelled"),
            (Reason::Shutdown,b"shutdown"), (Reason::DocumentLost,b"document-lost"), (Reason::None,b"other")] {
            assert!(OriginDetail::reason(reason).token() == token && token.len() <= 15);
        }
        for (receipt, token) in [(JoinReceipt::New,b"new".as_slice()), (JoinReceipt::Pending,b"pending"),
            (JoinReceipt::Returned,b"returned"), (JoinReceipt::Failed,b"failed")] {
            new.child.try_lock().unwrap().receipt = receipt;
            assert!(FirstOrigin::at_transition(UnknownOrigin::StagedRefusal, Some(&new)).unwrap().detail.token() == token);
        }
        let child = new.child.try_lock().unwrap();
        assert!(FirstOrigin::at_transition(UnknownOrigin::StagedRefusal, Some(&new)).unwrap().detail == OriginDetail::Unavailable);
        drop(child);
        for origin in [UnknownOrigin::NotRecorded, UnknownOrigin::OperationCleanup(Reason::Deadline), UnknownOrigin::Registry,
            UnknownOrigin::CoordinatorLock, UnknownOrigin::CoordinatorJoin, UnknownOrigin::SupervisorDisabled,
            UnknownOrigin::StagedCollision, UnknownOrigin::InstallRetirement, UnknownOrigin::RetirementRetain,
            UnknownOrigin::RetirementDrain, UnknownOrigin::StagedRefusal, UnknownOrigin::GatePoisoned, UnknownOrigin::Exhausted] {
            assert!(origin.token().len() <= 19 && origin.token().is_ascii());
        }
        assert!(FirstOrigin::at_transition(UnknownOrigin::NotRecorded, Some(&new)).is_none());
    }
    fn joined(owner: &OriginalWork) -> bool {
        owner.resources_settled() && owner.retired.load(Ordering::SeqCst)
            && owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
            && owner.child.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned) && book.handle.is_none())
            && owner.source.try_lock().is_ok_and(|book| book.not_started() || book.settled())
            && owner.gui.facts().is_some_and(|facts| facts.selected.is_none() && facts.released
                && (facts.not_created || facts.created && facts.response && facts.destroyed && facts.close_ack && facts.refusal.is_none()))
    }
    impl DocumentBinding {
        pub(super) fn installed_record_original(&self, owner: &Arc<OriginalWork>, operation: Option<Operation>) -> Result<(), AssetError> {
            let mut book = self.inner.installed_session.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
            let Some(book) = book.as_mut() else { return Ok(()); };
            if book.originals.len() >= 128 || book.originals.iter().any(|(old,_)| old.id == owner.id) { return Err(AssetError::new(Reason::Capacity)); }
            book.originals.try_reserve(1).map_err(|_| AssetError::new(Reason::Capacity))?;
            if operation == Some(Operation::ChooseFile) {
                book.choose = book.choose.checked_add(1).ok_or_else(AssetError::invalid)?;
                if book.case == SessionCase::Refusals && book.choose == 4 {
                    let checkpoint = Arc::new(asset_source::InstalledCaptureCheckpoint::default());
                    if !owner.source.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?.installed_checkpoint(checkpoint.clone()) {
                        return Err(AssetError::new(Reason::CleanupUnknown));
                    }
                    *owner.installed_capture.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))? = Some(checkpoint);
                }
            }
            if operation == Some(Operation::Prepare) {
                book.assess = book.assess.checked_add(1).ok_or_else(AssetError::invalid)?;
                let hold = match (book.case, book.assess) {
                    (SessionCase::Loss,1) => SessionQueryHold::Loss, (SessionCase::Deadline,1) => SessionQueryHold::Deadline,
                    _ => SessionQueryHold::Observe,
                };
                self.inner.bridge.supervisor.arm_installed_session_query(owner, hold).map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
            }
            book.originals.push((owner.clone(),operation)); Ok(())
        }
        pub(crate) fn installed_session_snapshot(&self) -> Option<Snapshot> {
            self.reconcile(); let state = self.lock();
            let mut book = self.inner.installed_session.lock().ok()?; let book = book.as_mut()?;
            let mut sources = Vec::new();
            for (owner,kind) in &book.originals {
                if *kind == Some(Operation::ChooseFile) {
                    if let Ok(source) = owner.source.try_lock() { sources.push((owner.id,source.installed_facts())); }
                }
            }
            let status = serde_json::to_value(self.snapshot(&state)).ok()?;
            let first_failure = (state.unknown || state.exhausted).then(|| book.first_failure(state.first_origin.as_ref(),
                |original| self.inner.bridge.supervisor.installed_session_query_diagnostic(original)));
            Some(Snapshot { status, owner: state.slot.as_ref().map(|slot| slot.owner.clone()),
                review_end: state.slot.as_ref().and_then(|slot| slot.review_end), cleanup_end: state.slot.as_ref().and_then(|slot| slot.cleanup_end),
                work_end: state.slot.as_ref().and_then(|slot| slot.owner.endpoint()),
                payloads: state.records.iter().map(|r| (r.key.id.0.clone(),r.key.revision,Arc::as_ptr(&r.payload) as usize)).collect(), sources,
                settled: state.slot.as_ref().is_none_or(|slot| joined(&slot.owner)),
                lost: state.lost_observed, bound: state.lifetime.original_bound(), unknown: state.unknown || state.exhausted,
                quit_pending: state.quit_pending, quit_declined: state.quit.as_ref().is_some_and(|owner| owner.normally_declined()),
                empty: session_data_empty(&state) && !state.session && !state.lock_pending && !state.retiring,
                first_failure,
            })
        }
        pub(crate) fn installed_session_capture_checkpoint(&self) -> Option<Arc<asset_source::InstalledCaptureCheckpoint>> {
            let state = self.lock();
            let checkpoint = state.slot.as_ref()?.owner.installed_capture.lock().ok()?.clone();
            checkpoint
        }
        pub(crate) fn take_installed_session_queries(&self) -> Result<crate::supervisor::InstalledSessionQueries, BridgeError> {
            // Forward only the original document's original Supervisor; no
            // RuntimeConfig/owner clone can issue an observation of another R1.
            self.inner.bridge.supervisor.take_installed_session_queries()
        }
        pub(crate) fn installed_session_final(&self, project: &super::installed_project_observation::ProjectWitness, loss: bool) -> bool {
            let state = self.lock();
            let Ok(book) = self.inner.installed_session.lock() else { return false; }; let Some(book) = book.as_ref() else { return false; };
            !state.unknown && !state.exhausted && state.lost_observed == loss && state.lifetime.original_bound() != loss
                // can_exit joins the original quit before the relay may clear
                // quit_pending. The same positive originals below, not that UI
                // admission flag's scheduling, establish finality.
                && state.stopping && state.quit_accepted && !state.session && !state.lock_pending
                && state.context.is_none() && state.records.is_empty() && state.assignments.is_empty() && assets_can_exit_locked(&state)
                && state.evidence.revoked && state.evidence.selection.is_none() && state.evidence.result.is_none()
                && !state.github.native_work_pending() && state.github.material_settled()
                && !self.inner.bridge.supervisor.disabled() && self.inner.bridge.supervisor.stopping() && self.inner.bridge.supervisor.can_exit()
                && !self.inner.bridge.edits.disabled() && self.inner.bridge.edits.stopping() && self.inner.bridge.edits.can_exit()
                && self.observed_source_unchanged(project) && book.originals.len() == state.next_operation as usize
                && book.originals.iter().enumerate().all(|(i,(owner,_))| owner.id == i as u32 + 1 && joined(owner))
                && state.quit_cleanup_end.is_some() && state.quit.as_ref().is_some_and(|quit| joined(quit) && quit.stopped()
                    && quit.gui.facts().is_some_and(|facts| facts.accepted && !facts.declined))
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use installed_session_observation::{Snapshot as InstalledSessionSnapshot, Failure as InstalledSessionFailure};

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod fixture_observation {
    use super::*;
    // Private equality only: no extra payload/GTK/FD owner and no serialization
    // of material, selection tokens, pointer values or original deadlines.
    #[derive(PartialEq, Eq)]
    pub(crate) struct Selection {
        owner: u32, payload: usize, context: usize, token: String, record: String,
        context_revision: u32, registry_generation: u32, review: Instant,
    }
    impl DocumentBinding {
        pub(crate) fn same_original(&self, other: &Self) -> bool { Arc::ptr_eq(&self.inner, &other.inner) }
        pub(crate) fn fixture_bootstrap(&self) -> bool {
            let state = self.lock(); state.lifetime.original_bound() && !state.unknown && !state.stopping && !state.session
                && state.next_operation == 0 && state.slot.is_none() && state.quit.is_none()
        }
        pub(crate) fn fixture_picker_preserved(&self) -> bool {
            let state = self.lock();
            !state.unknown && !state.stopping && !state.quit_pending && !state.retiring && !state.session && state.quit.is_none()
                && state.lifetime.original_bound() && state.next_operation == 1 && state.slot.as_ref().is_some_and(|slot|
                    slot.owner.id == 1 && slot.phase == Phase::Picking && slot.review_end.is_none() && slot.cleanup_end.is_none()
                        && slot.owner.endpoint().is_none() && !slot.owner.stopped()
                        && slot.owner.gui.facts().is_some_and(|f| f.created && f.showing && !f.response && !f.destroyed && !f.released)
                        && slot.owner.source.try_lock().is_ok_and(|book| book.not_started()))
        }
        pub(crate) fn fixture_cancelled(&self) -> bool {
            self.reconcile(); let state = self.lock();
            !state.unknown && !state.stopping && !state.quit_pending && state.quit.is_none() && state.next_operation == 1
                && state.slot.as_ref().is_some_and(|slot| slot.owner.id == 1 && slot.phase == Phase::Idle && slot.reason == Reason::UserCancelled
                    && slot.owner.resources_settled() && slot.project.is_none())
                && self.inner.bridge.native_roster().is_ok_and(|roster| roster.roots.is_empty())
        }
        pub(crate) fn fixture_project(&self) -> Option<(Project, serde_json::Value)> {
            self.reconcile(); let state = self.lock(); let slot = state.slot.as_ref()?;
            if state.unknown || state.stopping || state.quit_pending || state.next_operation != 2
                || slot.owner.id != 2 || slot.phase != Phase::Idle || !slot.owner.resources_settled() { return None; }
            let roster = self.inner.bridge.native_roster().ok()?;
            if roster.roots.len() != 1 { return None; }
            Some((slot.project.clone()?, roster.roots[0].identity.posix().ok()?.fixture_value()))
        }
        pub(crate) fn fixture_selection(&self) -> Option<Selection> {
            self.reconcile(); let state = self.lock(); let slot = state.slot.as_ref()?;
            if state.unknown || state.stopping || state.quit_pending || state.retiring || !state.session || !state.lifetime.original_bound()
                || slot.owner.id != 3 || slot.phase != Phase::Selected || slot.source != SourceState::Captured
                || slot.settlement != Settlement::Known || !slot.owner.resources_settled() || slot.owner.stopped()
                || slot.cleanup_end.is_some() || !state.records.is_empty() || !state.assignments.is_empty() { return None; }
            let context = state.context.as_ref()?;
            if !slot.context.as_ref().is_some_and(|bound| Arc::ptr_eq(bound, context)) { return None; }
            let candidate = slot.candidate.as_ref()?; let material = candidate.payload.material.as_ref()?;
            if candidate.payload.kind != Kind::AndroidKeystore || !material.observation.is_observed()
                || material.captured.bytes != [0xfe,0xed,0xfe,0xed,0,0,0,2,0,0,0,0] || candidate.existing.is_some() { return None; }
            let review = slot.review_end?; if Instant::now() >= review { return None; }
            Some(Selection { owner:slot.owner.id, payload:Arc::as_ptr(&candidate.payload) as usize,
                context:Arc::as_ptr(context) as usize, token:slot.selection.as_ref()?.0.clone(), record:candidate.record_id.0.clone(),
                context_revision:context.revision, registry_generation:context.registry_generation, review })
        }
        pub(crate) fn fixture_cancel_preserved(&self, before: &Selection) -> bool {
            if self.fixture_selection().as_ref() != Some(before) { return false; }
            let state = self.lock(); !state.quit_pending && !state.quit_accepted && state.next_operation == 4
                && state.quit.as_ref().is_some_and(|quit| quit.id == 4 && quit.normally_declined() && quit.resources_settled())
                && !self.inner.bridge.supervisor.stopping() && !self.inner.bridge.edits.stopping()
        }
        pub(crate) fn fixture_final(&self) -> bool {
            let state = self.lock(); !state.unknown && !state.exhausted && state.lifetime.original_bound() && !state.lost_observed
                && state.next_operation == 5 && state.stopping && state.quit_accepted && !state.session && !state.lock_pending
                && assets_can_exit_locked(&state) && state.quit.as_ref().is_some_and(|quit| quit.id == 5 && quit.resources_settled()
                    && quit.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none()))
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use fixture_observation::Selection as FixtureSelection;

#[cfg(test)]
#[path = "android_build_wiring_tests.rs"]
mod android_build_wiring_tests;

#[cfg(test)]
pub(crate) fn assert_installed_session_owner_contract() { tests::live_session_owner_contract(); }

#[cfg(test)]
pub(crate) fn assert_project_path_document_contracts() {
    // Explicit-call DATA predicates/models only. No DesktopBridge/runtime,
    // task, real GUI/source original, RNG or registered project is fabricated.
    fn state(bound: bool) -> DocumentState {
        let mut lifetime = DocumentLifetime::default();
        if bound { lifetime.crash_hook_installed(); lifetime.started(true); lifetime.finished(true); }
        DocumentState { lifetime, revision: 0, next_operation: 0, next_context: 0, exhausted: false, lost_observed: false,
            session: false, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            compatibility_picker_pending: false, session_owner_reason: None, context: None, slot: None, records: Vec::new(), assignments: Vec::new(),
            quit: None, quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(), evidence: EvidenceRegistry::new(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            first_origin: None }
    }
    fn gui(selected: bool) -> GuiFacts {
        GuiFacts { dispatched: true, constructing: false, created: true, showing: false, response: true,
            accepted: selected, declined: !selected, accepted_at: selected.then(Instant::now), destroyed: true, released: true,
            not_created: false, close_queued: true, close_ack: true, release_queued: true, selected: None, refusal: None }
    }
    assert!(!NATIVE_QUALIFIED);
    let ready = state(true);
    assert!(project_path_idle_gate(&ready, true).is_ok());
    assert_eq!(project_path_idle_gate(&ready, false).err().map(|e| e.reason), Some(Reason::Unqualified));
    let unbound = state(false);
    assert_eq!(common_document_gate(&unbound, false, || panic!("unbound admission reached owners")).err().map(|e| e.reason), Some(Reason::DocumentLost));
    for (modify, expected) in [
        ((|s: &mut DocumentState| s.unknown = true) as fn(&mut DocumentState), Reason::CleanupUnknown),
        (|s| s.stopping = true, Reason::Shutdown), (|s| s.quit_pending = true, Reason::Busy),
        (|s| s.retiring = true, Reason::Busy), (|s| s.lock_pending = true, Reason::Busy),
        (|s| s.compatibility_picker_pending = true, Reason::Busy),
        (|s| { s.lifetime.invalidate(); s.lost_observed = true; }, Reason::DocumentLost),
    ] {
        let mut blocked = state(true); modify(&mut blocked);
        assert_eq!(common_document_gate(&blocked, false, || Ok(())).err().map(|e| e.reason), Some(expected));
        assert!(!blocked.session && blocked.records.is_empty() && blocked.assignments.is_empty());
    }
    for reason in [Reason::Busy, Reason::Shutdown, Reason::CleanupUnknown] {
        assert_eq!(common_document_gate(&ready, false, || Err(AssetError::new(reason))).err().map(|e| e.reason), Some(reason));
    }
    assert!(common_document_gate(&ready, false, || Ok(())).is_ok());
    assert!(Operation::ChooseProjectPath.blocks_context() && !Operation::ChooseProjectPath.evidence());
    for operation in [Operation::ChooseProject, Operation::ChooseEvidenceFolder, Operation::InspectEvidence] { assert!(operation.blocks_context()); }
    for operation in [Operation::ChooseFile, Operation::Prepare, Operation::PrepareDelete, Operation::Commit, Operation::Bind] { assert!(!operation.blocks_context()); }

    let owner = OriginalWork::new(1, false, Weak::new());
    let mut blocked = state(true);
    let mut slot = Slot::new(owner.clone(), Operation::ChooseProjectPath, None, None, None); slot.phase = Phase::Idle;
    blocked.slot = Some(slot);
    assert!(project_path_pending(&blocked)); // Idle label is not original settlement.
    assert_eq!(project_path_idle_gate(&blocked, true).err().map(|e| e.reason), Some(Reason::Busy));
    assert_eq!(passive_document_gate(&blocked).err().map(|e| e.code), Some("busy".into()));
    assert_eq!(common_document_gate(&blocked, true, || Ok(())).err().map(|e| e.reason), Some(Reason::Busy));
    owner.ended.store(true, Ordering::SeqCst);
    owner.coordinator.lock().unwrap().receipt = JoinReceipt::Pending;
    assert!(owner.join_if_ended().is_none()); assert!(project_path_pending(&blocked));
    assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::Pending);
    owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned; // Model facts, not a native receipt.
    assert!(!project_path_pending(&blocked)); assert!(passive_document_gate(&blocked).is_ok());
    assert!(!owner.project_path_settled(false) && !owner.project_path_settled(true)); // Not-created is never Cancel/success.
    owner.retired.store(false, Ordering::SeqCst); assert!(project_path_pending(&blocked));
    owner.retired.store(true, Ordering::SeqCst);
    blocked.slot.as_mut().unwrap().phase = Phase::Picking; assert!(project_path_pending(&blocked));
    blocked.slot.as_mut().unwrap().operation = Operation::ChooseFile;
    assert!(!project_path_pending(&blocked) && passive_document_gate(&blocked).is_ok()); // No widening of unrelated passive gates.
    blocked.slot.as_mut().unwrap().operation = Operation::ChooseProjectPath;
    blocked.slot.as_mut().unwrap().phase = Phase::Unknown; blocked.slot.as_mut().unwrap().settlement = Settlement::LateKnown;
    blocked.unknown = true;
    assert_eq!(passive_document_gate(&blocked).err().map(|e| e.code), Some("cleanup_unknown".into()));
    assert!(project_path_pending(&blocked)); // Late known settlement never restores admission.

    assert!(project_path_gui_settled(&gui(true), true)); assert!(project_path_gui_settled(&gui(false), false));
    assert!(!project_path_gui_settled(&gui(true), false) && !project_path_gui_settled(&gui(false), true));
    for modify in [
        (|f: &mut GuiFacts| f.dispatched = false) as fn(&mut GuiFacts), |f| f.constructing = true,
        |f| f.created = false, |f| f.showing = true, |f| f.response = false, |f| f.destroyed = false,
        |f| f.released = false, |f| f.not_created = true, |f| f.close_queued = false, |f| f.close_ack = false,
        |f| f.release_queued = false, |f| f.refusal = Some(Reason::SourceRefused),
        |f| f.selected = Some(std::path::PathBuf::from("/inert/not-a-receipt")),
    ] {
        for selected in [false, true] { let mut facts = gui(selected); modify(&mut facts); assert!(!project_path_gui_settled(&facts, selected)); }
    }
    let mut other = gui(false); other.declined = false; assert!(!project_path_gui_settled(&other, false));
    assert_eq!(admitted_response(NativeResponse::Decline, true, false, true), (false, true));
    for response in [NativeResponse::Accept, NativeResponse::Decline, NativeResponse::Other] {
        assert_eq!(admitted_response(response, true, true, true), (false, false));
        assert_eq!(admitted_response(response, false, false, true), (false, false));
    }
    // The existing Project/File/Evidence path still does not record a new
    // declined receipt. Only this purpose opts into the fourth argument.
    assert_eq!(admitted_response(NativeResponse::Decline, true, false, false), (false, false));
    let cancelled = OriginalWork::new(2, true, Weak::new());
    *cancelled.gui.facts().unwrap() = gui(false);
    cancelled.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
    assert!(!cancelled.project_path_settled(false)); // Actual admitted Cancel also latches STOP.
    cancelled.stop(); assert!(cancelled.project_path_settled(false));
    cancelled.coordinator.lock().unwrap().receipt = JoinReceipt::Failed;
    assert!(cancelled.resources_settled() && !cancelled.project_path_settled(false));
    cancelled.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
    for receipt in [JoinReceipt::Pending, JoinReceipt::Returned, JoinReceipt::Failed] {
        cancelled.child.try_lock().unwrap().receipt = receipt; assert!(!cancelled.project_path_settled(false));
    }
    cancelled.child.try_lock().unwrap().receipt = JoinReceipt::New;
    cancelled.retired.store(false, Ordering::SeqCst); assert!(!cancelled.project_path_settled(false));
    cancelled.retired.store(true, Ordering::SeqCst); assert!(cancelled.project_path_settled(false));
    let selected = OriginalWork::new(3, true, Weak::new());
    *selected.gui.facts().unwrap() = gui(true);
    selected.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
    selected.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
    assert!(selected.resources_settled() && !selected.project_path_settled(true)); // No actual source probe, hence no success.

    // Synthetic directory identity is comparison DATA only, not a SourceBook
    // proof or a fixture permit for this new purpose.
    let root = asset_source::RegisteredRoot { path: "/inert/project".into(), identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
    let binding = Arc::new(ProjectPathBinding { project_id: "project-1".into(), field: commands::ProjectPathField::VersionSource, root: root.clone(), generation: 7 });
    assert!(binding.registration_matches(7, &root)); assert!(!binding.registration_matches(8, &root));
    let changed = asset_source::RegisteredRoot { path: "/inert/other".into(), ..root };
    assert!(!binding.registration_matches(7, &changed));
    let mut slot = Slot::new(OriginalWork::new(4, true, Weak::new()), Operation::ChooseProjectPath, None, None, None);
    slot.project_path = Some(binding);
    assert!(slot.context.is_none() && slot.target.is_none() && slot.review_end.is_none() && slot.kind.is_none()
        && slot.candidate.is_none() && slot.selection.is_none() && slot.assessment.is_none() && slot.preview.is_none()
        && slot.project.is_none() && slot.result_record.is_none() && slot.evidence.is_none());
    assert_eq!(serde_json::to_value(slot.operation).unwrap(), serde_json::json!("choose-project-path"));
    slot.path_result = commands::project_path_result("project-1", commands::ProjectPathField::VersionSource, "VERSION".into()).ok();
    let now = Instant::now(); slot.stop(Reason::Deadline, now); let first = slot.cleanup_end;
    slot.stop(Reason::UserCancelled, now + Duration::from_secs(1));
    assert!(slot.path_result.is_none() && slot.reason == Reason::Deadline && slot.cleanup_end == first && slot.owner.stopped());
    assert!(!ready.session && ready.context.is_none() && ready.records.is_empty() && ready.assignments.is_empty());
}

#[cfg(test)]
pub(crate) fn assert_project_selection_gate_contract() {
    // DATA-only truth table shared with the harness=false observer's explicit
    // pre-GTK entry. No DesktopBridge constructor, source IO, task or native
    // work is performed; model facts are not actual original join receipts.
    fn state(bound: bool) -> DocumentState {
        let mut lifetime = DocumentLifetime::default();
        if bound { lifetime.crash_hook_installed(); lifetime.started(true); lifetime.finished(true); }
        DocumentState { lifetime, revision: 0, next_operation: 0, next_context: 0, exhausted: false, lost_observed: false,
            session: false, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            compatibility_picker_pending: false, session_owner_reason: None, context: None, slot: None, records: Vec::new(), assignments: Vec::new(),
            quit: None, quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(), evidence: EvidenceRegistry::new(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            first_origin: None }
    }
    let reason = |state: &DocumentState| common_document_gate(state, false, || Ok(())).err().map(|error| error.reason);
    assert!(!NATIVE_QUALIFIED, "Project profile admission cannot open the broad asset gate.");
    let unbound = state(false);
    assert_eq!(common_document_gate(&unbound, false, || panic!("Unbound document reached an owner gate.")).err().map(|error| error.reason), Some(Reason::DocumentLost));
    let mut lost = state(true); lost.lifetime.invalidate(); lost.lost_observed = true;
    assert_eq!(reason(&lost), Some(Reason::DocumentLost));
    for (modify, expected) in [
        ((|state: &mut DocumentState| state.unknown = true) as fn(&mut DocumentState), Reason::CleanupUnknown),
        (|state| state.stopping = true, Reason::Shutdown),
        (|state| state.quit_pending = true, Reason::Busy),
        (|state| state.retiring = true, Reason::Busy),
        (|state| state.lock_pending = true, Reason::Busy),
        (|state| state.compatibility_picker_pending = true, Reason::Busy),
    ] {
        let mut blocked = state(true); modify(&mut blocked);
        assert_eq!(reason(&blocked), Some(expected));
        assert!(!blocked.session && blocked.records.is_empty() && blocked.assignments.is_empty());
    }
    let mut ready = state(true);
    for refusal in [Reason::CleanupUnknown, Reason::Shutdown, Reason::Busy] {
        assert_eq!(common_document_gate(&ready, false, || Err(AssetError::new(refusal))).err().map(|error| error.reason), Some(refusal));
    }
    assert_eq!(reason(&ready), None);
    let platform = if cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { None } else { Some(Reason::UnsupportedPlatform) };
    assert_eq!(ordinary_asset_platform_gate().err().map(|error| error.reason), platform);
    assert!(!ready.session && ready.context.is_none() && ready.records.is_empty() && ready.assignments.is_empty());
    assert!(idle(&ready).is_ok());
    // Model original join/retirement facts only, not actual native settlement.
    let owner = OriginalWork::new(1, false, Weak::new());
    let mut slot = Slot::new(owner.clone(), Operation::ChooseProject, None, None, None); slot.phase = Phase::Idle;
    ready.slot = Some(slot);
    assert_eq!(idle(&ready).err().map(|error| error.reason), Some(Reason::Busy));
    owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
    assert!(idle(&ready).is_ok());
    owner.retired.store(false, Ordering::SeqCst);
    assert_eq!(idle(&ready).err().map(|error| error.reason), Some(Reason::Busy));
    owner.retired.store(true, Ordering::SeqCst);
    ready.slot.as_mut().unwrap().phase = Phase::Capturing;
    assert_eq!(idle(&ready).err().map(|error| error.reason), Some(Reason::Busy));
    ready.slot.as_mut().unwrap().operation = Operation::InspectEvidence;
    assert_eq!(common_document_gate(&ready, true, || Ok(())).err().map(|error| error.reason), Some(Reason::Busy));
    assert!(!ready.session && ready.records.is_empty() && ready.assignments.is_empty());
}

#[cfg(test)]
pub(crate) fn assert_installed_evidence_gate_contract() {
    // Shared document/owner refusals are covered by the existing project gate
    // contract. This is the added profile intersection and evidence-only tail;
    // these memory-only models never grant a native original receipt.
    assert!(!NATIVE_QUALIFIED);
    for project in [false, true] {
        for method in [false, true] {
            assert_eq!(installed_evidence_profile(project, method), project && method);
        }
    }
    let mut state = tests::empty_state(); state.session = false;
    assert!(evidence_selection_gate(&state).is_ok());
    state.evidence.revoked = true;
    let before = serde_json::to_value(evidence_snapshot(&state, true)).unwrap();
    assert_eq!(evidence_selection_gate(&state).unwrap_err().code, evidence_wire::refused(EvidenceProblem::StaleSelection).code);
    assert_eq!(serde_json::to_value(evidence_snapshot(&state, true)).unwrap(), before);
    state.evidence.revoked = false;
    let owner = OriginalWork::new(1, false, Weak::new());
    state.slot = Some(Slot::new(owner, Operation::ChooseEvidenceFolder, None, None, None));
    let before = serde_json::to_value(evidence_snapshot(&state, true)).unwrap();
    assert_eq!(evidence_selection_gate(&state).unwrap_err().code, evidence_wire::refused(EvidenceProblem::Busy).code);
    assert_eq!(serde_json::to_value(evidence_snapshot(&state, true)).unwrap(), before);
    assert!(!state.session && state.context.is_none() && state.records.is_empty() && state.assignments.is_empty());
    tests::evidence_stop_matches_original_job_not_just_selection_or_shared_slot_body();
    tests::evidence_cancel_preserves_source_context_records_github_and_first_cleanup_body();
    tests::evidence_late_error_preserves_first_stop_and_original_deadline_body();
    tests::evidence_unknown_retains_original_binding_and_cannot_become_late_success_body();
    tests::evidence_folder_label_is_bounded_and_never_a_full_or_controlled_path_body();
}

#[cfg(test)]
mod tests {
    // Synthetic in-memory predicates. No DesktopBridge constructor/RNG, dialog,
    // source path access or native receipts. One explicit Tokio test stages
    // (but NEVER polls) the owned startup; it does not start an SDK task or I/O.
    use super::*;
    #[test]
    fn project_path_shares_exclusions_but_not_asset_authority_or_synthetic_finality() { assert_project_path_document_contracts(); }
    fn token(byte: char) -> Token { Token(byte.to_string().repeat(32)) }
    pub(super) fn empty_state() -> DocumentState {
        DocumentState { lifetime: DocumentLifetime::default(), revision: 0, next_operation: 0, next_context: 0, exhausted: false, lost_observed: false,
            session: true, stopping: false, unknown: false, quit_pending: false, retiring: false, lock_pending: false,
            compatibility_picker_pending: false, session_owner_reason: None,
            context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None, quit_accepted: false, quit_cleanup_end: None,
            github: ConnectionState::new(), evidence: EvidenceRegistry::new(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            first_origin: None }
    }

    pub(super) fn live_session_owner_contract() {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        installed_session_observation::assert_first_origin_contract();
        for sd in [false,true] { for ed in [false,true] { for ss in [false,true] { for es in [false,true] {
            let reason = session_owner_reason(sd,ed,ss,es);
            let expected = if sd || ed { Some(Reason::CleanupUnknown) } else if ss || es { Some(Reason::Shutdown) } else { None };
            assert_eq!(reason,expected);
            let mut state = empty_state();
            state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
            let before = state.revision;
            let changed = observe_session_owner_reason(&mut state,reason);
            assert_eq!(changed,reason.is_some());
            if changed { state.revision = state.revision.checked_add(1).unwrap(); }
            assert_eq!(state.session_owner_reason,reason);
            assert!(!observe_session_owner_reason(&mut state,reason));
            assert_eq!(state.revision,before + u32::from(reason.is_some()));
            assert_eq!(common_document_gate(&state,true,|| reason.map_or(Ok(()),|r| Err(AssetError::new(r)))).err().map(|e|e.reason),reason);
            // Display observation cannot fabricate local Unknown/STOP or
            // prevent teardown. These unchanged original predicates ignore it.
            assert!(!state.unknown && !state.stopping && state.slot.is_none());
            assert!(quit_question_admitted(&state));
            state.session = false;
            assert!(assets_can_exit_locked(&state));
        } } } }
    }
    #[test]
    fn actual_owner_reason_blocks_new_session_work_not_retirement() { live_session_owner_contract(); }

    #[test]
    fn project_selection_shares_lifecycle_checks_without_granting_an_asset_session() {
        assert_project_selection_gate_contract();
    }

    #[test]
    fn installed_evidence_is_separate_from_the_private_asset_profile() {
        assert_installed_evidence_gate_contract();
    }

    #[test]
    fn offline_preflight_startup_and_unsupported_gates_preserve_passive_services() {
        use crate::offline_preflight_protocol::{Availability, Profile};
        let mut state = empty_state();
        assert!(passive_document_gate(&state).is_ok());
        assert_eq!(preflight_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::Busy));
        assert_eq!(preflight_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
        state.lifetime.crash_hook_installed();
        state.lifetime.started(true);
        state.lifetime.finished(true);
        assert!(state.lifetime.original_bound());
        assert!(passive_document_gate(&state).is_ok());
        assert_eq!(preflight_document_gate(&state, Some(Profile::LinuxX64)), None);
        state.lifetime.invalidate(); state.lost_observed = true;
        assert_eq!(preflight_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::DocumentLost));
        assert_eq!(preflight_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
        // This is not native binding proof: Windows/no-hook passive behavior
        // stays separate from an executing owner's real loss/Unknown gates.
        assert!(passive_document_gate(&state).is_ok());
        state.quit_pending = true; assert!(passive_document_gate(&state).is_err());
        state.quit_pending = false; state.stopping = true; assert!(passive_document_gate(&state).is_err());
        state.stopping = false; state.unknown = true; assert!(passive_document_gate(&state).is_err());
        state.unknown = false; state.exhausted = true; assert!(passive_document_gate(&state).is_err());
    }

    fn scalar() -> Arc<Payload> { Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None }) }
    fn slot(target: Option<RecordKey>, review: Option<Instant>) -> Slot {
        let mut slot = Slot::new(OriginalWork::new(1, false, Weak::new()), Operation::Prepare, None, target, review);
        slot.kind = Some(Kind::GoogleWif); slot
    }

    fn evidence_model(id: u32) -> (DocumentState, Arc<OriginalWork>) {
        let mut state = empty_state();
        let owner = OriginalWork::new(id, false, Weak::new());
        let binding = EvidenceBinding { operation_id: id, kind: evidence_wire::OperationKind::Observe,
            selection_id: Some("evidence-model".to_owned()), epoch: 4 };
        let mut work = Slot::new(owner.clone(), Operation::InspectEvidence, None, None, None); work.evidence = Some(binding.clone());
        state.evidence.epoch = 4; state.evidence.operation = Some(binding); state.evidence.phase = evidence_wire::Phase::Observing;
        state.evidence.selection = Some(EvidenceSelection { view: evidence_wire::Selection { selection_id: "evidence-model".to_owned(), display_name: "Model".to_owned() },
            root: asset_source::RegisteredRoot { path: "/synthetic/never-opened/evidence".into(), identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) }, epoch: 4 });
        state.slot = Some(work); (state, owner)
    }
    fn evidence_cancel(id: u32) -> evidence_wire::Cancel {
        evidence_wire::Cancel { operation_id: id.to_string(), selection_id: Some("evidence-model".to_owned()) }
    }

    #[test]
    fn evidence_stop_matches_original_job_not_just_selection_or_shared_slot() { evidence_stop_matches_original_job_not_just_selection_or_shared_slot_body(); }

    pub(super) fn evidence_stop_matches_original_job_not_just_selection_or_shared_slot_body() {
        let (mut state, owner) = evidence_model(2); let at = Instant::now();
        let before = serde_json::to_value(evidence_snapshot(&state, true)).unwrap();
        // Observe1's delayed STOP cannot affect Observe2 under the same folder.
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(1), at).is_err());
        let mut wrong = evidence_cancel(2); wrong.selection_id = Some("evidence-other".to_owned());
        assert!(cancel_evidence_locked(&mut state, &wrong, at).is_err());
        assert_eq!(serde_json::to_value(evidence_snapshot(&state, true)).unwrap(), before); assert!(!owner.stopped());
        state.slot.as_mut().unwrap().operation = Operation::Prepare;
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(2), at).is_err()); assert!(!owner.stopped());
        state.slot.as_mut().unwrap().operation = Operation::InspectEvidence;
        state.evidence.epoch += 1;
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(2), at).is_err()); assert!(!owner.stopped());
    }

    #[test]
    fn evidence_cancel_preserves_source_context_records_github_and_first_cleanup() { evidence_cancel_preserves_source_context_records_github_and_first_cleanup_body(); }

    pub(super) fn evidence_cancel_preserves_source_context_records_github_and_first_cleanup_body() {
        let (mut state, owner) = evidence_model(3); let at = Instant::now();
        let root = asset_source::RegisteredRoot { path: "/synthetic/never-opened/project".into(), identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        let context = Arc::new(NativeContext { revision: 9, project_id: "source-project".to_owned(), project: root, registry_generation: 7,
            draft: b"{\"unchanged\":true}".to_vec(), platform: Platform::Android, stage: Stage::Candidate, purpose: Purpose::Full });
        state.context = Some(context.clone());
        state.records.push(Record { key: RecordKey { id: token('a'), revision: 1 }, payload: scalar(), mutation_pending: false });
        state.assignments.push(Assignment { kind: Kind::GoogleWif, record_id: token('a'), record_revision: 1, context_revision: 9, availability: AssignmentAvailability::Available });
        let github = serde_json::to_value(state.github.snapshot()).unwrap(); let original_endpoint = owner.endpoint();
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(3), at).unwrap());
        let cleanup = state.slot.as_ref().unwrap().cleanup_end;
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(3), at + WORK).unwrap());
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, cleanup); assert_eq!(owner.endpoint(), original_endpoint);
        assert!(Arc::ptr_eq(state.context.as_ref().unwrap(), &context)); assert_eq!(state.records.len(), 1); assert!(!state.records[0].mutation_pending);
        assert_eq!(state.assignments.len(), 1); assert!(state.assignments[0].availability == AssignmentAvailability::Available);
        assert_eq!(serde_json::to_value(state.github.snapshot()).unwrap(), github);
        assert!(state.evidence.selection.is_some()); assert!(owner.stopped());
        assert_eq!(evidence_snapshot(&state, true).phase, evidence_wire::Phase::Stopping);
        // Synthetic coordinator fact tests the publication predicate only.
        // No task ran, and this is not native join/cleanup evidence.
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        state.slot.as_mut().unwrap().phase = Phase::Idle;
        settle_evidence_status(&mut state);
        assert_eq!(evidence_snapshot(&state, true).phase, evidence_wire::Phase::Cancelled);
        assert_eq!(evidence_snapshot(&state, true).problem, Some(EvidenceProblem::Cancelled));
        let unrelated = OriginalWork::new(4, false, Weak::new());
        state.slot = Some(Slot::new(unrelated.clone(), Operation::Prepare, None, None, None));
        assert!(!cancel_evidence_locked(&mut state, &evidence_cancel(3), at).unwrap()); assert!(!unrelated.stopped());
    }

    #[test]
    fn evidence_late_error_preserves_first_stop_and_original_deadline() { evidence_late_error_preserves_first_stop_and_original_deadline_body(); }

    pub(super) fn evidence_late_error_preserves_first_stop_and_original_deadline_body() {
        for first in [Reason::UserCancelled, Reason::Deadline] {
            let (mut state, owner) = evidence_model(5); let at = Instant::now();
            state.slot.as_mut().unwrap().stop(first, at); let cleanup = state.slot.as_ref().unwrap().cleanup_end;
            for later in [EvidenceProblem::ObservationFailed, EvidenceProblem::Deadline, EvidenceProblem::Limit] {
                assert!(!record_evidence_failure(&mut state, &owner, later, at + WORK));
                assert_eq!(evidence_snapshot(&state, true).problem, Some(evidence_reason(first)));
                assert_eq!(state.slot.as_ref().unwrap().cleanup_end, cleanup);
            }
        }
        let (mut state, owner) = evidence_model(6); let end = owner.endpoint().unwrap();
        assert!(record_evidence_failure(&mut state, &owner, EvidenceProblem::ObservationFailed, end + WORK));
        assert_eq!(evidence_snapshot(&state, true).problem, Some(EvidenceProblem::Deadline));
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(end + CLEANUP));
        let (mut state, owner) = evidence_model(7); let end = owner.endpoint().unwrap();
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(7), end + WORK).unwrap());
        assert_eq!(evidence_snapshot(&state, true).problem, Some(EvidenceProblem::Deadline));
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(end + CLEANUP));
    }

    #[test]
    fn evidence_unknown_retains_original_binding_and_cannot_become_late_success() { evidence_unknown_retains_original_binding_and_cannot_become_late_success_body(); }

    pub(super) fn evidence_unknown_retains_original_binding_and_cannot_become_late_success_body() {
        let (mut state, owner) = evidence_model(8); let at = Instant::now();
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(8), at).unwrap());
        let cleanup = state.slot.as_ref().unwrap().cleanup_end;
        assert!(record_evidence_failure(&mut state, &owner, EvidenceProblem::CleanupUnknown, at + WORK));
        state.evidence.revoke(true);
        assert!(cancel_evidence_locked(&mut state, &evidence_cancel(8), at + WORK).unwrap());
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, cleanup);
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        let slot = state.slot.as_mut().unwrap(); slot.phase = Phase::Idle; slot.settlement = Settlement::LateKnown;
        settle_evidence_status(&mut state);
        let status = evidence_snapshot(&state, true);
        assert_eq!(status.phase, evidence_wire::Phase::Unknown); assert_eq!(status.problem, Some(EvidenceProblem::CleanupUnknown));
        assert_eq!(status.operation.unwrap().operation_id, "8"); assert!(status.selection.is_none() && status.result.is_none());
    }

    #[test]
    fn evidence_folder_label_is_bounded_and_never_a_full_or_controlled_path() { evidence_folder_label_is_bounded_and_never_a_full_or_controlled_path_body(); }

    pub(super) fn evidence_folder_label_is_bounded_and_never_a_full_or_controlled_path_body() {
        use std::path::Path;
        assert_eq!(evidence_display_name(Path::new("/private/source/Évidence")), "Évidence");
        for leaf in ["hidden\u{200b}name", "soft\u{00ad}name", "bidi\u{202e}name", "slash\\name", "line\nname"] {
            assert_eq!(evidence_display_name(&Path::new("/private/source").join(leaf)), "Selected evidence folder");
        }
        assert_eq!(evidence_display_name(&Path::new("/private/source").join("a".repeat(129))), "Selected evidence folder");
        assert_eq!(evidence_display_name(Path::new("/")), "Selected evidence folder");
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
    fn gui_failure_stops_exact_original_without_response_or_settlement() {
        // Actual state transition, closed DATA only: no bridge, native panel,
        // worker, callback or purported execution/settlement receipt.
        let at = Instant::now(); let mut state = empty_state();
        let owner = OriginalWork::new(7, true, Weak::new()); owner.set_endpoint(None);
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Pending;
        {
            let mut facts = owner.gui.facts().unwrap();
            facts.dispatched = true; facts.created = true; facts.showing = true;
        }
        let mut work = Slot::new(owner.clone(), Operation::ChooseProject, None, None, None);
        work.phase = Phase::Picking; state.slot = Some(work);
        assert!(!quit_question_admitted(&state));

        fail_gui_original_locked(&mut state, &owner.gui, &owner, Reason::SourceRefused, at);
        let work = state.slot.as_ref().unwrap();
        assert!(Arc::ptr_eq(&work.owner, &owner) && owner.stopped() && work.discard);
        assert!(work.operation == Operation::ChooseProject && work.phase == Phase::Stopping);
        assert_eq!(work.reason, Reason::SourceRefused);
        assert_eq!(work.cleanup_end, Some(at + CLEANUP));
        assert_eq!((work.review_end, owner.endpoint()), (None, None));
        {
            let facts = owner.gui.facts().unwrap();
            assert_eq!(facts.refusal, Some(Reason::SourceRefused));
            assert!(facts.dispatched && facts.created && facts.showing);
            assert!(!facts.response && !facts.accepted && !facts.declined && facts.accepted_at.is_none());
            assert!(!facts.not_created && !facts.destroyed && !facts.released && !facts.close_queued
                && !facts.close_ack && !facts.release_queued && facts.selected.is_none());
        }
        assert!(!owner.resources_settled() && !quit_question_admitted(&state));
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::Pending);

        // Later receipt/lock delay does not choose a fresh cleanup endpoint;
        // an existing Unknown or first reason cannot be repaired by STOP.
        state.slot.as_mut().unwrap().phase = Phase::Unknown;
        state.slot.as_mut().unwrap().settlement = Settlement::Unknown; state.unknown = true;
        fail_gui_original_locked(&mut state, &owner.gui, &owner, Reason::Deadline, at + WORK);
        let work = state.slot.as_ref().unwrap();
        assert!(state.unknown && work.phase == Phase::Unknown && work.settlement == Settlement::Unknown);
        assert_eq!((work.reason, work.cleanup_end), (Reason::SourceRefused, Some(at + CLEANUP)));
        assert_eq!(owner.gui.facts().unwrap().refusal, Some(Reason::SourceRefused));

        // A reused numeric operation ID is never authority over a successor's
        // Slot/quit, GUI facts, clocks or STOP bit. Only the old original stops.
        let other = OriginalWork::new(owner.id, true, Weak::new()); other.set_endpoint(None);
        let mut foreign = Slot::new(other.clone(), Operation::ChooseProject, None, None, None);
        foreign.phase = Phase::Picking; state.slot = Some(foreign); state.quit = Some(other.clone());
        fail_gui_original_locked(&mut state, &owner.gui, &owner, Reason::Deadline, at + WORK + CLEANUP);
        let work = state.slot.as_ref().unwrap();
        assert!(Arc::ptr_eq(&work.owner, &other) && work.phase == Phase::Picking && !other.stopped());
        assert_eq!((work.reason, work.cleanup_end, state.quit_cleanup_end), (Reason::None, None, None));
        assert_eq!(other.gui.facts().unwrap().refusal, None);
        assert!(!owner.resources_settled() && !quit_question_admitted(&state));
    }

    #[test]
    fn human_quit_stop_has_one_clock_without_inventing_a_work_endpoint() {
        let at = Instant::now(); let mut state = empty_state();
        let owner = OriginalWork::new(2, false, Weak::new()); owner.set_endpoint(None); state.quit = Some(owner.clone());
        stop_quit(&mut state, at); stop_quit(&mut state, at + WORK);
        assert_eq!(state.quit_cleanup_end, Some(at + CLEANUP)); assert_eq!(owner.endpoint(), None); assert!(owner.stopped());
        assert_eq!(accepted_quit_cleanup_end(&state), None);
        state.stopping = true;
        assert_eq!(accepted_quit_cleanup_end(&state), None);
        state.quit_accepted = true;
        assert_eq!(accepted_quit_cleanup_end(&state), Some(at + CLEANUP));
        stop_quit(&mut state, at + WORK + CLEANUP);
        assert_eq!(accepted_quit_cleanup_end(&state), Some(at + CLEANUP));
        state.quit = None;
        assert_eq!(accepted_quit_cleanup_end(&state), None);
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

    // Synthetic facts for predicate coverage only: no native join/GUI evidence
    // is produced, and no owner task or filesystem operation is started.
    fn late_unknown() -> DocumentState {
        let mut state = empty_state();
        state.lifetime.navigation(true); state.lifetime.started(true);
        state.lifetime.crash_hook_installed(); state.lifetime.finished(true);
        state.unknown = true; state.session = false;
        let mut original = slot(None, Some(Instant::now() + REVIEW));
        original.phase = Phase::Unknown; original.settlement = Settlement::LateKnown;
        original.cleanup_end = Some(Instant::now());
        original.owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        state.slot = Some(original); state
    }

    #[test]
    fn first_unknown_quit_requires_closed_session_and_complete_original_settlement() {
        let state = late_unknown();
        let original = state.slot.as_ref().unwrap();
        let endpoints = (original.cleanup_end, original.review_end, original.owner.endpoint());
        assert!(quit_question_admitted(&state)); assert!(state.unknown);
        assert_eq!(endpoints, (original.cleanup_end, original.review_end, original.owner.endpoint()));
        for modify in [
            (|s: &mut DocumentState| s.session = true) as fn(&mut DocumentState),
            |s| s.lock_pending = true, |s| s.retiring = true, |s| s.exhausted = true,
            |s| s.lost_observed = true, |s| { s.lifetime.invalidate(); },
            |s| s.stopping = true, |s| s.quit_pending = true, |s| s.quit_accepted = true,
            |s| s.slot.as_ref().unwrap().owner.coordinator.lock().unwrap().receipt = JoinReceipt::Pending,
            |s| s.slot.as_ref().unwrap().owner.gui.facts().unwrap().not_created = false,
            |s| s.slot.as_ref().unwrap().owner.retired.store(false, Ordering::SeqCst),
            |s| s.slot.as_mut().unwrap().candidate = Some(Candidate { payload: scalar(), record_id: token('a'), existing: None }),
            |s| s.records.push(Record { key: RecordKey { id: token('a'), revision: 1 }, payload: scalar(), mutation_pending: false }),
        ] {
            let mut state = late_unknown(); modify(&mut state); assert!(!quit_question_admitted(&state));
        }
        // Ordinary pre-existing behavior allows asking before an open session
        // is discarded; only native OK initiates that shutdown.
        assert!(quit_question_admitted(&empty_state()));
    }

    #[test]
    fn unknown_quit_repeat_requires_genuine_decline_and_normal_original_join() {
        let mut state = late_unknown(); let quit = OriginalWork::new(2, true, Weak::new());
        quit.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        {
            let mut facts = quit.gui.facts().unwrap();
            facts.created = true; facts.response = true; facts.declined = true;
            facts.destroyed = true; facts.released = true; facts.close_ack = true;
        }
        state.quit = Some(quit.clone()); state.quit_cleanup_end = Some(Instant::now());
        let endpoint = state.quit_cleanup_end;
        assert!(quit_question_admitted(&state));
        for receipt in [JoinReceipt::New, JoinReceipt::Pending, JoinReceipt::Failed] {
            quit.coordinator.lock().unwrap().receipt = receipt;
            assert!(!quit_question_admitted(&state));
        }
        quit.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        for modify in [
            (|f: &mut GuiFacts| f.declined = false) as fn(&mut GuiFacts),
            |f| f.accepted = true, |f| f.response = false, |f| f.not_created = true,
            |f| f.created = false, |f| f.refusal = Some(Reason::SourceRefused),
            |f| f.close_ack = false, |f| f.destroyed = false, |f| f.released = false,
        ] {
            {
                let mut facts = quit.gui.facts().unwrap();
                facts.declined = true; facts.accepted = false; facts.response = true;
                facts.not_created = false; facts.created = true; facts.refusal = None;
                facts.close_ack = true; facts.destroyed = true; facts.released = true;
                modify(&mut facts);
            }
            assert!(!quit_question_admitted(&state));
        }
        assert!(state.unknown && !state.quit_accepted && !state.stopping);
        assert_eq!(state.quit_cleanup_end, endpoint);
    }

    #[test]
    fn native_decline_cannot_be_inferred_from_interruption_or_a_late_accept() {
        assert_eq!(admitted_response(NativeResponse::Accept, true, false, true), (true, false));
        assert_eq!(admitted_response(NativeResponse::Decline, true, false, true), (false, true));
        assert_eq!(admitted_response(NativeResponse::Decline, true, false, false), (false, false));
        for response in [NativeResponse::Accept, NativeResponse::Decline, NativeResponse::Other] {
            assert_eq!(admitted_response(response, true, true, true), (false, false));
            assert_eq!(admitted_response(response, false, false, true), (false, false));
        }
        assert_eq!(admitted_response(NativeResponse::Other, true, false, true), (false, false));
    }

    #[test]
    fn late_known_empty_lock_requires_reinserted_slot_and_positive_original_resources() {
        let mut state = late_unknown(); state.session = true; state.lock_pending = true;
        let mut original = state.slot.take().unwrap();
        original.candidate = Some(Candidate { payload: scalar(), record_id: token('a'), existing: None });
        state.slot = Some(original); // Actual reconcile must do this before the predicate.
        assert!(!complete_empty_session_lock(&mut state));
        state.slot.as_mut().unwrap().candidate = None;
        state.retiring = true; assert!(!complete_empty_session_lock(&mut state)); state.retiring = false;
        state.slot.as_ref().unwrap().owner.coordinator.lock().unwrap().receipt = JoinReceipt::Pending;
        assert!(!complete_empty_session_lock(&mut state));
        state.slot.as_ref().unwrap().owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        let original = state.slot.as_ref().unwrap();
        let endpoints = (original.cleanup_end, original.review_end, original.owner.endpoint());
        assert!(complete_empty_session_lock(&mut state));
        assert!(state.unknown && !state.session && !state.lock_pending);
        let original = state.slot.as_ref().unwrap();
        assert_eq!(endpoints, (original.cleanup_end, original.review_end, original.owner.endpoint()));
        assert!(!complete_empty_session_lock(&mut state));
    }


    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn keyring_memory_model() -> (DocumentState, Arc<OriginalWork>) {
        let mut state = empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let owner = OriginalWork::new(1, false, Weak::new());
        let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None); slot.phase = Phase::Assessing;
        state.slot = Some(slot); (state, owner)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn lookup_charge_blocks_context_copy_and_same_owner_child_before_dispatch() {
        let (mut state, owner) = keyring_memory_model();
        *owner.keyring.lock().unwrap() = crate::vault_keyring_linux::LookupBook::constructor_refusal_data();
        let copied = std::cell::Cell::new(false);
        let context_copy = (|| -> Result<(), AssetError> {
            lookup_allocation_gate(&state)?; // Same predicate, before context() allocates a draft.
            copied.set(true); let _ = commands::draft_bytes(&Value::Object(Map::new()))?; Ok(())
        })();
        assert_eq!(context_copy.err().map(|error| error.reason), Some(Reason::Busy)); assert!(!copied.get());
        assert_eq!(common_document_gate(&state, true, || Ok(())).err().map(|error| error.reason), Some(Reason::Busy));
        assert_eq!(prepare_copy_start(&mut state, &owner), Err(Reason::Busy));
        assert!(!owner.large_work_started.load(Ordering::SeqCst));
        let mut original = Box::pin(child(&owner, ChildJob::Tokens));
        let mut cx = TaskContext::from_waker(Waker::noop());
        assert!(matches!(original.as_mut().poll(&mut cx), Poll::Ready(Err(Reason::Busy))));
        drop(original);
        let book = owner.child.try_lock().unwrap();
        assert!(book.handle.is_none() && book.receipt == JoinReceipt::New); drop(book);
        // STOP still works and cannot refund or relax the reciprocal predicate.
        state.slot.as_mut().unwrap().stop(Reason::UserCancelled, Instant::now());
        assert!(owner.stopped() && owner.keyring.lock().unwrap().memory_held());
        assert_eq!(lookup_allocation_gate(&state).err().map(|error| error.reason), Some(Reason::Busy));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn lookup_request_copy_start_is_sticky_and_busy_books_never_enter() {
        use crate::vault_keyring_linux::{LookupInput, Problem};
        let (mut state, owner) = keyring_memory_model();
        assert!(prepare_copy_start(&mut state, &owner).is_ok());
        assert!(owner.large_work_started.load(Ordering::SeqCst));
        state.slot.as_mut().unwrap().phase = Phase::Admitting;
        assert!(prepare_copy_start(&mut state, &owner).is_ok());
        assert!(owner.large_work_started.load(Ordering::SeqCst));
        let enter = || lookup_memory::enter(&state, &owner,
            LookupInput::new(std::path::Path::new("/inert/not-opened"), "/collection", "data-vault", "data-generation").unwrap(),
            Instant::now() + WORK);
        // Exercise the actual nonblocking custody-lock seams before any SDK
        // construction; these model owners have no original coordinator handle.
        {
            let _held = owner.child.try_lock().unwrap();
            assert_eq!(enter(), Err(Problem::CleanupUnknown));
        }
        {
            let _held = owner.source.lock().unwrap();
            assert_eq!(enter(), Err(Problem::CleanupUnknown));
        }
        {
            let _held = owner.retirement.lock().unwrap();
            assert_eq!(enter(), Err(Problem::CleanupUnknown));
        }
        {
            let _held = owner.keyring.lock().unwrap();
            assert_eq!(enter(), Err(Problem::CleanupUnknown));
        }
        assert!(!owner.keyring.lock().unwrap().started());
        assert!(!owner.keyring.lock().unwrap().memory_held());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn lookup_refund_requires_join_predicates_disposal_and_keeps_unknown_started_facts() {
        let (mut state, owner) = keyring_memory_model();
        *owner.keyring.lock().unwrap() = crate::vault_keyring_linux::LookupBook::constructor_refusal_data();
        assert!(!owner.dispose_keyring_storage());
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Pending;
        assert!(!owner.dispose_keyring_storage());
        // These are explicit predicate DATA inputs, not fabricated native joins.
        // Constructor refusal has positively created NO original SDK resource.
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        assert!(owner.original_resources_settled() && !owner.resources_settled());
        owner.retired.store(false, Ordering::SeqCst); assert!(!owner.dispose_keyring_storage());
        owner.retired.store(true, Ordering::SeqCst);
        {
            let _draining = owner.retirement.lock().unwrap();
            assert!(!owner.dispose_keyring_storage());
        }
        state.unknown = true;
        let slot = state.slot.as_mut().unwrap(); slot.phase = Phase::Unknown; slot.settlement = Settlement::Unknown;
        owner.stop(); let at = owner.keyring.lock().unwrap().problem_at();
        assert!(owner.keyring.lock().unwrap().memory_held());
        assert!(owner.dispose_keyring_storage()); assert!(!owner.dispose_keyring_storage());
        assert!(owner.resources_settled());
        let book = owner.keyring.lock().unwrap();
        assert!(book.started() && book.allocations_released() && !book.memory_held() && !book.can_begin());
        assert_eq!(book.problem_at(), at); drop(book);
        assert!(state.unknown && state.slot.as_ref().unwrap().phase == Phase::Unknown
            && state.slot.as_ref().unwrap().settlement == Settlement::Unknown);
        let other = OriginalWork::new(2, false, Weak::new());
        other.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        *other.keyring.lock().unwrap() = crate::vault_keyring_linux::LookupBook::shutdown_gate_data(Instant::now() + WORK);
        assert!(!other.dispose_keyring_storage());
        let held = other.keyring.lock().unwrap().memory_held();
        assert!(held && !other.resources_settled());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn keyring_gate_requires_current_original_and_never_renews_cleanup_cutoff() {
        use crate::vault_keyring_linux::{Problem, Step};
        let mut state = empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let owner = OriginalWork::new(1, false, Weak::new()); let now = Instant::now();
        owner.set_endpoint(Some(now + WORK));
        let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None); slot.phase = Phase::Assessing;
        state.slot = Some(slot);
        assert_eq!(keyring_slot_gate(&state, &owner, None, now), Ok(now + WORK));
        let other = OriginalWork::new(1, false, Weak::new()); // even the same numeric ID is not this original
        assert_eq!(keyring_slot_gate(&state, &other, Some(Step::RemoveMatch), now), Err(Problem::Interrupted));
        state.slot.as_mut().unwrap().operation = Operation::InspectEvidence;
        assert!(keyring_slot_gate(&state, &owner, Some(Step::RemoveMatch), now).is_err());
        state.slot.as_mut().unwrap().operation = Operation::Prepare;
        assert!(keyring_slot_gate(&state, &owner, Some(Step::SearchItems), now + WORK).is_err());
        state.slot.as_mut().unwrap().stop(Reason::UserCancelled, now);
        state.lifetime.invalidate(); state.lost_observed = true; state.stopping = true;
        let cleanup_end = state.slot.as_ref().unwrap().cleanup_end.unwrap();
        assert_eq!(cleanup_end, now + CLEANUP);
        assert!(keyring_slot_gate(&state, &owner, Some(Step::SearchItems), now).is_err());
        assert_eq!(keyring_slot_gate(&state, &owner, Some(Step::RemoveMatch), cleanup_end - Duration::from_nanos(1)), Ok(cleanup_end));
        assert_eq!(keyring_slot_gate(&state, &owner, Some(Step::RemoveMatch), cleanup_end), Err(Problem::CleanupUnknown));
        assert_eq!(keyring_slot_gate(&state, &owner, Some(Step::RemoveMatch), cleanup_end + Duration::from_nanos(1)), Err(Problem::CleanupUnknown));
        state.slot.as_mut().unwrap().phase = Phase::Unknown;
        assert_eq!(keyring_slot_gate(&state, &owner, Some(Step::RemoveMatch), now), Err(Problem::CleanupUnknown));
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(cleanup_end));
        assert_eq!(owner.endpoint(), Some(now + WORK)); // checks never create/extend a lease
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn keyring_final_gate_rechecks_changes_after_stream_readiness() {
        use crate::vault_keyring_linux::{LookupBook, Next, Problem, Step};
        use std::sync::atomic::AtomicUsize;
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Change { Cutoff, SlotUnknown, DocumentUnknown, OtherOriginal, AlreadyPolled }
        struct DataCall { polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>, ready: Arc<AtomicBool> }
        impl Future for DataCall {
            type Output = zbus::Result<zbus::Message>;
            fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Self::Output> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.ready.load(Ordering::SeqCst) { Poll::Ready(Err(zbus::Error::InvalidReply)) } else { Poll::Pending }
            }
        }
        impl Drop for DataCall { fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); } }
        for step in [Step::CloseSession, Step::RemoveMatch] {
        for change in [Change::Cutoff, Change::SlotUnknown, Change::DocumentUnknown, Change::OtherOriginal, Change::AlreadyPolled] {
            let mut state = empty_state();
            state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
            let now = Instant::now(); let work_end = now + WORK;
            let owner = OriginalWork::new(1, false, Weak::new()); owner.set_endpoint(Some(work_end));
            let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None); slot.phase = Phase::Assessing;
            state.slot = Some(slot);
            let admitted_end = keyring_slot_gate(&state, &owner, Some(step), now).unwrap();
            assert_eq!(admitted_end, work_end);
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(AtomicBool::new(false));
            *owner.keyring.lock().unwrap() = LookupBook::cleanup_step_data(step, admitted_end,
                DataCall { polls: polls.clone(), drops: drops.clone(), ready: ready.clone() });
            let mut cx = TaskContext::from_waker(Waker::noop());
            {
                let mut book = owner.keyring.lock().unwrap();
                assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
                assert_eq!(polls.load(Ordering::SeqCst), 0); // Stream readiness is NOT permission to send.
                if change == Change::AlreadyPolled {
                    let gate = keyring_poll_gate(&state, &owner, &book, now);
                    book.first_poll(&mut cx, gate);
                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                }
            }
            // Change the ACTUAL slot after stream readiness, before final gate.
            // This is the rejected SOURCE01 interleaving, not a replacement gate
            // model or a fake live DBus/SDK task-settlement receipt.
            let mut gate_at = now;
            match change {
                Change::Cutoff => {
                    state.slot.as_mut().unwrap().stop(Reason::UserCancelled, now);
                    gate_at = state.slot.as_ref().unwrap().cleanup_end.unwrap();
                    assert_eq!(gate_at, now + CLEANUP); assert!(gate_at < admitted_end);
                }
                Change::SlotUnknown | Change::AlreadyPolled => {
                    let slot = state.slot.as_mut().unwrap(); slot.stop(Reason::UserCancelled, now);
                    slot.phase = Phase::Unknown; slot.settlement = Settlement::Unknown;
                }
                Change::DocumentUnknown => state.unknown = true,
                Change::OtherOriginal => {
                    // Same numeric ID cannot stand in for the original Arc.
                    state.slot.as_mut().unwrap().owner = OriginalWork::new(owner.id, false, Weak::new());
                }
            }
            let mut book = owner.keyring.lock().unwrap();
            let gate = keyring_poll_gate(&state, &owner, &book, gate_at);
            assert_eq!(gate, Err(if change == Change::OtherOriginal { Problem::Interrupted } else { Problem::CleanupUnknown }));
            if change == Change::AlreadyPolled {
                // The final gate now denies every NEW call, but an already-polled
                // original bypasses re-admission and remains owned until Ready.
                book.interrupt();
                assert!(book.idle_data_turn(&mut cx).is_pending());
                assert_eq!(polls.load(Ordering::SeqCst), 2); assert_eq!(drops.load(Ordering::SeqCst), 0);
                ready.store(true, Ordering::SeqCst);
                assert!(book.idle_data_turn(&mut cx).is_pending());
                assert_eq!(polls.load(Ordering::SeqCst), 3); assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(book.idle_data_turn(&mut cx).is_pending()); // Keep the original failure, not success.
                book.shutdown_admission_refused(Problem::CleanupUnknown); // Existing Unknown also denies NEW local shutdown.
            } else {
                book.first_poll(&mut cx, gate);
                assert_eq!(polls.load(Ordering::SeqCst), 0); assert_eq!(drops.load(Ordering::SeqCst), 1);
            }
            assert!(book.cleanup_unknown() && !book.resources_settled());
            assert_eq!(owner.endpoint(), Some(work_end));
        }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn keyring_pending_cleanup_contracts_to_first_stop_without_losing_original() {
        use crate::vault_keyring_linux::{LookupBook, Next, Problem, Step};
        use std::sync::atomic::AtomicUsize;
        struct DataCall { ready: bool, polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize> }
        impl Future for DataCall {
            type Output = zbus::Result<zbus::Message>;
            fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Self::Output> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.ready {
                    let call = zbus::Message::method_call("/", "Test").unwrap().build(&()).unwrap();
                    Poll::Ready(Ok(zbus::Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap().build(&()).unwrap()))
                } else { Poll::Pending }
            }
        }
        impl Drop for DataCall { fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); } }
        for step in [Step::CloseSession, Step::RemoveMatch] {
            for raw_boundary in [false, true] {
                let (mut state, owner) = keyring_memory_model();
                let work_end = Instant::now() + WORK; owner.set_endpoint(Some(work_end));
                let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
                let mut book = LookupBook::cleanup_step_data(step, work_end,
                    DataCall { ready: raw_boundary, polls: polls.clone(), drops: drops.clone() });
                let mut cx = TaskContext::from_waker(Waker::noop());
                assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
                book.first_poll(&mut cx, keyring_poll_gate(&state, &owner, &book, Instant::now()));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), usize::from(raw_boundary));

                // The real original slot changes AFTER first poll; no sleep,
                // alternate lifecycle model or fabricated SDK join is involved.
                let stop_at = Instant::now();
                assert!(keyring_problem_stop(&mut state, &owner, Some((Problem::Interrupted, stop_at))));
                let end = state.slot.as_ref().unwrap().cleanup_end.unwrap();
                assert_eq!(end, stop_at + CLEANUP); assert!(end < work_end);
                book.interrupt(); let first_failure = book.problem_at();
                keyring_constrain_cleanup(&state, &owner, &mut book);
                let midpoint = stop_at + CLEANUP / 2;
                assert_eq!(book.cleanup_progress_data(midpoint), (Some(midpoint), true, !raw_boundary, raw_boundary));
                assert!(!book.cleanup_progress_data(midpoint - Duration::from_nanos(1)).1);
                assert!(keyring_slot_gate(&state, &owner, Some(step), midpoint).is_ok());
                assert!(keyring_slot_gate(&state, &owner, Some(Step::GetSecret), midpoint).is_err());
                assert_eq!(keyring_slot_gate(&state, &owner, Some(step), end), Err(Problem::CleanupUnknown));
                assert!(!state.unknown && !book.document_cleanup_unknown());

                // Repeated/later failures cannot extend either clock or consume
                // the original future/raw boundary. Another equal-ID owner is
                // not the same slot; existing Unknown still denies new work.
                assert!(!keyring_problem_stop(&mut state, &owner, Some((Problem::Crypto, end))));
                keyring_constrain_cleanup(&state, &owner, &mut book);
                assert_eq!(book.cleanup_progress_data(midpoint), (Some(midpoint), true, !raw_boundary, raw_boundary));
                assert_eq!(book.problem_at(), first_failure);
                assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(end));
                assert_eq!(owner.endpoint(), Some(work_end));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), usize::from(raw_boundary));
                assert!(!book.resources_settled() && book.memory_held());
                let other = OriginalWork::new(owner.id, false, Weak::new());
                assert!(keyring_slot_gate(&state, &other, Some(step), midpoint).is_err());
                state.unknown = true;
                assert_eq!(keyring_slot_gate(&state, &owner, Some(step), midpoint), Err(Problem::CleanupUnknown));
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn keyring_local_shutdown_has_its_own_current_slot_cutoff_and_one_use_grant() {
        use crate::vault_keyring_linux::{LookupBook, Next, Problem};
        let mut state = empty_state();
        let owner = OriginalWork::new(1, false, Weak::new());
        let now = Instant::now(); let end = now + WORK;
        owner.set_endpoint(Some(end));
        let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None);
        slot.phase = Phase::Assessing; state.slot = Some(slot);
        let mut book = LookupBook::shutdown_gate_data(end);
        let original_failure_at = book.problem_at();
        assert!(original_failure_at.is_some() && !book.cleanup_unknown());
        let mut cx = TaskContext::from_waker(Waker::noop());
        assert!(book.current_step().is_none()); // It never impersonates RemoveMatch.
        assert!(keyring_shutdown_gate(&state, &owner, &book, now).is_err());
        assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPollShutdown)));
        let grant = keyring_shutdown_gate(&state, &owner, &book, now).unwrap();
        assert_eq!(grant.into_endpoint(), end);
        let other = OriginalWork::new(owner.id, false, Weak::new());
        assert!(matches!(keyring_shutdown_gate(&state, &other, &book, now), Err(Problem::Interrupted)));

        state.slot.as_mut().unwrap().stop(Reason::UserCancelled, now);
        state.stopping = true; state.lost_observed = true;
        let cleanup_end = state.slot.as_ref().unwrap().cleanup_end.unwrap();
        assert!(cleanup_end < end);
        assert_eq!(keyring_shutdown_gate(&state, &owner, &book, now).unwrap().into_endpoint(), cleanup_end);
        assert!(matches!(keyring_shutdown_gate(&state, &owner, &book, cleanup_end), Err(Problem::CleanupUnknown)));
        state.unknown = true;
        let denied = keyring_shutdown_gate(&state, &owner, &book, now);
        assert!(matches!(denied, Err(Problem::CleanupUnknown)));
        book.first_poll_shutdown(&mut cx, denied);
        assert!(!book.shutdown_waiting_first_poll() && !book.resources_settled());
        assert!(book.cleanup_unknown());
        assert_eq!(book.problem_at(), original_failure_at);
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(cleanup_end));
        assert_eq!(owner.endpoint(), Some(end));

        // Even an earlier, valid typed grant cannot outlive the original
        // staged endpoint when the consumer finally reaches its first poll.
        let mut expired = LookupBook::shutdown_gate_data(Instant::now());
        let expired_failure_at = expired.problem_at();
        assert!(matches!(expired.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPollShutdown)));
        state.unknown = false;
        let earlier_grant = keyring_shutdown_gate(&state, &owner, &expired, now).unwrap();
        expired.first_poll_shutdown(&mut cx, Ok(earlier_grant));
        assert_eq!(expired.problem(), Some(Problem::CleanupUnknown));
        assert!(!expired.shutdown_waiting_first_poll() && !expired.resources_settled());
        assert!(expired.cleanup_unknown());
        assert_eq!(expired.problem_at(), expired_failure_at);

        // A real typed grant cannot manufacture an absent SDK attempt or hide
        // the already-reconciled failed removal on that impossible path.
        let mut absent = LookupBook::shutdown_gate_data(end);
        let absent_failure_at = absent.problem_at();
        assert!(matches!(absent.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPollShutdown)));
        let grant = keyring_shutdown_gate(&state, &owner, &absent, now).unwrap();
        absent.first_poll_shutdown(&mut cx, Ok(grant));
        assert!(absent.cleanup_unknown() && !absent.resources_settled());
        assert!(!absent.shutdown_waiting_first_poll());
        assert_eq!(absent.problem_at(), absent_failure_at);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[tokio::test]
    async fn unstarted_keyring_preserves_session_predicate_but_entered_sdk_never_grants_finality() {
        // Existing DATA-only receipts exercise the predicate, not native joins.
        // The newly retained Builder future is NEVER polled or connected here.
        let owner = OriginalWork::new(1, false, Weak::new());
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        assert!(owner.original_resources_settled());
        let input = crate::vault_keyring_linux::LookupInput::new(std::path::Path::new("/synthetic/never-opened/bus"),
            "/collection", "reserved-vault", "reserved-generation").unwrap();
        owner.keyring.lock().unwrap().begin(input, Instant::now() + WORK, KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        assert!(!owner.original_resources_settled());
        owner.stop(); owner.set_endpoint(Some(Instant::now()));
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Failed;
        assert!(!owner.original_resources_settled());
        assert!(owner.keyring.lock().unwrap().started());
        assert!(owner.keyring.lock().unwrap().memory_held());
        assert!(!owner.dispose_keyring_storage());
    }
}
