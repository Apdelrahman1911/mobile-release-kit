//! Three fixed observations of the ordinary installed Windows application.
//! This is the existing harness=false process main and existing relay, not a
//! replacement executor, document, runtime or shipping automation interface.
//! All native actions target B's retained original STA dialog. Child result
//! bytes report pre-exit readiness only; the native owner/finalizer proves exit.
use std::{path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, atomic::{AtomicBool, Ordering}},
    thread::ThreadId, time::Instant};
use serde_json::{json, Value};
use tauri::Manager;
use crate::{asset_commands::{AssetError, Reason}, asset_session::{DocumentBinding, GuiCall, OriginalWork},
    bridge::AppInfo, bridge::Project, edit_owner::EditOwner, edit_protocol as edit,
    error::BridgeError, supervisor::{Supervisor, WindowsPassiveWitness}};
use mrk_windows_installed_native::{self as native, UiCaseFacts, UiRole};
use native::ui_observer_diagnostic_data::{PendingKind, Refusal, Snapshot, Step};
use super::owned_windows::observation::{observed_dialog, observe_dialog_action, session_final,
    DialogAction, DialogKind, ObservedDialog};

const METHODS: [&str; 6] = ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"];
const APP_ID: &str = "org.example.mrk.observed";
const DRAFT_SOURCE: &str = "draft-version.properties";
const DOM_LIMIT: u16 = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Case { ProjectDraft, QuitPassive, DocumentLoss }
impl Case {
    fn selected_id(self) -> u32 { if self == Self::ProjectDraft { 2 } else { 1 } }
    fn held(self) -> bool { self != Self::ProjectDraft }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomDispatch { step: Step, sequence: u16 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pending { Dom(DomDispatch), Native(Step), Close(Step), Reload }
struct DialogWitness { id: u32, kind: DialogKind, call: Arc<GuiCall>, owner: Arc<OriginalWork> }
impl DialogWitness {
    fn same(&self, dialog: &ObservedDialog) -> bool {
        self.id == dialog.id && self.kind == dialog.native.kind && Arc::ptr_eq(&self.call, &dialog.call)
            && self.call.owner().is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
            && Arc::ptr_eq(&self.owner.gui, &self.call)
    }
    fn settled(&self, accepted: bool, quit_cancel: bool) -> bool {
        self.call.owner().is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
            && self.owner.id == self.id && Arc::ptr_eq(&self.owner.gui, &self.call)
            && self.call.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.not_created
                && !facts.constructing && !facts.showing && facts.response && facts.destroyed && facts.released
                && facts.close_queued && facts.close_ack && facts.release_queued && facts.refusal.is_none() && facts.selected.is_none()
                && facts.accepted == accepted && facts.declined == quit_cancel && facts.accepted_at.is_some() == accepted)
    }
}
struct Record {
    step: Step, pending: Option<Pending>, evaluations: u16,
    attached: bool, navigation: bool, started: bool, loaded: bool,
    methods: [bool; 6], method_rows: usize, project_calls: u8,
    cancel_returned: bool, project: Option<Project>, lost_picker_returned: bool,
    dialogs: Vec<DialogWitness>, visible: [bool; 3], actions_attempted: [bool; 5], actions_returned: [bool; 5],
    snapshot_requests: u8, snapshot_pending: bool, snapshots: u8, held_snapshot_refused: bool,
    suggestion_requested: bool, suggestion: Option<Value>, validation_requested: bool,
    preview_requested: bool, preview: Option<Value>, hydrated: bool, edited: bool, preserved: bool,
    mutation_returned: bool, quit_cancelled: bool, close_count: u8,
    initial: Option<WindowsPassiveWitness>, held: Option<WindowsPassiveWitness>, held_seen: bool,
    generation: Option<String>, loss_generation: Option<String>, registry_generation: Option<u32>,
    picker_pending: bool, reload_requested: bool, reload_returned: bool, reload_navigation: bool, reload_started: bool,
    loss_settled: bool, relay_joined: bool, actual_exit: bool, finality: [bool; 6],
}
impl Record {
    fn diagnostic(&self) -> Snapshot {
        let (pending, pending_step, dispatch) = match self.pending {
            None => (PendingKind::None, None, 0),
            Some(Pending::Dom(value)) => (PendingKind::Dom, Some(value.step), value.sequence),
            Some(Pending::Native(step)) => (PendingKind::Native, Some(step), 0),
            Some(Pending::Close(step)) => (PendingKind::Close, Some(step), 0),
            Some(Pending::Reload) => (PendingKind::Reload, None, 0),
        };
        let flags = [self.attached, self.navigation, self.started, self.loaded, self.initial.is_some(),
            self.methods[0], self.methods[1], self.snapshot_pending, self.project.is_some(), self.cancel_returned,
            self.mutation_returned, self.held_seen, self.reload_requested, self.loss_settled, self.relay_joined, self.actual_exit]
            .into_iter().enumerate().fold(0u16, |bits, (index, value)| bits | (u16::from(value) << index));
        Snapshot { step: self.step, pending, pending_step, dispatch, flags }
    }
}
pub(super) struct Observation {
    case: Case, main: ThreadId, end: Instant, project_path: PathBuf, base: Value, changed: Value,
    draft: Value, failed: AtomicBool, reported: AtomicBool, record: Mutex<Record>,
    diagnostic: Option<Arc<native::ObserverDiagnostic>>, diagnostic_document: OnceLock<DocumentBinding>,
}
impl Observation {
    fn new(case: Case, end: Instant, project_path: PathBuf, diagnostic: Option<Arc<native::ObserverDiagnostic>>) -> Result<Self, ()> {
        let base = crate::protocol::strict_json(native::UI_FIXTURE_CONFIG).map_err(|_| ())?;
        let changed = crate::protocol::strict_json(native::UI_FIXTURE_CONFIG_AFTER).map_err(|_| ())?;
        let mut draft = base.clone(); draft["version"]["source"] = json!(DRAFT_SOURCE);
        Ok(Self { case, main: std::thread::current().id(), end, project_path, base, changed, draft,
            diagnostic, diagnostic_document: OnceLock::new(),
            failed: AtomicBool::new(false), reported: AtomicBool::new(false), record: Mutex::new(Record {
                step: Step::Bootstrap, pending: None, evaluations: 0,
                attached: false, navigation: false, started: false, loaded: false,
                methods: [false; 6], method_rows: 0, project_calls: 0,
                cancel_returned: false, project: None, lost_picker_returned: false,
                dialogs: Vec::with_capacity(3), visible: [false; 3], actions_attempted: [false; 5], actions_returned: [false; 5],
                snapshot_requests: 0, snapshot_pending: false, snapshots: 0, held_snapshot_refused: false,
                suggestion_requested: false, suggestion: None, validation_requested: false,
                preview_requested: false, preview: None, hydrated: false, edited: false, preserved: false,
                mutation_returned: false, quit_cancelled: false, close_count: 0,
                initial: None, held: None, held_seen: false,
                generation: None, loss_generation: None, registry_generation: None,
                picker_pending: false, reload_requested: false, reload_returned: false, reload_navigation: false, reload_started: false,
                loss_settled: false, relay_joined: false, actual_exit: false, finality: [false; 6],
            }) })
    }
    fn fail(&self, reason: Refusal) {
        self.failed.store(true, Ordering::SeqCst);
        // Existing callers may hold Record. This is only a first-wins atomic
        // latch: no recursive lock, formatting, native effect or app repair.
        if let Some(diagnostic) = &self.diagnostic { diagnostic.refuse(reason); }
    }
    pub(super) fn diagnostic(&self) -> Option<Arc<native::ObserverDiagnostic>> { self.diagnostic.clone() }
    pub(super) fn bind_diagnostic_document(&self, document: DocumentBinding) {
        if self.diagnostic_document.set(document).is_err() {
            if let Some(diagnostic) = &self.diagnostic { diagnostic.unavailable(); }
        }
    }
    fn diagnostic_permitted(&self) -> bool {
        self.diagnostic_document.get().and_then(DocumentBinding::exit_cleanup_end).is_none_or(|end| Instant::now() < end)
    }
    fn diagnostic_snapshot(&self) {
        let Some(diagnostic) = &self.diagnostic else { return; };
        // Nonwaiting copy of closed scalars; the actual guard is gone before
        // even atomic publication, and certainly before any native operation.
        let snapshot = match self.record.try_lock() { Ok(record) => Some(record.diagnostic()), Err(_) => None };
        match snapshot { Some(snapshot) => diagnostic.observe(snapshot), None => diagnostic.unavailable() }
    }
    fn diagnostic_progress(&self) {
        self.diagnostic_snapshot();
        if let Some(diagnostic) = &self.diagnostic { diagnostic.progress(&|| self.diagnostic_permitted()); }
    }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.fail(Refusal::Record); None } }
    }
    fn try_record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.try_lock() {
            Ok(record) => Some(record), Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(_)) => { self.fail(Refusal::Record); None },
        }
    }
    fn timely(&self) -> bool {
        if Instant::now() >= self.end { self.fail(Refusal::Deadline); }
        !self.failed.load(Ordering::SeqCst)
    }
    fn report_failure(&self) {
        self.diagnostic_progress();
        if self.failed.load(Ordering::SeqCst) && !self.reported.swap(true, Ordering::SeqCst) {
            // Fixed public category only. Never emit paths/native errors/DTOs.
            super::diagnostic(b"MRK_WINDOWS_NORMAL_UI=observer-refused\n");
        }
    }
    pub(super) fn attach(&self, supervisor: &Supervisor) -> Result<(), BridgeError> {
        let Some(mut r) = self.record() else { return Err(BridgeError::cleanup_unknown()); };
        if !self.timely() || std::thread::current().id() != self.main || r.attached
            || supervisor.arm_windows_ui_observation().is_err() { self.fail(Refusal::Attach); return Err(BridgeError::invalid()); }
        r.attached = true; Ok(())
    }
    pub(super) fn navigation(&self, trusted: bool, allowed: bool) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !trusted || !r.attached { self.fail(Refusal::Navigation); return; }
        if !r.navigation && !r.loaded && allowed { r.navigation = true; return; }
        if self.case == Case::DocumentLoss && r.reload_requested && r.loaded && !allowed && !r.reload_navigation {
            r.reload_navigation = true; return;
        }
        self.fail(Refusal::Navigation);
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !trusted || !r.attached { self.fail(Refusal::PageLoad); return; }
        if r.reload_requested {
            if self.case == Case::DocumentLoss && !finished && r.loaded && !r.reload_started { r.reload_started = true; return; }
            // No second Finished can create or restore a usable document.
            self.fail(Refusal::PageLoad); return;
        }
        if if finished { !r.started || r.loaded } else { r.started } { self.fail(Refusal::PageLoad); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        let Some(methods) = info.capabilities.as_ref().and_then(|value| value["methods"].as_array()) else { self.fail(Refusal::AppInfo); return; };
        let Some(actions) = info.capabilities.as_ref().and_then(|value| value["actions"].as_array()) else { self.fail(Refusal::AppInfo); return; };
        let open = |row: &&Value| row["available"].as_bool() == Some(true);
        let valid = info.runtime.state == "available" && info.runtime.mode == "bundled" && info.runtime.reason.is_none()
            && info.app_name == "Mobile Release Kit" && info.app_version == env!("CARGO_PKG_VERSION")
            && info.capabilities.as_ref().is_some_and(|value| value["hostPlatform"] == "windows")
            && info.project_selection.available && info.project_selection.reason.is_none() && !info.project_path_selection.available
            && (6..=64).contains(&methods.len()) && (1..=64).contains(&actions.len())
            && methods.iter().filter(open).count() == 6
            && METHODS.iter().all(|name| methods.iter().filter(open).filter(|row| row["method"].as_str() == Some(*name)).count() == 1)
            && methods.iter().all(|row| row["available"].is_boolean())
            && actions.iter().all(|row| row["available"].as_bool() == Some(false));
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !valid || r.methods[0] || r.reload_requested || r.step != Step::Bootstrap { self.fail(Refusal::AppInfo); return; }
        r.methods[0] = true; r.method_rows = methods.len();
    }
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        let valid = result.as_ref().ok().and_then(|value| value["fields"].as_array()).is_some_and(|fields|
            fields.len() <= 64 && fields.iter().filter(|field| field["path"] == "version.source"
                && ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"].iter()
                    .all(|key| field[*key].as_str().is_some_and(|text| !text.is_empty() && text.len() <= 16384))).count() == 1);
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !valid || !r.methods[0] || r.methods[1] || r.reload_requested || r.step != Step::Bootstrap { self.fail(Refusal::Catalog); return; }
        r.methods[1] = true;
    }
    pub(super) fn project_result(&self, result: &Result<Option<Project>, AssetError>) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() { return; }
        if r.reload_requested && self.case == Case::DocumentLoss {
            if r.lost_picker_returned || !r.picker_pending
                || !matches!(result, Err(error) if error.reason == Reason::DocumentLost) { self.fail(Refusal::ProjectResult); return; }
            r.lost_picker_returned = true; return;
        }
        if self.case == Case::ProjectDraft && matches!(r.step, Step::CancelProject | Step::CancelSettled) {
            if r.cancel_returned || !matches!(result, Ok(None)) || !r.actions_attempted[0] { self.fail(Refusal::ProjectResult); return; }
            r.cancel_returned = true; return;
        }
        let Ok(Some(project)) = result else { self.fail(Refusal::ProjectResult); return; };
        if !matches!(r.step, Step::AcceptProject | Step::ProjectSettled) || r.project.is_some()
            || !r.actions_attempted[2] || Path::new(&project.path) != self.project_path
            || project.name != "project" || !crate::protocol::valid_id(&project.id) { self.fail(Refusal::ProjectResult); return; }
        r.project = Some(project.clone());
    }
    pub(super) fn snapshot_request(&self, project: &str) {
        let Some(mut r) = self.record() else { return; };
        let permitted = r.snapshot_requests == 0 && matches!(r.step, Step::AcceptProject | Step::ProjectSettled | Step::Snapshot)
            || r.snapshot_requests == 1 && matches!(r.step, Step::Refresh | Step::Refreshed | Step::HeldRefresh | Step::Held);
        if !self.timely() || !permitted || r.snapshot_pending || r.reload_requested
            || !r.project.as_ref().is_some_and(|original| original.id == project) { self.fail(Refusal::SnapshotRequest); return; }
        r.snapshot_requests += 1; r.snapshot_pending = true;
    }
    pub(super) fn snapshot(&self, project: &str, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.snapshot_pending || !r.project.as_ref().is_some_and(|original| original.id == project) { self.fail(Refusal::Snapshot); return; }
        if self.case.held() && r.snapshot_requests == 2 {
            if !r.actions_attempted[4] || r.held_snapshot_refused || !r.held_seen
                || !matches!(result, Err(error) if error.code == "shutting_down") { self.fail(Refusal::Snapshot); return; }
            r.held_snapshot_refused = true; r.snapshot_pending = false; return;
        }
        let saved = self.case != Case::ProjectDraft || r.snapshot_requests == 2;
        let config = if self.case == Case::ProjectDraft { &self.changed } else { &self.base };
        let valid = result.as_ref().is_ok_and(|value| {
            let observed = &value["config"]; let hints = &value["discovery"]["hints"];
            value["root"].as_str() == self.project_path.to_str() && value["observationScope"] == "single-request-non-atomic"
                && assurance(value, "static-text") && value["issues"].as_array().is_some_and(Vec::is_empty)
                && observed["path"] == "release/mobile-release.json" && hints["android"]["applicationId"] == APP_ID
                && hints["android"]["module"] == ":app" && hints["android"]["buildFile"] == "app/build.gradle.kts"
                && hints["versionSource"] == "version.properties" && hints["versionNameKey"] == "VERSION_NAME"
                && hints["versionBuildKey"] == "BUILD_NUMBER" && value["discovery"]["partial"] == false && value["discovery"]["state"] == "unverified"
                // Frozen Windows C19 returns JSON DATA, not a POSIX save-input
                // fingerprint. Exact fixture bytes have their native readback;
                // never fabricate config.content or enable a Save family here.
                && if saved { observed["state"] == "format-valid" && &observed["data"] == config && observed["content"].is_null()
                    && observed["issues"].as_array().is_some_and(Vec::is_empty) }
                else { observed["state"] == "missing" && observed["data"].is_null() && observed["content"].is_null()
                    && observed["issues"].as_array().is_some_and(|issues| issues.len() == 1 && issues[0]["code"] == "config.missing") }
        });
        if !valid || r.snapshots + 1 != r.snapshot_requests || r.reload_requested
            || r.snapshot_requests == 2 && !r.mutation_returned { self.fail(Refusal::Snapshot); return; }
        r.snapshot_pending = false; r.snapshots += 1; r.methods[2] = true;
    }
    pub(super) fn suggest_request(&self, hints: &Value) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || self.case != Case::ProjectDraft || r.suggestion_requested
            || !matches!(r.step, Step::Suggest | Step::Suggestion)
            || *hints != json!({"platforms":["android"], "androidApplicationId":APP_ID,
                "versionSource":"version.properties", "versionNameKey":"VERSION_NAME", "versionBuildKey":"BUILD_NUMBER"}) { self.fail(Refusal::SuggestRequest); return; }
        r.suggestion_requested = true;
    }
    pub(super) fn suggestion(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(value) = result.as_ref().ok().filter(|value| value["draft"] == self.base && value["schemaVersion"] == 1
            && value["platformSelectionRequired"] == false && format_valid(&value["validation"]) && assurance(value, "schema-policy")) else { self.fail(Refusal::Suggestion); return; };
        if !self.timely() || !r.suggestion_requested || r.suggestion.is_some() || r.reload_requested { self.fail(Refusal::Suggestion); return; }
        let Some(rows) = value["provenance"].as_array().filter(|rows| !rows.is_empty() && rows.len() <= 64) else { self.fail(Refusal::Suggestion); return; };
        let sample: Option<Vec<Value>> = rows.iter().map(|row| {
            let path = row["path"].as_str()?; let source = row["source"].as_str()?;
            (path.len() <= 128 && matches!(source, "hint" | "default" | "example")).then(|| json!({"path":path,"source":source}))
        }).collect();
        let Some(sample) = sample else { self.fail(Refusal::Suggestion); return; };
        r.suggestion = Some(Value::Array(sample)); r.methods[4] = true;
    }
    pub(super) fn validate_request(&self, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.edited || r.validation_requested || self.case != Case::ProjectDraft
            || !matches!(r.step, Step::Validate | Step::Validated) || draft != &self.draft { self.fail(Refusal::ValidateRequest); return; }
        r.validation_requested = true;
    }
    pub(super) fn validation(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.validation_requested || r.methods[3] || !result.as_ref().is_ok_and(format_valid) { self.fail(Refusal::Validation); return; }
        r.methods[3] = true;
    }
    pub(super) fn preview_request(&self, base: &Value, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.methods[3] || r.preview_requested || !matches!(r.step, Step::Preview | Step::Previewed)
            || !base.is_null() || draft != &self.draft { self.fail(Refusal::PreviewRequest); return; }
        r.preview_requested = true;
    }
    pub(super) fn preview_result(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(value) = result.as_ref().ok().filter(|value| format_valid(&value["validation"]) && assurance(value, "schema-policy")
            && value["comparison"]["state"] == "complete" && value["comparison"]["unreviewedCount"] == 0
            && value["comparison"]["baseProvided"] == false) else { self.fail(Refusal::PreviewResult); return; };
        if !self.timely() || !r.preview_requested || r.preview.is_some() { self.fail(Refusal::PreviewResult); return; }
        r.preview = Some(json!({"counts":value["comparison"]["counts"], "fields":value["fields"].as_array().map(Vec::len),
            "valid":value["validation"]["state"]})); r.methods[5] = true;
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record() else { return; };
        let Some(Pending::Close(step)) = r.pending else { self.fail(Refusal::ClosePrevented); return; };
        if !self.timely() || !matches!((step, r.step), (Step::CloseCancel, Step::QuitCancel) | (Step::Close, Step::QuitConfirm)) {
            self.fail(Refusal::ClosePrevented); return;
        }
        r.pending = None; r.close_count += 1;
    }

    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if !self.timely() { self.report_failure(); return; }
        if std::thread::current().id() == self.main { self.fail(Refusal::Tick); return; }
        self.diagnostic_progress();
        let state = app.state::<super::ShellState>();
        let step = {
            let Some(mut r) = self.record() else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.initial.is_none() {
                match state.bridge.supervisor.retain_windows_initial() {
                    Ok(Some(witness)) => r.initial = Some(witness), Ok(None) => return, Err(_) => { self.fail(Refusal::Tick); return; },
                }
            }
            if !self.document_sample(&state, &mut r) { return; }
            match r.step {
                Step::Bootstrap => {
                    if !r.navigation || !r.methods[0] || !r.methods[1] { return; }
                    r.step = Step::Environment;
                },
                Step::CancelSettled => {
                    if !r.cancel_returned { return; }
                    if !r.dialogs.first().is_some_and(|dialog| dialog.settled(false, false))
                        || !source_idle(&state.document, 1, "user-cancelled") || state.bridge.native_generation().ok() != Some(1) { self.fail(Refusal::Tick); return; }
                    r.step = Step::ReadCancelled;
                },
                Step::ProjectSettled => {
                    if r.project.is_none() { return; }
                    if !r.dialogs.iter().find(|dialog| dialog.id == self.case.selected_id()).is_some_and(|dialog| dialog.settled(true, false) && !dialog.owner.stopped())
                        || !source_idle(&state.document, self.case.selected_id(), "none") || state.bridge.native_generation().ok() != Some(2) { self.fail(Refusal::Tick); return; }
                    r.registry_generation = Some(2); r.step = Step::Snapshot;
                },
                Step::Snapshot if r.snapshots != 1 => return,
                Step::Suggestion if r.suggestion.is_none() => return,
                Step::Validated if !r.methods[3] => return,
                Step::Previewed if r.preview.is_none() => return,
                Step::MutateFixture => {
                    if self.case != Case::ProjectDraft || r.mutation_returned || !r.edited || !r.methods.iter().all(|done| *done) { self.fail(Refusal::Tick); return; }
                    // Fixed native CREATE_NEW of config_AFTER in the owner-created
                    // synthetic fixture. This is labelled test input mutation,
                    // never Save, a project hook or arbitrary supplied file write.
                    if native::mutate_normal_ui_fixture(self.end).is_err() || !self.timely() { self.fail(Refusal::Tick); return; }
                    r.mutation_returned = true; r.step = Step::ReturnDashboard; return;
                },
                Step::Refreshed if r.snapshots != 2 => return,
                Step::ArmHold => {
                    if !self.case.held() || r.held.is_some() || r.snapshots != 1
                        || state.bridge.supervisor.arm_windows_refresh_hold().is_err() { self.fail(Refusal::Tick); return; }
                    r.step = Step::HeldRefresh;
                },
                Step::Held => {
                    if r.held.is_none() {
                        match state.bridge.supervisor.retain_windows_held_refresh() {
                            Ok(Some(witness)) => r.held = Some(witness), Ok(None) => return, Err(_) => { self.fail(Refusal::Tick); return; },
                        }
                    }
                    if !r.snapshot_pending || !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { self.fail(Refusal::Tick); return; }
                    r.held_seen = true;
                    r.step = if self.case == Case::QuitPassive { Step::CloseCancel } else { Step::ChoosePending };
                },
                Step::QuitCancelled => {
                    // status()/assets_can_exit reconcile only already-ended
                    // originals; not_quitting cannot bypass an unresolved quit.
                    if !state.document.assets_can_exit() || state.document.not_quitting().is_err() { return; }
                    if !r.dialogs.iter().find(|dialog| dialog.id == 2).is_some_and(|dialog| dialog.settled(false, true))
                        || !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { self.fail(Refusal::Tick); return; }
                    r.quit_cancelled = true; r.step = Step::Close;
                },
                Step::Lost => {
                    if !r.reload_returned || !(r.reload_navigation || r.reload_started) || r.loss_generation.is_none()
                        || !r.lost_picker_returned { return; }
                    if !source_idle(&state.document, 2, "document-lost")
                        || !r.dialogs.iter().find(|dialog| dialog.id == 2).is_some_and(|dialog| dialog.settled(false, false))
                        || !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { self.fail(Refusal::Tick); return; }
                    r.loss_settled = true; r.step = Step::Close;
                },
                Step::Exit => return,
                _ => {},
            }
            r.step
        };
        self.diagnostic_progress(); // The first-phase Record guard has ended.
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(Refusal::Tick); return; };
        if matches!(step, Step::Close | Step::CloseCancel) {
            let Some(mut r) = self.record() else { return; };
            if !self.timely() || r.pending.is_some() || r.step != step || self.case.held()
                && !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { self.fail(Refusal::Tick); return; }
            r.pending = Some(Pending::Close(step));
            r.step = if step == Step::CloseCancel { Step::QuitCancel } else { Step::QuitConfirm };
            drop(r);
            // Original production CloseRequested -> actual native confirmation.
            // A dispatch return is not a response, completion or exit permit.
            if !self.timely() || window.close().is_err() { self.fail(Refusal::Tick); } return;
        }
        if matches!(step, Step::CancelProject | Step::SetFolder | Step::AcceptProject | Step::QuitCancel | Step::QuitConfirm | Step::PickerPending) {
            let Some(mut r) = self.record() else { return; };
            if !self.timely() || r.pending.is_some() || r.step != step { self.fail(Refusal::Tick); return; }
            // The already-owned dialog's timer services this exact pending
            // value. No Tauri task may wait behind the Show it must dismiss.
            r.pending = Some(Pending::Native(step)); return;
        }
        if step == Step::Reload {
            let Some(mut r) = self.record() else { return; };
            if !self.timely() || r.pending.is_some() || r.step != step || self.case != Case::DocumentLoss || r.reload_requested || !r.picker_pending
                || !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { self.fail(Refusal::Tick); return; }
            r.pending = Some(Pending::Reload); return;
        }
        let Some(script) = script(step) else { self.fail(Refusal::Tick); return; };
        let original = {
            let Some(mut r) = self.record() else { return; };
            if !self.timely() || r.evaluations == DOM_LIMIT || r.pending.is_some() || r.step != step { self.fail(Refusal::Tick); return; }
            r.evaluations += 1; let original = DomDispatch { step, sequence: r.evaluations };
            r.pending = Some(Pending::Dom(original)); original
        };
        let q = self.clone();
        // Exactly one outstanding synchronous expression. Unknown callbacks
        // stay pending; never replay a possibly effectful click or edit.
        if window.eval_with_callback(script, move |value| q.dom(original, &value)).is_err() { self.fail(Refusal::Tick); }
    }
    fn document_sample(&self, state: &super::ShellState, r: &mut Record) -> bool {
        let Ok(status) = state.bridge.edits.status() else { self.fail(Refusal::DocumentSample); return false; };
        if status.schema_version != 1 || !edit::token(&status.window_generation) || status.capability.available
            || status.active.is_some() || status.last_terminal.is_some() || state.bridge.edits.disabled()
            || state.bridge.supervisor.disabled() || state.bridge.diagnostics.disabled()
            || state.bridge.preflight.disabled() || state.bridge.android_build.disabled() { self.fail(Refusal::DocumentSample); return false; }
        match &r.generation {
            None => r.generation = Some(status.window_generation.clone()),
            Some(original) if original != &status.window_generation => {
                if self.case != Case::DocumentLoss || !r.reload_requested || !(r.reload_navigation || r.reload_started) { self.fail(Refusal::DocumentSample); return false; }
                if let Some(lost) = &r.loss_generation {
                    if lost != &status.window_generation { self.fail(Refusal::DocumentSample); return false; }
                } else { r.loss_generation = Some(status.window_generation.clone()); }
            },
            Some(_) if r.loss_generation.is_some() => { self.fail(Refusal::DocumentSample); return false; },
            _ => {},
        }
        if let Some(generation) = r.registry_generation {
            if state.bridge.native_generation().ok() != Some(generation) { self.fail(Refusal::DocumentSample); return false; }
        }
        true
    }
    pub(super) fn modal_turn(&self, app: &tauri::AppHandle, id: u32, kind: DialogKind, call: &Arc<GuiCall>) {
        if std::thread::current().id() != self.main || !self.timely() { self.fail(Refusal::NativeStep); return; }
        let pending = {
            let Some(r) = self.try_record() else { return; };
            r.pending
        }; // No Record/TLS/GuiFacts guard crosses a native action or eval.
        match pending {
            Some(Pending::Native(step)) => self.native_step(step, id, kind, call),
            Some(Pending::Reload) => self.reload_step(app, id, kind, call),
            _ => {},
        }
    }
    fn reload_step(&self, app: &tauri::AppHandle, id: u32, kind: DialogKind, call: &Arc<GuiCall>) {
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(Refusal::Tick); return; };
        let Some(mut r) = self.try_record() else { return; };
        if self.case != Case::DocumentLoss || id != 2 || kind != DialogKind::Project
            || r.pending != Some(Pending::Reload) || r.step != Step::Reload || r.reload_requested || r.reload_returned || !r.picker_pending
            || !r.dialogs.iter().find(|witness| witness.id == id).is_some_and(|witness|
                witness.kind == kind && Arc::ptr_eq(&witness.call, call) && witness.owner.id == id
                    && witness.call.owner().is_some_and(|owner| Arc::ptr_eq(&owner, &witness.owner))
                    && Arc::ptr_eq(&witness.owner.gui, call) && !witness.owner.interrupted())
            || !call.facts().is_some_and(|facts| facts.dispatched && facts.created && facts.showing && !facts.constructing
                && !facts.not_created && facts.refusal.is_none() && !facts.response && !facts.accepted && !facts.declined
                && !facts.close_queued && !facts.destroyed && !facts.close_ack && !facts.release_queued && !facts.released)
            || !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) || !self.timely() {
            self.fail(Refusal::Tick); return;
        }
        r.reload_requested = true; drop(r); // One-shot effect entry, never a queued/replayable task.
        // Real reload on this original main-STA modal turn. Only production
        // navigation/Started can invalidate the document; no lost() injection.
        let returned = window.eval("window.location.reload()");
        let Some(mut r) = self.record() else { return; };
        if r.pending != Some(Pending::Reload) || r.step != Step::Reload || returned.is_err() || !self.timely() {
            self.fail(Refusal::Tick); return;
        }
        r.pending = None; r.reload_returned = true; r.step = Step::Lost;
    }
    fn native_step(&self, step: Step, id: u32, kind: DialogKind, call: &Arc<GuiCall>) {
        if std::thread::current().id() != self.main || !self.timely() { self.fail(Refusal::NativeStep); return; }
        let returned = self.native_body(step, id, kind, call);
        if returned == Ok(None) { return; } // Record contention never consumes the pending operation.
        if returned.is_err() { self.fail(Refusal::NativeStep); }
        let Some(mut r) = self.record() else { return; };
        if r.pending != Some(Pending::Native(step)) || r.step != step { self.fail(Refusal::NativeStep); return; }
        // Only this very synchronous body return retires its dispatch marker.
        r.pending = None;
        if returned != Ok(Some(true)) || !self.timely() { return; }
        let (index, next) = match step {
            Step::CancelProject => (0, Step::CancelSettled), Step::SetFolder => (1, Step::AcceptProject),
            Step::AcceptProject => (2, Step::ProjectSettled), Step::QuitCancel => (3, Step::QuitCancelled),
            Step::QuitConfirm => (4, Step::Exit), Step::PickerPending => { r.picker_pending = true; r.step = Step::Reload; return; },
            _ => { self.fail(Refusal::NativeStep); return; },
        };
        if r.actions_returned[index] { self.fail(Refusal::NativeStep); return; }
        r.actions_returned[index] = true; r.step = next;
    }
    fn native_body(&self, step: Step, callback_id: u32, callback_kind: DialogKind, call: &Arc<GuiCall>) -> Result<Option<bool>, ()> {
        let (id, kind) = match step {
            Step::CancelProject => (1, DialogKind::Project),
            Step::SetFolder | Step::AcceptProject => (self.case.selected_id(), DialogKind::Project),
            Step::PickerPending => (2, DialogKind::Project), Step::QuitCancel => (2, DialogKind::Quit),
            Step::QuitConfirm => (3, DialogKind::Quit), _ => return Err(()),
        };
        if callback_id != id || callback_kind != kind { return Err(()); }
        let Some(dialog) = observed_dialog().map_err(|_| ())? else { return Ok(Some(false)); };
        let Some(mut r) = self.try_record() else { return Ok(None); };
        if r.pending != Some(Pending::Native(step)) || r.step != step || dialog.id != id || dialog.native.kind != kind
            || !Arc::ptr_eq(call, &dialog.call)
            || dialog.native.stopped || dialog.native.close_entered
            || dialog.native.show_returned || dialog.native.settled || dialog.native.response.is_some()
            || !self.timely() { return Err(()); }
        let owner = dialog.call.owner().ok_or(())?;
        if owner.interrupted() || !dialog.call.facts().is_some_and(|facts| facts.dispatched && !facts.not_created
            && !facts.response && !facts.accepted && !facts.declined && facts.refusal.is_none()
            && !facts.close_queued && !facts.close_ack && !facts.release_queued && !facts.released) { return Err(()); }
        if let Some(witness) = r.dialogs.iter().find(|witness| witness.id == id) {
            if !witness.same(&dialog) { return Err(()); }
        } else {
            if r.dialogs.len() >= 3 || id as usize != r.dialogs.len() + 1 || owner.id != id
                || !Arc::ptr_eq(&owner.gui, &dialog.call) { return Err(()); }
            r.dialogs.push(DialogWitness { id, kind, call: dialog.call.clone(), owner });
        }
        if !dialog.native.created || !dialog.native.showing || !dialog.native.visible || !dialog.native.presented {
            return if r.visible[(id - 1) as usize] { Err(()) } else { Ok(Some(false)) };
        }
        // The one known timer is truthfully still live. A nested/foreign live
        // callback is never an admitted observer turn or a finality fact.
        if !dialog.native.callbacks_active || !dialog.native.observation_turn { return Err(()); }
        r.visible[(id - 1) as usize] = true;
        if !dialog.action_allowed || !dialog.call.facts().is_some_and(|facts| facts.dispatched && facts.created && !facts.not_created
            && facts.showing && !facts.constructing && !facts.response && !facts.accepted && !facts.declined
            && facts.selected.is_none() && facts.refusal.is_none() && !facts.destroyed && !facts.released) { return Err(()); }
        if self.case.held() && matches!(step, Step::QuitCancel | Step::QuitConfirm | Step::PickerPending)
            && !r.held.as_ref().is_some_and(|witness| witness.outstanding().is_ok()) { return Err(()); }
        if step == Step::PickerPending { return Ok(Some(true)); } // Read only; no fake Cancel.
        if step == Step::AcceptProject && !dialog.native.folder_ready { return Ok(Some(false)); }
        let (index, action) = match step {
            Step::CancelProject => (0, DialogAction::Decline), Step::SetFolder => (1, DialogAction::ChooseFolder(&self.project_path)),
            Step::AcceptProject => (2, DialogAction::Accept), Step::QuitCancel => (3, DialogAction::Decline),
            Step::QuitConfirm => (4, DialogAction::Accept), _ => return Err(()),
        };
        if r.actions_attempted[index] || !self.timely() { return Err(()); }
        r.actions_attempted[index] = true; drop(r);
        // The native adapter rechecks the original object/STA/current folder.
        // Any post-effect error is sticky; it can never become a retry.
        if observe_dialog_action(id, action).map_err(|_| ())? { Ok(Some(true)) } else { Err(()) }
    }
    fn dom(&self, original: DomDispatch, raw: &str) {
        let result = self.dom_body(original, raw);
        if result.is_err() { self.fail(Refusal::Dom); }
        let Some(mut r) = self.record() else { return; };
        if r.pending != Some(Pending::Dom(original)) || original.sequence == 0 || original.sequence > DOM_LIMIT { self.fail(Refusal::Dom); return; }
        r.pending = None; // Actual callback-body return, not eval dispatch Ok.
    }
    fn dom_body(&self, original: DomDispatch, raw: &str) -> Result<(), ()> {
        if !self.timely() || raw.len() > 16 * 1024 { return Err(()); }
        let value = crate::protocol::strict_json(raw.as_bytes()).map_err(|_| ())?;
        let mut r = self.record().ok_or(())?;
        if r.pending != Some(Pending::Dom(original)) || r.step != original.step || !value.is_object() { return Err(()); }
        match value["state"].as_str() { Some("wait") => return Ok(()), Some("ready") => {}, _ => return Err(()) }
        let step = original.step;
        let valid = match step {
            Step::ReadEnvironment => value["runtimeTitle"] == "Bundled runtime" && value["runtimeState"] == "available" && value["platform"] == "windows"
                && value["rows"].as_u64() == Some(r.method_rows as u64) && value["available"] == 6
                && value["unavailable"].as_u64() == Some((r.method_rows - 6) as u64),
            Step::ReadCancelled => value["chooseEnabled"] == true && value["unselected"] == true,
            Step::Snapshot => value["name"] == "project" && value["configuration"] == if self.case == Case::ProjectDraft { "Not configured" } else { "Format-valid only" },
            Step::Suggestion => r.suggestion.as_ref() == value.get("provenance"),
            Step::Hydrated => value["source"] == "version.properties" && value["dirty"] == true && value["saveAvailable"] == false,
            Step::Edited => value["source"] == DRAFT_SOURCE && value["dirty"] == true && value["saveAvailable"] == false,
            Step::Validated => r.methods[3] && value["title"] == "Format validation complete" && value["issues"] == 0,
            Step::Previewed => r.preview.as_ref() == value.get("preview") && value["current"] == true,
            Step::Refreshed => r.snapshots == 2 && value["name"] == "project" && value["configuration"] == "Format-valid only",
            Step::Preserved => value["source"] == DRAFT_SOURCE && value["dirty"] == true && value["saveAvailable"] == false
                && value["sourceChanged"] == true && value["current"] == true && r.preview.as_ref() == value.get("preview"),
            _ => true,
        };
        if !valid || !self.timely() { return Err(()); }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment, Step::ReadEnvironment => Step::Dashboard,
            Step::Dashboard => if self.case == Case::ProjectDraft { Step::ChooseCancel } else { Step::ChooseProject },
            Step::ChooseCancel => { r.project_calls += 1; Step::CancelProject }, Step::ReadCancelled => Step::ChooseProject,
            Step::ChooseProject => { r.project_calls += 1; Step::SetFolder },
            Step::Snapshot => if self.case == Case::ProjectDraft { Step::Settings } else { Step::ArmHold },
            Step::Settings => Step::Suggest, Step::Suggest => Step::Suggestion, Step::Suggestion => Step::Adopt,
            Step::Adopt => Step::Hydrated, Step::Hydrated => { r.hydrated = true; Step::EditDraft },
            Step::EditDraft => Step::Edited, Step::Edited => { r.edited = true; Step::Validate },
            Step::Validate => Step::Validated, Step::Validated => Step::Preview, Step::Preview => Step::Previewed,
            Step::Previewed => Step::MutateFixture, Step::ReturnDashboard => Step::Refresh, Step::Refresh => Step::Refreshed,
            Step::Refreshed => Step::ReturnSettings, Step::ReturnSettings => Step::Preserved,
            Step::Preserved => { r.preserved = true; Step::Close },
            Step::HeldRefresh => Step::Held, Step::ChoosePending => { r.project_calls += 1; Step::PickerPending },
            _ => return Err(()),
        };
        Ok(())
    }
    pub(super) fn relay_joined(&self, joined: bool) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !joined || r.relay_joined || !r.actions_returned[4] || r.pending.is_some() || r.step != Step::Exit { self.fail(Refusal::RelayJoined); return; }
        r.relay_joined = true; r.finality[4] = true;
    }
    pub(super) fn actual_exit(&self, ready: bool, document: &DocumentBinding, edits: &EditOwner) {
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || std::thread::current().id() != self.main || !ready || r.actual_exit || !r.relay_joined
            || r.pending.is_some() || r.step != Step::Exit || r.dialogs.len() != 3 || !r.visible.iter().all(|seen| *seen)
            || !document.can_exit() || !document.assets_can_exit() || edits.disabled() || !edits.can_exit()
            || !matches!(session_final(), Ok(true)) { self.fail(Refusal::ActualExit); return; }
        // Exit can remain possible after late cleanup becomes known. This
        // qualification cannot upgrade a prior document Unknown into success.
        if !source_idle(document, if self.case == Case::DocumentLoss { 2 } else { self.case.selected_id() },
            if self.case == Case::DocumentLoss { "document-lost" } else { "shutdown" }) { self.fail(Refusal::ActualExit); return; }
        let Ok(status) = edits.status() else { self.fail(Refusal::ActualExit); return; };
        // Native normal teardown intentionally invalidates the same original
        // after relay join. The loss case must retain its already-observed
        // tombstone; ordinary cases must not remain/rebind to the live one.
        if status.schema_version != 1 || status.capability.available || status.active.is_some() || status.last_terminal.is_some()
            || !edit::token(&status.window_generation)
            || if self.case == Case::DocumentLoss { r.loss_generation.as_ref() != Some(&status.window_generation) }
                else { r.generation.as_ref() == Some(&status.window_generation) } { self.fail(Refusal::ActualExit); return; }
        let dialogs = r.dialogs.iter().all(|dialog| {
            let accepted = dialog.id == self.case.selected_id() || dialog.id == 3;
            let quit_cancel = self.case == Case::QuitPassive && dialog.id == 2;
            // The loss case replaced its already-settled first selection with
            // the second picker. That retired original never receives STOP;
            // every Cancel, pending lost picker and current Quit original does.
            let stopped = !(self.case == Case::DocumentLoss && dialog.id == 1);
            dialog.settled(accepted, quit_cancel) && dialog.owner.stopped() == stopped
        });
        if !dialogs { self.fail(Refusal::ActualExit); return; }
        r.finality[0] = true; r.finality[1] = true; r.finality[3] = true; r.finality[5] = true;
        r.actual_exit = true;
    }
    fn finish(&self) -> Option<UiCaseFacts> {
        if !self.timely() { return None; }
        let (mut initial, mut held) = {
            let mut r = self.record()?;
            if !r.actual_exit || !r.relay_joined || r.pending.is_some() || r.step != Step::Exit
                || r.snapshot_pending || r.snapshot_requests != 2 || !r.methods[..3].iter().all(|done| *done) { return None; }
            (r.initial.take()?, r.held.take())
        };
        // Only after actual run_return, on process main and on the EXISTING
        // Tauri executor. Borrow/join retained original tails, no new runner.
        let version = tauri::async_runtime::block_on(initial.observe_retired(self.end)).ok()?;
        if let Some(witness) = &mut held {
            let observed = tauri::async_runtime::block_on(witness.observe_retired(self.end)).ok()?;
            if observed != version { return None; }
        }
        // The native helper checks the whole fixed tree, exact bytes/EOF and
        // original handle settlement, then latches its independent writer gate.
        // A child boolean alone cannot claim the labelled-only fixture change.
        native::verify_normal_ui_fixture(self.end).ok()?;
        let mut r = self.record()?;
        let checks = match self.case {
            Case::ProjectDraft => {
                if held.is_some() || !r.methods.iter().all(|done| *done) || r.snapshots != 2 || r.project_calls != 2
                    || !r.cancel_returned || !r.hydrated || !r.edited || !r.preserved || !r.mutation_returned
                    || r.close_count != 1 || r.actions_returned != [true, true, true, false, true] { return None; }
                // The shared native writer requires the full-fixture latch
                // above in addition to these observed production UI facts.
                [true; 7]
            },
            Case::QuitPassive => {
                if held.is_none() || !r.held_seen || !r.quit_cancelled || !r.held_snapshot_refused || r.snapshots != 1
                    || r.project_calls != 1 || r.close_count != 2 || r.actions_returned != [false, true, true, true, true]
                    || r.reload_requested || r.mutation_returned { return None; }
                [true, true, true, true, false, false, false]
            },
            Case::DocumentLoss => {
                if held.is_none() || !r.held_seen || !r.held_snapshot_refused || r.snapshots != 1 || r.project_calls != 2
                    || !r.picker_pending || !r.reload_requested || !r.reload_returned || !r.loss_settled || !r.lost_picker_returned
                    || r.loss_generation.is_none() || r.close_count != 1 || r.actions_returned != [false, true, true, false, true]
                    || r.mutation_returned { return None; }
                [true, true, true, true, true, false, false]
            },
        };
        r.finality[2] = true;
        if !r.finality.iter().all(|settled| *settled) || !self.timely() { return None; }
        // Lifecycle roles did bootstrap/select/snapshot. Zero is deliberately
        // verifiedMethods (no six-method feature credit), NOT zero invocations.
        Some(UiCaseFacts { version, verified_methods: if self.case == Case::ProjectDraft { 6 } else { 0 }, checks, finality: r.finality })
    }
}

fn assurance(value: &Value, basis: &str) -> bool {
    value["assurance"]["basis"] == basis && value["assurance"]["releaseReadiness"] == "unknown"
        && ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"]
            .iter().all(|key| value["assurance"][*key] == false)
}
fn format_valid(value: &Value) -> bool {
    value["valid"] == true && value["state"] == "format-valid" && value["issues"].as_array().is_some_and(Vec::is_empty)
        && value["requirements"].as_array().is_some_and(|rows| rows.len() <= 128 && rows.iter().all(|row| row["state"] == "unknown"))
        && assurance(value, "schema-policy")
}
fn source_idle(document: &DocumentBinding, id: u32, reason: &str) -> bool {
    let status = document.status();
    if edit::bounded(&status, 16 * 1024).is_err() { return false; }
    let Ok(value) = serde_json::to_value(status) else { return false; };
    let operation = &value["operation"];
    value["schemaVersion"] == 1 && value["mode"] == "closed" && value["capability"]["available"] == false
        && value["capability"]["reason"].as_str().is_some_and(|reason| matches!(reason, "unsupported-platform" | "document-lost" | "shutdown"))
        && value["context"].is_null() && value["records"].as_array().is_some_and(Vec::is_empty)
        && value["assignments"].as_array().is_some_and(Vec::is_empty)
        && operation["operationId"] == id && operation["operation"] == "choose-project"
        && operation["phase"] == "idle" && operation["settlement"] == "known" && operation["reason"] == reason
        && operation["source"] == "not-run" && operation["selectionToken"].is_null()
        && operation["assessment"].is_null() && operation["preview"].is_null() && document.assets_can_exit()
}

// Synchronous expressions act only on visible production controls. No direct
// invoke/reducer access, DTO injection, synthetic dispatchEvent, Promise or
// replacement document. `wait` is only returned BEFORE any effect.
fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Environment => "return nav('Environment');",
        Step::Dashboard | Step::ReturnDashboard => "return nav('Dashboard');",
        Step::Settings | Step::ReturnSettings => "return nav('Project settings');",
        Step::ReadEnvironment => r#"const card=document.querySelector('.runtime-card'),rows=[...document.querySelectorAll('.capability-list > div')];
            if(!selected('Environment')||!card||rows.length<6)return wait();if(rows.length>64)throw 0;
            show(card);const versions=[...card.querySelectorAll('.runtime-versions strong')].map(text);if(versions.length!==3)throw 0;
            return {state:'ready',runtimeTitle:text(card.querySelector('h2')),runtimeState:text(card.querySelector('.badge')),platform:versions[2],rows:rows.length,
                available:rows.filter(r=>text(r.querySelector('.badge'))==='Available · passive').length,
                unavailable:rows.filter(r=>text(r.querySelector('.badge'))==='Unavailable').length};"#,
        Step::ChooseCancel | Step::ChooseProject => r#"if(!selected('Dashboard'))return wait();
            const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Choose a project');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::ChoosePending => r#"if(!selected('Dashboard'))return wait();
            const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Open another project');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::ReadCancelled => r#"const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Choose a project');
            if(!b||b.disabled)return wait();show(b);return {state:'ready',chooseEnabled:!b.disabled,
                unselected:text(document.querySelector('.project-identity h2'))==='Your next release, organized.'&&!document.querySelector('.observation-facts,.draft-banner')};"#,
        Step::Snapshot => r#"const facts=document.querySelector('.observation-facts');if(!selected('Dashboard')||!facts)return wait();show(facts);
            return {state:'ready',name:text(document.querySelector('.project-identity h2')),configuration:text(document.querySelector('.project-badges .badge'))};"#,
        Step::Refreshed => r#"const facts=document.querySelector('.observation-facts');if(!selected('Dashboard')||!facts)return wait();
            const buttons=[...document.querySelectorAll('.observation-card > .section-heading button')];
            const name=text(document.querySelector('.project-identity h2')),configuration=text(document.querySelector('.project-badges .badge'));
            if(name!=='project'||buttons.length!==1||[...document.querySelectorAll('[role="alert"] strong')].some(e=>text(e)==='Static observation unavailable'))throw 0;
            if(configuration!=='Not configured'&&configuration!=='Format-valid only')throw 0;
            const b=buttons[0],label=text(b);
            if(label==='Reading…'&&b.disabled)return wait();
            if(label!=='Refresh static view'||b.disabled)throw 0;
            if(configuration==='Not configured')return wait();
            show(facts);show(b);return {state:'ready',name,configuration};"#,
        Step::Suggest => r#"const b=document.querySelector('.suggestion-card button[aria-describedby="suggestion-reason"]');
            if(!selected('Project settings')||!b||b.disabled)return wait();if(text(b)!=='Prepare suggested draft'||document.querySelector('.draft-banner,.suggestion-result'))throw 0;
            show(b);b.click();return ready();"#,
        Step::Suggestion => r#"const result=document.querySelector('.suggestion-result');if(!result)return wait();
            const rows=[...result.querySelectorAll('.provenance-list > li')];if(!rows.length||rows.length>64)throw 0;show(result);
            const codes={'Unverified hint':'hint','Core default':'default','Example only':'example'};
            return {state:'ready',provenance:rows.map(row=>({path:text(row.querySelector('code')),source:codes[text(row.querySelector('.badge'))]??'error'}))};"#,
        Step::Adopt => r#"const b=document.querySelector('.suggestion-adopt button');if(!b||b.disabled)return wait();
            if(text(b)!=='Use as an in-memory draft'||document.querySelector('.draft-banner'))throw 0;show(b);b.click();return ready();"#,
        Step::Hydrated | Step::Edited => r#"if(!selected('Project settings')||!document.querySelector('.draft-banner')||!field())return wait();return {state:'ready',...draft()};"#,
        Step::EditDraft => r#"const f=field();if(!f)return wait();if(f.value!=='version.properties'||f.disabled||f.readOnly)throw 0;
            show(f);f.focus();f.select();if(document.activeElement!==f||f.selectionStart!==0||f.selectionEnd!==f.value.length)throw 0;
            if(!document.execCommand('insertText',false,'draft-version.properties'))throw 0;return ready();"#,
        Step::Validate => "return toolbar('draft-validation-reason','Validate only');",
        Step::Validated => r#"const card=document.querySelector('.validation-card');if(!card)return wait();show(card);
            return {state:'ready',title:text(card.querySelector('h2')),issues:card.querySelectorAll('.issues > li').length};"#,
        Step::Preview => "return toolbar('draft-review-reason','Review draft changes');",
        Step::Previewed => "if(!document.querySelector('.draft-review'))return wait();return {state:'ready',...review()};",
        Step::Refresh | Step::HeldRefresh => r#"if(!selected('Dashboard'))return wait();const b=[...document.querySelectorAll('.observation-card button')].find(b=>text(b)==='Refresh static view');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::Preserved => r#"if(!selected('Project settings')||!field()||!document.querySelector('.draft-review'))return wait();
            return {state:'ready',...draft(),...review(),sourceChanged:[...document.querySelectorAll('.notice-warning strong')].some(e=>text(e)==='A newer observation differs from the draft baseline')};"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{try{{
        const ready=()=>({{state:'ready'}}),wait=()=>({{state:'wait'}}),text=e=>(e?.textContent??'').replace(/\s+/g,' ').trim();
        const show=e=>{{if(!e)throw 0;e.scrollIntoView({{block:'center'}});if(!e.getClientRects().length||getComputedStyle(e).visibility==='hidden')throw 0}};
        const selected=name=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"][aria-current="page"]');
        const nav=name=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"]');if(!b)return wait();if(b.disabled)throw 0;show(b);b.click();return ready()}};
        const number=e=>{{const s=text(e);if(!/^[0-9]{{1,7}}$/.test(s))throw 0;return Number(s)}};
        const field=()=>{{const rows=[...document.querySelectorAll('.form-field')].filter(f=>f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: Committed version file');
            if(!rows.length)return null;if(rows.length!==1)throw 0;const f=rows[0].querySelector('input[type="text"]');if(!f||f.disabled||f.value.length>512)throw 0;return f}};
        const draft=()=>{{const f=field(),banner=document.querySelector('.draft-banner'),save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if(!f||!banner||!save)throw 0;show(f);return {{source:f.value,dirty:text(banner.querySelector('.badge'))==='Unsaved changes',saveAvailable:!save.disabled}}}};
        const toolbar=(reason,label)=>{{if(!selected('Project settings'))return wait();if(document.querySelector('dialog'))throw 0;
            const b=document.querySelector('.draft-toolbar button[aria-describedby="'+reason+'"]');if(!b||b.disabled)return wait();if(text(b)!==label)throw 0;show(b);b.click();return ready()}};
        const review=()=>{{const r=document.querySelector('.draft-review');show(r);const detail=r.querySelector('.context-details'),nums=[...r.querySelectorAll('.review-counts > span > strong')].map(number);
            if(!detail||nums.length!==3)throw 0;const sections=r.querySelectorAll(':scope > .review-section-heading');if(sections.length!==2)throw 0;
            return {{current:text(r.querySelector('.section-heading .badge'))==='Current draft · retained baseline',
                preview:{{counts:{{added:nums[0],changed:nums[1],removed:nums[2]}},fields:detail.querySelectorAll('ul > li').length,valid:text(sections[1].querySelector('.badge'))}}}}}};
        {body}
    }}catch{{return {{state:'error'}}}}}})()"#))
}

pub(crate) fn main() -> std::process::ExitCode {
    // Require actual argv[0]-only process main and the fixed native-owned request.
    // Parsing/fixture paths are DATA, never permission to bypass production
    // admission. This is the sole inherited monotonic owner deadline capture.
    let admitted = (|| -> Option<Arc<Observation>> {
        let end = native::normal_ui_deadline().ok()?;
        let case = match native::require_normal_ui_qualification().ok()? {
            UiRole::ProjectDraft => Case::ProjectDraft, UiRole::QuitPassive => Case::QuitPassive,
            UiRole::DocumentLoss => Case::DocumentLoss, _ => return None,
        };
        let project = native::normal_ui_project().ok()?;
        // A known diagnostic-channel refusal is not an application refusal.
        let diagnostic = native::ObserverDiagnostic::admit(end).ok().map(Arc::new);
        Observation::new(case, end, project, diagnostic).ok().map(Arc::new)
    })();
    let Some(q) = admitted else { super::diagnostic(b"MRK_WINDOWS_NORMAL_UI=route-refused\n"); return std::process::ExitCode::FAILURE; };
    q.diagnostic_snapshot();
    if let Some(diagnostic) = &q.diagnostic { diagnostic.admitted(); }
    let returned = super::run_builder(super::builder().manage(q.clone()));
    if !matches!(returned, Ok(0)) { q.fail(Refusal::MainReturn); }
    q.diagnostic_snapshot();
    if let Some(diagnostic) = &q.diagnostic { diagnostic.builder_returned(&|| q.diagnostic_permitted()); }
    let facts = matches!(returned, Ok(0)).then(|| {
        let facts = q.finish(); if facts.is_none() { q.fail(Refusal::Finish); } facts
    }).flatten();
    if let Some(facts) = facts {
        if q.timely() && native::write_normal_ui_result_once(&facts, q.end).is_ok() && q.timely() {
            // The ORIGINAL native launch still has to observe this process's
            // actual exit, profile/account retirement and its own original exit.
            return std::process::ExitCode::SUCCESS;
        }
    }
    q.fail(Refusal::MainReturn); q.report_failure(); std::process::ExitCode::FAILURE
}
