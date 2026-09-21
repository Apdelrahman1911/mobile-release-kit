//! Two bounded observations of the NORMAL builder/bridge/packaged selector.
//! No alternate runtime, document, IPC command, timer, task or shutdown owner.
//! Only the existing relay drives these steps; failures cannot authorize exit.
use std::{ffi::OsStr, io::Write, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Manager;
use crate::{bridge::{AppInfo, Project}, edit_owner::{EditOwner, InstalledConfigFinality},
    edit_protocol::{self as edit, ConfigEditStatus, EditProjection}, error::BridgeError, supervisor::{HeldAppInfo, Supervisor}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Positive, Outstanding }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Bootstrap, Environment, ReadEnvironment, Dashboard, ChooseCancel, Cancel, Cancelled, ReadCancelled,
    ChooseSelect, SetProject, SelectProject, Selected, ReadSnapshot, Settings, Suggest, ReadSuggestion, Adopt, ReadDraft,
    GuidanceEnvironment, LoadRequirements, ReadRequirements, GitHub, ReadGitHubEmpty, EnterRepository, EnterSha,
    ReadGitHubInputs, ProposeGitHub, ReadProposal, OpenWorkflows, ReadWorkflows, GuidanceSettings, ReadRetainedDraft,
    PrepareSave, ReadSaveReview, OpenConfirmation, ReadConfirmation, KeepReviewing, ReadKeptReview,
    ReopenConfirmation, ReadReopenedConfirmation, Acknowledge, ReadAcknowledged, Apply, ReadSaved,
    SavedDashboard, Refresh, ReadReadback, SavedSettings, ReadSavedDraft, PrepareNoop, ReadNoopReview, Close, Quit, Exit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending { Dom(Step), Project(Step), Close, Gtk }

const PROJECT_SOURCE: &str = "plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
const APP_ID: &str = "org.example.mrk.observed";
const FIELD: &str = "version.source";
const METHODS: [&str; 8] = ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
    "github.setup.propose", "environment.requirements"];
const TOOLKIT_REPOSITORY: &str = "example/toolkit";
const TOOLKIT_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GITHUB_RESOURCE: &str = "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c";
const WORKFLOWS: [(&str, &str, usize); 4] = [
    ("preflight", ".github/workflows/mobile-preflight.yml", 567),
    ("candidate", ".github/workflows/mobile-candidate.yml", 1379),
    ("external-testing", ".github/workflows/mobile-external-testing.yml", 2150),
    ("production-submit", ".github/workflows/mobile-production-submit.yml", 2881),
];

// Source-bound synthetic fixture output DATA. The outer fixture's focused pure
// core contract derives these bytes from config.suggest + the real serializer;
// this observer never serializes a replacement config or opens the fixture.
const CONFIG_BYTES: u32 = 692;
const CONFIG_SHA256: &str = "4b3a5aaa718b018101ee0fcd0e612285be8a1b93cab20c5ff15e8d441069b917";
const IGNORE_BYTES: u32 = 208;
const IGNORE_LINES: [&str; 7] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/", ".mobile-release-init-cleanup/",
    ".mobile-release-metadata-text-prepare/", ".mobile-release-metadata-text/", ".mobile-release-metadata-text-cleanup/"];

// This is the fixed original service's protected sibling, not an environment
// path or a renderer-selected fixture. It is only passed to GtkFileChooser.
fn project_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    if executable.file_name()? != OsStr::new("shell-observer") { return None; }
    let root = executable.parent()?;
    if root.parent()? != Path::new("/var/lib") { return None; }
    let parts: Vec<_> = root.file_name()?.to_str()?.strip_prefix("mrk-ubuntu-native-")?.split('-').collect();
    if parts.len() != 2 || !parts.iter().all(|part| !part.is_empty() && part.len() <= 20
        && !part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())) { return None; }
    Some(root.join("positive-project"))
}

#[derive(Default)]
struct Picker {
    created: bool, selected: bool, activated: bool, responded: bool, filename: bool,
    disposal: bool, destroyed: bool, released: bool, returned: bool,
}
impl Picker {
    fn settled(&self, select: bool) -> bool {
        self.created && self.activated && self.responded && self.destroyed && self.released && self.returned
            && self.selected == select && self.filename == select
    }
}
fn assurance(value: &Value, basis: &str) -> bool {
    // This assurance belongs to each passive reply, never to the whole Save
    // observation: the explicit configuration Apply DOES perform writes.
    value.get("assurance").is_some_and(|a| a.get("basis").and_then(Value::as_str) == Some(basis)
        && a.get("releaseReadiness").and_then(Value::as_str) == Some("unknown")
        && ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"]
            .iter().all(|key| a.get(*key).and_then(Value::as_bool) == Some(false)))
}
fn format_valid(value: &Value) -> bool {
    // Observe the existing core verdict, not another configuration validator.
    value["valid"].as_bool() == Some(true) && value["state"].as_str() == Some("format-valid")
        && value["issues"].as_array().is_some_and(Vec::is_empty)
        && value["requirements"].as_array().is_some_and(|rows| rows.len() <= 128
            && rows.iter().all(|row| row["state"].as_str() == Some("unknown"))) && assurance(value, "schema-policy")
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|row| row.len() == names.len() && names.iter().all(|name| row.contains_key(*name)))
}
const HELP_KEYS: [&str; 8] = ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"];
#[derive(PartialEq, Eq)]
struct HelpSample { values: [String; 8] }
impl HelpSample {
    fn read(field: &Value) -> Option<Self> {
        let mut values = std::array::from_fn(|_| String::new());
        for (index, key) in HELP_KEYS.iter().enumerate() {
            let text = field.get(*key)?.as_str()?;
            if text.is_empty() || text.len() > 16384 || text.encode_utf16().count() > 4096 { return None; }
            values[index] = text.to_owned();
        }
        Some(Self { values })
    }
}

fn requirements_display(result: &crate::environment::Requirements) -> Option<Value> {
    // Serialize the original already-admitted private DTO under its unchanged
    // limit. Retain displayed comparison DATA only; never expose DTO fields.
    let raw = crate::edit_protocol::bounded(result, crate::environment::RESPONSE_LIMIT).ok()?;
    let value = crate::protocol::strict_json(&raw).ok()?;
    if value["schemaVersion"].as_u64() != Some(1) || value["hostPlatform"].as_str() != Some("linux")
        || value["context"] != serde_json::json!({"platform":"android","operation":"build"})
        || value["platformEnabled"].as_bool() != Some(true) || value["state"].as_str() != Some("requirements-only")
        || value["coverage"].as_str() != Some("toolchain-prerequisites-only")
        || value["nativeInspection"].as_str() != Some("unavailable") || value["dependencyCompleteness"].as_str() != Some("unknown")
        || !assurance(&value, "schema-policy") { return None; }
    let rows = value["requirements"].as_array().filter(|rows| rows.len() == 3)?;
    let mut displayed = Vec::new();
    for (index, (row, role)) in rows.iter().zip(["android-jdk", "android-gradle-wrapper", "android-sdk"]).enumerate() {
        let baseline = &row["baseline"];
        if row["id"].as_str() != Some(role) || row["presence"].as_str() != Some("unknown")
            || row["versionState"].as_str() != Some("unknown") || row["inspection"].as_str() != Some("not-run")
            || baseline["kind"].as_str() != Some(if index == 0 { "workflow-reference" } else { "project-defined" })
            || !(if index == 0 { baseline["version"].as_str() == Some("21") } else { baseline.get("version") == Some(&Value::Null) })
            || !["build", "sha256", "maxBytes"].iter().all(|key| baseline.get(*key) == Some(&Value::Null)) { return None; }
        let help = HelpSample::read(&row["help"])?;
        if help.values[1] != "required" { return None; }
        displayed.push(serde_json::json!({"label":help.values[0], "helpLabel":format!("Help: {}", help.values[0]),
            "help":[help.values[2], help.values[6], format!("Where to find it: {}", help.values[4])], "badges":["Not checked"],
            "baseline":[if index == 0 { "Workflow reference · not a local compatibility rule" } else { "Defined by your project" },
                baseline["version"].as_str().unwrap_or("No universal version inferred")]}));
    }
    Some(serde_json::json!({"heading":"Build / archive prerequisites", "badges":["Tools not checked","Release readiness unknown"],
        "host":"Core host: linux", "roles":displayed, "limitations":value["limitations"]}))
}

struct ProposalSample { display: Value, workflows: Value }
impl ProposalSample {
    fn read(value: &Value, draft: &Value) -> Option<Self> {
        crate::edit_protocol::bounded(value, 256 * 1024).ok()?;
        let schema = format!("https://raw.githubusercontent.com/{TOOLKIT_REPOSITORY}/{TOOLKIT_SHA}/schemas/project.schema.json");
        if !keys(value, &["schemaVersion", "state", "validation", "facts", "assurance", "templateSet", "tooling", "workflows", "settings"])
            || value["schemaVersion"].as_u64() != Some(1) || value["state"].as_str() != Some("proposed")
            || !format_valid(&value["validation"]) || !assurance(value, "schema-policy")
            || value["facts"] != serde_json::json!({"githubContacted":false,"repositoryObserved":false,"toolingRefResolved":false,
                "templateCompatibility":"unknown","comparisonBasis":"caller-supplied-digest-summary","snapshotProvided":false,"applyAvailable":false})
            || value["templateSet"] != serde_json::json!({"coreVersion":crate::runtime::CORE_VERSION,"resourceVersion":1,"resourceSha256":GITHUB_RESOURCE})
            || value["tooling"] != serde_json::json!({"repository":TOOLKIT_REPOSITORY,"sha":TOOLKIT_SHA,"schemaReference":schema,"state":"format-only"})
            || value["settings"]["configPath"].as_str() != Some("release/mobile-release.json")
            || value["settings"]["sourcePolicy"] != serde_json::json!({"candidateBranch":draft["source"]["candidateBranch"],
                "productionBranch":draft["source"]["productionBranch"],"basis":"configured-policy"}) { return None; }
        let rows = value["workflows"].as_array().filter(|rows| rows.len() == WORKFLOWS.len())?;
        let mut workflows = Vec::new();
        for (row, (id, path, size)) in rows.iter().zip(WORKFLOWS) {
            let content = row["content"].as_str()?;
            let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
            if !keys(row, &["id", "path", "content", "byteLength", "sha256", "comparison"])
                || row["id"].as_str() != Some(id) || row["path"].as_str() != Some(path)
                || content.len() != size || content.encode_utf16().count() > 4096 || row["byteLength"].as_u64() != Some(size as u64)
                || row["sha256"].as_str() != Some(digest.as_str()) || row["comparison"].as_str() != Some("not-supplied") { return None; }
            workflows.push(serde_json::json!({"path":path,"comparison":"Not supplied · presence unknown",
                "metadata":format!("{size} UTF-8 bytes · Core-reported SHA256 {digest}"),"content":content}));
        }
        // Only genuine response fields enter these private expected displays.
        // Fixed surrounding labels are UI disclaimers, not substituted replies.
        Some(Self { workflows: Value::Array(workflows), display: serde_json::json!({
            "heading":"Passive proposal — nothing applied by this preview", "badge":"GitHub not contacted",
            "description":"Complete caller text from the shared core. This preview saves no files and observes no GitHub, Git or Store state. Any separate native operation is reported in Local workflow files.",
            "facts":[["Toolkit repository",value["tooling"]["repository"]], ["Toolkit commit · format-only",value["tooling"]["sha"]],
                ["Installed core / resource version",format!("{} / {}", value["templateSet"]["coreVersion"].as_str()?, value["templateSet"]["resourceVersion"].as_u64()?)],
                ["Shipped resource SHA256 · identity only",value["templateSet"]["resourceSha256"]],
                ["Remote ref / template compatibility","Not resolved / unknown"], ["Repository / release readiness","Not observed / unknown"],
                ["Draft assessment","Format-valid only · not saved by this preview"], ["Informational schema reference · not fetched or saved",value["tooling"]["schemaReference"]]],
            "settings":[["Caller configuration convention · not an observed file",value["settings"]["configPath"]],
                ["Source basis","Configured policy only · protection unverified"], ["Candidate branch policy",value["settings"]["sourcePolicy"]["candidateBranch"]],
                ["Production branch policy",value["settings"]["sourcePolicy"]["productionBranch"]]],
            "scope":["No project code was executed, tools probed, credentials read, files written or workflow dispatched. This is not a full init configuration, metadata skeleton, .gitignore transaction or an Apply plan.",
                "No comparison summary was supplied; existing workflow presence is unknown. A match is not a verified no-op or an unchanged repository."],
            "workflowHeading":"Four read-only workflow previews", "workflowDescription":"Selectable text only. Paths and hashes identify proposed content, not existing repository files or permission to overwrite them.",
            "settingsHeading":"Environment checklist · not configured", "settingsDescription":"Desired policy and unresolved administrator work, not remote API requests. Existing environments, approvals, permissions and values remain unknown.",
            "localReviewAvailable":false, "remoteAvailable":false
        }) })
    }
}

#[derive(Default)]
struct Guidance {
    requirements_called: bool, requirements: Option<Value>, requirements_visible: bool,
    github_empty: bool, repository_entered: bool, sha_entered: bool, inputs_visible: bool,
    github_called: bool, proposal: Option<ProposalSample>, proposal_visible: bool, workflows_visible: bool, draft_retained: bool,
}
impl Guidance {
    fn complete(&self) -> bool {
        self.requirements_called && self.requirements.is_some() && self.requirements_visible && self.github_empty
            && self.repository_entered && self.sha_entered && self.inputs_visible && self.github_called
            && self.proposal.is_some() && self.proposal_visible && self.workflows_visible && self.draft_retained
    }
}


fn review_sample(view: &edit::PreparedConfigView, no_op: bool) -> Option<Value> {
    if edit::bounded(view, 128 * 1024).is_err() || view.schema_version != 1 || view.files.len() != 2
        || view.create_release_directory == no_op || view.rewrites_config_formatting
        || !format_valid(&view.preview["validation"]) || !assurance(&view.preview, "schema-policy") { return None; }
    for (file, path, size) in [(&view.files[0], "release/mobile-release.json", CONFIG_BYTES), (&view.files[1], ".gitignore", IGNORE_BYTES)] {
        if file.path != path || file.after_bytes != size || file.before_bytes != no_op.then_some(size)
            || file.action != (if no_op { "preserve" } else { "create" }) { return None; }
    }
    if if no_op { !view.ignore_additions.is_empty() } else { !view.ignore_additions.iter().map(String::as_str).eq(IGNORE_LINES) } { return None; }
    let comparison = &view.preview["comparison"];
    if comparison["baseProvided"].as_bool() != Some(no_op) || comparison["state"].as_str() != Some("complete")
        || comparison["kind"].as_str() != Some(if no_op { "compare" } else { "proposed-create" })
        || comparison["semanticallyChanged"].as_bool() != Some(!no_op) || comparison["unreviewedCount"].as_u64() != Some(0)
        || !comparison["changes"].as_array().is_some_and(|changes| changes.len() <= 64 && changes.is_empty() == no_op)
        || no_op && comparison["counts"] != serde_json::json!({"added":0,"changed":0,"removed":0}) { return None; }
    Some(serde_json::json!({"files":view.files,"release":view.create_release_directory,"rewrite":view.rewrites_config_formatting,
        "ignore":view.ignore_additions,"counts":comparison["counts"],
        "basis":if no_op { "The native plan contains no file writes" } else { "Only this reviewed native inventory can be applied" },
        "badge":if no_op { "No writes planned" } else { "Explicit Apply required" }}))
}
fn phase_order(phase: edit::Phase) -> u8 {
    match phase { edit::Phase::Opening => 0, edit::Phase::Editing => 1, edit::Phase::Preparing => 2,
        edit::Phase::Reviewing => 3, edit::Phase::Applying => 4, edit::Phase::Finalizing => 5, edit::Phase::Final => 6, edit::Phase::Unknown => 7 }
}
fn original_final(facts: &InstalledConfigFinality, projection: &EditProjection, no_op: bool) -> bool {
    facts.session_id == projection.session_id && facts.project_id == projection.project_id && facts.owner_generation == projection.owner_generation
        && facts.writer_frames == (if no_op { 2 } else { 3 }) && facts.stdout_frames == 3
        && facts.inspection_joined && facts.acquisition_joined && facts.child_waited_success
        && facts.stdin_closed && facts.stdout_eof_closed && facts.stderr_eof_closed && facts.io_joined
        && facts.driver_joined && facts.watchdog_joined && facts.manager_joined
        && facts.runtime_ledger_settled && facts.runtime_settlement_joined
}
struct SaveSession {
    projection: EditProjection, prepared: Option<Value>, review: Option<Value>,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, finality: Option<InstalledConfigFinality>,
}
impl SaveSession {
    fn live_review(&self) -> bool {
        self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
            && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
            && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
            && self.prepared.is_some() && self.review.is_some() && self.finality.is_none()
    }
}
struct Record {
    attached: bool, started: bool, loaded: bool, info: bool, methods: usize, catalog: bool, environment: bool,
    pickers: [Picker; 2], cancel_returned: bool, cancelled: bool, project: Option<Project>, selected: bool,
    snapshot_requests: u8, snapshot: bool, snapshot_visible: bool, suggest_called: bool, suggested: Option<Value>, provenance: Option<Value>,
    provenance_visible: bool, adopted: bool, draft_visible: bool, guidance: Guidance,
    capability: bool, generation: Option<String>, native_revision: Option<u32>, sessions: Vec<SaveSession>, requests: [u8; 4],
    open_pending: bool, prepare_pending: Option<usize>, apply_returned: bool,
    confirmation_opened: u8, kept_reviewing: bool, acknowledged: bool, saved_visible: bool,
    readback: bool, readback_visible: bool, saved_draft_retained: bool, noop_outstanding: bool, originals_final: bool,
    step: Step, pending: Option<Pending>, evaluations: u16,
    close_prevented: bool, native_id: Option<u32>, activated: bool,
    responded: bool, disposal_response: bool, destroyed: bool, released: bool, gtk_returned: bool,
    relay_joined: bool, exit: bool, held: Option<HeldAppInfo>,
}
pub(super) struct Observation {
    case: Case, main: ThreadId, end: Instant, project_path: Option<PathBuf>, failed: AtomicBool, record: Mutex<Record>,
}
impl Observation {
    fn new(case: Case) -> Self {
        let project_path = (case == Case::Positive).then(project_path).flatten();
        Self { case, main: std::thread::current().id(), end: Instant::now() + Duration::from_secs(45),
            failed: AtomicBool::new(case == Case::Positive && project_path.is_none()), project_path, record: Mutex::new(Record {
                attached: false, started: false, loaded: false, info: false, methods: 0, catalog: false, environment: false,
                step: Step::Bootstrap, pending: None, evaluations: 0,
                pickers: std::array::from_fn(|_| Picker::default()), cancel_returned: false, cancelled: false, project: None, selected: false,
                snapshot_requests: 0, snapshot: false, snapshot_visible: false, suggest_called: false, suggested: None, provenance: None,
                provenance_visible: false, adopted: false, draft_visible: false, guidance: Guidance::default(),
                capability: false, generation: None, native_revision: None, sessions: Vec::new(), requests: [0; 4],
                open_pending: false, prepare_pending: None, apply_returned: false,
                confirmation_opened: 0, kept_reviewing: false, acknowledged: false, saved_visible: false,
                readback: false, readback_visible: false, saved_draft_retained: false, noop_outstanding: false, originals_final: false,
                close_prevented: false, native_id: None, activated: false, responded: false, disposal_response: false,
                destroyed: false, released: false, gtk_returned: false, relay_joined: false, exit: false, held: None,
            }) }
    }
    fn fail(&self) { self.failed.store(true, Ordering::SeqCst); }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.fail(); None } }
    }
    pub(super) fn attach(&self, supervisor: &Supervisor) -> Result<(), BridgeError> {
        if std::thread::current().id() != self.main { self.fail(); return Err(BridgeError::invalid()); }
        // This is the supervisor just created by DesktopBridge::new in setup,
        // before the real window/bootstrap. Positive leaves all hooks unarmed.
        if self.case == Case::Outstanding { supervisor.arm_initial_app_info_shutdown()?; }
        let mut record = self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if record.attached { self.fail(); return Err(BridgeError::invalid()); }
        record.attached = true;
        Ok(())
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record() else { return; };
        if !trusted || !r.attached || if finished { !r.started || r.loaded } else { r.started } { self.fail(); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        if self.case == Case::Outstanding {
            if info.runtime.state == "available" || info.capabilities.is_some() { self.fail(); }
            return;
        }
        let Some(methods) = info.capabilities.as_ref().and_then(|c| c.get("methods")).and_then(Value::as_array) else { self.fail(); return; };
        let Some(actions) = info.capabilities.as_ref().and_then(|c| c.get("actions")).and_then(Value::as_array) else { self.fail(); return; };
        if !(METHODS.len()..=64).contains(&methods.len()) || actions.is_empty() || actions.len() > 64 { self.fail(); return; }
        let available = |m: &&Value| m.get("available").and_then(Value::as_bool) == Some(true);
        let valid = info.runtime.state == "available" && info.runtime.mode == "bundled" && info.runtime.reason.is_none()
            && info.app_name == "Mobile Release Kit" && info.app_version == env!("CARGO_PKG_VERSION")
            && info.project_selection.available && info.project_selection.reason.is_none()
            && methods.iter().filter(available).count() == METHODS.len()
            && METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m.get("method").and_then(Value::as_str) == Some(*name)).count() == 1)
            && methods.iter().all(|m| m.get("available").and_then(Value::as_bool).is_some())
            && actions.iter().all(|a| a.get("available").and_then(Value::as_bool) == Some(false));
        let Some(mut r) = self.record() else { return; };
        if !valid || r.info { self.fail(); return; }
        r.info = true; r.methods = methods.len();
    }
    pub(super) fn unexpected(&self) { self.fail(); }
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        // Bootstrap still consumes the real catalogue. Guidance later uses the
        // adopted draft; field-help, Unset and standalone Validate/Review are not replayed.
        let valid = result.as_ref().ok().and_then(|v| v.get("fields")).and_then(Value::as_array)
            .filter(|fields| fields.len() <= 64).is_some_and(|fields| {
                let mut matches = fields.iter().filter(|field| field["path"].as_str() == Some(FIELD));
                let Some(field) = matches.next() else { return false; };
                matches.next().is_none() && field["requiredness"].as_str() == Some("required")
                    && ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"].iter().all(|key|
                        field[*key].as_str().is_some_and(|text| !text.is_empty() && text.len() <= 16384 && text.encode_utf16().count() <= 4096))
            });
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.info || r.catalog || !valid { self.fail(); return; }
        r.catalog = true;
    }
    pub(super) fn project_path(&self) -> Option<&Path> { self.project_path.as_deref() }
    pub(super) fn project_result(&self, result: &Result<Option<Project>, crate::asset_commands::AssetError>) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive { self.fail(); return; }
        match result {
            Ok(None) if r.step == Step::Cancelled && !r.cancel_returned && r.pickers[0].responded && r.pickers[0].returned => r.cancel_returned = true,
            Ok(Some(project)) if r.step == Step::Selected && r.cancelled && r.project.is_none() && r.pickers[1].responded && r.pickers[1].returned
                && self.project_path().is_some_and(|path| Path::new(&project.path) == path)
                && project.name == "positive-project" && crate::protocol::valid_id(&project.id) => r.project = Some(project.clone()),
            _ => self.fail(),
        }
    }
    pub(super) fn snapshot_request(&self, project_id: &str) {
        let Some(mut r) = self.record() else { return; };
        let allowed = match r.snapshot_requests {
            0 => matches!(r.step, Step::Selected | Step::ReadSnapshot) && !r.snapshot,
            1 => matches!(r.step, Step::Refresh | Step::ReadReadback) && r.saved_visible && !r.readback
                && r.sessions.first().is_some_and(|session| session.finality.is_some()),
            _ => false,
        };
        if self.case != Case::Positive || !allowed || !r.project.as_ref().is_some_and(|project| project.id == project_id) { self.fail(); return; }
        r.snapshot_requests += 1;
    }
    pub(super) fn snapshot(&self, project_id: &str, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let saved = r.snapshot_requests == 2;
        let valid = result.as_ref().is_ok_and(|value| {
            let config = &value["config"]; let discovery = &value["discovery"]; let scan = &discovery["scan"];
            let configuration = if saved {
                config["state"].as_str() == Some("format-valid") && config["issues"].as_array().is_some_and(Vec::is_empty)
                    && r.suggested.as_ref() == config.get("data")
                    // Exact raw-byte descriptor is produced by the fresh core
                    // file reader, not by this observer or a renderer baseline.
                    && config["content"] == serde_json::json!({"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256})
                    && r.sessions.first().and_then(|session| session.projection.prepared.as_ref())
                        .is_some_and(|prepared| prepared.view.files[0].after_bytes == CONFIG_BYTES)
            } else {
                config["state"].as_str() == Some("missing") && config.get("data") == Some(&Value::Null)
                    && config.get("content") == Some(&Value::Null)
                    && config["issues"].as_array().is_some_and(|issues| issues.len() == 1 && issues[0]["code"].as_str() == Some("config.missing"))
            };
            r.project.as_ref().is_some_and(|project| project.id == project_id && value["root"].as_str() == Some(project.path.as_str()))
                && value["observationScope"].as_str() == Some("single-request-non-atomic")
                && config["path"].as_str() == Some("release/mobile-release.json") && configuration
                && discovery["state"].as_str() == Some("unverified") && discovery["partial"].as_bool() == Some(false)
                && discovery["hints"].as_object().is_some_and(|hints| hints.len() == 1)
                && discovery["hints"]["android"]["applicationId"].as_str() == Some(APP_ID)
                && discovery["hints"]["android"]["module"].as_str() == Some(":app")
                && discovery["hints"]["android"]["buildFile"].as_str() == Some("app/build.gradle.kts")
                && scan["sourceFiles"].as_u64() == Some(if saved { 2 } else { 1 })
                && scan["sourceBytes"].as_u64() == Some(PROJECT_SOURCE.len() as u64 + if saved { u64::from(CONFIG_BYTES) } else { 0 })
                && scan["entries"].as_u64() == Some(if saved { 5 } else { 2 })
                && scan["excludedEntries"].as_u64() == Some(u64::from(saved))
                && value["issues"].as_array().is_some_and(Vec::is_empty) && assurance(value, "static-text")
        });
        let stage = if saved { matches!(r.step, Step::Refresh | Step::ReadReadback) && r.saved_visible && !r.readback }
            else { r.snapshot_requests == 1 && matches!(r.step, Step::Selected | Step::ReadSnapshot) && !r.snapshot };
        if self.case != Case::Positive || !stage || !valid { self.fail(); return; }
        if saved { r.readback = true; } else { r.snapshot = true; }
    }
    pub(super) fn suggest_request(&self, hints: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.snapshot_visible || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
            || r.suggest_called || *hints != serde_json::json!({"platforms":["android"],"androidApplicationId":APP_ID}) { self.fail(); return; }
        r.suggest_called = true;
    }
    pub(super) fn suggestion(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(value) = result.as_ref().ok().filter(|value| value["schemaVersion"].as_u64() == Some(1)
            && value["platformSelectionRequired"].as_bool() == Some(false) && assurance(value, "schema-policy")
            && format_valid(&value["validation"])
            && value["draft"]["android"]["enabled"].as_bool() == Some(true)
            && value["draft"]["android"]["applicationId"].as_str() == Some(APP_ID)
            && value["draft"]["android"]["identityStatus"].as_str() == Some("unverified")
            && value["draft"]["ios"]["enabled"].as_bool() == Some(false)
            && value["draft"]["version"]["source"].as_str() == Some("release/version.properties")) else { self.fail(); return; };
        let Some(provenance) = value["provenance"].as_array().filter(|rows| !rows.is_empty() && rows.len() <= 64) else { self.fail(); return; };
        let mut projected = Vec::new();
        for row in provenance {
            let (Some(path), Some(source)) = (row["path"].as_str(), row["source"].as_str()) else { self.fail(); return; };
            if path.is_empty() || path.len() > 128 || !matches!(source, "hint" | "default" | "example") { self.fail(); return; }
            projected.push(serde_json::json!({"path":path,"source":source}));
        }
        if self.case != Case::Positive || !r.suggest_called || r.suggested.is_some() || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
            || !["android.enabled", "android.applicationId"].iter().all(|path| provenance.iter().any(|row| row["path"].as_str() == Some(*path) && row["source"].as_str() == Some("hint")))
            || !provenance.iter().any(|row| row["path"].as_str() == Some(FIELD) && row["source"].as_str() == Some("default")) { self.fail(); return; }
        // Private comparison DATA copied from the genuine core response. Never
        // sent to the renderer, installed in its reducer, or printed in a log.
        r.suggested = Some(value["draft"].clone()); r.provenance = Some(Value::Array(projected));
    }
    pub(super) fn requirements_request(&self, body: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || r.guidance.requirements_called
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements)
            || !keys(body, &["draft", "platform", "operation"]) || body["platform"].as_str() != Some("android")
            || body["operation"].as_str() != Some("build")
            || !r.suggested.as_ref().is_some_and(|draft| body.get("draft") == Some(draft)) { self.fail(); return; }
        r.guidance.requirements_called = true;
    }
    pub(super) fn requirements(&self, result: &Result<crate::environment::Requirements, BridgeError>) {
        let sample = result.as_ref().ok().and_then(requirements_display);
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.requirements_called || r.guidance.requirements.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements) { self.fail(); return; }
        r.guidance.requirements = sample;
    }
    pub(super) fn github_request(&self, body: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.requirements_visible || !r.guidance.github_empty
            || !r.guidance.repository_entered || !r.guidance.sha_entered || !r.guidance.inputs_visible || r.guidance.github_called
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal)
            || !keys(body, &["draft", "toolingRepository", "toolingSha", "suppliedSnapshot"])
            || body["toolingRepository"].as_str() != Some(TOOLKIT_REPOSITORY) || body["toolingSha"].as_str() != Some(TOOLKIT_SHA)
            || body.get("suppliedSnapshot") != Some(&Value::Null)
            || !r.suggested.as_ref().is_some_and(|draft| body.get("draft") == Some(draft)) { self.fail(); return; }
        r.guidance.github_called = true;
    }
    pub(super) fn github_proposal(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let sample = result.as_ref().ok().and_then(|value| r.suggested.as_ref().and_then(|draft| ProposalSample::read(value, draft)));
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.github_called || r.guidance.proposal.is_some() || sample.is_none()
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal) { self.fail(); return; }
        r.guidance.proposal = sample;
    }
    pub(super) fn open_request(&self, project_id: &str) {
        let Some(mut r) = self.record() else { return; };
        let index = r.sessions.len();
        let allowed = match index {
            0 => matches!(r.step, Step::PrepareSave | Step::ReadSaveReview) && r.draft_visible && r.guidance.complete(),
            1 => matches!(r.step, Step::PrepareNoop | Step::ReadNoopReview) && r.saved_draft_retained && r.readback_visible
                && r.sessions[0].finality.is_some() && r.saved_visible && r.requests == [1, 1, 1, 0],
            _ => false,
        };
        if self.case != Case::Positive || !allowed || !r.capability || r.open_pending || usize::from(r.requests[0]) != index
            || !r.project.as_ref().is_some_and(|project| project.id == project_id) { self.fail(); return; }
        r.open_pending = true; r.requests[0] += 1;
    }
    pub(super) fn open_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(status) = result.as_ref().ok() else { self.fail(); return; };
            let Some(owner) = status.active.as_ref() else { self.fail(); return; };
            if self.case != Case::Positive || !r.open_pending || r.sessions.len() >= 2 || usize::from(r.requests[0]) != r.sessions.len() + 1
                || owner.phase != edit::Phase::Opening || owner.checkout.is_some() || owner.prepared.is_some() || owner.apply_submitted
                || r.sessions.iter().any(|session| session.projection.session_id == owner.session_id)
                || !r.project.as_ref().is_some_and(|project| project.id == owner.project_id) { self.fail(); return; }
            r.open_pending = false;
            r.sessions.push(SaveSession { projection: owner.clone(), prepared: None, review: None,
                prepare_requested: false, prepare_returned: false, review_visible: false, finality: None });
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn prepare_request(&self, args: &edit::PrepareConfigEdit) {
        let Some(mut r) = self.record() else { return; };
        let index = usize::from(r.requests[1]);
        let Some(session) = r.sessions.get(index) else { self.fail(); return; };
        let allowed = if index == 0 { matches!(r.step, Step::PrepareSave | Step::ReadSaveReview) }
            else { index == 1 && matches!(r.step, Step::PrepareNoop | Step::ReadNoopReview) && r.readback_visible && r.saved_draft_retained };
        let base = if index == 0 { &Value::Null } else { r.suggested.as_ref().unwrap_or(&Value::Null) };
        if self.case != Case::Positive || !allowed || r.prepare_pending.is_some() || session.prepare_requested
            || session.projection.phase != edit::Phase::Editing || session.projection.session_id != args.session_id
            || !session.projection.checkout.as_ref().is_some_and(|checkout| checkout.revision == args.revision && checkout.base == args.expected_base)
            || &args.expected_base != base || r.suggested.as_ref() != Some(&args.draft)
            || args.draft_revision != 1 || args.baseline_generation != index as u32 + 1 { self.fail(); return; }
        r.sessions[index].prepare_requested = true; r.prepare_pending = Some(index); r.requests[1] += 1;
    }
    pub(super) fn prepare_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(index) = r.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            let session = &mut r.sessions[index];
            if session.prepare_returned || owner.session_id != session.projection.session_id || owner.phase != edit::Phase::Preparing
                || owner.prepared.is_some() || owner.apply_submitted || owner.checkout.as_ref().map(|checkout| &checkout.revision)
                    != session.projection.checkout.as_ref().map(|checkout| &checkout.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn apply_request(&self, session_id: &str, plan_token: &str) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !matches!(r.step, Step::Apply | Step::ReadSaved) || r.requests != [1, 1, 0, 0]
            || r.confirmation_opened != 2 || !r.kept_reviewing || !r.acknowledged
            || !r.sessions.first().is_some_and(|session| session.review_visible && session.prepare_returned && session.live_review()
                && session.projection.session_id == session_id
                && session.projection.prepared.as_ref().is_some_and(|prepared| prepared.plan_token == plan_token)) { self.fail(); return; }
        r.requests[2] += 1;
    }
    pub(super) fn apply_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            if r.apply_returned || r.requests != [1, 1, 1, 0] || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || !r.sessions.first().is_some_and(|session| session.projection.session_id == owner.session_id
                    && session.projection.prepared.as_ref().map(|prepared| &prepared.plan_token)
                        == owner.prepared.as_ref().map(|prepared| &prepared.plan_token)) { self.fail(); return; }
            r.apply_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn close_request(&self) {
        if let Some(mut r) = self.record() { r.requests[3] = r.requests[3].saturating_add(1); }
        self.fail(); // Keep reviewing is not Close; native Quit owns the sole EOF.
    }
    pub(super) fn edit_status(&self, status: &ConfigEditStatus, edits: &EditOwner) {
        if self.case != Case::Positive { return; }
        let Some(mut r) = self.record() else { return; };
        if status.schema_version != 1 || !edit::token(&status.window_generation)
            || r.generation.as_ref().is_some_and(|generation| generation != &status.window_generation) { self.fail(); return; }
        if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
        if r.native_revision.is_some_and(|revision| status.status_revision < revision) { return; }
        if let Some(active) = &status.active {
            if !r.sessions.iter().any(|session| session.projection.session_id == active.session_id) {
                // A relay may see admission between the real Open call and its
                // synchronous reply hook. Do not guess that original identity.
                if r.open_pending && usize::from(r.requests[0]) == r.sessions.len() + 1 { return; }
                self.fail(); return;
            }
        }
        if status.capability.available && status.capability.reason == edit::EditAvailability::Available { r.capability = true; }
        else if r.capability && !(r.close_prevented && status.capability.reason == edit::EditAvailability::Shutdown && !status.capability.available) {
            self.fail(); return;
        }
        for projection in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(index) = r.sessions.iter().position(|session| session.projection.session_id == projection.session_id) else { self.fail(); return; };
            let no_op = index == 1;
            let base = if no_op { r.suggested.as_ref().unwrap_or(&Value::Null) } else { &Value::Null };
            let old = &r.sessions[index].projection;
            if projection.domain != edit::EditDomain::Configuration || projection.workflow.is_some() || projection.metadata_text.is_some()
                || projection.project_id != old.project_id || projection.owner_generation != status.window_generation
                || !edit::token(&projection.session_id) || projection.late_settled || projection.phase == edit::Phase::Unknown
                || phase_order(projection.phase) < phase_order(old.phase) || projection.native_finality == edit::NativeFinality::Unknown
                || projection.apply_submitted != (!no_op && r.requests[2] == 1 && phase_order(projection.phase) >= phase_order(edit::Phase::Applying))
                || projection.native_reason != (if no_op && r.close_prevented && phase_order(projection.phase) >= phase_order(edit::Phase::Finalizing) {
                    edit::NativeEditReason::Shutdown
                } else { edit::NativeEditReason::None }) { self.fail(); return; }
            if let Some(checkout) = &projection.checkout {
                if !edit::token(&checkout.revision) || &checkout.base != base
                    || old.checkout.as_ref().is_some_and(|before| before.revision != checkout.revision || before.base != checkout.base)
                    || no_op && r.sessions[0].projection.checkout.as_ref().is_some_and(|before| before.revision == checkout.revision) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            if let Some(prepared) = &projection.prepared {
                let Some(review) = review_sample(&prepared.view, no_op) else { self.fail(); return; };
                let Ok(value) = serde_json::to_value(prepared) else { self.fail(); return; };
                if !r.sessions[index].prepare_requested || !edit::token(&prepared.plan_token)
                    || !projection.checkout.as_ref().is_some_and(|checkout| checkout.revision == prepared.revision)
                    || prepared.draft_revision != 1 || prepared.baseline_generation != index as u32 + 1
                    || r.sessions[index].prepared.as_ref().is_some_and(|before| before != &value)
                    || no_op && r.sessions[0].projection.prepared.as_ref().is_some_and(|before| before.plan_token == prepared.plan_token) { self.fail(); return; }
                r.sessions[index].prepared = Some(value); r.sessions[index].review = Some(review);
            } else if r.sessions[index].prepared.is_some() { self.fail(); return; }
            if let Some(core) = &projection.core_outcome {
                if core.effect != (if no_op { edit::Effect::NotStarted } else { edit::Effect::Committed })
                    || core.journal != (if no_op { edit::Journal::NotCreated } else { edit::Journal::Clean })
                    || core.resources != edit::ResourceState::Settled
                    || core.reason != (if no_op { edit::CoreReason::Cancelled } else { edit::CoreReason::None })
                    || phase_order(projection.phase) < phase_order(edit::Phase::Finalizing) { self.fail(); return; }
            }
            if projection.phase == edit::Phase::Final {
                if projection.native_finality != edit::NativeFinality::Settled || projection.core_outcome.is_none()
                    || projection.prepared.is_none() || no_op && !r.noop_outstanding { self.fail(); return; }
                if r.sessions[index].finality.is_none() {
                    let Some(facts) = edits.installed_observation_final(&projection.session_id) else { self.fail(); return; };
                    if !original_final(&facts, projection, no_op) { self.fail(); return; }
                    r.sessions[index].finality = Some(facts);
                }
            } else if projection.native_finality != edit::NativeFinality::Pending { self.fail(); return; }
            r.sessions[index].projection = projection.clone();
        }
        r.native_revision = Some(status.status_revision);
    }
    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.failed.load(Ordering::SeqCst) { return; }
        if Instant::now() >= self.end || std::thread::current().id() == self.main { self.fail(); return; }
        let step = {
            let Some(mut r) = self.record() else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.step == Step::Bootstrap {
                // Observe the same owners after start_relay returned and its
                // barrier opened. Teardown may legitimately report document loss.
                let state = app.state::<super::ShellState>();
                match (state.bridge.preflight.original_for_test().observed_document_lost_for_test(),
                       state.bridge.android_build.original_for_test().observed_document_lost_for_test()) {
                    (Some(false), Some(false)) => {},
                    (Some(true), _) | (_, Some(true)) => { self.fail(); return; },
                    _ => return, // No absent/busy/unknown observation becomes false.
                }
            }
            if r.step == Step::Bootstrap && self.case == Case::Positive {
                if !r.info || !r.catalog { return; }
                r.step = Step::Environment;
            }
            // Wait for already-requested native replies without spending DOM
            // evaluations on work that has not returned. No new task/deadline.
            let native_pending = match r.step {
                Step::ReadSnapshot => !r.snapshot,
                Step::ReadSuggestion => r.suggested.is_none(),
                Step::ReadRequirements => r.guidance.requirements.is_none(),
                Step::ReadProposal => r.guidance.proposal.is_none(),
                Step::ReadSaveReview => !r.sessions.first().is_some_and(|session| session.prepare_returned && session.review.is_some()),
                Step::ReadSaved => !r.apply_returned || !r.sessions.first().is_some_and(|session| session.finality.is_some()),
                Step::ReadReadback => !r.readback,
                Step::ReadNoopReview => !r.sessions.get(1).is_some_and(|session| session.prepare_returned && session.review.is_some()),
                _ => false,
            };
            if native_pending { return; }
            r.step
        };
        if step == Step::Bootstrap {
            // The original J seam holds this actual initial app-info child
            // before its writer. No query, candidate constructor or resource
            // lock is introduced here. The returned token retains that owner.
            match app.state::<super::ShellState>().bridge.supervisor.retain_held_app_info() {
                Ok(Some(held)) => {
                    let Some(mut r) = self.record() else { return; };
                    if r.held.is_some() { self.fail(); return; }
                    r.held = Some(held); r.step = Step::Close;
                },
                Ok(None) => {}, Err(_) => self.fail(),
            }
            return;
        }
        if matches!(step, Step::Cancelled | Step::Selected) {
            // IPC completion is only a display receipt. Read the same retained
            // document/operation/source/worker/coordinator originals before any
            // next UI intent; no new task, request, clock or owner is created.
            let state = app.state::<super::ShellState>();
            if step == Step::Cancelled {
                if !state.document.installed_observation_cancelled() { return; }
                let Some(mut r) = self.record() else { return; };
                if !r.cancel_returned || !r.pickers[0].settled(false) { return; }
                r.cancelled = true; r.step = Step::ReadCancelled;
            } else {
                let Some(project) = state.document.installed_observation_project() else { return; };
                let Some(mut r) = self.record() else { return; };
                let Some(returned) = &r.project else { return; };
                if project.id != returned.id || project.path != returned.path || project.name != returned.name { self.fail(); return; }
                if !r.pickers[1].settled(true) { return; }
                r.selected = true; r.step = Step::ReadSnapshot;
            }
            return;
        }
        if step == Step::Exit { return; }
        {
            let Some(mut r) = self.record() else { return; };
            r.pending = Some(match step {
                Step::Close => {
                    if self.case == Case::Positive {
                        if !r.sessions.get(1).is_some_and(|session| session.review_visible && session.live_review())
                            || r.requests != [2, 2, 1, 0] || !r.readback_visible || !r.saved_draft_retained { self.fail(); return; }
                        r.noop_outstanding = true;
                    }
                    r.step = Step::Quit; Pending::Close
                },
                Step::Quit => { if !r.close_prevented { self.fail(); return; } Pending::Gtk },
                Step::Cancel | Step::SetProject | Step::SelectProject => Pending::Project(step),
                _ => {
                    if r.evaluations >= 128 { self.fail(); return; }
                    r.evaluations += 1; Pending::Dom(step)
                },
            });
        }
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(); return; };
        match step {
            Step::Close => { if window.close().is_err() { self.fail(); } },
            Step::Quit => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = super::owned_gtk::activate_observed_quit(&app, &q);
                    q.gtk_returned(result);
                }).is_err() { self.fail(); }
            },
            Step::Cancel | Step::SetProject | Step::SelectProject => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = if step == Step::SetProject { super::owned_gtk::select_observed_project(&app, &q) }
                        else { super::owned_gtk::activate_observed_project(&app, &q, step == Step::SelectProject) };
                    q.project_gtk_returned(step, result);
                }).is_err() { self.fail(); }
            },
            _ => {
                let Some(script) = script(step) else { self.fail(); return; };
                let q = self.clone();
                // Outer Ok is dispatch, never an evaluation or DOM receipt.
                // An absent callback remains pending; it is never retried.
                if window.eval_with_callback(script, move |value| q.dom(step, &value)).is_err() { self.fail(); }
            },
        }
    }
    fn dom(&self, step: Step, raw: &str) {
        if raw.len() > 262144 || Instant::now() >= self.end { self.fail(); return; }
        let Ok(value) = crate::protocol::strict_json(raw.as_bytes()) else { self.fail(); return; };
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Dom(step)) || r.step != step { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let draft = |saved: bool, available: bool| value["unsaved"].as_bool() == Some(!saved)
            && value["saved"].as_bool() == Some(saved) && value["saveAvailable"].as_bool() == Some(available);
        let source = || r.suggested.as_ref().is_some_and(|suggested| value["source"].as_str() == suggested["version"]["source"].as_str());
        let review = |index: usize| r.sessions.get(index).is_some_and(|session| session.prepare_returned && session.live_review()
            && session.review.as_ref() == value.get("review"))
            && r.project.as_ref().is_some_and(|project| value["projectPath"].as_str() == Some(project.path.as_str()));
        let valid = match step {
            Step::ReadEnvironment => {
                let versions = value.get("versions").and_then(Value::as_array);
                let available = value.get("available").and_then(Value::as_array);
                object.len() == 7 && value["title"].as_str() == Some("Bundled runtime") && value["badge"].as_str() == Some("available")
                    && value["rows"].as_u64() == Some(r.methods as u64) && value["unavailable"].as_u64() == Some((r.methods - METHODS.len()) as u64)
                    && versions.is_some_and(|v| v.len() == 3 && v[0].as_str() == Some(env!("CARGO_PKG_VERSION"))
                        && v[1].as_str() == Some(crate::runtime::CORE_VERSION) && v[2].as_str() == Some("linux"))
                    && available.is_some_and(|a| a.len() == METHODS.len() && a.iter().zip([
                        "Read engine capabilities", "Load schema & field help", "Read a static project observation",
                        "Validate a configuration draft", "Suggest an unverified configuration draft", "Review draft changes and field requirements",
                        "Prepare a GitHub setup preview", "Explain project toolchain requirements",
                    ]).all(|(actual, expected)| actual.as_str() == Some(expected)))
            },
            Step::ReadCancelled => object.len() == 3 && r.cancelled && value["unselected"].as_bool() == Some(true)
                && value["chooseEnabled"].as_bool() == Some(true),
            Step::ReadSnapshot => object.len() == 4 && r.selected && r.snapshot
                && value["configuration"].as_str() == Some("Not configured") && value["sourceFiles"].as_str() == Some("1 recognized files")
                && value["name"].as_str() == Some("positive-project"),
            Step::ReadSuggestion => object.len() == 2 && r.suggested.is_some() && r.provenance.as_ref() == value.get("provenance"),
            Step::ReadDraft | Step::ReadRetainedDraft => object.len() == 5 && r.adopted && r.capability && source() && draft(false, true)
                && (step != Step::ReadRetainedDraft || r.guidance.workflows_visible),
            Step::ReadRequirements => object.len() == 2 && r.guidance.requirements_called
                && r.guidance.requirements.as_ref().is_some_and(|display| value.get("display") == Some(display)),
            Step::ReadGitHubEmpty => object.len() == 3 && r.guidance.requirements_visible && !r.guidance.github_empty
                && value["inputs"] == serde_json::json!({"repository":"","sha":"","comparison":false,"previewAvailable":false})
                && r.suggested.as_ref().is_some_and(|draft| value["branches"] == serde_json::json!(
                    [draft["source"]["candidateBranch"],draft["source"]["productionBranch"]])),
            Step::ReadGitHubInputs => object.len() == 2 && r.guidance.repository_entered && r.guidance.sha_entered
                && value["inputs"] == serde_json::json!({"repository":TOOLKIT_REPOSITORY,"sha":TOOLKIT_SHA,"comparison":false,"previewAvailable":true}),
            Step::ReadProposal => object.len() == 2 && r.guidance.github_called
                && r.guidance.proposal.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.display)),
            Step::ReadWorkflows => object.len() == 2 && r.guidance.proposal_visible
                && r.guidance.proposal.as_ref().is_some_and(|sample| value.get("workflows") == Some(&sample.workflows)),
            Step::ReadSaveReview | Step::ReadKeptReview => object.len() == 6 && review(0) && draft(false, false)
                && r.requests == [1, 1, 0, 0] && (step != Step::ReadKeptReview || r.confirmation_opened == 1),
            Step::ReadNoopReview => object.len() == 6 && review(1) && draft(true, false)
                && r.requests == [2, 2, 1, 0] && r.readback_visible && r.saved_draft_retained,
            Step::ReadConfirmation | Step::ReadReopenedConfirmation | Step::ReadAcknowledged => {
                let acknowledged = step == Step::ReadAcknowledged;
                let dialog = &value["confirmation"];
                object.len() == 2 && r.requests == [1, 1, 0, 0]
                    && r.sessions.first().is_some_and(|session| session.review_visible && session.live_review()
                        && session.review.as_ref().is_some_and(|review| dialog["files"] == review["files"]))
                    && r.project.as_ref().is_some_and(|project| dialog["projectPath"].as_str() == Some(project.path.as_str()))
                    && keys(dialog, &["title", "projectPath", "draftRevision", "files", "release", "rewrite", "checked", "applyAvailable"])
                    && dialog["title"].as_str() == Some("Apply this configuration save?") && dialog["draftRevision"].as_u64() == Some(1)
                    && dialog["release"].as_bool() == Some(true) && dialog["rewrite"].as_bool() == Some(false)
                    && dialog["checked"].as_bool() == Some(acknowledged) && dialog["applyAvailable"].as_bool() == Some(acknowledged)
                    && r.confirmation_opened == (if step == Step::ReadConfirmation { 1 } else { 2 })
                    && (step == Step::ReadConfirmation || r.kept_reviewing)
            },
            Step::ReadSaved => object.len() == 9 && source() && draft(true, true) && r.apply_returned
                && r.sessions.first().is_some_and(|session| session.finality.is_some())
                && value["title"].as_str() == Some("Submitted configuration saved")
                && value["banner"].as_str() == Some("The submitted revision was saved")
                && value["staleSnapshot"].as_bool() == Some(true)
                && value["facts"] == serde_json::json!([["Transaction effect","committed"],["Journal","clean"],
                    ["Core resources","settled"],["Native finality","settled"]]),
            Step::ReadReadback => object.len() == 6 && r.readback && r.snapshot_requests == 2 && r.saved_visible
                && value["configuration"].as_str() == Some("Format-valid only") && value["sourceFiles"].as_str() == Some("2 recognized files")
                && value["name"].as_str() == Some("positive-project") && value["applicationId"].as_str() == Some(APP_ID)
                && value["staleSnapshot"].as_bool() == Some(false),
            Step::ReadSavedDraft => object.len() == 6 && r.readback_visible && source() && draft(true, true)
                && value["staleSnapshot"].as_bool() == Some(false),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment,
            Step::ReadEnvironment => { r.environment = true; Step::Dashboard },
            Step::Dashboard => Step::ChooseCancel,
            Step::ChooseCancel => Step::Cancel,
            Step::ReadCancelled => Step::ChooseSelect,
            Step::ChooseSelect => Step::SetProject,
            Step::ReadSnapshot => { r.snapshot_visible = true; Step::Settings },
            Step::Settings => Step::Suggest,
            Step::Suggest => Step::ReadSuggestion,
            Step::ReadSuggestion => { r.provenance_visible = true; Step::Adopt },
            Step::Adopt => { r.adopted = true; Step::ReadDraft },
            Step::ReadDraft => { r.draft_visible = true; Step::GuidanceEnvironment },
            Step::GuidanceEnvironment => Step::LoadRequirements,
            Step::LoadRequirements => Step::ReadRequirements,
            Step::ReadRequirements => { r.guidance.requirements_visible = true; Step::GitHub },
            Step::GitHub => Step::ReadGitHubEmpty,
            Step::ReadGitHubEmpty => { r.guidance.github_empty = true; Step::EnterRepository },
            Step::EnterRepository => { r.guidance.repository_entered = true; Step::EnterSha },
            Step::EnterSha => { r.guidance.sha_entered = true; Step::ReadGitHubInputs },
            Step::ReadGitHubInputs => { r.guidance.inputs_visible = true; Step::ProposeGitHub },
            Step::ProposeGitHub => Step::ReadProposal,
            Step::ReadProposal => { r.guidance.proposal_visible = true; Step::OpenWorkflows },
            Step::OpenWorkflows => Step::ReadWorkflows,
            Step::ReadWorkflows => { r.guidance.workflows_visible = true; Step::GuidanceSettings },
            Step::GuidanceSettings => Step::ReadRetainedDraft,
            Step::ReadRetainedDraft => { r.guidance.draft_retained = true; Step::PrepareSave },
            Step::PrepareSave => Step::ReadSaveReview,
            Step::ReadSaveReview => { r.sessions[0].review_visible = true; Step::OpenConfirmation },
            Step::OpenConfirmation => { r.confirmation_opened += 1; Step::ReadConfirmation },
            Step::ReadConfirmation => Step::KeepReviewing,
            Step::KeepReviewing => Step::ReadKeptReview,
            Step::ReadKeptReview => { r.kept_reviewing = true; Step::ReopenConfirmation },
            Step::ReopenConfirmation => { r.confirmation_opened += 1; Step::ReadReopenedConfirmation },
            Step::ReadReopenedConfirmation => Step::Acknowledge,
            Step::Acknowledge => Step::ReadAcknowledged,
            Step::ReadAcknowledged => { r.acknowledged = true; Step::Apply },
            Step::Apply => Step::ReadSaved,
            Step::ReadSaved => { r.saved_visible = true; Step::SavedDashboard },
            Step::SavedDashboard => Step::Refresh,
            Step::Refresh => Step::ReadReadback,
            Step::ReadReadback => { r.readback_visible = true; Step::SavedSettings },
            Step::SavedSettings => Step::ReadSavedDraft,
            Step::ReadSavedDraft => { r.saved_draft_retained = true; Step::PrepareNoop },
            Step::PrepareNoop => Step::ReadNoopReview,
            Step::ReadNoopReview => { r.sessions[1].review_visible = true; Step::Close },
            _ => { self.fail(); return; },
        };
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Close) || r.step != Step::Quit || r.close_prevented { self.fail(); return; }
        r.close_prevented = true;
    }
    pub(super) fn project_created(&self, id: u32) {
        let Some(mut r) = self.record() else { return; };
        let allowed = match id {
            1 => matches!(r.step, Step::ChooseCancel | Step::Cancel) && !r.cancelled,
            2 => matches!(r.step, Step::ChooseSelect | Step::SetProject) && r.cancelled,
            _ => false,
        };
        if self.case != Case::Positive || !allowed || r.pickers[(id - 1) as usize].created { self.fail(); return; }
        r.pickers[(id - 1) as usize].created = true;
    }
    pub(super) fn project_selection(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record() else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case != Case::Positive
            || id != 2 || r.pending != Some(Pending::Project(Step::SetProject))
            || !r.pickers[1].created || r.pickers[1].selected { self.fail(); return Err(()); }
        r.pickers[1].selected = true; Ok(())
    }
    pub(super) fn project_activation(&self, id: u32, select: bool) -> Result<(), ()> {
        let Some(mut r) = self.record() else { return Err(()); };
        let index = usize::from(select);
        let step = if select { Step::SelectProject } else { Step::Cancel };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case != Case::Positive
            || id != index as u32 + 1 || r.pending != Some(Pending::Project(step))
            || !r.pickers[index].created || r.pickers[index].activated || r.pickers[index].selected != select { self.fail(); return Err(()); }
        r.pickers[index].activated = true; Ok(())
    }
    pub(super) fn project_filename(&self, id: u32, path: Option<&Path>) {
        let Some(mut r) = self.record() else { return; };
        if id != 2 || !r.pickers[1].activated || r.pickers[1].filename || r.pickers[1].responded
            || path.is_none() || path != self.project_path() { self.fail(); return; }
        r.pickers[1].filename = true;
    }
    pub(super) fn project_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !(1..=2).contains(&id) { self.fail(); return; }
        let p = &mut r.pickers[(id - 1) as usize];
        if !p.activated || p.destroyed || p.released { self.fail(); return; }
        if !p.responded && !disposal && (id == 1 && cancelled && !accepted && !p.filename
            || id == 2 && accepted && !cancelled && p.filename) { p.responded = true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal = true; }
        else { self.fail(); }
    }
    fn project_gtk_returned(&self, step: Step, result: Result<bool, ()>) {
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Project(step)) || r.step != step { self.fail(); return; }
        let index = usize::from(step != Step::Cancel);
        match result {
            Ok(false) if !r.pickers[index].activated && (step != Step::SetProject || !r.pickers[index].selected) => {},
            Ok(true) if step == Step::SetProject && r.pickers[1].selected && !r.pickers[1].activated => r.step = Step::SelectProject,
            Ok(true) if r.pickers[index].activated && r.pickers[index].responded && !r.pickers[index].returned => {
                r.pickers[index].returned = true;
                r.step = if index == 0 { Step::Cancelled } else { Step::Selected };
            },
            _ => self.fail(),
        }
    }
    pub(super) fn native_created(&self, id: u32, quit: bool) {
        let Some(mut r) = self.record() else { return; };
        if !quit || id == 0 || self.case == Case::Positive && id != 3
            || !r.close_prevented || r.step != Step::Quit || r.native_id.is_some() { self.fail(); return; }
        r.native_id = Some(id);
    }
    pub(super) fn native_activation(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record() else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || r.native_id != Some(id)
            || r.pending != Some(Pending::Gtk) || r.activated { self.fail(); return Err(()); }
        r.activated = true; Ok(())
    }
    pub(super) fn native_response(&self, id: u32, accepted: bool, disposal: bool) {
        let Some(mut r) = self.record() else { return; };
        if r.native_id != Some(id) || !r.activated || r.destroyed || r.released { self.fail(); return; }
        if accepted && !disposal && !r.responded { r.responded = true; }
        else if disposal && !accepted && r.responded && r.gtk_returned && !r.disposal_response {
            // At most one close-generated DeleteEvent, witnessed by the same
            // original close_ack/accepted/returned-None facts in shell.rs.
            r.disposal_response = true;
        } else { self.fail(); }
    }
    fn gtk_returned(&self, result: Result<bool, ()>) {
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Gtk) { self.fail(); return; }
        match result {
            Ok(false) if !r.activated => {},
            Ok(true) if r.activated && r.responded => { r.gtk_returned = true; r.step = Step::Exit; },
            _ => self.fail(),
        }
    }
    pub(super) fn native_destroyed(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record() else { return; };
        if self.case == Case::Positive && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.responded || p.destroyed { self.fail(); return; }
            p.destroyed = true; return;
        }
        if !seen || r.native_id != Some(id) || !r.responded || r.destroyed { self.fail(); return; }
        r.destroyed = true;
    }
    pub(super) fn native_released(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record() else { return; };
        if self.case == Case::Positive && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.destroyed || p.released { self.fail(); return; }
            p.released = true; return;
        }
        if !seen || r.native_id != Some(id) || !r.destroyed || r.released { self.fail(); return; }
        r.released = true;
    }
    pub(super) fn relay_joined(&self, joined: bool) {
        let Some(mut r) = self.record() else { return; };
        if !joined || !r.released || !r.gtk_returned || r.relay_joined { self.fail(); return; }
        r.relay_joined = true;
    }
    pub(super) fn actual_exit(&self, ready: bool, document: &crate::asset_session::DocumentBinding, edits: &EditOwner) {
        // The relay may have stopped before its last publication. Read only the
        // SAME already-retired original ledger facts; never start cleanup here.
        if self.case == Case::Positive {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
        }
        let originals_final = self.case == Case::Outstanding || document.installed_observation_final();
        let Some(mut r) = self.record() else { return; };
        if !ready || !originals_final || !r.relay_joined || !r.released || r.exit
            || self.case == Case::Positive && (r.sessions.len() != 2 || !r.sessions.iter().all(|session| session.finality.is_some())) { self.fail(); return; }
        r.originals_final = originals_final; r.exit = true;
    }
    fn finish(&self) -> bool {
        let held = match self.record() { Some(mut r) => r.held.take(), None => return false };
        let retired = match (self.case, held) {
            (Case::Positive, None) => true,
            (Case::Outstanding, Some(mut held)) => {
                // Borrow/join the same original after the NORMAL event loop
                // exits. No additional task, shutdown call, or replacement
                // settlement flag. The once-captured observation end is reused.
                tauri::async_runtime::block_on(held.observe_retired(self.end)).is_ok()
            },
            _ => false,
        };
        let Some(r) = self.record() else { return false; };
        retired && !self.failed.load(Ordering::SeqCst) && Instant::now() < self.end && r.attached && r.loaded
            && r.close_prevented && r.activated && r.responded && r.destroyed && r.released && r.gtk_returned
            && r.relay_joined && r.exit && r.pending.is_none() && r.step == Step::Exit
            && (self.case == Case::Outstanding || r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.suggested.is_some() && r.provenance_visible && r.adopted && r.draft_visible
                && r.guidance.complete() && r.capability && r.requests == [2, 2, 1, 0] && !r.open_pending && r.prepare_pending.is_none() && r.apply_returned
                && r.confirmation_opened == 2 && r.kept_reviewing && r.acknowledged && r.saved_visible
                && r.snapshot_requests == 2 && r.readback && r.readback_visible && r.saved_draft_retained && r.noop_outstanding
                && r.sessions.len() == 2 && r.sessions.iter().all(|session| session.prepare_returned && session.review_visible && session.finality.is_some())
                && r.originals_final)
    }
    fn positive_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::Positive || !r.exit || !r.originals_final || r.sessions.len() != 2 || !r.guidance.complete() { return None; }
        let finals: Vec<_> = r.sessions.iter().filter_map(|session| session.finality.as_ref()).collect();
        if finals.len() != 2 { return None; }
        let count = |test: fn(&InstalledConfigFinality) -> bool| finals.iter().filter(|facts| test(facts)).count();
        let prepared: Vec<_> = r.sessions.iter().filter_map(|session| session.projection.prepared.as_ref()).collect();
        if prepared.len() != 2 { return None; }
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"fixture":"android-config-save-v1","projectGateContract":true,"methods":"eight-passive","passiveActions":false,
            "cancel":{"operation":1,"widget":"cancel","guiSettled":r.pickers[0].settled(false),"originalsSettled":r.cancelled,"registered":false},
            "select":{"operation":2,"widget":"select","filenameRead":r.pickers[1].filename,"guiSettled":r.pickers[1].settled(true),"originalsSettled":r.selected,"registered":r.project.is_some()},
            "snapshot":{"initial":"missing","sourceFiles":1,"androidHint":r.snapshot},
            "suggestion":{"coreProvenance":r.provenance_visible,"explicitAdoption":r.adopted},
            "save":{"capability":r.capability,"requests":{"open":r.requests[0],"prepare":r.requests[1],"apply":r.requests[2],"close":r.requests[3]},
                "bindingsMatched":r.sessions.iter().all(|session| session.prepare_requested && session.prepare_returned),
                "draftRevisions":prepared.iter().map(|p| p.draft_revision).collect::<Vec<_>>(),
                "baselineGenerations":prepared.iter().map(|p| p.baseline_generation).collect::<Vec<_>>(),"reviewMatched":r.sessions[0].review_visible,
                "confirmation":{"opened":r.confirmation_opened,"keepReviewing":r.kept_reviewing,"applyBeforeAck":0,"acknowledged":r.acknowledged},
                "outcome":["committed","clean","settled","none"],"nativeFinality":"settled","savedVisible":r.saved_visible,
                "baselineAdvanced":prepared[1].baseline_generation == prepared[0].baseline_generation + 1},
            "readback":{"fresh":r.readback && r.snapshot_requests == 2,"domMatched":r.readback_visible,"draftMatched":r.saved_draft_retained,
                "size":CONFIG_BYTES,"sha256":CONFIG_SHA256},
            "noop":{"reviewMatched":r.sessions[1].review_visible,"apply":0,"quitOutstanding":r.noop_outstanding,
                "outcome":["not_started","not_created","settled","cancelled"],"nativeReason":"shutdown"},
            "originals":{"sessions":finals.len(),"writerFrames":finals.iter().map(|f| f.writer_frames).collect::<Vec<_>>(),
                "stdoutFrames":finals.iter().map(|f| f.stdout_frames).collect::<Vec<_>>(),
                "startupJoined":count(|f| f.inspection_joined && f.acquisition_joined),"childWaited":count(|f| f.child_waited_success),
                "ioSettled":count(|f| f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined),
                "ownersJoined":count(|f| f.driver_joined && f.watchdog_joined && f.manager_joined),
                "runtimeLedgerSettled":count(|f| f.runtime_ledger_settled),"runtimeSettlementJoined":count(|f| f.runtime_settlement_joined)},
            "quit":{"operation":3,"originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit},
            "guidance":{"draftUnchanged":r.guidance.draft_retained && r.sessions.iter().all(|session| session.prepare_requested && session.prepare_returned),
                "requirements":{"requestResultDomMatched":r.guidance.requirements_called && r.guidance.requirements.is_some() && r.guidance.requirements_visible,
                    "context":"android/build","roles":3,"presence":"unknown","version":"unknown","inspection":"not-run",
                    "nativeInspection":"unavailable","dependencies":"unknown"},
                "github":{"requestResultDomMatched":r.guidance.github_called && r.guidance.proposal.is_some() && r.guidance.proposal_visible && r.guidance.workflows_visible,
                    "explicitInputs":r.guidance.github_empty && r.guidance.repository_entered && r.guidance.sha_entered && r.guidance.inputs_visible,
                    "browserEdit":"insertText","comparison":"not-supplied","workflowCount":4,"tooling":"format-only","githubContacted":false,
                    "repositoryObserved":false,"toolingRefResolved":false,"templateCompatibility":"unknown","applyAvailable":false},
                "assuranceActions":false,"releaseReadiness":"unknown"}
        })).ok().filter(|raw| raw.len() + 1 <= 2048)
    }
}

// Fixed synchronous DOM expressions. Click only existing UI controls, wait for
// later React/effect rendering, and return actual bounded text for comparison.
// No injected DTO, controller/invoke call, .value assignment, synthetic dispatch,
// async Promise, substitute reply, alternate bootstrap or review owner.
fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Environment | Step::GuidanceEnvironment => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadEnvironment => r#"
            const selectedTab = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"][aria-current="page"]');
            const card = document.querySelector('.runtime-card');
            if (!selectedTab || !card) return {state:'wait'};
            card.scrollIntoView({block:'start'}); if (!visible(card)) return {state:'error'};
            const rows = [...document.querySelectorAll('.capability-list > div')];
            if (rows.length < 2 || rows.length > 64) return {state:'error'};
            const available = rows.filter(r => text(r.querySelector('.badge')) === 'Available · passive').map(r => text(r.querySelector('strong')));
            const versions = [...card.querySelectorAll('.runtime-versions strong')].map(text);
            return {state:'ready', title:text(card.querySelector('h2')), badge:text(card.querySelector('.badge')),
                versions, available, rows:rows.length, unavailable:rows.filter(r => text(r.querySelector('.badge')) === 'Unavailable').length};"#,
        Step::Dashboard | Step::SavedDashboard => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Dashboard"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ChooseCancel | Step::ChooseSelect => r#"
            if (!selected('Dashboard') || !document.querySelector('.project-overview')) return {state:'wait'};
            const b = [...document.querySelectorAll('.page-heading button')].find(b => text(b) === 'Choose a project');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadCancelled => r#"
            const b = [...document.querySelectorAll('.page-heading button')].find(b => text(b) === 'Choose a project');
            if (!selected('Dashboard') || !b || !visible(b) || b.disabled) return {state:'wait'};
            return {state:'ready', unselected:text(document.querySelector('.project-identity h2')) === 'Your next release, organized.'
                && !document.querySelector('.observation-facts, .draft-banner'), chooseEnabled:!b.disabled};"#,
        Step::ReadSnapshot => r#"
            const facts = document.querySelector('.observation-facts');
            const refresh = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            if (!selected('Dashboard') || !facts || !refresh || refresh.disabled) return {state:'wait'};
            facts.scrollIntoView({block:'center'}); if (!visible(facts)) return {state:'error'};
            return {state:'ready', configuration:text(document.querySelector('.project-badges .badge')),
                sourceFiles:text(facts.querySelector('strong')), name:text(document.querySelector('.project-identity h2'))};"#,
        Step::Settings | Step::GuidanceSettings | Step::SavedSettings => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Project settings"]');
            if (!b || b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::Suggest => r#"
            if (!selected('Project settings')) return {state:'wait'};
            const b = document.querySelector('.suggestion-card button[aria-describedby="suggestion-reason"]');
            if (!b || b.disabled) return {state:'wait'};
            if (text(b) !== 'Prepare suggested draft' || document.querySelector('.draft-banner, .suggestion-result')) return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadSuggestion => r#"
            const result = document.querySelector('.suggestion-result');
            if (!result) return {state:'wait'};
            const b = result.querySelector('.suggestion-adopt button');
            if (!b || b.disabled || document.querySelector('.draft-banner')) return {state:'error'};
            const rows = [...result.querySelectorAll('.provenance-list > li')];
            if (rows.length === 0 || rows.length > 64) return {state:'error'};
            result.scrollIntoView({block:'start'}); if (!visible(result)) return {state:'error'};
            const codes = {'Unverified hint':'hint', 'Core default':'default', 'Example only':'example'};
            return {state:'ready', provenance:rows.map(row => ({path:text(row.querySelector('code')), source:codes[text(row.querySelector('.badge'))] ?? 'error'}))};"#,
        Step::Adopt => r#"
            const b = document.querySelector('.suggestion-adopt button');
            if (!b || b.disabled || text(b) !== 'Use as an in-memory draft' || document.querySelector('.draft-banner')) return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadDraft | Step::ReadRetainedDraft => r#"
            if (!selected('Project settings') || !field() || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saveAvailable) return {state:'wait'};
            return {state:'ready', source:sourceValue(), ...draft};"#,
        Step::LoadRequirements => r#"
            if (!selected('Environment')) return {state:'wait'};
            const controls = document.querySelector('.environment-controls'); if (!controls) return {state:'wait'};
            const platform = controls.querySelector('#environment-platform'), operation = controls.querySelector('#environment-operation');
            if (!platform || !operation || platform.disabled || operation.disabled || platform.value !== 'android' || operation.value !== 'build'
                || document.querySelector('.environment-requirements, dialog')) return {state:'error'};
            controls.scrollIntoView({block:'center'}); if (!visible(platform) || !visible(operation)) return {state:'error'};
            const card = controls.closest('section.card');
            const b = [...card.querySelectorAll('.button-row button')].find(b => text(b) === 'Load draft requirements');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadRequirements => r#"
            if (!selected('Environment')) return {state:'error'};
            const list = document.querySelector('.environment-requirements'); if (!list) return {state:'wait'};
            const card = list.closest('section.card'); if (card.getAttribute('aria-busy') !== 'false') return {state:'wait'};
            const rows = [...list.querySelectorAll(':scope > article.tool-card')]; if (rows.length !== 3) return {state:'error'};
            const status = card.querySelector(':scope > .button-row');
            const roles = rows.map(row => {
                row.scrollIntoView({block:'center'}); if (!visible(row)) throw 0;
                const help = row.querySelector('.help-button'); if (!help || help.disabled) throw 0;
                return {label:text(row.querySelector('h3')), helpLabel:help.getAttribute('aria-label'),
                    help:[...row.querySelectorAll(':scope > p')].map(text), badges:[...row.querySelectorAll('.button-row .badge')].map(text),
                    baseline:[...row.querySelectorAll('.environment-baseline > *')].map(text)};
            });
            return {state:'ready', display:{heading:text(card.querySelector('h2')), badges:[...status.querySelectorAll('.badge')].map(text),
                host:text(status.querySelector('.save-note')), roles, limitations:[...card.querySelectorAll(':scope > ul.plain-list > li > span')].map(text)}};"#,
        Step::GitHub => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');
            if (!b || b.disabled) return {state:'error'}; b.click(); return {state:'ready'};"#,
        Step::ReadGitHubEmpty => r#"
            if (!selected('GitHub') || !document.querySelector('form.github-form')) return {state:'wait'};
            const g = githubInputs();
            if (document.querySelector('.github-proposal') || text(g.form.querySelector('.github-draft > strong')) !== 'positive-project · current draft'
                || text(g.button) !== 'Preview GitHub setup') return {state:'error'};
            g.form.scrollIntoView({block:'start'}); if (!visible(g.repository) || !visible(g.sha)) return {state:'error'};
            return {state:'ready', inputs:inputValues(g), branches:[...g.form.querySelectorAll('.github-draft .github-facts dd code')].map(text)};"#,
        Step::EnterRepository => r#"
            const g = githubInputs();
            if (g.repository.value !== '' || g.sha.value !== '' || g.comparison.checked || !g.button.disabled) return {state:'error'};
            const input = g.repository; input.scrollIntoView({block:'center'}); if (!visible(input)) return {state:'error'};
            input.focus(); input.select();
            if (document.activeElement !== input || input.selectionStart !== 0 || input.selectionEnd !== 0
                || !document.execCommand('insertText', false, 'example/toolkit')) return {state:'error'};
            return {state:'ready'};"#,
        Step::EnterSha => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== '' || g.comparison.checked || !g.button.disabled) return {state:'error'};
            const input = g.sha; input.scrollIntoView({block:'center'}); if (!visible(input)) return {state:'error'};
            input.focus(); input.select();
            if (document.activeElement !== input || input.selectionStart !== 0 || input.selectionEnd !== 0
                || !document.execCommand('insertText', false, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')) return {state:'error'};
            return {state:'ready'};"#,
        Step::ReadGitHubInputs => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' || g.comparison.checked) return {state:'error'};
            if (g.button.disabled) return {state:'wait'};
            return {state:'ready', inputs:inputValues(g)};"#,
        Step::ProposeGitHub => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' || g.comparison.checked
                || g.button.disabled || text(g.button) !== 'Preview GitHub setup' || document.querySelector('.github-proposal')) return {state:'error'};
            g.button.scrollIntoView({block:'center'}); if (!visible(g.button)) return {state:'error'};
            g.button.click(); return {state:'ready'};"#,
        Step::ReadProposal => r#"
            const g = githubInputs(); const proposal = document.querySelector('.github-proposal');
            if (!proposal || g.button.disabled) return {state:'wait'};
            proposal.scrollIntoView({block:'start'}); if (!visible(proposal)) return {state:'error'};
            const cards = [...proposal.children]; if (cards.length !== 3 || cards.some(card => !card.classList.contains('card'))) return {state:'error'};
            const facts = card => [...card.querySelectorAll('.github-facts > div')].map(row => [text(row.querySelector('dt')),text(row.querySelector('dd'))]);
            const local = document.querySelector('button[aria-describedby="github-workflow-start-reason"]');
            const remote = [...document.querySelectorAll('.github-disabled-actions button')];
            if (!local || remote.length !== 3) return {state:'error'};
            return {state:'ready', display:{heading:text(cards[0].querySelector('h2')), badge:text(cards[0].querySelector('.badge')),
                description:text(cards[0].querySelector('.section-heading p')), facts:facts(cards[0]), settings:facts(cards[2]),
                scope:[text(cards[0].querySelector('.github-scope-note')),text(cards[1].querySelector('.github-scope-note'))],
                workflowHeading:text(cards[1].querySelector('h2')), workflowDescription:text(cards[1].querySelector('.section-heading p')),
                settingsHeading:text(cards[2].querySelector('h2')), settingsDescription:text(cards[2].querySelector('.section-heading p')),
                localReviewAvailable:!local.disabled, remoteAvailable:remote.some(b => !b.disabled)}};"#,
        Step::OpenWorkflows => r#"
            if (!selected('GitHub')) return {state:'error'};
            const rows = [...document.querySelectorAll('.github-proposal details.github-workflow')];
            if (rows.length !== 4 || rows.some(row => row.open)) return {state:'error'};
            for (const row of rows) {
                const summary = row.querySelector(':scope > summary'); if (!summary) return {state:'error'};
                summary.scrollIntoView({block:'center'}); if (!visible(summary)) return {state:'error'}; summary.click();
            }
            return {state:'ready'};"#,
        Step::ReadWorkflows => r#"
            if (!selected('GitHub')) return {state:'error'};
            const rows = [...document.querySelectorAll('.github-proposal details.github-workflow')];
            if (rows.length !== 4) return {state:'error'}; if (rows.some(row => !row.open)) return {state:'wait'};
            return {state:'ready', workflows:rows.map(row => {
                const pre = row.querySelector('pre'); const path = text(row.querySelector('summary > code'));
                if (!pre || pre.getAttribute('aria-label') !== 'Read-only proposed content for ' + path) throw 0;
                pre.scrollIntoView({block:'start'}); if (!visible(pre)) throw 0;
                return {path, comparison:text(row.querySelector('summary > .badge')), metadata:text(row.querySelector('.github-workflow-meta')), content:text(pre.querySelector('code'))};
            })};"#,
        Step::PrepareSave | Step::PrepareNoop => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'error'};
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if (!b || b.disabled) return {state:'wait'};
            if (text(b) !== 'Prepare save review') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadSaveReview | Step::ReadKeptReview | Step::ReadNoopReview => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'wait'};
            const panel = document.querySelector('.native-save-panel'), review = panel?.querySelector('.save-review');
            const apply = panel?.querySelector('.save-actions button.primary');
            if (!review || !apply || apply.disabled) return {state:'wait'};
            if (!['Apply reviewed save','Review no-op confirmation'].includes(text(apply))) return {state:'error'};
            const paths = panel.querySelectorAll(':scope > .save-project-path code'); if (paths.length !== 1) return {state:'error'};
            paths[0].scrollIntoView({block:'center'}); if (!visible(paths[0])) return {state:'error'};
            return {state:'ready', projectPath:text(paths[0]), review:reviewDisplay(review), ...draftState()};"#,
        Step::OpenConfirmation | Step::ReopenConfirmation => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'error'};
            const panel = document.querySelector('.native-save-panel'), b = panel?.querySelector('.save-actions button.primary');
            if (!panel?.querySelector('.save-review') || !b || b.disabled || text(b) !== 'Apply reviewed save') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadConfirmation | Step::ReadReopenedConfirmation | Step::ReadAcknowledged => r#"
            const d = document.querySelector('dialog.save-confirm-dialog');
            if (!d || !d.open || !visible(d)) return {state:'wait'};
            return {state:'ready', confirmation:confirmationDisplay()};"#,
        Step::KeepReviewing => r#"
            const c = confirmationControls(); if (c.check.checked || !c.apply.disabled) return {state:'error'};
            c.keep.scrollIntoView({block:'center'}); if (!visible(c.keep)) return {state:'error'};
            c.keep.click(); return {state:'ready'};"#,
        Step::Acknowledge => r#"
            const c = confirmationControls(); if (c.check.checked || !c.apply.disabled) return {state:'error'};
            c.check.scrollIntoView({block:'center'}); if (!visible(c.check)) return {state:'error'};
            c.check.click(); return {state:'ready'};"#,
        Step::Apply => r#"
            const c = confirmationControls(); if (!c.check.checked || c.apply.disabled) return {state:'error'};
            c.apply.scrollIntoView({block:'center'}); if (!visible(c.apply)) return {state:'error'};
            c.apply.click(); return {state:'ready'};"#,
        Step::ReadSaved => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'wait'};
            const panel = document.querySelector('.native-save-panel'), facts = panel?.querySelector('.save-outcome-facts');
            if (!facts || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saved || !draft.saveAvailable) return {state:'wait'};
            facts.scrollIntoView({block:'center'}); if (!visible(facts)) return {state:'error'};
            const rows = [...facts.querySelectorAll(':scope > div')]; if (rows.length !== 4) return {state:'error'};
            return {state:'ready', source:sourceValue(), ...draft, title:text(panel.querySelector('h2')),
                banner:text(document.querySelector('.draft-banner strong')), staleSnapshot:staleSettings(),
                facts:rows.map(row => [text(row.querySelector('dt')),text(row.querySelector('dd'))])};"#,
        Step::Refresh => r#"
            if (!selected('Dashboard') || !document.querySelector('.observation-facts')) return {state:'wait'};
            if (text(document.querySelector('.project-badges .badge')) !== 'Earlier static observation') return {state:'error'};
            const b = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadReadback => r#"
            if (!selected('Dashboard')) return {state:'wait'};
            const facts = document.querySelector('.observation-facts');
            const refresh = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            const identity = document.querySelector('.identity-strip .identity-detail strong');
            if (!facts || !refresh || refresh.disabled || !identity) return {state:'wait'};
            identity.scrollIntoView({block:'center'}); if (!visible(identity)) return {state:'error'};
            return {state:'ready', configuration:text(document.querySelector('.project-badges .badge')),
                sourceFiles:text(facts.querySelector('strong')), name:text(document.querySelector('.project-identity h2')),
                applicationId:text(identity), staleSnapshot:[...document.querySelectorAll('.notice-info strong')].some(e => text(e) === 'This static observation predates the last settled save check')};"#,
        Step::ReadSavedDraft => r#"
            if (!selected('Project settings') || !field() || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saved || !draft.saveAvailable) return {state:'wait'};
            return {state:'ready', source:sourceValue(), ...draft, staleSnapshot:staleSettings()};"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .native-save-panel .notice-danger')) return {{state:'error'}};
        const text = e => {{ if (!e) throw 0; const t=e.textContent; if (typeof t!=='string' || t.length>4096) throw 0; return t; }};
        const visible = e => {{ const r=e.getBoundingClientRect(), s=getComputedStyle(e); return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible'; }};
        const selected = label => [...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b => b.getAttribute('aria-label')===label);
        const githubInputs = () => {{
            const forms=document.querySelectorAll('form.github-form');
            if (!selected('GitHub') || forms.length!==1 || document.querySelector('dialog, .github-assertions')) throw 0;
            const form=forms[0], repositories=form.querySelectorAll('input#github-toolkit-repository'), shas=form.querySelectorAll('input#github-toolkit-sha');
            const comparison=form.querySelector('.github-comparison-toggle input[type="checkbox"]'), button=form.querySelector('.github-propose-action button[type="submit"]');
            if (repositories.length!==1 || shas.length!==1 || !comparison || !button) throw 0;
            const repository=repositories[0], sha=shas[0];
            if ([repository,sha].some(input => input.type!=='text' || input.disabled || input.readOnly) || repository.value.length>140 || sha.value.length>40) throw 0;
            return {{form,repository,sha,comparison,button}};
        }};
        const inputValues = g => ({{repository:g.repository.value,sha:g.sha.value,comparison:g.comparison.checked,previewAvailable:!g.button.disabled}});
        const field = () => [...document.querySelectorAll('.form-field')].find(f => f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: Committed version file');
        const sourceValue = () => {{
            const f=field(); if (!f || document.querySelector('.suggestion-card') || text(f.querySelector('.field-presence'))!=='Set') throw 0;
            f.scrollIntoView({{block:'center'}}); const input=f.querySelector('input');
            if (!visible(f) || !input || input.value.length>512) throw 0; return input.value;
        }};
        const draftState = () => {{
            const banner=document.querySelector('.draft-banner'), save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if (!banner || !save || !selected('Project settings') || document.querySelector('dialog')) throw 0;
            const badge=text(banner.querySelector('.badge'));
            return {{unsaved:badge==='Unsaved changes', saved:badge==='Settled submitted revision'
                && text(banner.querySelector('strong'))==='The submitted revision was saved'
                && text(document.querySelector('.draft-toolbar-status .badge'))==='Saved revision · not verified', saveAvailable:!save.disabled}};
        }};
        const staleSettings = () => [...document.querySelectorAll('.context-refresh-note')].some(e => text(e).startsWith('The latest static observation predates the last settled native save check.'));
        const inventory = root => {{
            const tables=root.querySelectorAll('.save-files table'); if (tables.length!==1) throw 0;
            const table=tables[0]; if (text(table.querySelector('caption'))!=='Exact native destination inventory') throw 0;
            table.scrollIntoView({{block:'center'}}); if (!visible(table)) throw 0;
            const rows=[...table.querySelectorAll('tbody > tr')]; if (rows.length!==2) throw 0;
            const actions={{'Create':'create','Replace document':'replace','Append fixed rules':'append','Preserve original':'preserve'}};
            const bytes=(value, absent) => {{ if (absent && value==='Observed absent') return null;
                const match=/^([0-9]{{1,7}}) bytes$/.exec(value); if (!match) throw 0; return Number(match[1]); }};
            return rows.map(row => {{ const cells=[...row.querySelectorAll(':scope > td')]; if (cells.length!==3) throw 0;
                const action=actions[text(cells[0])]; if (!action) throw 0;
                return {{path:text(row.querySelector(':scope > th code')),action,beforeBytes:bytes(text(cells[1]),true),afterBytes:bytes(text(cells[2]),false)}};
            }});
        }};
        const reviewDisplay = review => {{
            const files=inventory(review), ignore=[...review.querySelectorAll('.save-ignore li code')]; if (ignore.length>7) throw 0;
            for (const line of ignore) {{ line.scrollIntoView({{block:'center'}}); if (!visible(line)) throw 0; }}
            const counts=[...review.querySelectorAll('.review-counts > span > strong')].map(e => {{ const t=text(e); if (!/^[0-9]{{1,2}}$/.test(t)) throw 0; return Number(t); }});
            if (counts.length!==3) throw 0;
            return {{files,release:[...review.querySelectorAll(':scope > .save-note code')].some(e => text(e)==='release'),
                rewrite:!!review.querySelector(':scope > .notice-warning'),ignore:ignore.map(text),counts:{{added:counts[0],changed:counts[1],removed:counts[2]}},
                basis:text(review.querySelector('.review-basis strong')),badge:text(review.querySelector('.review-counts .badge'))}};
        }};
        const confirmationControls = () => {{
            const dialogs=document.querySelectorAll('dialog'); if (!selected('Project settings') || dialogs.length!==1) throw 0;
            const dialog=dialogs[0]; if (!dialog.classList.contains('save-confirm-dialog') || !dialog.open || !visible(dialog) || dialog.querySelector('[role="alert"]')) throw 0;
            const choices=dialog.querySelectorAll('.save-confirm-choice input[type="checkbox"]'), buttons=[...dialog.querySelectorAll('.button-row > button')];
            if (choices.length!==1 || choices[0].disabled || buttons.length!==2 || buttons[0].disabled
                || text(buttons[0])!=='Keep reviewing' || text(buttons[1])!=='Apply reviewed save'
                || text(dialog.querySelector('.save-confirm-choice'))!=='I reviewed this exact inventory and understand that cancellation may be too late after Apply.') throw 0;
            return {{dialog,check:choices[0],keep:buttons[0],apply:buttons[1]}};
        }};
        const confirmationDisplay = () => {{
            const c=confirmationControls(), paragraphs=[...c.dialog.querySelectorAll('.dialog-content > p')];
            const revision=/^This confirms submitted draft revision ([0-9]{{1,10}}), not any later edits\. /.exec(text(paragraphs[0]));
            const paths=c.dialog.querySelectorAll('.save-project-path code'); if (!revision || paths.length!==1) throw 0;
            return {{title:text(c.dialog.querySelector('h2')),projectPath:text(paths[0]),draftRevision:Number(revision[1]),files:inventory(c.dialog),
                release:paragraphs.some(p => text(p)==='The missing release directory is included.'),rewrite:!!c.dialog.querySelector('.review-caution'),
                checked:c.check.checked,applyAvailable:!c.apply.disabled}};
        }};
        {body}
    }} catch {{ return {{state:'error'}}; }} }})()"#))
}

fn route() -> bool {
    let Some(source) = option_env!("GITHUB_SHA") else { return false; };
    source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && [("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("MRK_DESKTOP_HOSTED_CHECKS", "installed-shell-connection-v1"), ("GITHUB_SHA", source)]
            .iter().all(|(key, value)| std::env::var(key).ok().as_deref() == Some(*value))
        && rustix::process::getuid().as_raw() != 0 && rustix::process::getuid() == rustix::process::geteuid()
}
pub(crate) fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let case = match args.next().as_deref() {
        Some(value) if value == OsStr::new("positive") => Some(Case::Positive),
        Some(value) if value == OsStr::new("quit-outstanding") => Some(Case::Outstanding),
        _ => None,
    };
    let Some(case) = case.filter(|_| args.next().is_none() && route()) else {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=route-refused\n");
        return std::process::ExitCode::FAILURE;
    };
    let q = Arc::new(Observation::new(case));
    // This target has no libtest harness. Execute the existing pure contracts
    // and positive configuration-domain contracts before GTK; a failed
    // assertion cannot reach the success report.
    crate::bridge::assert_native_capability_intersection_contract();
    crate::runtime::assert_packaged_shell_allowlist_contract();
    if case == Case::Positive {
        crate::asset_session::assert_project_selection_gate_contract();
        crate::runtime::assert_installed_configuration_profile_contract();
        crate::installed_runtime::assert_installed_configuration_slots_contract();
        crate::edit_owner::assert_installed_configuration_owner_contract();
    }
    // Routing DATA is not native admission. The ordinary builder constructs
    // DesktopBridge::new / RuntimeConfig::packaged and owes every real check.
    let returned = super::run_builder(super::builder().manage(q.clone()));
    if !matches!(returned, Ok(0)) || !q.finish() {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n");
        return std::process::ExitCode::FAILURE;
    }
    let line: &[u8] = match case {
        Case::Positive => b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n",
        Case::Outstanding => b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n",
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n")
        .and_then(|_| {
            if case != Case::Positive { return Ok(()); }
            let report = q.positive_report().ok_or_else(|| std::io::Error::other("positive receipt unavailable"))?;
            stdout.write_all(b"MRK_INSTALLED_SHELL_PROJECT_DRAFT=")?;
            stdout.write_all(&report)?; stdout.write_all(b"\n")
        })
        .and_then(|_| stdout.write_all(line)).is_ok() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
}
