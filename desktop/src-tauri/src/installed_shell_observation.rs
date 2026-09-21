//! Two bounded observations of the NORMAL builder/bridge/packaged selector.
//! No alternate runtime, document, IPC command, timer, task or shutdown owner.
//! Only the existing relay drives these steps; failures cannot authorize exit.
use std::{ffi::OsStr, io::Write, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Manager;
use crate::{bridge::{AppInfo, Project}, error::BridgeError, supervisor::{HeldAppInfo, Supervisor}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Positive, Outstanding }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Bootstrap, Environment, ReadEnvironment, Dashboard, ChooseCancel, Cancel, Cancelled, ReadCancelled,
    ChooseSelect, SetProject, SelectProject, Selected, ReadSnapshot, Settings, Suggest, ReadSuggestion,
    Adopt, ReadDraft, OpenHelp, ReadHelp, CloseHelp, HelpGone,
    GuidanceEnvironment, LoadRequirements, ReadRequirements, GitHub, ReadGitHubEmpty, EnterRepository, EnterSha,
    ReadGitHubInputs, ProposeGitHub, ReadProposal, OpenWorkflows, ReadWorkflows, GuidanceSettings, ReadRetainedDraft,
    Unset, ReadUnset, Validate, ReadValidation,
    Review, ReadReview, Close, Quit, Exit,
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
    value.get("assurance").is_some_and(|a| a.get("basis").and_then(Value::as_str) == Some(basis)
        && a.get("releaseReadiness").and_then(Value::as_str) == Some("unknown")
        && ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"]
            .iter().all(|key| a.get(*key).and_then(Value::as_bool) == Some(false)))
}
fn invalid(value: &Value) -> bool {
    value.get("valid").and_then(Value::as_bool) == Some(false) && value.get("state").and_then(Value::as_str) == Some("invalid")
        && value.get("issues").and_then(Value::as_array).is_some_and(|issues| issues.len() == 1
            && issues[0].get("code").and_then(Value::as_str) == Some("config.invalid"))
        && assurance(value, "schema-policy")
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
fn after_unset(suggested: &Value, actual: &Value) -> bool {
    let (Some(before), Some(after)) = (suggested.as_object(), actual.as_object()) else { return false; };
    before.len() == after.len() && before.iter().all(|(key, value)| {
        if key != "version" { return after.get(key) == Some(value); }
        let (Some(before), Some(after)) = (value.as_object(), after.get(key).and_then(Value::as_object)) else { return false; };
        before.contains_key("source") && !after.contains_key("source") && before.len() == after.len() + 1
            && after.iter().all(|(key, value)| before.get(key) == Some(value))
    })
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

struct Record {
    attached: bool, started: bool, loaded: bool,
    info: bool, methods: usize, sample: Option<HelpSample>,
    environment: bool, help: bool, help_gone: bool,
    pickers: [Picker; 2], cancel_returned: bool, cancelled: bool, project: Option<Project>, selected: bool,
    snapshot: bool, snapshot_visible: bool, suggest_called: bool, suggested: Option<Value>, provenance: Option<Value>,
    provenance_visible: bool, adopted: bool, draft_visible: bool, unset: bool,
    validate_called: bool, validated: bool, validation_visible: bool, review_called: bool, reviewed: bool, review_visible: bool,
    guidance: Guidance, originals_final: bool,
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
                attached: false, started: false, loaded: false, info: false, methods: 0, sample: None,
                environment: false, help: false, help_gone: false, step: Step::Bootstrap, pending: None, evaluations: 0,
                pickers: std::array::from_fn(|_| Picker::default()), cancel_returned: false, cancelled: false, project: None, selected: false,
                snapshot: false, snapshot_visible: false, suggest_called: false, suggested: None, provenance: None,
                provenance_visible: false, adopted: false, draft_visible: false, unset: false,
                validate_called: false, validated: false, validation_visible: false, review_called: false, reviewed: false, review_visible: false,
                guidance: Guidance::default(), originals_final: false,
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
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        // Eight bounded public help fields only, captured from the real reply.
        // The frontend still parses/adopts that reply itself, with no injection.
        let sample = result.as_ref().ok().and_then(|v| v.get("fields")).and_then(Value::as_array)
            .filter(|fields| fields.len() <= 64).and_then(|fields| {
                let mut matches = fields.iter().filter(|field| field.get("path").and_then(Value::as_str) == Some(FIELD));
                let field = matches.next()?;
                if matches.next().is_some() || field.get("requiredness").and_then(Value::as_str) != Some("required") { return None; }
                HelpSample::read(field)
            });
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.info || r.sample.is_some() || sample.is_none() { self.fail(); return; }
        r.sample = sample;
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
    pub(super) fn snapshot(&self, project_id: &str, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let valid = result.as_ref().is_ok_and(|value| {
            let config = &value["config"]; let discovery = &value["discovery"]; let scan = &discovery["scan"];
            r.project.as_ref().is_some_and(|project| project.id == project_id && value["root"].as_str() == Some(project.path.as_str()))
                && value["observationScope"].as_str() == Some("single-request-non-atomic")
                && config["path"].as_str() == Some("release/mobile-release.json") && config["state"].as_str() == Some("missing")
                && config.get("data") == Some(&Value::Null) && config.get("content") == Some(&Value::Null)
                && config["issues"].as_array().is_some_and(|issues| issues.len() == 1 && issues[0]["code"].as_str() == Some("config.missing"))
                && discovery["state"].as_str() == Some("unverified") && discovery["partial"].as_bool() == Some(false)
                && discovery["hints"].as_object().is_some_and(|hints| hints.len() == 1)
                && discovery["hints"]["android"]["applicationId"].as_str() == Some(APP_ID)
                && discovery["hints"]["android"]["module"].as_str() == Some(":app")
                && discovery["hints"]["android"]["buildFile"].as_str() == Some("app/build.gradle.kts")
                && scan["sourceFiles"].as_u64() == Some(1) && scan["sourceBytes"].as_u64() == Some(PROJECT_SOURCE.len() as u64)
                && scan["entries"].as_u64() == Some(2) && scan["excludedEntries"].as_u64() == Some(0)
                && value["issues"].as_array().is_some_and(Vec::is_empty) && assurance(value, "static-text")
        });
        if self.case != Case::Positive || !matches!(r.step, Step::Selected | Step::ReadSnapshot) || r.snapshot || !valid { self.fail(); return; }
        r.snapshot = true;
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
        if self.case != Case::Positive || !r.help_gone || !r.adopted || !r.draft_visible || r.guidance.requirements_called
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements)
            || !keys(body, &["draft", "platform", "operation"]) || body["platform"].as_str() != Some("android")
            || body["operation"].as_str() != Some("build")
            || !r.suggested.as_ref().is_some_and(|draft| body.get("draft") == Some(draft)) { self.fail(); return; }
        r.guidance.requirements_called = true;
    }
    pub(super) fn requirements(&self, result: &Result<crate::environment::Requirements, BridgeError>) {
        let sample = result.as_ref().ok().and_then(requirements_display);
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.guidance.requirements_called || r.guidance.requirements.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements) { self.fail(); return; }
        r.guidance.requirements = sample;
    }
    pub(super) fn github_request(&self, body: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.guidance.requirements_visible || !r.guidance.github_empty
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
        if self.case != Case::Positive || !r.guidance.github_called || r.guidance.proposal.is_some() || sample.is_none()
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal) { self.fail(); return; }
        r.guidance.proposal = sample;
    }
    pub(super) fn validate_request(&self, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.unset || !r.guidance.complete() || r.validate_called || !matches!(r.step, Step::Validate | Step::ReadValidation)
            || !r.suggested.as_ref().is_some_and(|suggested| after_unset(suggested, draft)) { self.fail(); return; }
        r.validate_called = true;
    }
    pub(super) fn validation(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        if !r.validate_called || r.validated || !matches!(r.step, Step::Validate | Step::ReadValidation)
            || !result.as_ref().is_ok_and(|value| invalid(value)) { self.fail(); return; }
        // Do not capture or label the possibly reflective ConfigurationError
        // message as redacted. This observation retains only typed state/code.
        r.validated = true;
    }
    pub(super) fn review_request(&self, base: &Value, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.validation_visible || r.review_called || !matches!(r.step, Step::Review | Step::ReadReview)
            || !base.is_null() || !r.suggested.as_ref().is_some_and(|suggested| after_unset(suggested, draft)) { self.fail(); return; }
        r.review_called = true;
    }
    pub(super) fn review(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let valid = result.as_ref().is_ok_and(|value| value["schemaVersion"].as_u64() == Some(1) && invalid(&value["validation"])
            && assurance(value, "schema-policy") && value["comparison"]["baseProvided"].as_bool() == Some(false)
            && value["comparison"]["kind"].as_str() == Some("proposed-create") && value["comparison"]["state"].as_str() == Some("complete")
            && value["fields"].as_array().is_some_and(|fields| !fields.is_empty() && fields.len() <= 64
                && fields.iter().filter(|field| field["path"].as_str() == Some(FIELD)).count() == 1
                && fields.iter().any(|field| field["path"].as_str() == Some(FIELD) && field["state"].as_str() == Some("required")
                    && field["present"].as_bool() == Some(false))));
        if !r.review_called || r.reviewed || !matches!(r.step, Step::Review | Step::ReadReview) || !valid { self.fail(); return; }
        r.reviewed = true;
    }
    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.failed.load(Ordering::SeqCst) { return; }
        if Instant::now() >= self.end || std::thread::current().id() == self.main { self.fail(); return; }
        let step = {
            let Some(mut r) = self.record() else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.step == Step::Bootstrap && self.case == Case::Positive {
                if !r.info || r.sample.is_none() { return; }
                r.step = Step::Environment;
            }
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
                Step::Close => { r.step = Step::Quit; Pending::Close },
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
        let valid = match step {
            Step::ReadEnvironment => {
                let versions = value.get("versions").and_then(Value::as_array);
                let available = value.get("available").and_then(Value::as_array);
                object.len() == 7 && value.get("title").and_then(Value::as_str) == Some("Bundled runtime")
                    && value.get("badge").and_then(Value::as_str) == Some("available")
                    && value.get("rows").and_then(Value::as_u64) == Some(r.methods as u64)
                    && value.get("unavailable").and_then(Value::as_u64) == Some((r.methods - METHODS.len()) as u64)
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
            Step::ReadDraft | Step::ReadRetainedDraft => object.len() == 4 && r.adopted
                && (step != Step::ReadRetainedDraft || r.guidance.workflows_visible)
                && r.suggested.as_ref().is_some_and(|suggested|
                value["source"].as_str() == suggested["version"]["source"].as_str())
                && value["unsaved"].as_bool() == Some(true) && value["saveAvailable"].as_bool() == Some(false),
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
            Step::ReadUnset => object.len() == 4 && r.draft_visible && r.help && r.help_gone && r.guidance.complete()
                && value["unset"].as_bool() == Some(true) && value["unsaved"].as_bool() == Some(true) && value["saveAvailable"].as_bool() == Some(false),
            Step::ReadValidation => object.len() == 4 && r.validated && value["invalid"].as_bool() == Some(true)
                && value["unsaved"].as_bool() == Some(true) && value["saveAvailable"].as_bool() == Some(false),
            Step::ReadReview => object.len() == 7 && r.reviewed && value["required"].as_bool() == Some(true)
                && value["present"].as_bool() == Some(false) && value["redacted"].as_bool() == Some(true)
                && value["validation"].as_str() == Some("invalid")
                && value["unsaved"].as_bool() == Some(true) && value["saveAvailable"].as_bool() == Some(false),
            Step::OpenHelp => object.len() == 3 && r.sample.as_ref().is_some_and(|sample|
                value.get("label").and_then(Value::as_str) == Some(sample.values[0].as_str())
                    && value.get("ariaLabel").and_then(Value::as_str).is_some_and(|label| label.strip_prefix("Help: ") == Some(sample.values[0].as_str()))),
            Step::ReadHelp => object.len() == 2 && value.get("help").and_then(Value::as_object).is_some_and(|h| h.len() == 8)
                && value.get("help").and_then(HelpSample::read).as_ref().is_some_and(|actual| r.sample.as_ref() == Some(actual)),
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
            Step::ReadDraft => { r.draft_visible = true; Step::OpenHelp },
            Step::OpenHelp => Step::ReadHelp,
            Step::ReadHelp => { r.help = true; Step::CloseHelp },
            Step::CloseHelp => Step::HelpGone,
            Step::HelpGone => { r.help_gone = true; Step::GuidanceEnvironment },
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
            Step::ReadRetainedDraft => { r.guidance.draft_retained = true; Step::Unset },
            Step::Unset => Step::ReadUnset,
            Step::ReadUnset => { r.unset = true; Step::Validate },
            Step::Validate => Step::ReadValidation,
            Step::ReadValidation => { r.validation_visible = true; Step::Review },
            Step::Review => Step::ReadReview,
            Step::ReadReview => { r.review_visible = true; Step::Close },
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
    pub(super) fn actual_exit(&self, ready: bool, document: &crate::asset_session::DocumentBinding) {
        let originals_final = self.case == Case::Outstanding || document.installed_observation_final();
        let Some(mut r) = self.record() else { return; };
        if !ready || !originals_final || !r.relay_joined || !r.released || r.exit { self.fail(); return; }
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
            && (self.case == Case::Outstanding || r.info && r.sample.is_some() && r.environment && r.help && r.help_gone
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.suggested.is_some() && r.provenance_visible && r.adopted && r.draft_visible
                && r.guidance.complete()
                && r.unset && r.validated && r.validation_visible && r.reviewed && r.review_visible && r.originals_final)
    }
    fn positive_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::Positive || !r.exit || !r.originals_final { return None; }
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,"fixture":"android-static-v1","projectGateContract":true,"methods":"eight-passive","mutationActions":false,
            "cancel":{"operation":1,"widget":"cancel","guiSettled":r.pickers[0].settled(false),"originalsSettled":r.cancelled,"registered":false},
            "select":{"operation":2,"widget":"select","filenameRead":r.pickers[1].filename,"guiSettled":r.pickers[1].settled(true),"originalsSettled":r.selected,"registered":r.project.is_some()},
            "snapshot":{"config":"missing","androidHint":r.snapshot,"sourceFiles":1},
            "suggestion":{"coreProvenance":r.provenance_visible,"explicitAdoption":r.adopted},
            "field":{"path":FIELD,"catalogHelp":r.help && r.help_gone,"explicitUnset":r.unset},
            "validation":{"valid":false,"issue":"config.invalid"},"review":{"kind":"redacted","required":r.review_visible,"present":false},
            "draft":{"unsaved":r.draft_visible && r.review_visible,"saveAvailable":false},
            "guidance":{"draftFormatValid":r.suggested.is_some(),"draftUnchanged":r.guidance.draft_retained && r.validate_called && r.review_called,
                "requirements":{"requestMatched":r.guidance.requirements_called,"resultMatched":r.guidance.requirements.is_some(),
                    "domMatched":r.guidance.requirements_visible,"context":"android/build","roles":3,"presence":"unknown","version":"unknown",
                    "inspection":"not-run","nativeInspection":"unavailable","dependencies":"unknown"},
                "github":{"requestMatched":r.guidance.github_called,"resultMatched":r.guidance.proposal.is_some(),
                    "domMatched":r.guidance.proposal_visible && r.guidance.workflows_visible,
                    "explicitInputs":r.guidance.github_empty && r.guidance.repository_entered && r.guidance.sha_entered && r.guidance.inputs_visible,
                    "browserEdit":"insertText","comparison":"not-supplied","snapshotProvided":false,"workflowCount":4,
                    "workflowContentMatched":r.guidance.workflows_visible,"resourceMatched":r.guidance.proposal.is_some(),"tooling":"format-only",
                    "githubContacted":false,"repositoryObserved":false,"toolingRefResolved":false,"templateCompatibility":"unknown","applyAvailable":false},
                "assuranceActions":false,"releaseReadiness":"unknown"},
            "quit":{"operation":3,"originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit}
        })).ok().filter(|raw| raw.len() <= 2048)
    }
}

// Fixed synchronous DOM expressions. Click only existing UI controls, wait for
// later React/effect rendering, and return actual bounded text for comparison.
// No injected data, invoke, artificial event emission, async Promise or reply.
// The two fixed text edits use the browser's own editing operation, once each.
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
        Step::Dashboard => r#"
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
            if (!selected('Dashboard') || !b || b.disabled) return {state:'wait'};
            return {state:'ready', unselected:text(document.querySelector('.project-identity h2')) === 'Your next release, organized.'
                && !document.querySelector('.observation-facts, .draft-banner'), chooseEnabled:!b.disabled};"#,
        Step::ReadSnapshot => r#"
            const facts = document.querySelector('.observation-facts');
            const refresh = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            if (!selected('Dashboard') || !facts || !refresh || refresh.disabled) return {state:'wait'};
            facts.scrollIntoView({block:'center'}); if (!visible(facts)) return {state:'error'};
            return {state:'ready', configuration:text(document.querySelector('.project-badges .badge')),
                sourceFiles:text(facts.querySelector('strong')), name:text(document.querySelector('.project-identity h2'))};"#,
        Step::Settings | Step::GuidanceSettings => r#"
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
            const f = field(); if (!f) return {state:'wait'};
            if (document.querySelector('.suggestion-card') || text(f.querySelector('.field-presence')) !== 'Set') return {state:'error'};
            f.scrollIntoView({block:'center'}); if (!visible(f)) return {state:'error'};
            const input = f.querySelector('input'); if (!input || input.value.length > 512) return {state:'error'};
            return {state:'ready', source:input.value, ...draftState()};"#,
        Step::OpenHelp => r#"
            const f = field();
            if (!selected('Project settings') || !f) return {state:'wait'};
            const b = f.querySelector('.help-button');
            if (!b || b.disabled || document.querySelector('dialog')) return {state:'error'};
            b.scrollIntoView({block:'center'});
            if (!visible(b)) return {state:'error'};
            const label = text(f.querySelector('.field-label-row label')); const ariaLabel = b.getAttribute('aria-label');
            if (typeof ariaLabel !== 'string' || ariaLabel.length > 4110) return {state:'error'};
            b.click(); return {state:'ready', label, ariaLabel};"#,
        Step::ReadHelp => r#"
            const dialogs = document.querySelectorAll('dialog.help-dialog');
            if (dialogs.length === 0) return {state:'wait'};
            if (dialogs.length !== 1) return {state:'error'};
            const d = dialogs[0]; if (!d.open || !visible(d)) return {state:'wait'};
            const values = [...d.querySelectorAll('.help-definitions dd')].map(text);
            if (values.length !== 6) return {state:'error'};
            return {state:'ready', help:{label:text(d.querySelector('h2')), requiredness:text(d.querySelector('.badge')),
                what:values[0], why:values[1], where:values[2], format:values[3], requiredWhen:values[4], failure:values[5]}};"#,
        Step::CloseHelp => r#"
            const d = document.querySelector('dialog.help-dialog[open]');
            const b = d && d.querySelector('button[aria-label="Close help"]');
            if (!b || b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::HelpGone => r#"
            return {state:document.querySelector('dialog.help-dialog') ? 'wait' : 'ready'};"#,
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
        Step::Unset => r#"
            const f = field(); const b = f && f.querySelector('.clear-field');
            if (!b || b.disabled || text(b) !== 'Unset' || document.querySelector('dialog')) return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadUnset => r#"
            const f = field(); if (!f) return {state:'error'};
            if (f.querySelector('.clear-field')) return {state:'wait'};
            return {state:'ready', unset:text(f.querySelector('.field-presence')) === 'Not set' && f.querySelector('input')?.value === '', ...draftState()};"#,
        Step::Validate => r#"
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-validation-reason"]');
            if (!b || b.disabled || text(b) !== 'Validate only') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadValidation => r#"
            const card = document.querySelector('.validation-card');
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-validation-reason"]');
            if (!card || !b || b.disabled) return {state:'wait'};
            card.scrollIntoView({block:'center'}); if (!visible(card)) return {state:'error'};
            return {state:'ready', invalid:text(card.querySelector('h2')) === 'Review these configuration issues'
                && text(card.querySelector('.badge')) === 'Needs correction', ...draftState()};"#,
        Step::Review => r#"
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-review-reason"]');
            if (!b || b.disabled || text(b) !== 'Review draft changes') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadReview => r#"
            const card = document.querySelector('.draft-review'); const f = field();
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-review-reason"]');
            if (!card || !f || !b || b.disabled) return {state:'wait'};
            card.scrollIntoView({block:'start'}); if (!visible(card)) return {state:'error'};
            const headings = [...card.querySelectorAll('h3')].map(text);
            return {state:'ready', required:text(f.querySelector('.requiredness')) === 'required',
                present:text(f.querySelector('.field-presence')) !== 'Not set',
                redacted:text(card.querySelector('h2')) === 'Review the draft, not the filesystem.'
                    && text(card.querySelector('.review-table caption')) === 'Known configuration changes. Raw values are omitted.',
                validation:headings.includes('Format validation needs attention') ? 'invalid' : 'error', ...draftState()};"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger')) return {{state:'error'}};
        const text = e => {{ if (!e) throw 0; const t = e.textContent; if (typeof t !== 'string' || t.length > 4096) throw 0; return t; }};
        const visible = e => {{ const r=e.getBoundingClientRect(); const s=getComputedStyle(e); return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible'; }};
        const selected = label => [...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b => b.getAttribute('aria-label') === label);
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
        const field = () => [...document.querySelectorAll('.form-field')].find(f => f.querySelector('.help-button')?.getAttribute('aria-label') === 'Help: Committed version file');
        const draftState = () => {{
            const banner=document.querySelector('.draft-banner'); const save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if (!banner || !save || !selected('Project settings') || document.querySelector('dialog')) throw 0;
            return {{unsaved:text(banner.querySelector('.badge')) === 'Unsaved changes', saveAvailable:!save.disabled}};
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
    // This target has no libtest harness. Execute the same two pure contracts
    // here, before GTK; an assertion failure cannot reach the success report.
    crate::bridge::assert_native_capability_intersection_contract();
    crate::runtime::assert_packaged_shell_allowlist_contract();
    if case == Case::Positive { crate::asset_session::assert_project_selection_gate_contract(); }
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
