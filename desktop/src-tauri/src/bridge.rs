//! Fixed application services. Project roots enter the registry only through
//! the Rust-side native picker, never through a renderer-supplied path.
use std::{collections::BTreeMap, path::PathBuf, sync::{Mutex, atomic::{AtomicU32, Ordering}}};
#[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
use std::sync::atomic::AtomicU64;
#[cfg(all(feature = "desktop-shell", not(target_os = "linux")))]
use std::path::Component;
use serde::Serialize;
use serde_json::{json, Value};
use crate::{edit_owner::EditOwner, edit_protocol::ConfigEditStatus, error::BridgeError, protocol::Method, runtime::{RuntimeConfig, RuntimeStatus}, supervisor::Supervisor};

#[derive(Clone, Debug, Serialize)]
pub struct Project { pub id: String, pub name: String, pub path: String }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub app_name: &'static str, pub app_version: &'static str,
    pub runtime: RuntimeStatus, pub capabilities: Option<Value>,
}

struct RegisteredProject { view: Project, root: PathBuf, identity: Option<crate::asset_source::DirectoryIdentity> }
pub(crate) struct ProjectRoster { pub(crate) generation: u32, pub(crate) roots: Vec<crate::asset_source::RegisteredRoot> }

pub struct DesktopBridge {
    pub supervisor: Supervisor,
    pub edits: EditOwner,
    projects: Mutex<BTreeMap<String, RegisteredProject>>,
    project_generation: AtomicU32,
    #[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    sequence: AtomicU64,
}
impl DesktopBridge {
    pub fn new(resource_dir: PathBuf) -> Self {
        let runtime = RuntimeConfig::packaged(resource_dir);
        Self {
            supervisor: Supervisor::new(runtime.clone()), edits: EditOwner::new(runtime), projects: Mutex::new(BTreeMap::new()), project_generation: AtomicU32::new(1),
            #[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
            sequence: AtomicU64::new(1),
        }
    }
    pub async fn app_info(&self) -> AppInfo {
        let result = self.supervisor.query(Method::Capabilities, json!({})).await;
        let (runtime, capabilities) = match result {
            Ok(value) => (RuntimeStatus { state: "available", reason: None, mode: self.supervisor.runtime_mode() }, Some(value)),
            Err(error) => (RuntimeStatus {
                state: if self.supervisor.disabled() { "disabled" } else { "unavailable" },
                reason: Some(error.message), mode: self.supervisor.runtime_mode(),
            }, None),
        };
        AppInfo { app_name: "Mobile Release Kit", app_version: env!("CARGO_PKG_VERSION"), runtime, capabilities }
    }
    pub async fn catalog(&self) -> Result<Value, BridgeError> { self.supervisor.query(Method::Catalog, json!({})).await }
    pub(crate) async fn environment_requirements(&self, input: crate::environment::Request) -> Result<crate::environment::Requirements, BridgeError> {
        // Current draft DATA only; no selected path, tool or execution owner.
        let context = input.context();
        let value = self.supervisor.query(Method::EnvironmentRequirements, input.into_params()?).await
            .map_err(crate::environment::public_error)?;
        crate::environment::result(value, context)
    }
    pub async fn validate_config(&self, draft: Value) -> Result<Value, BridgeError> {
        if !draft.is_object() { return Err(BridgeError::invalid()); }
        self.supervisor.query(Method::ValidateConfig, json!({"draft": draft})).await
    }
    pub async fn suggest_config(&self, hints: Value) -> Result<Value, BridgeError> {
        if !hints.is_object() { return Err(BridgeError::invalid()); }
        self.supervisor.query(Method::SuggestConfig, json!({"hints": hints})).await
    }
    pub async fn preview_config(&self, base: Value, draft: Value) -> Result<Value, BridgeError> {
        // Both documents are caller-owned draft data, never a disk revision or
        // permission to write. Only the core derives policy and change summaries.
        if !(base.is_null() || base.is_object()) || !draft.is_object() { return Err(BridgeError::invalid()); }
        self.supervisor.query(Method::PreviewConfig, json!({"base": base, "draft": draft})).await
    }
    pub(crate) async fn propose_github_setup(&self, input: crate::github_commands::Proposal) -> Result<Value, BridgeError> {
        // A passive proposal has no selected-root, login, write or dispatch
        // authority. Only the core renders its fixed shipped workflow set.
        self.supervisor.query(Method::ProposeGithubSetup, input.into_params()?).await
    }
    pub async fn project_snapshot(&self, project_id: String) -> Result<Value, BridgeError> {
        let root = self.project_root(&project_id)?;
        self.supervisor.query(Method::ProjectSnapshot, json!({"root": root})).await
    }
    pub(crate) async fn observe_metadata_text(&self, input: crate::metadata_text_commands::Open) -> Result<crate::metadata_text_edit_protocol::Observation, BridgeError> {
        // Only the native-selected root reaches this bounded named-file query.
        // No checkout/write authority is created by a passive observation.
        let root = self.project_root(&input.project_id)?;
        let value = self.supervisor.query(Method::MetadataTextObserve, json!({"root":root,"platform":input.platform,"locale":&input.locale})).await?;
        crate::metadata_text_edit_protocol::observation_result(value, input.platform, &input.locale)
    }
    pub(crate) async fn validate_metadata_text(&self, input: crate::metadata_text_commands::Validate) -> Result<crate::metadata_text_edit_protocol::ValidationResult, BridgeError> {
        let value = self.supervisor.query(Method::MetadataTextValidate, json!({"platform":input.platform,"fields":&input.fields})).await?;
        crate::metadata_text_edit_protocol::validation_result(value, input.platform, &input.fields)
    }
    fn project_root(&self, project_id: &str) -> Result<PathBuf, BridgeError> {
        if !crate::protocol::valid_id(project_id) { return Err(BridgeError::invalid()); }
        let projects = self.projects.lock().map_err(|_| BridgeError::new("unavailable", "The project registry is unavailable."))?;
        projects.get(project_id).map(|project| project.root.clone())
            .ok_or_else(|| BridgeError::new("unknown_project", "Select this project through the native folder picker first."))
    }
    pub fn open_config_edit(&self, window: &str, project_id: String) -> Result<ConfigEditStatus, BridgeError> {
        if self.supervisor.stopping() { return Err(BridgeError::shutdown()); }
        if self.supervisor.disabled() { return Err(BridgeError::cleanup_unknown()); }
        // The same exact native-selected root is retained separately from its
        // display string. The edit registry linearizes registration with STOP
        // and document invalidation after this in-memory lookup.
        let root = self.project_root(&project_id)?;
        self.edits.open(window, project_id, root)
    }
    pub(crate) fn open_workflow_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        project_id: String) -> Result<crate::github_workflow_edit_protocol::WorkflowEditStatus, BridgeError> {
        // A ticket contains only preallocated identity/executor DATA. The real
        // document mutex rechecks admission and encloses native_project plus
        // the shared owner's synchronous claim/enqueue, with no path fallback.
        let ticket = self.edits.workflow_open_ticket(window)?;
        let selected = project_id.clone();
        document.workflow_edit_admit(|_| Ok(selected), |bridge, registration|
            bridge.edits.open_workflow(window, project_id, registration, ticket))
    }
    pub(crate) fn prepare_workflow_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        args: crate::github_workflow_edit_protocol::PrepareWorkflowEdit) -> Result<crate::github_workflow_edit_protocol::WorkflowEditStatus, BridgeError> {
        let session_id = args.session_id.clone();
        document.workflow_edit_admit(|bridge| bridge.edits.workflow_project(window, &session_id), |bridge, registration|
            bridge.edits.prepare_workflow(window, args, registration))
    }
    pub(crate) fn apply_workflow_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        session_id: &str, plan_token: &str) -> Result<crate::github_workflow_edit_protocol::WorkflowEditStatus, BridgeError> {
        document.workflow_edit_admit(|bridge| bridge.edits.workflow_project(window, session_id), |bridge, registration|
            bridge.edits.apply_workflow(window, session_id, plan_token, registration))
    }
    pub(crate) fn open_metadata_text_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        args: crate::metadata_text_commands::Open) -> Result<crate::metadata_text_edit_protocol::MetadataTextEditStatus, BridgeError> {
        let ticket = self.edits.metadata_text_open_ticket(window)?;
        let context = args.context();
        let selected = args.project_id.clone();
        document.metadata_text_edit_admit(|_| Ok(selected), |bridge, registration|
            bridge.edits.open_metadata_text(window, args.project_id, context, registration, ticket))
    }
    pub(crate) fn prepare_metadata_text_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        args: crate::metadata_text_edit_protocol::PrepareMetadataTextEdit) -> Result<crate::metadata_text_edit_protocol::MetadataTextEditStatus, BridgeError> {
        let session_id = args.session_id.clone();
        document.metadata_text_edit_admit(|bridge| bridge.edits.metadata_text_project(window, &session_id), |bridge, registration|
            bridge.edits.prepare_metadata_text(window, args, registration))
    }
    pub(crate) fn apply_metadata_text_edit(&self, document: &crate::asset_session::DocumentBinding, window: &str,
        session_id: &str, plan_token: &str) -> Result<crate::metadata_text_edit_protocol::MetadataTextEditStatus, BridgeError> {
        document.metadata_text_edit_admit(|bridge| bridge.edits.metadata_text_project(window, session_id), |bridge, registration|
            bridge.edits.apply_metadata_text(window, session_id, plan_token, registration))
    }
    /// Only called while the real DocumentBinding admission lock is held. No
    /// project method calls back into that lock. These are private native hints.
    pub(crate) fn native_roster(&self) -> Result<ProjectRoster, crate::asset_commands::AssetError> {
        use crate::asset_commands::{AssetError, Reason};
        let projects = self.projects.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        let mut roots = Vec::new(); roots.try_reserve_exact(projects.len()).map_err(|_| AssetError::new(Reason::Capacity))?;
        for project in projects.values() {
            roots.push(crate::asset_source::RegisteredRoot { path: project.root.clone(), identity: project.identity.ok_or_else(|| AssetError::new(Reason::Unqualified))? });
        }
        Ok(ProjectRoster { generation: self.project_generation.load(Ordering::SeqCst), roots })
    }
    pub(crate) fn native_project(&self, id: &str) -> Result<(u32, crate::asset_source::RegisteredRoot), crate::asset_commands::AssetError> {
        use crate::asset_commands::{AssetError, Reason};
        let projects = self.projects.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        let project = projects.get(id).ok_or_else(AssetError::invalid)?;
        Ok((self.project_generation.load(Ordering::SeqCst), crate::asset_source::RegisteredRoot {
            path: project.root.clone(), identity: project.identity.ok_or_else(|| AssetError::new(Reason::Unqualified))?,
        }))
    }
    /// In-memory native registration only. GitHub observations receive neither
    /// a root/path nor filesystem authority. Hold the real registry mutex while
    /// checking membership and its generation; an atomic sample alone is not
    /// a registration and poisoned state must never be recovered as usable.
    pub(crate) fn github_registration(&self, id: &str) -> Result<u32, crate::asset_commands::AssetError> {
        use crate::asset_commands::{AssetError, Reason};
        if !crate::protocol::valid_id(id) { return Err(AssetError::invalid()); }
        let projects = self.projects.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        if !projects.contains_key(id) { return Err(AssetError::invalid()); }
        let generation = self.project_generation.load(Ordering::SeqCst);
        if generation == 0 { return Err(AssetError::new(Reason::CleanupUnknown)); }
        Ok(generation)
    }
    pub(crate) fn registry_generation(&self) -> u32 { self.project_generation.load(Ordering::SeqCst) }
    pub(crate) fn native_generation(&self) -> Result<u32, crate::asset_commands::AssetError> {
        let _projects = self.projects.lock().map_err(|_| crate::asset_commands::AssetError::new(crate::asset_commands::Reason::CleanupUnknown))?;
        Ok(self.project_generation.load(Ordering::SeqCst))
    }

    #[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    pub(crate) fn publish_checked_project(&self, proof: crate::asset_source::ProjectProbe, expected_generation: u32) -> Result<Project, crate::asset_commands::AssetError> {
        use crate::asset_commands::{AssetError, Reason};
        let mut projects = self.projects.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        if self.project_generation.load(Ordering::SeqCst) != expected_generation { return Err(AssetError::new(Reason::ContextStale)); }
        if let Some(existing) = projects.values().find(|entry| entry.root == proof.path()) {
            if existing.identity != Some(proof.identity()) { return Err(AssetError::new(Reason::SourceChanged)); }
            return Ok(existing.view.clone());
        }
        if projects.len() >= 64 { return Err(AssetError::new(Reason::Capacity)); }
        let text = proof.path().to_str().ok_or_else(AssetError::invalid)?;
        if text.len() > crate::asset_source::PATH_LIMIT { return Err(AssetError::invalid()); }
        let next_generation = expected_generation.checked_add(1).ok_or_else(|| AssetError::new(Reason::CleanupUnknown))?;
        let sequence = self.sequence.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1))
            .map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        let project = Project { id: format!("project-{sequence}"),
            name: proof.path().file_name().and_then(|name| name.to_str()).unwrap_or(text).to_owned(), path: text.to_owned() };
        projects.insert(project.id.clone(), RegisteredProject { view: project.clone(), root: proof.path().to_path_buf(), identity: Some(proof.identity()) });
        self.project_generation.store(next_generation, Ordering::SeqCst);
        Ok(project)
    }
    #[cfg(all(feature = "desktop-shell", not(target_os = "linux")))]
    pub(crate) fn register_picked_project(&self, path: PathBuf) -> Result<Project, BridgeError> {
        if self.supervisor.stopping() || self.edits.stopping() { return Err(BridgeError::shutdown()); }
        if self.supervisor.disabled() || self.edits.disabled() { return Err(BridgeError::cleanup_unknown()); }
        let text = path.to_str().ok_or_else(|| BridgeError::new("unsupported_path", "The selected project path is not valid UTF-8."))?;
        if text.len() > 4096 || !path.is_absolute() || path.components().any(|component| matches!(component, Component::ParentDir | Component::CurDir)) {
            return Err(BridgeError::new("unsupported_path", "Select an absolute project folder without ambiguous components."));
        }
        let mut projects = self.projects.lock().map_err(|_| BridgeError::new("unavailable", "The project registry is unavailable."))?;
        if let Some(project) = projects.values().find(|project| project.root == path) { return Ok(project.view.clone()); }
        if projects.len() >= 64 { return Err(BridgeError::new("project_limit", "This session has reached its 64-project selection limit.")); }
        let sequence = self.sequence.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1))
            .map_err(|_| BridgeError::new("unavailable", "The project identity space is exhausted."))?;
        let project = Project {
            id: format!("project-{sequence}"),
            name: path.file_name().and_then(|name| name.to_str()).unwrap_or(text).to_owned(), path: text.to_owned(),
        };
        let generation = self.project_generation.load(Ordering::SeqCst).checked_add(1)
            .ok_or_else(|| BridgeError::new("unavailable", "The project registry generation is exhausted."))?;
        projects.insert(project.id.clone(), RegisteredProject { view: project.clone(), root: path, identity: None });
        self.project_generation.store(generation, Ordering::SeqCst);
        Ok(project)
    }
}
