//! Fixed application services. Project roots enter the registry only through
//! the Rust-side native picker, never through a renderer-supplied path.
use std::{collections::BTreeMap, path::PathBuf, sync::{Mutex, atomic::{AtomicU32, Ordering}}};
#[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
use std::sync::atomic::AtomicU64;
#[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos"))))]
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
    pub runtime: RuntimeStatus, pub capabilities: Option<Value>, pub project_selection: ProjectSelectionAvailability,
    pub project_path_selection: ProjectPathSelectionAvailability,
}
#[derive(Serialize)]
pub struct ProjectSelectionAvailability { pub available: bool, pub reason: Option<&'static str> }
impl ProjectSelectionAvailability {
    fn new(available: bool) -> Self {
        Self { available, reason: if available { None } else { Some("Project selection is not available in the current desktop runtime profile.") } }
    }
}
#[derive(Serialize)]
pub struct ProjectPathSelectionAvailability { pub available: bool, pub reason: Option<&'static str> }
impl ProjectPathSelectionAvailability {
    fn new(available: bool) -> Self {
        Self { available, reason: if available { None } else { Some("Browsing existing project paths is not available in the current desktop runtime profile.") } }
    }
}

fn native_capabilities(mut value: Value, available: impl Fn(&str) -> bool) -> Value {
    if let Some(methods) = value.get_mut("methods").and_then(Value::as_array_mut) {
        for method in methods {
            let admitted = method.get("method").and_then(Value::as_str).is_some_and(&available);
            if method.get("available").and_then(Value::as_bool) == Some(true) && !admitted {
                if let Some(row) = method.as_object_mut() {
                    row.insert("available".into(), Value::Bool(false));
                    row.insert("reason".into(), Value::String("This function is not available in the current desktop runtime profile.".into()));
                }
            }
        }
    }
    value
}

#[cfg(any(feature = "desktop-shell", test))]
#[derive(Clone, Copy)]
enum CapabilitiesFailureOrigin { Admission, QueryWait }

#[cfg(any(feature = "desktop-shell", test))]
fn capabilities_failure_line(origin: CapabilitiesFailureOrigin, error: &BridgeError) -> &'static [u8] {
    // Only complete source literals leave this classifier. QueryWait means the
    // SAME original wait returned an error, not that dispatch/finality succeeded.
    use CapabilitiesFailureOrigin::{Admission, QueryWait};
    match (origin, error.code.as_str()) {
        (Admission, "runtime_unavailable") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-runtime_unavailable\n",
        (Admission, "cleanup_unknown") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-cleanup_unknown\n",
        (Admission, "invalid_request") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-invalid_request\n",
        (Admission, "shutting_down") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-shutting_down\n",
        (Admission, "busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-busy\n",
        (Admission, "unavailable") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-unavailable\n",
        (Admission, "offline_preflight_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-offline_preflight_busy\n",
        (Admission, "android_build_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-android_build_busy\n",
        (Admission, "environment_diagnostics_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-environment_diagnostics_busy\n",
        (Admission, "query_timeout") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-query_timeout\n",
        (Admission, "protocol_error") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-protocol_error\n",
        (Admission, "engine_failed") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-engine_failed\n",
        (Admission, "io_error") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-io_error\n",
        (Admission, "output_limit") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-output_limit\n",
        (Admission, _) => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-other\n",
        (QueryWait, "runtime_unavailable") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-runtime_unavailable\n",
        (QueryWait, "cleanup_unknown") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-cleanup_unknown\n",
        (QueryWait, "invalid_request") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-invalid_request\n",
        (QueryWait, "shutting_down") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-shutting_down\n",
        (QueryWait, "busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-busy\n",
        (QueryWait, "unavailable") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-unavailable\n",
        (QueryWait, "offline_preflight_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-offline_preflight_busy\n",
        (QueryWait, "android_build_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-android_build_busy\n",
        (QueryWait, "environment_diagnostics_busy") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-environment_diagnostics_busy\n",
        (QueryWait, "query_timeout") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-query_timeout\n",
        (QueryWait, "protocol_error") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-protocol_error\n",
        (QueryWait, "engine_failed") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-engine_failed\n",
        (QueryWait, "io_error") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-io_error\n",
        (QueryWait, "output_limit") => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-output_limit\n",
        (QueryWait, _) => b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-other\n",
    }
}

struct RegisteredProject { view: Project, root: PathBuf, identity: Option<crate::asset_source::DirectoryIdentity> }
pub(crate) struct ProjectRoster { pub(crate) generation: u32, pub(crate) roots: Vec<crate::asset_source::RegisteredRoot> }

pub struct DesktopBridge {
    pub supervisor: Supervisor,
    pub edits: EditOwner,
    pub(crate) diagnostics: crate::environment_diagnostics_owner::EnvironmentDiagnosticsOwner,
    pub(crate) preflight: crate::offline_preflight_owner::OfflinePreflightOwner,
    pub(crate) android_build: crate::android_build_owner::AndroidBuildOwner,
    installed_project_selection_available: bool,
    installed_project_path_selection_available: bool,
    installed_evidence_selection_available: bool,
    projects: Mutex<BTreeMap<String, RegisteredProject>>,
    project_generation: AtomicU32,
    #[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    sequence: AtomicU64,
}
impl DesktopBridge {
    pub fn new(resource_dir: PathBuf) -> Self {
        let runtime = RuntimeConfig::packaged(resource_dir);
        let installed_project_selection_available = runtime.project_selection_profile_available();
        let installed_project_path_selection_available = runtime.project_path_selection_profile_available();
        let installed_evidence_selection_available = runtime.evidence_selection_profile_available();
        Self {
            supervisor: Supervisor::new(runtime.clone()), edits: EditOwner::new(runtime.clone()),
            diagnostics: crate::environment_diagnostics_owner::EnvironmentDiagnosticsOwner::new(runtime.clone()),
            preflight: crate::offline_preflight_owner::OfflinePreflightOwner::new(runtime.clone()),
            // Retain the owner and compiled profile DATA only; neither is tool
            // custody or qualification. The renderer cannot select this profile.
            android_build: crate::android_build_owner::AndroidBuildOwner::new(runtime, crate::android_toolchain::AndroidToolchainProfile::compiled()),
            installed_project_selection_available,
            installed_project_path_selection_available,
            installed_evidence_selection_available,
            projects: Mutex::new(BTreeMap::new()), project_generation: AtomicU32::new(1),
            #[cfg(any(feature = "desktop-shell", all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
            sequence: AtomicU64::new(1),
        }
    }
    pub(crate) fn installed_project_selection_available(&self) -> bool { self.installed_project_selection_available }
    pub(crate) fn installed_project_path_selection_available(&self) -> bool { self.installed_project_path_selection_available }
    pub(crate) fn installed_evidence_selection_available(&self) -> bool { self.installed_evidence_selection_available }
    pub(crate) async fn app_info(&self, document: &crate::asset_session::DocumentBinding) -> AppInfo {
        let result = match document.passive_query(self, Method::Capabilities, json!({})) {
            Ok(query) => {
                let result = query.wait().await;
                #[cfg(feature = "desktop-shell")]
                if let Err(error) = &result {
                    crate::shell::diagnostic(capabilities_failure_line(CapabilitiesFailureOrigin::QueryWait, error));
                }
                result
            },
            Err(error) => {
                #[cfg(feature = "desktop-shell")]
                crate::shell::diagnostic(capabilities_failure_line(CapabilitiesFailureOrigin::Admission, &error));
                Err(error)
            },
        };
        let (runtime, capabilities) = match result {
            Ok(value) => (RuntimeStatus { state: "available", reason: None, mode: self.supervisor.runtime_mode() },
                Some(native_capabilities(value, |name| self.supervisor.passive_method_available(name)))),
            Err(error) => (RuntimeStatus {
                state: if self.supervisor.disabled() { "disabled" } else { "unavailable" },
                reason: Some(error.message), mode: self.supervisor.runtime_mode(),
            }, None),
        };
        // Display DATA only. Selection does not imply that snapshot or any
        // other core method is available, nor that live native admission holds.
        AppInfo { app_name: "Mobile Release Kit", app_version: env!("CARGO_PKG_VERSION"), runtime, capabilities,
            project_selection: ProjectSelectionAvailability::new(document.project_selection_available()),
            project_path_selection: ProjectPathSelectionAvailability::new(document.project_path_selection_available()) }
    }
    pub(crate) async fn catalog(&self, document: &crate::asset_session::DocumentBinding) -> Result<Value, BridgeError> { document.passive_query(self, Method::Catalog, json!({}))?.wait().await }
    pub(crate) async fn environment_requirements(&self, document: &crate::asset_session::DocumentBinding, input: crate::environment::Request) -> Result<crate::environment::Requirements, BridgeError> {
        // Current draft DATA only; no selected path, tool or execution owner.
        let context = input.context();
        let value = document.passive_query(self, Method::EnvironmentRequirements, input.into_params()?).map_err(crate::environment::public_error)?.wait().await
            .map_err(crate::environment::public_error)?;
        crate::environment::result(value, context)
    }
    pub(crate) async fn validate_config(&self, document: &crate::asset_session::DocumentBinding, draft: Value) -> Result<Value, BridgeError> {
        if !draft.is_object() { return Err(BridgeError::invalid()); }
        document.passive_query(self, Method::ValidateConfig, json!({"draft": draft}))?.wait().await
    }
    pub(crate) async fn suggest_config(&self, document: &crate::asset_session::DocumentBinding, hints: Value) -> Result<Value, BridgeError> {
        if !hints.is_object() { return Err(BridgeError::invalid()); }
        document.passive_query(self, Method::SuggestConfig, json!({"hints": hints}))?.wait().await
    }
    pub(crate) async fn preview_config(&self, document: &crate::asset_session::DocumentBinding, base: Value, draft: Value) -> Result<Value, BridgeError> {
        // Both documents are caller-owned draft data, never a disk revision or
        // permission to write. Only the core derives policy and change summaries.
        if !(base.is_null() || base.is_object()) || !draft.is_object() { return Err(BridgeError::invalid()); }
        document.passive_query(self, Method::PreviewConfig, json!({"base": base, "draft": draft}))?.wait().await
    }
    pub(crate) async fn propose_github_setup(&self, document: &crate::asset_session::DocumentBinding, input: crate::github_commands::Proposal) -> Result<Value, BridgeError> {
        // A passive proposal has no selected-root, login, write or dispatch
        // authority. Only the core renders its fixed shipped workflow set.
        document.passive_query(self, Method::ProposeGithubSetup, input.into_params()?)?.wait().await
    }
    pub(crate) async fn project_snapshot(&self, document: &crate::asset_session::DocumentBinding, project_id: String) -> Result<Value, BridgeError> {
        let root = self.project_root(&project_id)?;
        document.passive_query(self, Method::ProjectSnapshot, json!({"root": root}))?.wait().await
    }
    pub(crate) async fn observe_release_version(&self, document: &crate::asset_session::DocumentBinding, input: crate::release_version_protocol::Request) -> Result<crate::release_version_protocol::Observation, BridgeError> {
        // Native-selected root only. The existing passive owner/runtime gate is
        // unchanged; this observation creates no write or preflight authority.
        let root = self.project_root(&input.project_id).map_err(crate::release_version_protocol::public_error)?;
        let params = crate::release_version_protocol::params(&root)?;
        let value = document.passive_query(self, Method::ReleaseVersionObserve, params).map_err(crate::release_version_protocol::public_error)?.wait().await
            .map_err(crate::release_version_protocol::public_error)?;
        crate::release_version_protocol::result(value)
    }
    pub(crate) async fn observe_candidate_evidence(&self, root: &crate::asset_source::RegisteredRoot) -> Result<crate::candidate_evidence_protocol::Observation, BridgeError> {
        // Only the separate native evidence registry can supply this identity.
        // The caller retains its original coordinator through query settlement.
        let params = crate::candidate_evidence_protocol::params(root)?;
        let value = self.supervisor.query(Method::CandidateEvidenceObserve, params).await?;
        crate::candidate_evidence_protocol::result(value)
    }
    pub(crate) async fn observe_metadata_text(&self, document: &crate::asset_session::DocumentBinding, input: crate::metadata_text_commands::Open) -> Result<crate::metadata_text_edit_protocol::Observation, BridgeError> {
        // Only the native-selected root reaches this bounded named-file query.
        // No checkout/write authority is created by a passive observation.
        let root = self.project_root(&input.project_id)?;
        let value = document.passive_query(self, Method::MetadataTextObserve, json!({"root":root,"platform":input.platform,"locale":&input.locale}))?.wait().await?;
        crate::metadata_text_edit_protocol::observation_result(value, input.platform, &input.locale)
    }
    pub(crate) async fn validate_metadata_text(&self, document: &crate::asset_session::DocumentBinding, input: crate::metadata_text_commands::Validate) -> Result<crate::metadata_text_edit_protocol::ValidationResult, BridgeError> {
        let value = document.passive_query(self, Method::MetadataTextValidate, json!({"platform":input.platform,"fields":&input.fields}))?.wait().await?;
        crate::metadata_text_edit_protocol::validation_result(value, input.platform, &input.fields)
    }
    fn project_root(&self, project_id: &str) -> Result<PathBuf, BridgeError> {
        if !crate::protocol::valid_id(project_id) { return Err(BridgeError::invalid()); }
        let projects = self.projects.lock().map_err(|_| BridgeError::new("unavailable", "The project registry is unavailable."))?;
        projects.get(project_id).map(|project| project.root.clone())
            .ok_or_else(|| BridgeError::new("unknown_project", "Select this project through the native folder picker first."))
    }
    /// Native registry DATA only, under DocumentBinding's admission mutex.
    /// No selected directory is opened or discovery executed. This retained
    /// path is solely overlap context, not a claim of qualified root custody.
    pub(crate) fn environment_registration(&self, project_id: &str) -> Result<(u32, PathBuf), BridgeError> {
        if !crate::protocol::valid_id(project_id) { return Err(crate::environment_diagnostics_protocol::invalid()); }
        let projects = self.projects.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let root = projects.get(project_id).ok_or_else(|| BridgeError::new("unknown_project", "Select this project through the native folder picker first."))?;
        Ok((self.project_generation.load(Ordering::SeqCst), root.root.clone()))
    }
    /// Fixture DATA only, called under the original DocumentBinding lock. It
    /// grants no ProjectProbe, picker, filesystem identity, asset or GitHub gate.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn environment_fixture_registration(&self,
        permit: &crate::environment_diagnostics_owner::EnvironmentRegistrationPermit, change: bool) -> Result<(), BridgeError> {
        let (id, root, generation) = permit.validate(&self.diagnostics)?;
        let mut projects = self.projects.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let current = self.project_generation.load(Ordering::SeqCst);
        if change {
            if current != generation || !projects.get(id).is_some_and(|p| p.root == root) { return Err(BridgeError::invalid()); }
            self.project_generation.store(current.checked_add(1).ok_or_else(BridgeError::cleanup_unknown)?, Ordering::SeqCst);
        } else {
            if !projects.is_empty() || current != 1 || generation != 2 { return Err(BridgeError::invalid()); }
            let view = Project { id: id.into(), name: "Synthetic diagnostics project".into(), path: root.to_string_lossy().into_owned() };
            projects.insert(id.into(), RegisteredProject { view, root: root.to_path_buf(), identity: None });
            self.project_generation.store(generation, Ordering::SeqCst);
        }
        Ok(())
    }
    /// Separate offline fixture permit and actual held-root identity. Never
    /// upgrade the diagnostics fixture's identity:None registration in place.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn offline_fixture_registration(&self,
        permit: &crate::offline_preflight_owner::OfflineRegistrationPermit) -> Result<(), BridgeError> {
        let (id, root, generation) = permit.validate(&self.preflight)?;
        let mut projects = self.projects.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !projects.is_empty() || self.project_generation.load(Ordering::SeqCst) != 1 || generation != 2 {
            return Err(BridgeError::invalid());
        }
        let view = Project { id: id.into(), name: "Synthetic saved offline project".into(), path: root.path.to_string_lossy().into_owned() };
        projects.insert(id.into(), RegisteredProject { view, root: root.path.clone(), identity: Some(root.identity) });
        self.project_generation.store(generation, Ordering::SeqCst);
        Ok(())
    }
    pub fn open_config_edit(&self, window: &str, project_id: String) -> Result<ConfigEditStatus, BridgeError> {
        self.preflight.ensure_idle()?;
        self.android_build.ensure_idle()?;
        self.diagnostics.ensure_idle()?;
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
    #[cfg(all(feature = "desktop-shell", not(any(target_os = "linux", target_os = "macos"))))]
    pub(crate) fn register_picked_project(&self, path: PathBuf) -> Result<Project, BridgeError> {
        self.preflight.ensure_idle()?;
        self.android_build.ensure_idle()?;
        self.diagnostics.ensure_idle()?;
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

#[cfg(test)]
pub(crate) fn assert_native_capability_intersection_contract() {
    let input = json!({"coreVersion": "0.3.0", "actions": [{"action": "release", "available": false}],
        "methods": [
            {"method": "capabilities", "available": true, "reason": "implemented"},
            {"method": "catalog", "available": false, "reason": "core refusal"},
            {"method": "project.snapshot", "available": true, "reason": "implemented"},
            {"method": "config.validate", "available": true, "reason": "implemented"},
            {"method": "config.suggest", "available": false, "reason": "core refusal"},
            {"method": "config.preview", "available": true, "reason": "implemented"},
            {"method": "environment.requirements", "available": true, "reason": "implemented"},
            {"method": "github.setup.propose", "available": false, "reason": "core refusal"},
            {"method": "release.version.observe", "available": true, "reason": "implemented"},
            {"method": "future.method", "available": true, "reason": "implemented"}
        ]});
    let result = native_capabilities(input.clone(), |name|
        matches!(name, "capabilities" | "catalog" | "project.snapshot" | "config.validate" | "config.suggest" | "config.preview"
            | "environment.requirements" | "github.setup.propose"));
    assert_eq!(result["coreVersion"], input["coreVersion"]);
    assert_eq!(result["actions"], input["actions"]);
    for index in 0..8 { assert_eq!(result["methods"][index], input["methods"][index]); }
    for index in [8, 9] {
        assert_eq!(result["methods"][index]["available"], false);
        assert_eq!(result["methods"][index]["method"], input["methods"][index]["method"]);
        assert_eq!(result["methods"][index]["reason"], "This function is not available in the current desktop runtime profile.");
    }
}

#[cfg(test)]
pub(crate) fn assert_project_path_availability_contract() {
    // Display DATA only: no runtime resolution, native owner or asset permit.
    for available in [false, true] {
        let value = serde_json::to_value(ProjectPathSelectionAvailability::new(available)).unwrap();
        assert_eq!(value, json!({"available": available, "reason": if available { None } else {
            Some("Browsing existing project paths is not available in the current desktop runtime profile.") }}));
        assert!(serde_json::to_vec(&value).unwrap().len() <= 1024);
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    #[test]
    fn capability_failure_diagnostic_is_closed_data_with_original_origins() {
        let codes = ["runtime_unavailable", "cleanup_unknown", "invalid_request", "shutting_down", "busy", "unavailable",
            "offline_preflight_busy", "android_build_busy", "environment_diagnostics_busy", "query_timeout",
            "protocol_error", "engine_failed", "io_error", "output_limit"];
        let mut records = std::collections::BTreeSet::new();
        for (origin, name) in [(CapabilitiesFailureOrigin::Admission, "admission"), (CapabilitiesFailureOrigin::QueryWait, "query-wait")] {
            for code in codes {
                let error = BridgeError::new(code, "PRIVATE_MESSAGE must not enter diagnostic DATA");
                let original = error.clone();
                let line = capabilities_failure_line(origin, &error);
                assert_eq!(line, format!("MRKDBG_DESKTOP_BOOTSTRAP=capabilities-{name}-{code}\n").as_bytes());
                assert!(line.len() <= 78 && records.insert(line));
                assert_eq!(error, original);
            }
            let long_code = "PRIVATE_CODE".repeat(1024);
            for code in ["", "PRIVATE_CODE", "runtime_unavailable\nPRIVATE_CODE", "runtime_unavailable\r", "\u{1b}[31mPRIVATE_CODE", long_code.as_str()] {
                let error = BridgeError::new(code, "PRIVATE_MESSAGE");
                let line = capabilities_failure_line(origin, &error);
                assert_eq!(line, format!("MRKDBG_DESKTOP_BOOTSTRAP=capabilities-{name}-other\n").as_bytes());
                assert!(line.len() <= 78);
                records.insert(line);
            }
        }
        assert_eq!(records.len(), 30);
    }
    #[test]
    fn project_path_availability_is_separate_bounded_display_data() { assert_project_path_availability_contract(); }
    #[test]
    fn core_availability_is_intersected_without_enabling_actions_or_rewriting_core_failures() {
        assert_native_capability_intersection_contract();
    }
    #[test]
    fn project_selection_availability_is_bounded_display_data() {
        assert_eq!(serde_json::to_value(ProjectSelectionAvailability::new(true)).unwrap(),
            json!({"available": true, "reason": null}));
        assert_eq!(serde_json::to_value(ProjectSelectionAvailability::new(false)).unwrap(),
            json!({"available": false, "reason": "Project selection is not available in the current desktop runtime profile."}));
    }
}
