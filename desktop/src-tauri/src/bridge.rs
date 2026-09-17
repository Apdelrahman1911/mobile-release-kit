//! Renderer authority ends at these seven typed passive operations. Project roots can
//! enter the registry only through the Rust-side native picker.
use std::{collections::BTreeMap, path::PathBuf, sync::Mutex};
#[cfg(feature = "desktop-shell")]
use std::{path::Component, sync::atomic::{AtomicU64, Ordering}};
use serde::Serialize;
use serde_json::{json, Value};
use crate::{error::BridgeError, protocol::Method, runtime::{RuntimeConfig, RuntimeStatus}, supervisor::Supervisor};

#[derive(Clone, Debug, Serialize)]
pub struct Project { pub id: String, pub name: String, pub path: String }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub app_name: &'static str, pub app_version: &'static str,
    pub runtime: RuntimeStatus, pub capabilities: Option<Value>,
}

pub struct DesktopBridge {
    pub supervisor: Supervisor, projects: Mutex<BTreeMap<String, Project>>,
    #[cfg(feature = "desktop-shell")]
    sequence: AtomicU64,
}
impl DesktopBridge {
    pub fn new(resource_dir: PathBuf) -> Self {
        Self {
            supervisor: Supervisor::new(RuntimeConfig::packaged(resource_dir)), projects: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "desktop-shell")]
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
    pub async fn project_snapshot(&self, project_id: String) -> Result<Value, BridgeError> {
        let root = {
            let projects = self.projects.lock().map_err(|_| BridgeError::new("unavailable", "The project registry is unavailable."))?;
            projects.get(&project_id).map(|project| project.path.clone())
                .ok_or_else(|| BridgeError::new("unknown_project", "Select this project through the native folder picker first."))?
        };
        self.supervisor.query(Method::ProjectSnapshot, json!({"root": root})).await
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn register_picked_project(&self, path: PathBuf) -> Result<Project, BridgeError> {
        if self.supervisor.stopping() { return Err(BridgeError::shutdown()); }
        if self.supervisor.disabled() { return Err(BridgeError::cleanup_unknown()); }
        let text = path.to_str().ok_or_else(|| BridgeError::new("unsupported_path", "The selected project path is not valid UTF-8."))?;
        if text.len() > 4096 || !path.is_absolute() || path.components().any(|component| matches!(component, Component::ParentDir | Component::CurDir)) {
            return Err(BridgeError::new("unsupported_path", "Select an absolute project folder without ambiguous components."));
        }
        let mut projects = self.projects.lock().map_err(|_| BridgeError::new("unavailable", "The project registry is unavailable."))?;
        if let Some(project) = projects.values().find(|project| project.path == text) { return Ok(project.clone()); }
        if projects.len() >= 64 { return Err(BridgeError::new("project_limit", "This session has reached its 64-project selection limit.")); }
        let sequence = self.sequence.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1))
            .map_err(|_| BridgeError::new("unavailable", "The project identity space is exhausted."))?;
        let project = Project {
            id: format!("project-{sequence}"),
            name: path.file_name().and_then(|name| name.to_str()).unwrap_or(text).to_owned(), path: text.to_owned(),
        };
        projects.insert(project.id.clone(), project.clone());
        Ok(project)
    }
}
